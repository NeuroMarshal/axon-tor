//! A running Tor client: an Axon node whose forwarding plane is
//! [`TorPlane`] and whose links speak Tor's link protocol, with the
//! directory it bootstrapped and the circuits it keeps.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use axon_addons::wire::{ForeignLink, foreign_link};
use axon_core::node::{EdgeId, ExtensionId, NodeCore, NodeId};
use axon_runtime::{NodeHandle, RuntimeConfig, RuntimeError, http::Response};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpStream,
    sync::mpsc,
    time::{Instant, sleep, timeout, timeout_at},
};

use crate::{
    cell::{
        ESTABLISH_RENDEZVOUS, INTRODUCE_ACK, INTRODUCE1, RELAY_DATA_LEN, RENDEZVOUS_ESTABLISHED,
        RENDEZVOUS2, RelayMessage,
    },
    directory::{
        AUTHORITIES, Consensus, KeyCertificate, Microdescriptor, Relay, flags,
        parse_key_certificates, parse_microdescriptors,
    },
    link::{RelayTarget, TorLink},
    now_seconds,
    onion::{self, DEFAULT_PERIOD_LENGTH},
    plane::{CircuitEvent, CircuitRef, Hop, StreamEvent, TOR_PLANE, TOR_PLANE_VERSION, TorPlane},
};

/// Extension id of Tor links.
pub const TOR_LINK: ExtensionId = ExtensionId(0x544f_524c); // TORL
/// Largest cell a link carries: variable cells have a 16-bit length.
const MAXIMUM_ENVELOPE: usize = 65_535 + 7;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Microdescriptors asked for in one request, which keeps the URL short.
const MICRODESCRIPTOR_BATCH: usize = 90;
/// Directory circuits used in parallel to fetch microdescriptors.
const DIRECTORY_CIRCUITS: usize = 4;
/// Circuits to exits and onion services are reused for this long.
const CIRCUIT_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// How long each step of reaching an onion service may take.
const ONION_STEP: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum TorError {
    Runtime(RuntimeError),
    Directory(String),
    Circuit(String),
    Stream(String),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "{error}"),
            Self::Directory(message) => write!(formatter, "directory: {message}"),
            Self::Circuit(message) => write!(formatter, "circuit: {message}"),
            Self::Stream(message) => write!(formatter, "stream: {message}"),
        }
    }
}

impl std::error::Error for TorError {}

impl From<RuntimeError> for TorError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

/// The consensus and the microdescriptors of its relays.
pub struct NetworkDirectory {
    pub consensus: Consensus,
    pub microdescriptors: HashMap<[u8; 32], Microdescriptor>,
}

impl NetworkDirectory {
    pub fn microdescriptor(&self, relay: &Relay) -> Option<&Microdescriptor> {
        self.microdescriptors.get(&relay.microdescriptor)
    }

    /// The hop for a relay whose microdescriptor is known.
    pub fn hop(&self, relay: &Relay) -> Option<Hop> {
        let micro = self.microdescriptor(relay)?;
        Some(Hop {
            target: RelayTarget {
                address: relay.address,
                rsa_identity: relay.rsa_identity,
                ed25519_identity: micro.ed25519_identity,
            },
            ntor_key: Some(micro.ntor_onion_key),
        })
    }

    /// A random relay with all of `required` flags that passes `accept`,
    /// weighted by bandwidth.
    pub fn pick(&self, required: u16, accept: impl Fn(&Relay) -> bool) -> Option<&Relay> {
        let candidates = self
            .consensus
            .relays
            .iter()
            .filter(|relay| relay.has(required | flags::RUNNING | flags::VALID))
            .filter(|relay| self.microdescriptor(relay).is_some() && accept(relay))
            .collect::<Vec<_>>();
        let total = candidates
            .iter()
            .map(|relay| relay.bandwidth.max(1))
            .sum::<u64>();
        if total == 0 {
            return None;
        }
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).expect("system random source");
        let mut point = u64::from_le_bytes(random) % total;
        candidates.into_iter().find(|relay| {
            let weight = relay.bandwidth.max(1);
            if point < weight {
                return true;
            }
            point -= weight;
            false
        })
    }
}

/// Two relays in the same /16 should not share a circuit.
fn same_network(a: &Relay, b: &Relay) -> bool {
    same_network_address(&a.address, &b.address)
}

fn same_network_address(a: &std::net::SocketAddr, b: &std::net::SocketAddr) -> bool {
    match (a.ip(), b.ip()) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => a.octets()[..2] == b.octets()[..2],
        (a, b) => a == b,
    }
}

/// A built circuit and the channel its events arrive on.
pub struct Circuit {
    pub reference: CircuitRef,
    pub events: mpsc::UnboundedReceiver<CircuitEvent>,
}

struct PooledCircuit {
    circuit: Circuit,
    exit: Relay,
    built: Instant,
}

struct OnionCircuit {
    circuit: Circuit,
    built: Instant,
}

#[derive(Clone)]
pub struct TorClient {
    handle: NodeHandle,
    directory: Arc<RwLock<Option<Arc<NetworkDirectory>>>>,
    guard: Arc<Mutex<Option<Relay>>>,
    exits: Arc<tokio::sync::Mutex<Vec<PooledCircuit>>>,
    onions: Arc<tokio::sync::Mutex<HashMap<[u8; 32], OnionCircuit>>>,
}

impl TorClient {
    /// Starts a client on the current tokio runtime.
    pub fn start() -> Result<Self, TorError> {
        let mut id = [0u8; 32];
        getrandom::getrandom(&mut id).expect("system random source");
        let core = NodeCore::builder(NodeId::from_bytes(id), TorPlane::default())
            .build()
            .map_err(RuntimeError::from)?;
        let client = Self {
            handle: axon_runtime::spawn(core, RuntimeConfig::default()),
            directory: Arc::default(),
            guard: Arc::default(),
            exits: Arc::default(),
            onions: Arc::default(),
        };
        tokio::spawn(client.clone().dial_loop());
        Ok(client)
    }

    pub fn handle(&self) -> &NodeHandle {
        &self.handle
    }

    /// Runs `call` on the plane inside the node and sends what it queued.
    pub async fn with_plane<R: Send + 'static>(
        &self,
        call: impl FnOnce(&mut TorPlane) -> R + Send + 'static,
    ) -> Result<R, RuntimeError> {
        self.handle
            .with_core(move |core, now| {
                let plane = core.forwarding_mut::<TorPlane>().expect("a Tor client");
                let result = call(plane);
                let _ = core.poll_forwarding(now);
                result
            })
            .await
    }

    pub fn directory(&self) -> Option<Arc<NetworkDirectory>> {
        self.directory.read().ok()?.clone()
    }

    /// Opens Tor links to the relays the plane has cells for.
    async fn dial_loop(self) {
        let dialing = Arc::new(Mutex::new(BTreeSet::<NodeId>::new()));
        loop {
            let Ok(wanted) = self.with_plane(|plane| plane.wanted_connections()).await else {
                return;
            };
            for (relay, target) in wanted {
                if !dialing.lock().is_ok_and(|mut set| set.insert(relay)) {
                    continue;
                }
                let (this, dialing) = (self.clone(), dialing.clone());
                tokio::spawn(async move {
                    if let Err(error) = this.dial(relay, target).await {
                        let reason = error.to_string();
                        let _ = this
                            .with_plane(move |plane| plane.connection_failed(relay, &reason))
                            .await;
                    }
                    if let Ok(mut set) = dialing.lock() {
                        set.remove(&relay);
                    }
                });
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    async fn dial(&self, relay: NodeId, target: RelayTarget) -> Result<(), RuntimeError> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(target.address))
            .await
            .map_err(|_| RuntimeError::Io("connect timed out".to_owned()))?
            .map_err(|error| RuntimeError::Io(error.to_string()))?;
        let edge = EdgeId(u64::from_be_bytes(
            target.rsa_identity[..8].try_into().expect("8 bytes"),
        ));
        let protocol = TorLink::new(target).map_err(RuntimeError::Node)?;
        let link = foreign_link(
            ForeignLink {
                neighbour: relay,
                edge,
                id: TOR_LINK,
                forwarding_id: TOR_PLANE,
                forwarding_version: TOR_PLANE_VERSION,
                maximum_envelope: MAXIMUM_ENVELOPE,
            },
            protocol,
        );
        self.handle.attach_tcp(link, stream).await
    }

    /// Builds a circuit through `path` and waits until it is ready.
    pub async fn build(&self, path: Vec<Hop>, wait: Duration) -> Result<Circuit, TorError> {
        let (events, mut receiver) = mpsc::unbounded_channel();
        let reference = self
            .with_plane(move |plane| plane.build_circuit(path, events))
            .await?
            .ok_or_else(|| TorError::Circuit("an empty path".to_owned()))?;
        match timeout(wait, receiver.recv()).await {
            Ok(Some(CircuitEvent::Built)) => Ok(Circuit {
                reference,
                events: receiver,
            }),
            Ok(Some(CircuitEvent::Closed(reason))) => Err(TorError::Circuit(reason)),
            Ok(_) => Err(TorError::Circuit("the circuit was dropped".to_owned())),
            Err(_) => {
                let _ = self.with_plane(move |plane| plane.destroy(reference)).await;
                Err(TorError::Circuit("building timed out".to_owned()))
            }
        }
    }

    /// Opens a stream at the end of `circuit`: to `target` (`host:port`) or,
    /// when `target` is None, to the last relay's directory. Waits until
    /// the stream is connected.
    pub async fn open_stream(
        &self,
        circuit: CircuitRef,
        target: Option<String>,
        wait: Duration,
    ) -> Result<DuplexStream, TorError> {
        let (events, mut arrivals) = mpsc::unbounded_channel();
        let stream = self
            .with_plane(move |plane| plane.open_stream(circuit, target.as_deref(), events))
            .await?
            .ok_or_else(|| TorError::Stream("the circuit is not open".to_owned()))?;
        match timeout(wait, arrivals.recv()).await {
            Ok(Some(StreamEvent::Connected)) => {}
            Ok(Some(StreamEvent::Closed(reason))) => {
                return Err(TorError::Stream(format!("refused, reason {reason}")));
            }
            Ok(_) => {
                return Err(TorError::Stream(
                    "unexpected data before CONNECTED".to_owned(),
                ));
            }
            Err(_) => {
                let _ = self
                    .with_plane(move |plane| plane.stream_close(circuit, stream))
                    .await;
                return Err(TorError::Stream("no answer".to_owned()));
            }
        }
        let (local, ours) = tokio::io::duplex(16 * RELAY_DATA_LEN);
        tokio::spawn(self.clone().carry(circuit, stream, ours, arrivals));
        Ok(local)
    }

    /// Moves bytes between a local stream end and a Tor stream.
    async fn carry(
        self,
        circuit: CircuitRef,
        stream: u16,
        mut local: DuplexStream,
        mut arrivals: mpsc::UnboundedReceiver<StreamEvent>,
    ) {
        let mut buffer = vec![0u8; 8 * RELAY_DATA_LEN];
        let mut sending = true;
        loop {
            tokio::select! {
                read = local.read(&mut buffer), if sending => match read {
                    Ok(0) | Err(_) => {
                        sending = false;
                        let _ = self.with_plane(move |plane| plane.stream_close(circuit, stream)).await;
                    }
                    Ok(read) => {
                        let data = buffer[..read].to_vec();
                        if self.with_plane(move |plane| plane.stream_send(circuit, stream, &data)).await.is_err() {
                            return;
                        }
                    }
                },
                event = arrivals.recv() => match event {
                    Some(StreamEvent::Data(data)) => {
                        if local.write_all(&data).await.is_err() {
                            let _ = self.with_plane(move |plane| plane.stream_close(circuit, stream)).await;
                            return;
                        }
                    }
                    Some(StreamEvent::Connected) => {}
                    Some(StreamEvent::Closed(_)) | None => {
                        let _ = local.shutdown().await;
                        return;
                    }
                },
            }
        }
    }

    /// Downloads a directory document over BEGIN_DIR at the end of
    /// `circuit`. Paths ending in `.z` are inflated.
    pub async fn directory_get(
        &self,
        circuit: CircuitRef,
        path: &str,
    ) -> Result<Vec<u8>, TorError> {
        let error = |message: String| TorError::Directory(format!("{path}: {message}"));
        let mut stream = self
            .open_stream(circuit, None, Duration::from_secs(30))
            .await?;
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
            .await
            .map_err(|e| error(e.to_string()))?;
        let mut raw = Vec::new();
        timeout(Duration::from_secs(180), stream.read_to_end(&mut raw))
            .await
            .map_err(|_| error("timed out".to_owned()))?
            .map_err(|e| error(e.to_string()))?;
        let response = Response::parse(&raw).map_err(|e| error(e.to_string()))?;
        if response.status != 200 {
            return Err(error(format!("status {}", response.status)));
        }
        if path.ends_with(".z") {
            miniz_oxide::inflate::decompress_to_vec_zlib(&response.body)
                .map_err(|e| error(format!("inflate: {e:?}")))
        } else {
            Ok(response.body)
        }
    }

    /// A one-hop circuit to a directory server, created with CREATE_FAST.
    async fn directory_circuit(&self, target: RelayTarget) -> Result<Circuit, TorError> {
        self.build(
            vec![Hop {
                target,
                ntor_key: None,
            }],
            Duration::from_secs(30),
        )
        .await
    }

    /// Fetches the consensus and the authorities' key certificates from an
    /// authority and checks that most authorities signed the consensus.
    async fn fetch_consensus(&self) -> Result<(Consensus, Vec<KeyCertificate>), TorError> {
        let mut order = AUTHORITIES.to_vec();
        shuffle(&mut order);
        let mut last = TorError::Directory("no authority answered".to_owned());
        for authority in order {
            let target = RelayTarget {
                address: authority.socket_address(),
                rsa_identity: authority.rsa_identity(),
                ed25519_identity: None,
            };
            let attempt = async {
                let circuit = self.directory_circuit(target).await?;
                let text = self
                    .directory_get(
                        circuit.reference,
                        "/tor/status-vote/current/consensus-microdesc.z",
                    )
                    .await?;
                let keys = self
                    .directory_get(circuit.reference, "/tor/keys/all.z")
                    .await?;
                let consensus = Consensus::parse(&String::from_utf8_lossy(&text))
                    .map_err(TorError::Directory)?;
                let certificates =
                    parse_key_certificates(&String::from_utf8_lossy(&keys), now_seconds());
                Ok::<_, TorError>((consensus, certificates))
            };
            match attempt.await {
                Ok((consensus, certificates)) if consensus.is_trusted(&certificates) => {
                    return Ok((consensus, certificates));
                }
                Ok(_) => {
                    last =
                        TorError::Directory(format!("{}: too few valid signatures", authority.name))
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Fetches the consensus, then the microdescriptors of its relays from
    /// several directory caches at once.
    pub async fn bootstrap(&self) -> Result<Arc<NetworkDirectory>, TorError> {
        let (consensus, _) = self.fetch_consensus().await?;
        let mut digests = consensus
            .relays
            .iter()
            .map(|relay| relay.microdescriptor)
            .collect::<Vec<_>>();
        digests.sort_unstable();
        digests.dedup();
        let batches = digests
            .chunks(MICRODESCRIPTOR_BATCH)
            .map(|batch| batch.to_vec())
            .collect::<Vec<_>>();
        let queue = Arc::new(Mutex::new(batches));
        let caches = consensus
            .relays
            .iter()
            .filter(|relay| {
                relay.has(flags::V2DIR | flags::GUARD | flags::FAST | flags::RUNNING | flags::VALID)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut workers = Vec::new();
        for _ in 0..DIRECTORY_CIRCUITS {
            let (client, queue, caches) = (self.clone(), queue.clone(), caches.clone());
            workers.push(tokio::spawn(async move {
                client.fetch_batches(queue, caches).await
            }));
        }
        let mut microdescriptors = HashMap::new();
        for worker in workers {
            if let Ok(found) = worker.await {
                for micro in found {
                    microdescriptors.insert(micro.digest, micro);
                }
            }
        }
        if microdescriptors.len() * 2 < digests.len() {
            return Err(TorError::Directory(format!(
                "only {} of {} microdescriptors",
                microdescriptors.len(),
                digests.len()
            )));
        }
        let directory = Arc::new(NetworkDirectory {
            consensus,
            microdescriptors,
        });
        if let Ok(mut slot) = self.directory.write() {
            *slot = Some(directory.clone());
        }
        Ok(directory)
    }

    /// Takes batches of microdescriptor digests from `queue` and fetches
    /// them over one directory circuit, moving to another cache on errors.
    async fn fetch_batches(
        &self,
        queue: Arc<Mutex<Vec<Vec<[u8; 32]>>>>,
        caches: Vec<Relay>,
    ) -> Vec<Microdescriptor> {
        let mut found = Vec::new();
        let mut circuit: Option<Circuit> = None;
        let mut failures = 0;
        while failures < 8 {
            if circuit.is_none() {
                let Some(cache) = pick_any(&caches) else {
                    break;
                };
                let target = RelayTarget {
                    address: cache.address,
                    rsa_identity: cache.rsa_identity,
                    ed25519_identity: None,
                };
                match self.directory_circuit(target).await {
                    Ok(built) => circuit = Some(built),
                    Err(_) => {
                        failures += 1;
                        continue;
                    }
                }
            }
            let Some(batch) = queue.lock().ok().and_then(|mut queue| queue.pop()) else {
                break;
            };
            let path = format!(
                "/tor/micro/d/{}.z",
                batch
                    .iter()
                    .map(|digest| data_encoding::BASE64_NOPAD.encode(digest))
                    .collect::<Vec<_>>()
                    .join("-")
            );
            let reference = circuit.as_ref().expect("built above").reference;
            match self.directory_get(reference, &path).await {
                Ok(text) => found.extend(parse_microdescriptors(&String::from_utf8_lossy(&text))),
                Err(_) => {
                    if let Ok(mut queue) = queue.lock() {
                        queue.push(batch);
                    }
                    circuit = None;
                    failures += 1;
                }
            }
        }
        found
    }

    fn bootstrapped(&self) -> Result<Arc<NetworkDirectory>, TorError> {
        self.directory()
            .ok_or_else(|| TorError::Directory("not bootstrapped".to_owned()))
    }

    /// The relay every circuit of this client starts at.
    fn guard(&self, directory: &NetworkDirectory) -> Result<Relay, TorError> {
        let mut slot = self
            .guard
            .lock()
            .map_err(|_| TorError::Circuit("poisoned".to_owned()))?;
        if slot.is_none() {
            *slot = directory
                .pick(
                    flags::GUARD | flags::FAST | flags::STABLE | flags::V2DIR,
                    |_| true,
                )
                .cloned();
        }
        slot.clone()
            .ok_or_else(|| TorError::Circuit("no guard".to_owned()))
    }

    /// The guard, a middle relay and `last`.
    fn path_to(&self, directory: &NetworkDirectory, last: Hop) -> Result<Vec<Hop>, TorError> {
        let guard = self.guard(directory)?;
        let middle = directory
            .pick(flags::FAST, |relay| {
                !same_network(relay, &guard)
                    && !same_network_address(&relay.address, &last.target.address)
            })
            .ok_or_else(|| TorError::Circuit("no middle relay".to_owned()))?;
        let hops = [&guard, middle]
            .into_iter()
            .map(|relay| directory.hop(relay))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| TorError::Circuit("a hop lacks its microdescriptor".to_owned()))?;
        Ok([hops, vec![last]].concat())
    }

    /// Three hops to an exit that allows `port`: the client's guard, a
    /// middle relay and the exit.
    pub fn exit_path(&self, port: u16) -> Result<(Vec<Hop>, Relay), TorError> {
        let directory = self.bootstrapped()?;
        let guard = self.guard(&directory)?;
        let exit = directory
            .pick(flags::EXIT | flags::FAST, |relay| {
                !relay.has(flags::BAD_EXIT)
                    && !same_network(relay, &guard)
                    && directory
                        .microdescriptor(relay)
                        .is_some_and(|micro| micro.exit_ports.allows(port))
            })
            .ok_or_else(|| TorError::Circuit(format!("no exit for port {port}")))?
            .clone();
        let last = directory
            .hop(&exit)
            .ok_or_else(|| TorError::Circuit("the exit lacks its microdescriptor".to_owned()))?;
        Ok((self.path_to(&directory, last)?, exit))
    }

    /// Connects to `host:port` through an exit, reusing a recent circuit
    /// whose exit allows the port.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        wait: Duration,
    ) -> Result<DuplexStream, TorError> {
        let deadline = Instant::now() + wait;
        let target = format!("{host}:{port}");
        let directory = self.bootstrapped()?;
        let mut pool = self.exits.lock().await;
        pool.retain(|pooled| {
            pooled.built.elapsed() < CIRCUIT_LIFETIME && !pooled.circuit.events.is_closed()
        });
        let reusable = pool.iter().position(|pooled| {
            directory
                .microdescriptor(&pooled.exit)
                .is_some_and(|micro| micro.exit_ports.allows(port))
        });
        if let Some(index) = reusable {
            let reference = pool[index].circuit.reference;
            drop(pool);
            if let Ok(stream) = self
                .open_stream(reference, Some(target.clone()), Duration::from_secs(30))
                .await
            {
                return Ok(stream);
            }
            pool = self.exits.lock().await;
            pool.retain(|pooled| pooled.circuit.reference != reference);
        }
        drop(pool);
        let mut last = TorError::Circuit("no attempt".to_owned());
        while Instant::now() < deadline {
            let (path, exit) = self.exit_path(port)?;
            let circuit =
                match timeout_at(deadline, self.build(path, Duration::from_secs(30))).await {
                    Ok(Ok(circuit)) => circuit,
                    Ok(Err(error)) => {
                        last = error;
                        continue;
                    }
                    Err(_) => break,
                };
            let reference = circuit.reference;
            self.exits.lock().await.push(PooledCircuit {
                circuit,
                exit,
                built: Instant::now(),
            });
            match self
                .open_stream(reference, Some(target.clone()), Duration::from_secs(30))
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Connects to `port` of the onion service named by `host`, reusing a
    /// recent rendezvous circuit to the same service.
    pub async fn connect_onion(
        &self,
        host: &str,
        port: u16,
        wait: Duration,
    ) -> Result<DuplexStream, TorError> {
        let identity = onion::parse_address(host)
            .ok_or_else(|| TorError::Circuit(format!("{host} is not a v3 onion address")))?;
        let target = format!(":{port}");
        let reusable = {
            let mut pool = self.onions.lock().await;
            pool.retain(|_, entry| {
                entry.built.elapsed() < CIRCUIT_LIFETIME && !entry.circuit.events.is_closed()
            });
            pool.get(&identity).map(|entry| entry.circuit.reference)
        };
        if let Some(reference) = reusable {
            if let Ok(stream) = self
                .open_stream(reference, Some(target.clone()), ONION_STEP)
                .await
            {
                return Ok(stream);
            }
            self.onions.lock().await.remove(&identity);
        }
        let circuit = timeout(wait, self.rendezvous(&identity))
            .await
            .map_err(|_| TorError::Circuit("reaching the onion service timed out".to_owned()))??;
        let reference = circuit.reference;
        self.onions.lock().await.insert(
            identity,
            OnionCircuit {
                circuit,
                built: Instant::now(),
            },
        );
        self.open_stream(reference, Some(target), ONION_STEP).await
    }

    /// Fetches the service's descriptor from one of the directories
    /// responsible for it and returns its introduction points.
    async fn introduction_points(
        &self,
        identity: &[u8; 32],
    ) -> Result<(Vec<onion::IntroPoint>, [u8; 32]), TorError> {
        let directory = self.bootstrapped()?;
        let consensus = &directory.consensus;
        let period_length = consensus.param("hsdir-interval", DEFAULT_PERIOD_LENGTH as i64) as u64;
        let period = onion::time_period(consensus, period_length);
        let blinded = onion::blind(identity, period, period_length)
            .ok_or_else(|| TorError::Circuit("not a valid service key".to_owned()))?;
        let shared_random = onion::shared_random_value(consensus).ok_or_else(|| {
            TorError::Directory("the consensus has no shared random value".to_owned())
        })?;
        let hsdirs = consensus
            .relays
            .iter()
            .enumerate()
            .filter(|(_, relay)| relay.has(flags::HSDIR | flags::RUNNING | flags::VALID))
            .filter_map(|(index, relay)| {
                Some((index, directory.microdescriptor(relay)?.ed25519_identity?))
            })
            .collect::<Vec<_>>();
        let mut responsible = onion::responsible_directories(
            &blinded,
            &hsdirs,
            &shared_random,
            period,
            period_length,
            consensus.param("hsdir_n_replicas", 2).max(1) as u64,
            consensus.param("hsdir_spread_fetch", 3).max(1) as usize,
        );
        shuffle(&mut responsible);
        let path = format!("/tor/hs/3/{}", data_encoding::BASE64_NOPAD.encode(&blinded));
        let mut last = TorError::Directory("no directory holds the descriptor".to_owned());
        for index in responsible {
            let relay = &consensus.relays[index];
            let Some(last_hop) = directory.hop(relay) else {
                continue;
            };
            let attempt = async {
                let circuit = self
                    .build(self.path_to(&directory, last_hop)?, ONION_STEP)
                    .await?;
                let text = self.directory_get(circuit.reference, &path).await?;
                onion::open_descriptor(
                    &String::from_utf8_lossy(&text),
                    identity,
                    &blinded,
                    now_seconds(),
                )
                .map_err(TorError::Directory)
            };
            match attempt.await {
                Ok(points) if !points.is_empty() => {
                    return Ok((points, onion::subcredential(identity, &blinded)));
                }
                Ok(_) => {
                    last = TorError::Directory(
                        "the descriptor lists no introduction points".to_owned(),
                    )
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Meets the service at a rendezvous point and returns the circuit with
    /// the service as its last hop.
    async fn rendezvous(&self, identity: &[u8; 32]) -> Result<Circuit, TorError> {
        let (mut points, subcredential) = self.introduction_points(identity).await?;
        let directory = self.bootstrapped()?;
        let guard = self.guard(&directory)?;
        let point = directory
            .pick(flags::FAST | flags::STABLE, |relay| {
                !same_network(relay, &guard)
            })
            .ok_or_else(|| TorError::Circuit("no rendezvous point".to_owned()))?
            .clone();
        let point_hop = directory.hop(&point).ok_or_else(|| {
            TorError::Circuit("the rendezvous point lacks its microdescriptor".to_owned())
        })?;
        let mut rendezvous = self
            .build(self.path_to(&directory, point_hop.clone())?, ONION_STEP)
            .await?;
        let mut cookie = [0u8; 20];
        getrandom::getrandom(&mut cookie).expect("system random source");
        let reference = rendezvous.reference;
        self.with_plane(move |plane| {
            plane.send_message(
                reference,
                RelayMessage::new(ESTABLISH_RENDEZVOUS, 0, cookie.to_vec()),
            )
        })
        .await?;
        wait_for(&mut rendezvous, RENDEZVOUS_ESTABLISHED).await?;

        shuffle(&mut points);
        let rendezvous_key = point_hop
            .ntor_key
            .expect("hops from the directory have ntor keys");
        let mut last = TorError::Circuit("no introduction point answered".to_owned());
        for intro in points {
            let hop = Hop {
                target: intro.target.clone(),
                ntor_key: Some(intro.ntor_key),
            };
            let attempt = async {
                let mut circuit = self
                    .build(self.path_to(&directory, hop)?, ONION_STEP)
                    .await?;
                let (introduction, cell) = onion::introduce1(
                    &intro,
                    &subcredential,
                    &cookie,
                    &point_hop.target,
                    &rendezvous_key,
                );
                let intro_ref = circuit.reference;
                self.with_plane(move |plane| {
                    plane.send_message(intro_ref, RelayMessage::new(INTRODUCE1, 0, cell))
                })
                .await?;
                let ack = wait_for(&mut circuit, INTRODUCE_ACK).await?;
                let _ = self.with_plane(move |plane| plane.destroy(intro_ref)).await;
                if ack.data.get(..2) != Some(&[0, 0]) {
                    return Err(TorError::Circuit(format!(
                        "introduction refused: {:?}",
                        ack.data.get(..2)
                    )));
                }
                Ok(introduction)
            };
            let introduction = match attempt.await {
                Ok(introduction) => introduction,
                Err(error) => {
                    last = error;
                    continue;
                }
            };
            let reply = wait_for(&mut rendezvous, RENDEZVOUS2).await?;
            let keys = introduction.finish(&reply.data).ok_or_else(|| {
                TorError::Circuit("the service's handshake does not verify".to_owned())
            })?;
            self.with_plane(move |plane| plane.add_hop(reference, keys))
                .await?;
            return Ok(rendezvous);
        }
        Err(last)
    }
}

fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).expect("system random source");
        items.swap(i, (u64::from_le_bytes(random) % (i as u64 + 1)) as usize);
    }
}

fn pick_any<T>(items: &[T]) -> Option<&T> {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random).expect("system random source");
    items.get((u64::from_le_bytes(random) % items.len().max(1) as u64) as usize)
}

/// Waits for a relay message with `command` on a circuit.
async fn wait_for(circuit: &mut Circuit, command: u8) -> Result<RelayMessage, TorError> {
    let deadline = Instant::now() + ONION_STEP;
    loop {
        match timeout_at(deadline, circuit.events.recv()).await {
            Ok(Some(CircuitEvent::Relay { message, .. })) if message.command == command => {
                return Ok(message);
            }
            Ok(Some(CircuitEvent::Relay { .. } | CircuitEvent::Built)) => {}
            Ok(Some(CircuitEvent::Closed(reason))) => return Err(TorError::Circuit(reason)),
            Ok(None) => return Err(TorError::Circuit("the circuit was dropped".to_owned())),
            Err(_) => return Err(TorError::Circuit(format!("no relay message {command}"))),
        }
    }
}
