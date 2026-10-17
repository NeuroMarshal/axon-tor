//! The Tor client as an Axon forwarding plane. Neighbours are relays,
//! envelopes are cells, and the plane keeps the client's circuits and the
//! streams inside them.
//!
//! The plane does not open connections. Cells for a relay without a link
//! wait here, [`TorPlane::wanted_connections`] tells the runtime whom to
//! dial, and the cells leave once the link is up.

use std::collections::{BTreeSet, HashMap, VecDeque};

use axon_core::node::{
    ExtensionError, ExtensionId, ExtensionVersion, ForwardingDecision, ForwardingOutput,
    ForwardingPlane, ForwardingTransmission, InboundRouteContext, NodeId, OutboundRouteContext,
    PollContext, RouteEnvelope,
};
use bytes::Bytes;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    cell::{
        BEGIN, BEGIN_DIR, CONNECTED, CREATE_FAST, CREATE2, CREATED_FAST, CREATED2, Cell, DATA,
        DESTROY, END, EXTEND2, EXTENDED2, PAYLOAD_LEN, RELAY, RELAY_DATA_LEN, RELAY_EARLY,
        RelayMessage, SENDME, TRUNCATED,
    },
    crypto::{CircuitCrypto, HopKeys, kdf_tor},
    link::RelayTarget,
    ntor::{NTOR, NtorClient},
};

pub const TOR_PLANE: ExtensionId = ExtensionId(0x544f_5250); // TORP
pub const TOR_PLANE_VERSION: ExtensionVersion = ExtensionVersion(1);

/// A circuit's window of data cells, and how much one SENDME adds.
const CIRCUIT_WINDOW: i32 = 1000;
const CIRCUIT_INCREMENT: i32 = 100;
const STREAM_WINDOW: i32 = 500;
const STREAM_INCREMENT: i32 = 50;
/// RELAY_EARLY cells a circuit may carry; EXTEND2 must travel in them.
const EARLY_CELLS: u8 = 8;
/// How long a circuit may take to build.
const BUILD_TIMEOUT_MS: u64 = 60_000;
/// How long a relay that could not be reached is left alone.
const UNREACHABLE_MS: u64 = 10 * 60_000;
const TRACE_LEN: usize = 256;
/// END reason for a stream closed normally.
const REASON_DONE: u8 = 6;

pub fn node_of(rsa_identity: &[u8; 20]) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[..20].copy_from_slice(rsa_identity);
    NodeId::from_bytes(bytes)
}

/// A relay to build a circuit through. Without an ntor key the hop must be
/// the first one and is created with CREATE_FAST.
#[derive(Debug, Clone)]
pub struct Hop {
    pub target: RelayTarget,
    pub ntor_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitRef {
    pub first: NodeId,
    pub id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitEvent {
    Built,
    /// A relay message the plane does not handle itself, from hop `hop`.
    Relay {
        hop: usize,
        message: RelayMessage,
    },
    Closed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Connected,
    Data(Vec<u8>),
    /// The other end closed the stream, with the END reason.
    Closed(u8),
}

enum Handshake {
    Fast([u8; 20]),
    Ntor(NtorClient),
}

struct Stream {
    events: UnboundedSender<StreamEvent>,
    received: u32,
    window: i32,
}

struct Circuit {
    crypto: CircuitCrypto,
    handshake: Option<Handshake>,
    remaining: VecDeque<Hop>,
    events: UnboundedSender<CircuitEvent>,
    built: bool,
    early_left: u8,
    streams: HashMap<u16, Stream>,
    next_stream: u16,
    received_data: u32,
    window: i32,
    /// Data cells waiting for a window: stream and data.
    waiting: VecDeque<(u16, Vec<u8>)>,
    started: u64,
}

#[derive(Default)]
pub struct TorPlane {
    neighbours: BTreeSet<NodeId>,
    targets: HashMap<NodeId, RelayTarget>,
    outbox: HashMap<NodeId, VecDeque<Bytes>>,
    unreachable: HashMap<NodeId, u64>,
    circuits: HashMap<CircuitRef, Circuit>,
    trace: VecDeque<String>,
    now_ms: u64,
}

fn now_ms() -> u64 {
    crate::now_seconds() * 1000
}

fn short(identity: &NodeId) -> String {
    data_encoding::HEXUPPER.encode(&identity.as_bytes()[..4])
}

fn extend2_payload(hop: &Hop, handshake: &[u8]) -> Vec<u8> {
    let target = &hop.target;
    let mut specifiers = Vec::new();
    if let std::net::IpAddr::V4(address) = target.address.ip() {
        let mut data = address.octets().to_vec();
        data.extend_from_slice(&target.address.port().to_be_bytes());
        specifiers.push((0u8, data));
    }
    specifiers.push((2, target.rsa_identity.to_vec()));
    if let Some(ed25519) = target.ed25519_identity {
        specifiers.push((3, ed25519.to_vec()));
    }
    if let std::net::IpAddr::V6(address) = target.address.ip() {
        let mut data = address.octets().to_vec();
        data.extend_from_slice(&target.address.port().to_be_bytes());
        specifiers.push((1, data));
    }
    let mut payload = vec![specifiers.len() as u8];
    for (kind, data) in specifiers {
        payload.push(kind);
        payload.push(data.len() as u8);
        payload.extend_from_slice(&data);
    }
    payload.extend_from_slice(&NTOR.to_be_bytes());
    payload.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    payload.extend_from_slice(handshake);
    payload
}

impl TorPlane {
    fn note(&mut self, event: String) {
        if self.trace.len() == TRACE_LEN {
            self.trace.pop_front();
        }
        self.trace.push_back(event);
    }

    /// Recent events, for diagnosis.
    pub fn take_trace(&mut self) -> Vec<String> {
        self.trace.drain(..).collect()
    }

    pub fn links(&self) -> usize {
        self.neighbours.len()
    }

    pub fn circuits(&self) -> usize {
        self.circuits
            .values()
            .filter(|circuit| circuit.built)
            .count()
    }

    fn send_cell(&mut self, relay: NodeId, cell: &Cell) {
        self.outbox
            .entry(relay)
            .or_default()
            .push_back(Bytes::from(cell.encode()));
    }

    /// Relays the client has cells for and no link to, with where to dial.
    pub fn wanted_connections(&self) -> Vec<(NodeId, RelayTarget)> {
        self.outbox
            .iter()
            .filter(|(relay, queue)| !queue.is_empty() && !self.neighbours.contains(relay))
            .filter(|(relay, _)| {
                self.unreachable
                    .get(relay)
                    .is_none_or(|since| self.now_ms.saturating_sub(*since) > UNREACHABLE_MS)
            })
            .filter_map(|(relay, _)| Some((*relay, self.targets.get(relay)?.clone())))
            .collect()
    }

    /// The runtime could not reach `relay`: its circuits fail.
    pub fn connection_failed(&mut self, relay: NodeId, reason: &str) {
        self.note(format!("could not reach {}: {reason}", short(&relay)));
        self.outbox.remove(&relay);
        self.unreachable.insert(relay, self.now_ms);
        let failed = self
            .circuits
            .keys()
            .filter(|circuit| circuit.first == relay)
            .copied()
            .collect::<Vec<_>>();
        for circuit in failed {
            self.close(circuit, format!("could not reach the first hop: {reason}"));
        }
    }

    /// Starts building a circuit through `path`. Progress and the relay
    /// messages the plane does not handle arrive on `events`.
    pub fn build_circuit(
        &mut self,
        path: Vec<Hop>,
        events: UnboundedSender<CircuitEvent>,
    ) -> Option<CircuitRef> {
        let mut remaining = VecDeque::from(path);
        let first = remaining.pop_front()?;
        let relay = node_of(&first.target.rsa_identity);
        self.targets.insert(relay, first.target.clone());
        let id = loop {
            let mut random = [0u8; 4];
            getrandom::getrandom(&mut random).expect("system random source");
            // Clients set the high bit of the circuit ids they choose.
            let id = u32::from_be_bytes(random) | 0x8000_0000;
            if !self.circuits.contains_key(&CircuitRef { first: relay, id }) {
                break id;
            }
        };
        let circuit_ref = CircuitRef { first: relay, id };
        let (handshake, cell) = match first.ntor_key {
            None => {
                let mut x = [0u8; 20];
                getrandom::getrandom(&mut x).expect("system random source");
                (Handshake::Fast(x), Cell::new(id, CREATE_FAST, x.to_vec()))
            }
            Some(key) => {
                let (client, data) = NtorClient::start(first.target.rsa_identity, key);
                let mut payload = NTOR.to_be_bytes().to_vec();
                payload.extend_from_slice(&(data.len() as u16).to_be_bytes());
                payload.extend_from_slice(&data);
                (Handshake::Ntor(client), Cell::new(id, CREATE2, payload))
            }
        };
        self.circuits.insert(
            circuit_ref,
            Circuit {
                crypto: CircuitCrypto::default(),
                handshake: Some(handshake),
                remaining,
                events,
                built: false,
                early_left: EARLY_CELLS,
                streams: HashMap::new(),
                next_stream: 1,
                received_data: 0,
                window: CIRCUIT_WINDOW,
                waiting: VecDeque::new(),
                started: self.now_ms,
            },
        );
        self.send_cell(relay, &cell);
        Some(circuit_ref)
    }

    /// Seals a relay message for hop `hop` (the last hop if None) and sends it.
    fn send_relay(
        &mut self,
        circuit_ref: CircuitRef,
        hop: Option<usize>,
        message: &RelayMessage,
    ) -> Option<[u8; 20]> {
        let circuit = self.circuits.get_mut(&circuit_ref)?;
        let target = hop.unwrap_or(circuit.crypto.len().checked_sub(1)?);
        let early = message.command == EXTEND2 && circuit.early_left > 0;
        if early {
            circuit.early_left -= 1;
        }
        let (payload, digest) = circuit.crypto.seal(target, message);
        let command = if early { RELAY_EARLY } else { RELAY };
        self.send_cell(
            circuit_ref.first,
            &Cell::new(circuit_ref.id, command, payload.to_vec()),
        );
        Some(digest)
    }

    /// Sends a relay message to the last hop, for protocols on top of
    /// circuits such as onion services.
    pub fn send_message(&mut self, circuit: CircuitRef, message: RelayMessage) -> bool {
        self.send_relay(circuit, None, &message).is_some()
    }

    /// Adds a hop whose keys came from a handshake outside the circuit, as
    /// an onion service's rendezvous does.
    pub fn add_hop(&mut self, circuit: CircuitRef, keys: HopKeys) -> bool {
        match self.circuits.get_mut(&circuit) {
            Some(circuit) => {
                circuit.crypto.push(keys);
                true
            }
            None => false,
        }
    }

    pub fn is_built(&self, circuit: CircuitRef) -> bool {
        self.circuits
            .get(&circuit)
            .is_some_and(|circuit| circuit.built)
    }

    /// Opens a stream to the last hop: BEGIN to `target` (`host:port`), or
    /// BEGIN_DIR to the relay's directory when `target` is None.
    pub fn open_stream(
        &mut self,
        circuit_ref: CircuitRef,
        target: Option<&str>,
        events: UnboundedSender<StreamEvent>,
    ) -> Option<u16> {
        let circuit = self
            .circuits
            .get_mut(&circuit_ref)
            .filter(|circuit| circuit.built)?;
        let stream = circuit.next_stream;
        circuit.next_stream = circuit.next_stream.checked_add(1)?;
        circuit.streams.insert(
            stream,
            Stream {
                events,
                received: 0,
                window: STREAM_WINDOW,
            },
        );
        let message = match target {
            Some(target) => {
                let mut data = target.to_ascii_lowercase().into_bytes();
                data.push(0);
                data.extend_from_slice(&[0, 0, 0, 0]);
                RelayMessage::new(BEGIN, stream, data)
            }
            None => RelayMessage::new(BEGIN_DIR, stream, Vec::new()),
        };
        self.send_relay(circuit_ref, None, &message)?;
        Some(stream)
    }

    /// Queues `data` on a stream; it leaves as the windows allow.
    pub fn stream_send(&mut self, circuit_ref: CircuitRef, stream: u16, data: &[u8]) {
        let Some(circuit) = self.circuits.get_mut(&circuit_ref) else {
            return;
        };
        for chunk in data.chunks(RELAY_DATA_LEN) {
            circuit.waiting.push_back((stream, chunk.to_vec()));
        }
        self.flush_waiting(circuit_ref);
    }

    pub fn stream_close(&mut self, circuit_ref: CircuitRef, stream: u16) {
        let removed = self
            .circuits
            .get_mut(&circuit_ref)
            .and_then(|circuit| circuit.streams.remove(&stream));
        if removed.is_some() {
            self.send_relay(
                circuit_ref,
                None,
                &RelayMessage::new(END, stream, vec![REASON_DONE]),
            );
        }
    }

    /// Sends waiting data while the circuit and stream windows allow.
    fn flush_waiting(&mut self, circuit_ref: CircuitRef) {
        loop {
            let Some(circuit) = self.circuits.get_mut(&circuit_ref) else {
                return;
            };
            let Some((stream, _)) = circuit.waiting.front() else {
                return;
            };
            let stream = *stream;
            let stream_window = circuit.streams.get(&stream).map(|entry| entry.window);
            match stream_window {
                None => {
                    circuit.waiting.pop_front();
                    continue;
                }
                Some(window) if window <= 0 || circuit.window <= 0 => return,
                Some(_) => {}
            }
            let (stream, data) = circuit.waiting.pop_front().expect("checked above");
            circuit.window -= 1;
            if let Some(entry) = circuit.streams.get_mut(&stream) {
                entry.window -= 1;
            }
            self.send_relay(circuit_ref, None, &RelayMessage::new(DATA, stream, data));
        }
    }

    /// Tears a circuit down and tells everyone waiting on it.
    pub fn close(&mut self, circuit_ref: CircuitRef, reason: String) {
        let Some(circuit) = self.circuits.remove(&circuit_ref) else {
            return;
        };
        for stream in circuit.streams.values() {
            let _ = stream.events.send(StreamEvent::Closed(0));
        }
        let _ = circuit.events.send(CircuitEvent::Closed(reason));
    }

    /// Tears a circuit down at the relays too.
    pub fn destroy(&mut self, circuit_ref: CircuitRef) {
        if self.circuits.contains_key(&circuit_ref) {
            self.send_cell(
                circuit_ref.first,
                &Cell::new(circuit_ref.id, DESTROY, vec![0]),
            );
            self.close(circuit_ref, "closed by the client".to_owned());
        }
    }

    /// Adds the hop a handshake reply completes, then extends further or
    /// reports the circuit built.
    fn hop_ready(&mut self, circuit_ref: CircuitRef, keys: Option<HopKeys>) {
        let Some(keys) = keys else {
            self.note("a hop's handshake reply did not verify".to_owned());
            self.destroy(circuit_ref);
            return;
        };
        let Some(circuit) = self.circuits.get_mut(&circuit_ref) else {
            return;
        };
        circuit.crypto.push(keys);
        let Some(next) = circuit.remaining.pop_front() else {
            circuit.built = true;
            let _ = circuit.events.send(CircuitEvent::Built);
            return;
        };
        let Some(key) = next.ntor_key else {
            self.destroy(circuit_ref);
            return;
        };
        let (client, data) = NtorClient::start(next.target.rsa_identity, key);
        circuit.handshake = Some(Handshake::Ntor(client));
        let payload = extend2_payload(&next, &data);
        self.send_relay(circuit_ref, None, &RelayMessage::new(EXTEND2, 0, payload));
    }

    fn handle_relay(
        &mut self,
        circuit_ref: CircuitRef,
        hop: usize,
        message: RelayMessage,
        digest: [u8; 20],
    ) {
        let Some(circuit) = self.circuits.get_mut(&circuit_ref) else {
            return;
        };
        match message.command {
            EXTENDED2 => {
                let keys = match circuit.handshake.take() {
                    Some(Handshake::Ntor(client)) => message
                        .data
                        .get(2..)
                        .and_then(|reply| client.finish(reply))
                        .map(|material| HopKeys::from_material(&material)),
                    _ => None,
                };
                self.hop_ready(circuit_ref, keys);
            }
            TRUNCATED => {
                let reason = message.data.first().copied().unwrap_or(0);
                self.destroy(circuit_ref);
                self.note(format!("circuit truncated, reason {reason}"));
            }
            SENDME if message.stream == 0 => {
                circuit.window += CIRCUIT_INCREMENT;
                self.flush_waiting(circuit_ref);
            }
            SENDME => {
                if let Some(stream) = circuit.streams.get_mut(&message.stream) {
                    stream.window += STREAM_INCREMENT;
                }
                self.flush_waiting(circuit_ref);
            }
            CONNECTED => {
                if let Some(stream) = circuit.streams.get(&message.stream) {
                    let _ = stream.events.send(StreamEvent::Connected);
                }
            }
            DATA => {
                circuit.received_data += 1;
                let circuit_sendme = circuit.received_data % CIRCUIT_INCREMENT as u32 == 0;
                let stream_sendme = match circuit.streams.get_mut(&message.stream) {
                    Some(stream) => {
                        stream.received += 1;
                        let _ = stream.events.send(StreamEvent::Data(message.data));
                        stream.received % STREAM_INCREMENT as u32 == 0
                    }
                    None => false,
                };
                if circuit_sendme {
                    // An authenticated SENDME echoes the digest of the cell
                    // that completed the increment.
                    let mut data = vec![1, 0, 20];
                    data.extend_from_slice(&digest);
                    self.send_relay(circuit_ref, Some(hop), &RelayMessage::new(SENDME, 0, data));
                }
                if stream_sendme {
                    self.send_relay(
                        circuit_ref,
                        Some(hop),
                        &RelayMessage::new(SENDME, message.stream, Vec::new()),
                    );
                }
            }
            END => {
                if let Some(stream) = circuit.streams.remove(&message.stream) {
                    let reason = message.data.first().copied().unwrap_or(0);
                    let _ = stream.events.send(StreamEvent::Closed(reason));
                }
            }
            _ => {
                let _ = circuit.events.send(CircuitEvent::Relay { hop, message });
            }
        }
    }

    fn handle(&mut self, from: NodeId, cell: Cell) {
        let circuit_ref = CircuitRef {
            first: from,
            id: cell.circuit,
        };
        let Some(circuit) = self.circuits.get_mut(&circuit_ref) else {
            return;
        };
        match cell.command {
            CREATED_FAST => {
                let keys = match circuit.handshake.take() {
                    Some(Handshake::Fast(x)) if cell.payload.len() >= 40 => {
                        let (material, kh) = kdf_tor(&[&x[..], &cell.payload[..20]].concat());
                        (kh[..] == cell.payload[20..40]).then(|| HopKeys::from_material(&material))
                    }
                    _ => None,
                };
                self.hop_ready(circuit_ref, keys);
            }
            CREATED2 => {
                let keys = match circuit.handshake.take() {
                    Some(Handshake::Ntor(client)) => cell
                        .payload
                        .get(2..)
                        .and_then(|reply| client.finish(reply))
                        .map(|material| HopKeys::from_material(&material)),
                    _ => None,
                };
                self.hop_ready(circuit_ref, keys);
            }
            RELAY | RELAY_EARLY => {
                let Ok(mut payload) = <[u8; PAYLOAD_LEN]>::try_from(
                    &cell.payload[..PAYLOAD_LEN.min(cell.payload.len())],
                ) else {
                    return;
                };
                match circuit.crypto.open(&mut payload) {
                    Some((hop, message, digest)) => {
                        self.handle_relay(circuit_ref, hop, message, digest)
                    }
                    None => self.note("a relay cell no hop recognized".to_owned()),
                }
            }
            DESTROY => {
                let reason = cell.payload.first().copied().unwrap_or(0);
                self.close(
                    circuit_ref,
                    format!("destroyed by the relay, reason {reason}"),
                );
            }
            _ => {}
        }
    }

    fn expire(&mut self) {
        let now = self.now_ms;
        let stale = self
            .circuits
            .iter()
            .filter(|(_, circuit)| {
                !circuit.built && now.saturating_sub(circuit.started) > BUILD_TIMEOUT_MS
            })
            .map(|(circuit_ref, _)| *circuit_ref)
            .collect::<Vec<_>>();
        for circuit_ref in stale {
            self.destroy(circuit_ref);
        }
        // Circuits nobody waits for any more are torn down.
        let abandoned = self
            .circuits
            .iter()
            .filter(|(_, circuit)| circuit.events.is_closed())
            .map(|(circuit_ref, _)| *circuit_ref)
            .collect::<Vec<_>>();
        for circuit_ref in abandoned {
            self.destroy(circuit_ref);
        }
        for circuit in self.circuits.values_mut() {
            circuit
                .streams
                .retain(|_, stream| !stream.events.is_closed());
        }
    }
}

impl ForwardingPlane for TorPlane {
    fn extension_id(&self) -> ExtensionId {
        TOR_PLANE
    }

    fn extension_version(&self) -> ExtensionVersion {
        TOR_PLANE_VERSION
    }

    fn originate(
        &mut self,
        _context: OutboundRouteContext<'_>,
        _payload: Bytes,
    ) -> Result<Vec<ForwardingTransmission>, ExtensionError> {
        Err(ExtensionError::provider(
            TOR_PLANE,
            "Tor carries no Axon sessions; use the plane's circuits".to_owned(),
        ))
    }

    fn receive(
        &mut self,
        context: InboundRouteContext<'_>,
    ) -> Result<ForwardingDecision, ExtensionError> {
        self.now_ms = now_ms();
        if let Some(cell) = Cell::decode(&context.envelope.0) {
            self.handle(context.previous_hop, cell);
        }
        Ok(ForwardingDecision::Consumed)
    }

    fn poll(&mut self, context: PollContext<'_>) -> Result<ForwardingOutput, ExtensionError> {
        self.now_ms = now_ms();
        self.neighbours = context
            .topology
            .outgoing(context.local_node)
            .map(|link| link.key.destination)
            .collect();
        self.expire();
        let mut output = ForwardingOutput::default();
        for relay in self.neighbours.clone() {
            if let Some(queue) = self.outbox.get_mut(&relay) {
                for envelope in queue.drain(..) {
                    output.transmissions.push(ForwardingTransmission {
                        next_hop: relay,
                        flow_hash: 0,
                        envelope: RouteEnvelope(envelope),
                    });
                }
            }
        }
        Ok(output)
    }
}
