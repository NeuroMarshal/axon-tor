//! Checks against the real Tor network. They need internet access, so they
//! only run when asked for: `cargo test -- --ignored`.

use std::time::Duration;

use axon_addons::wire::WireProtocol;
use axon_core::time::Instant;
use axon_tor::{
    cell::{
        BEGIN_DIR, CONNECTED, CREATE_FAST, CREATED_FAST, Cell, DATA, END, RELAY, RelayMessage,
        SENDME,
    },
    crypto::{CircuitCrypto, HopKeys, kdf_tor},
    directory::{AUTHORITIES, Consensus, parse_key_certificates, parse_microdescriptors},
    link::{RelayTarget, TorLink},
    now_seconds,
};
use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

/// Opens a link to an authority, builds a one-hop circuit with CREATE_FAST
/// and downloads directory documents over BEGIN_DIR: the consensus, the
/// authorities' key certificates and a batch of microdescriptors.
#[tokio::test]
#[ignore = "needs the real Tor network"]
async fn the_consensus_is_signed_by_most_authorities() {
    for authority in AUTHORITIES {
        let get = |path: String| async move {
            timeout(
                Duration::from_secs(120),
                fetch(authority.socket_address(), authority.rsa_identity(), &path),
            )
            .await
            .map_err(|_| "timed out".to_owned())?
        };
        let consensus = match get("/tor/status-vote/current/consensus-microdesc.z".to_owned()).await
        {
            Ok(document) => document,
            Err(error) => {
                println!("{}: {error}", authority.name);
                continue;
            }
        };
        let consensus = Consensus::parse(&String::from_utf8_lossy(&consensus)).unwrap();
        println!(
            "{}: {} relays, {} signatures",
            authority.name,
            consensus.relays.len(),
            consensus.signatures.len()
        );
        let keys = get("/tor/keys/all.z".to_owned()).await.unwrap();
        let certificates = parse_key_certificates(&String::from_utf8_lossy(&keys), now_seconds());
        let signers = consensus.signed_by(&certificates);
        println!(
            "{} key certificates, signed by {signers:?}",
            certificates.len()
        );
        assert!(consensus.is_trusted(&certificates));

        let wanted = consensus
            .relays
            .iter()
            .take(90)
            .map(|relay| relay.microdescriptor)
            .collect::<Vec<_>>();
        let digests = wanted
            .iter()
            .map(|digest| data_encoding::BASE64_NOPAD.encode(digest))
            .collect::<Vec<_>>()
            .join("-");
        let batch = get(format!("/tor/micro/d/{digests}.z")).await.unwrap();
        let parsed = parse_microdescriptors(&String::from_utf8_lossy(&batch));
        let matched = parsed
            .iter()
            .filter(|micro| wanted.contains(&micro.digest))
            .count();
        let with_ed25519 = parsed
            .iter()
            .filter(|micro| micro.ed25519_identity.is_some())
            .count();
        println!(
            "{} microdescriptors, {matched} match the consensus, {with_ed25519} with Ed25519 ids",
            parsed.len()
        );
        assert!(matched > 80);
        return;
    }
    panic!("no authority answered");
}

async fn fetch(
    address: std::net::SocketAddr,
    rsa_identity: [u8; 20],
    path: &str,
) -> Result<Vec<u8>, String> {
    let now = Instant::from_nanos(1);
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(address))
        .await
        .map_err(|_| "connect timed out")?
        .map_err(|error| error.to_string())?;
    let mut link = TorLink::new(RelayTarget {
        address,
        rsa_identity,
        ed25519_identity: None,
    })?;
    let mut x = [0u8; 20];
    getrandom::getrandom(&mut x).unwrap();
    let circuit = 0x8000_0001u32;
    let mut out = link.start(now)?.transmit;
    out.extend(
        link.send(
            Bytes::from(Cell::new(circuit, CREATE_FAST, x.to_vec()).encode()),
            now,
        )?
        .transmit,
    );
    for unit in out.drain(..) {
        stream.write_all(&unit).await.map_err(|e| e.to_string())?;
    }
    let mut crypto = CircuitCrypto::default();
    let mut body = Vec::new();
    let mut received = 0usize;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer).await.map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("closed by the relay".to_owned());
        }
        let output = link.receive(Bytes::copy_from_slice(&buffer[..read]), now)?;
        let mut replies = Vec::new();
        for envelope in output.envelopes {
            let cell = Cell::decode(&envelope).ok_or("bad cell")?;
            match cell.command {
                CREATED_FAST => {
                    let (material, kh) = kdf_tor(&[&x[..], &cell.payload[..20]].concat());
                    if kh[..] != cell.payload[20..40] {
                        return Err("KH does not match".to_owned());
                    }
                    crypto.push(HopKeys::from_material(&material));
                    let (payload, _) = crypto.seal(0, &RelayMessage::new(BEGIN_DIR, 1, Vec::new()));
                    replies.push(Cell::new(circuit, RELAY, payload.to_vec()));
                }
                RELAY => {
                    let mut payload: [u8; 509] = cell.payload[..].try_into().unwrap();
                    let (_, message, digest) =
                        crypto.open(&mut payload).ok_or("unrecognized relay cell")?;
                    match message.command {
                        CONNECTED => {
                            let request = format!("GET {path} HTTP/1.0\r\n\r\n");
                            for chunk in request.as_bytes().chunks(axon_tor::cell::RELAY_DATA_LEN) {
                                let (payload, _) =
                                    crypto.seal(0, &RelayMessage::new(DATA, 1, chunk.to_vec()));
                                replies.push(Cell::new(circuit, RELAY, payload.to_vec()));
                            }
                        }
                        DATA => {
                            body.extend_from_slice(&message.data);
                            received += 1;
                            if received.is_multiple_of(100) {
                                let mut sendme = vec![1, 0, 20];
                                sendme.extend_from_slice(&digest);
                                let (payload, _) =
                                    crypto.seal(0, &RelayMessage::new(SENDME, 0, sendme));
                                replies.push(Cell::new(circuit, RELAY, payload.to_vec()));
                            }
                            if received.is_multiple_of(50) {
                                let (payload, _) =
                                    crypto.seal(0, &RelayMessage::new(SENDME, 1, Vec::new()));
                                replies.push(Cell::new(circuit, RELAY, payload.to_vec()));
                            }
                        }
                        END => {
                            let end = body
                                .windows(4)
                                .position(|w| w == b"\r\n\r\n")
                                .ok_or("no HTTP head")?;
                            let head = String::from_utf8_lossy(&body[..end]).to_string();
                            println!("{}", head.lines().next().unwrap_or_default());
                            if !head.starts_with("HTTP/1.0 200") {
                                return Err(head);
                            }
                            return miniz_oxide::inflate::decompress_to_vec_zlib(&body[end + 4..])
                                .map_err(|error| format!("inflate: {error:?}"));
                        }
                        other => println!("relay command {other}"),
                    }
                }
                other => return Err(format!("cell {other}: {:?}", &cell.payload[..8])),
            }
        }
        let mut out = output.transmit;
        for reply in replies {
            out.extend(link.send(Bytes::from(reply.encode()), now)?.transmit);
        }
        for unit in out {
            stream.write_all(&unit).await.map_err(|e| e.to_string())?;
        }
    }
}
