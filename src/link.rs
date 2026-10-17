//! Tor's link protocol as an Axon wire protocol: TLS, then VERSIONS, CERTS
//! and NETINFO cells, then cells in both directions. Envelopes are cells
//! with four-byte circuit ids.
//!
//! Relays present self-signed TLS certificates, so TLS itself only proves
//! that the peer holds the certificate's key. The CERTS cell then chains
//! that certificate to the relay's RSA and Ed25519 identities, which come
//! from the consensus or from the list of directory authorities.

use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
};

use axon_addons::{
    noise::sha256,
    rsa::PublicKey,
    wire::{WireOutput, WireProtocol},
};
use axon_core::time::Instant;
use bytes::Bytes;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, ring},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha1::{Digest, Sha1};

use crate::{
    cell::{AUTH_CHALLENGE, CERTS, Cell, NETINFO, PADDING, VERSIONS, VPADDING},
    cert::{Ed25519Cert, SIGNING_KEY, TLS_LINK, rsa_cross_certificate},
    now_seconds,
};

/// Link protocol versions this client speaks: four-byte circuit ids.
const VERSIONS_OFFERED: [u16; 2] = [4, 5];

/// What a client knows about the relay it connects to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTarget {
    pub address: SocketAddr,
    /// SHA-1 of the relay's RSA identity key.
    pub rsa_identity: [u8; 20],
    /// The relay's Ed25519 identity, when the directory names it.
    pub ed25519_identity: Option<[u8; 32]>,
}

/// Accepts any certificate and leaves identity to the CERTS cell, but still
/// checks that the peer signs the handshake with the certificate's key.
#[derive(Debug)]
struct RelayCertificates(Arc<CryptoProvider>);

impl ServerCertVerifier for RelayCertificates {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(RelayCertificates(provider)))
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Versions,
    Certs,
    Netinfo,
    Open,
}

pub struct TorLink {
    tls: ClientConnection,
    relay: RelayTarget,
    state: State,
    /// Decrypted bytes not yet read as cells.
    plaintext: Vec<u8>,
    /// Envelopes the plane sent before the link was open.
    queued: Vec<Bytes>,
    certificates_checked: bool,
}

impl TorLink {
    pub fn new(relay: RelayTarget) -> Result<Self, String> {
        // An IP address as the server name makes rustls send no SNI, like
        // Tor itself.
        let name = ServerName::IpAddress(relay.address.ip().into());
        let tls = ClientConnection::new(tls_config(), name).map_err(|error| error.to_string())?;
        Ok(Self {
            tls,
            relay,
            state: State::Versions,
            plaintext: Vec::new(),
            queued: Vec::new(),
            certificates_checked: false,
        })
    }

    fn write_cell(&mut self, cell: &Cell, id_len: usize) -> Result<(), String> {
        self.tls
            .writer()
            .write_all(&cell.encode_with(id_len))
            .map_err(|error| error.to_string())
    }

    fn flush(&mut self, output: &mut WireOutput) -> Result<(), String> {
        while self.tls.wants_write() {
            let mut buffer = Vec::new();
            self.tls
                .write_tls(&mut buffer)
                .map_err(|error| error.to_string())?;
            if buffer.is_empty() {
                break;
            }
            output.transmit.push(Bytes::from(buffer));
        }
        Ok(())
    }

    /// Chains the TLS certificate to the relay's identities, as tor-spec
    /// section 4.2 asks of an initiator.
    fn check_certificates(&self, payload: &[u8]) -> Result<(), String> {
        let mut certificates = std::collections::BTreeMap::new();
        let count = *payload.first().ok_or("empty CERTS cell")?;
        let mut at = 1;
        for _ in 0..count {
            let header = payload.get(at..at + 3).ok_or("truncated CERTS cell")?;
            let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
            let body = payload
                .get(at + 3..at + 3 + length)
                .ok_or("truncated certificate")?;
            if certificates.insert(header[0], body).is_some() {
                return Err(format!("two certificates of type {}", header[0]));
            }
            at += 3 + length;
        }
        let now = now_seconds();
        let identity_cert = certificates.get(&2).ok_or("no RSA identity certificate")?;
        let rsa = PublicKey::from_certificate(identity_cert).ok_or("unreadable RSA identity")?;
        if rsa.bits() != 1024 {
            return Err("the RSA identity is not 1024 bits".to_owned());
        }
        let fingerprint: [u8; 20] = Sha1::digest(rsa.pkcs1_der()).into();
        if fingerprint != self.relay.rsa_identity {
            return Err("the relay has another RSA identity".to_owned());
        }
        let ed25519 = rsa_cross_certificate(
            certificates
                .get(&7)
                .ok_or("no RSA to Ed25519 certificate")?,
            &rsa,
            now,
        )
        .ok_or("the RSA to Ed25519 certificate does not verify")?;
        if self
            .relay
            .ed25519_identity
            .is_some_and(|expected| expected != ed25519)
        {
            return Err("the relay has another Ed25519 identity".to_owned());
        }
        let signing = Ed25519Cert::parse(certificates.get(&4).ok_or("no signing key certificate")?)
            .filter(|cert| {
                cert.cert_type == SIGNING_KEY && cert.verify(&ed25519) && !cert.is_expired(now)
            })
            .ok_or("the signing key certificate does not verify")?;
        let link = Ed25519Cert::parse(certificates.get(&5).ok_or("no TLS link certificate")?)
            .filter(|cert| {
                cert.cert_type == TLS_LINK
                    && cert.verify(&signing.certified)
                    && !cert.is_expired(now)
            })
            .ok_or("the TLS link certificate does not verify")?;
        let presented = self
            .tls
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or("no TLS certificate")?;
        if link.certified != sha256(&[presented.as_ref()]) {
            return Err("the TLS certificate is not the certified one".to_owned());
        }
        Ok(())
    }

    fn netinfo(&self) -> Cell {
        let mut payload = vec![0, 0, 0, 0];
        match self.relay.address.ip() {
            IpAddr::V4(address) => {
                payload.extend_from_slice(&[4, 4]);
                payload.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                payload.extend_from_slice(&[6, 16]);
                payload.extend_from_slice(&address.octets());
            }
        }
        payload.push(0);
        Cell::new(0, NETINFO, payload)
    }

    /// Handles the cells in the decrypted bytes.
    fn read_cells(&mut self, output: &mut WireOutput) -> Result<(), String> {
        loop {
            let id_len = if self.state == State::Versions { 2 } else { 4 };
            let Some((cell, length)) = Cell::decode_with(&self.plaintext, id_len) else {
                return Ok(());
            };
            let raw = self.plaintext.drain(..length).collect::<Vec<_>>();
            match (self.state, cell.command) {
                (_, PADDING | VPADDING) => {}
                (State::Versions, VERSIONS) => {
                    let theirs = cell
                        .payload
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect::<Vec<_>>();
                    if !VERSIONS_OFFERED
                        .iter()
                        .any(|version| theirs.contains(version))
                    {
                        return Err(format!("no common link version in {theirs:?}"));
                    }
                    self.state = State::Certs;
                }
                (State::Certs, CERTS) => {
                    self.check_certificates(&cell.payload)?;
                    self.certificates_checked = true;
                    self.state = State::Netinfo;
                }
                (State::Netinfo, AUTH_CHALLENGE) => {}
                (State::Netinfo, NETINFO) if self.certificates_checked => {
                    let netinfo = self.netinfo();
                    self.write_cell(&netinfo, 4)?;
                    self.state = State::Open;
                    for envelope in std::mem::take(&mut self.queued) {
                        self.tls
                            .writer()
                            .write_all(&envelope)
                            .map_err(|error| error.to_string())?;
                    }
                }
                (State::Open, _) => output.envelopes.push(Bytes::from(raw)),
                (state, command) => {
                    return Err(format!("unexpected cell {command} while in {state:?}"));
                }
            }
        }
    }
}

impl WireProtocol for TorLink {
    fn start(&mut self, _now: Instant) -> Result<WireOutput, String> {
        let payload = VERSIONS_OFFERED
            .iter()
            .flat_map(|version| version.to_be_bytes())
            .collect::<Vec<_>>();
        self.write_cell(&Cell::new(0, VERSIONS, payload), 2)?;
        let mut output = WireOutput::default();
        self.flush(&mut output)?;
        Ok(output)
    }

    fn send(&mut self, envelope: Bytes, _now: Instant) -> Result<WireOutput, String> {
        let mut output = WireOutput::default();
        if self.state == State::Open {
            self.tls
                .writer()
                .write_all(&envelope)
                .map_err(|error| error.to_string())?;
            self.flush(&mut output)?;
        } else {
            self.queued.push(envelope);
        }
        Ok(output)
    }

    fn receive(&mut self, unit: Bytes, _now: Instant) -> Result<WireOutput, String> {
        let mut output = WireOutput::default();
        let mut input = &unit[..];
        while !input.is_empty() {
            self.tls
                .read_tls(&mut input)
                .map_err(|error| error.to_string())?;
            self.tls
                .process_new_packets()
                .map_err(|error| error.to_string())?;
            let mut buffer = [0u8; 16 * 1024];
            loop {
                match self.tls.reader().read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => self.plaintext.extend_from_slice(&buffer[..read]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        self.read_cells(&mut output)?;
        self.flush(&mut output)?;
        Ok(output)
    }
}
