//! Tor's cells, link protocol and directory, written for an Axon node: cells
//! and relay messages, Ed25519 and RSA certificates, relay crypto, the ntor
//! handshake, TLS links that check a relay's identities, and the
//! microdescriptor consensus with its authority signatures.

pub mod cell;
pub mod cert;
pub mod crypto;
pub mod directory;
pub mod link;
pub mod ntor;

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
