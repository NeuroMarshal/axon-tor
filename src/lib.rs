//! A Tor client built on Axon that works in the real Tor network.
//!
//! The client is an Axon node: [`plane::TorPlane`] is its forwarding plane,
//! its links speak Tor's link protocol through Axon's foreign wire layer,
//! and the runtime drives it like any other node. It downloads and checks
//! the consensus, builds circuits through relays and opens streams through
//! exits and to onion services, for local programs behind SOCKS5 or an HTTP
//! proxy.

pub mod cell;
pub mod cert;
pub mod client;
pub mod crypto;
pub mod daemon;
pub mod directory;
pub mod link;
pub mod ntor;
pub mod onion;
pub mod plane;

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
