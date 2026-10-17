//! Circuit keys and the layered encryption of relay cells.
//!
//! Every hop of a circuit shares two keys and two running digests with the
//! client, one of each per direction. The client adds one layer per hop to
//! the cells it sends and removes them from the cells that come back; a hop
//! recognizes a cell meant for it by the digest.

use aes::{Aes128, Aes256};
use axon_addons::{noise::hmac_sha256, sha3::Sponge};
use ctr::{
    Ctr128BE,
    cipher::{KeyIvInit, StreamCipher},
};
use sha1::{Digest, Sha1};

use crate::cell::{PAYLOAD_LEN, RelayMessage};

#[derive(Clone)]
enum RunningDigest {
    Sha1(Sha1),
    Sha3(Box<Sponge>),
}

impl RunningDigest {
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha3(sponge) => {
                sponge.update(bytes);
            }
        }
    }

    /// The digest of everything so far, truncated to 20 bytes for SENDMEs.
    fn current(&self) -> [u8; 20] {
        match self {
            Self::Sha1(hash) => hash.clone().finalize().into(),
            Self::Sha3(sponge) => {
                let mut out = [0u8; 32];
                (**sponge).clone().finalize_into(&mut out);
                out[..20].try_into().expect("fixed slice")
            }
        }
    }
}

enum Cipher {
    Aes128(Box<Ctr128BE<Aes128>>),
    Aes256(Box<Ctr128BE<Aes256>>),
}

impl Cipher {
    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::Aes128(cipher) => cipher.apply_keystream(data),
            Self::Aes256(cipher) => cipher.apply_keystream(data),
        }
    }
}

struct Direction {
    cipher: Cipher,
    digest: RunningDigest,
}

/// The keys one hop shares with the client.
pub struct HopKeys {
    forward: Direction,
    backward: Direction,
}

impl HopKeys {
    /// Keys from KDF-TOR or ntor: digests Df and Db (SHA-1 seeds), then
    /// AES-128 keys Kf and Kb.
    pub fn from_material(material: &[u8]) -> Self {
        let direction = |seed: &[u8], key: &[u8]| {
            let mut digest = Sha1::new();
            digest.update(seed);
            Direction {
                cipher: Cipher::Aes128(Box::new(Ctr128BE::<Aes128>::new(
                    key.into(),
                    &[0u8; 16].into(),
                ))),
                digest: RunningDigest::Sha1(digest),
            }
        };
        Self {
            forward: direction(&material[..20], &material[40..56]),
            backward: direction(&material[20..40], &material[56..72]),
        }
    }

    /// Keys of an onion service's virtual hop: SHA3-256 digests and AES-256,
    /// 32 bytes each.
    pub fn from_onion_material(material: &[u8; 128]) -> Self {
        let direction = |seed: &[u8], key: &[u8]| {
            let mut sponge = Sponge::sha3_256();
            sponge.update(seed);
            Direction {
                cipher: Cipher::Aes256(Box::new(Ctr128BE::<Aes256>::new(
                    key.into(),
                    &[0u8; 16].into(),
                ))),
                digest: RunningDigest::Sha3(Box::new(sponge)),
            }
        };
        Self {
            forward: direction(&material[..32], &material[64..96]),
            backward: direction(&material[32..64], &material[96..128]),
        }
    }
}

/// KDF-TOR: SHA-1 over K0 and a counter, as CREATE_FAST uses it. Returns
/// the key material and KH, the value that proves the relay knows it.
pub fn kdf_tor(k0: &[u8]) -> ([u8; 72], [u8; 20]) {
    let mut stream = Vec::with_capacity(100);
    for counter in 0u8..5 {
        let mut hash = Sha1::new();
        hash.update(k0);
        hash.update([counter]);
        stream.extend_from_slice(&hash.finalize());
    }
    (
        stream[20..92].try_into().expect("fixed slice"),
        stream[..20].try_into().expect("fixed slice"),
    )
}

/// The expand step of HKDF-SHA256 with `seed` as the key, as ntor uses it.
pub fn hkdf_expand(seed: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let block = hmac_sha256(seed, &[&previous, info, &[counter]]);
        out.extend_from_slice(&block);
        previous = block.to_vec();
        counter += 1;
    }
    out.truncate(length);
    out
}

/// The client's side of a circuit's relay crypto, first hop first.
#[derive(Default)]
pub struct CircuitCrypto {
    hops: Vec<HopKeys>,
}

impl CircuitCrypto {
    pub fn push(&mut self, hop: HopKeys) {
        self.hops.push(hop);
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Encrypts a message for hop `target`. Returns the payload and the
    /// running digest after it, which an authenticated SENDME echoes.
    pub fn seal(&mut self, target: usize, message: &RelayMessage) -> ([u8; PAYLOAD_LEN], [u8; 20]) {
        let mut payload = message.encode();
        let hop = &mut self.hops[target];
        hop.forward.digest.update(&payload);
        let digest = hop.forward.digest.current();
        payload[5..9].copy_from_slice(&digest[..4]);
        for hop in self.hops[..=target].iter_mut().rev() {
            hop.forward.cipher.apply(&mut payload);
        }
        (payload, digest)
    }

    /// Removes layers until a hop recognizes the cell. Returns that hop, the
    /// message and the running digest after it.
    pub fn open(
        &mut self,
        payload: &mut [u8; PAYLOAD_LEN],
    ) -> Option<(usize, RelayMessage, [u8; 20])> {
        for (index, hop) in self.hops.iter_mut().enumerate() {
            hop.backward.cipher.apply(payload);
            if payload[1..3] != [0, 0] {
                continue;
            }
            let mut zeroed = *payload;
            zeroed[5..9].fill(0);
            let mut candidate = hop.backward.digest.clone();
            candidate.update(&zeroed);
            let digest = candidate.current();
            if digest[..4] == payload[5..9] {
                hop.backward.digest = candidate;
                return Some((index, RelayMessage::decode(payload)?, digest));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::DATA;

    /// The relay's side of one hop, mirroring the client's.
    struct RelaySide {
        forward: Direction,
        backward: Direction,
    }

    #[test]
    fn layered_cells_reach_the_right_hop_and_come_back() {
        let materials = (0..3u8).map(|i| [i + 1; 72]).collect::<Vec<_>>();
        let mut client = CircuitCrypto::default();
        let mut relays = Vec::new();
        for material in &materials {
            client.push(HopKeys::from_material(material));
            let keys = HopKeys::from_material(material);
            relays.push(RelaySide {
                forward: keys.forward,
                backward: keys.backward,
            });
        }
        let message = RelayMessage::new(DATA, 3, b"to the exit".to_vec());
        let (mut payload, sent_digest) = client.seal(2, &message);
        for relay in &mut relays {
            relay.forward.cipher.apply(&mut payload);
        }
        assert_eq!(RelayMessage::decode(&payload).unwrap(), message);
        relays[2].forward.digest.update(&{
            let mut zeroed = payload;
            zeroed[5..9].fill(0);
            zeroed
        });
        assert_eq!(relays[2].forward.digest.current(), sent_digest);

        // The middle hop answers: it sets its digest and adds its layer, the
        // first hop adds its own.
        let reply = RelayMessage::new(DATA, 3, b"from the middle".to_vec());
        let mut payload = reply.encode();
        relays[1].backward.digest.update(&payload);
        let digest = relays[1].backward.digest.current();
        payload[5..9].copy_from_slice(&digest[..4]);
        relays[1].backward.cipher.apply(&mut payload);
        relays[0].backward.cipher.apply(&mut payload);
        let (hop, opened, opened_digest) = client.open(&mut payload).unwrap();
        assert_eq!((hop, opened, opened_digest), (1, reply, digest));
    }

    #[test]
    fn kdf_tor_matches_its_definition() {
        let (material, kh) = kdf_tor(b"k0");
        let mut first = Sha1::new();
        first.update(b"k0\x00");
        assert_eq!(kh, <[u8; 20]>::from(first.finalize()));
        let mut second = Sha1::new();
        second.update(b"k0\x01");
        assert_eq!(material[..20], second.finalize()[..]);
    }
}
