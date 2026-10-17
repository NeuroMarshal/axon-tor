//! The client's side of onion services v3 (rend-spec-v3): addresses, key
//! blinding, the ring of descriptor directories, descriptor decryption,
//! and the introduction and rendezvous handshakes.

use aes::Aes256;
use axon_addons::{
    keys::{ExchangePublic, ExchangeSecret},
    sha3::{sha3_256, shake256},
};
use ctr::{
    Ctr128BE,
    cipher::{KeyIvInit, StreamCipher},
};
use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};

use crate::{
    cert::{DESCRIPTOR_SIGNING, Ed25519Cert},
    crypto::HopKeys,
    directory::{Consensus, decode_base64},
    link::RelayTarget,
};

const PROTOID: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1";
const T_HSENC: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract";
const T_HSVERIFY: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_verify";
const T_HSMAC: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_mac";
const M_HSEXPAND: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand";
/// The Ed25519 base point as rend-spec-v3 writes it into the blinding hash.
const BASEPOINT: &[u8] = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)";
/// Minutes in a time period, and the offset of period starts from midnight.
pub const DEFAULT_PERIOD_LENGTH: u64 = 1440;
const ROTATION_OFFSET_MINUTES: u64 = 12 * 60;

/// MAC(key, message) of rend-spec-v3: SHA3-256 over the key's length, the
/// key and the message.
fn mac(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    let length = (key.len() as u64).to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![&length, key];
    parts.extend_from_slice(message);
    sha3_256(&parts)
}

fn aes256_ctr(key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
    Ctr128BE::<Aes256>::new(key.into(), iv.into()).apply_keystream(data);
}

/// The identity key behind `<base32>.onion`, after checking the version
/// and checksum.
pub fn parse_address(host: &str) -> Option<[u8; 32]> {
    let encoded = host.to_ascii_lowercase();
    let encoded = encoded.strip_suffix(".onion")?;
    let encoded = encoded.rsplit('.').next()?;
    let bytes = data_encoding::BASE32_NOPAD
        .decode(encoded.to_ascii_uppercase().as_bytes())
        .ok()?;
    if bytes.len() != 35 || bytes[34] != 3 {
        return None;
    }
    let key: [u8; 32] = bytes[..32].try_into().ok()?;
    let checksum = sha3_256(&[b".onion checksum", &key, &[3]]);
    (checksum[..2] == bytes[32..34]).then_some(key)
}

/// The time period a consensus falls in, as clients number them.
pub fn time_period(consensus: &Consensus, period_length: u64) -> u64 {
    (consensus.valid_after / 60 - ROTATION_OFFSET_MINUTES) / period_length
}

/// The clamped blinding factor h for `identity` in a time period.
fn blinding_factor(identity: &[u8; 32], period: u64, period_length: u64) -> [u8; 32] {
    let nonce = [
        &b"key-blind"[..],
        &period.to_be_bytes(),
        &period_length.to_be_bytes(),
    ]
    .concat();
    let mut factor = sha3_256(&[
        b"Derive temporary signing key\0",
        identity,
        BASEPOINT,
        &nonce,
    ]);
    factor[0] &= 248;
    factor[31] &= 63;
    factor[31] |= 64;
    factor
}

/// The blinded public key of `identity` for a time period: h·A.
pub fn blind(identity: &[u8; 32], period: u64, period_length: u64) -> Option<[u8; 32]> {
    let factor = blinding_factor(identity, period, period_length);
    let point = CompressedEdwardsY(*identity).decompress()?;
    Some(
        (point * Scalar::from_bytes_mod_order(factor))
            .compress()
            .to_bytes(),
    )
}

/// The subcredential a period's descriptor is encrypted with.
pub fn subcredential(identity: &[u8; 32], blinded: &[u8; 32]) -> [u8; 32] {
    let credential = sha3_256(&[b"credential", identity]);
    sha3_256(&[b"subcredential", &credential, blinded])
}

/// The shared random value clients use with a consensus: the current one
/// from the start of a time period until the next value, at midnight.
pub fn shared_random_value(consensus: &Consensus) -> Option<[u8; 32]> {
    let hour = (consensus.valid_after / 3600) % 24;
    if hour >= 12 {
        consensus.shared_rand_current
    } else {
        consensus.shared_rand_previous
    }
}

/// A directory that may hold the descriptor: its Ed25519 identity and
/// position in the ring.
#[derive(Debug, Clone)]
pub struct RingEntry {
    pub index: [u8; 32],
    pub relay: usize,
}

/// Picks the descriptor directories for `blinded`: for each replica, the
/// `spread` directories after its position in the ring, skipping those an
/// earlier replica took. `hsdirs` lists consensus positions and Ed25519
/// identities of the relays with the HSDir flag.
pub fn responsible_directories(
    blinded: &[u8; 32],
    hsdirs: &[(usize, [u8; 32])],
    shared_random: &[u8; 32],
    period: u64,
    period_length: u64,
    replicas: u64,
    spread: usize,
) -> Vec<usize> {
    let mut ring = hsdirs
        .iter()
        .map(|(relay, identity)| RingEntry {
            index: sha3_256(&[
                b"node-idx",
                identity,
                shared_random,
                &period.to_be_bytes(),
                &period_length.to_be_bytes(),
            ]),
            relay: *relay,
        })
        .collect::<Vec<_>>();
    ring.sort_by_key(|entry| entry.index);
    let mut chosen = Vec::new();
    if ring.is_empty() {
        return chosen;
    }
    for replica in 1..=replicas {
        let position = sha3_256(&[
            b"store-at-idx",
            blinded,
            &replica.to_be_bytes(),
            &period_length.to_be_bytes(),
            &period.to_be_bytes(),
        ]);
        let start = ring.partition_point(|entry| entry.index <= position);
        let mut taken = 0;
        for offset in 0..ring.len() {
            let relay = ring[(start + offset) % ring.len()].relay;
            if chosen.contains(&relay) {
                continue;
            }
            chosen.push(relay);
            taken += 1;
            if taken == spread {
                break;
            }
        }
    }
    chosen
}

/// One layer of descriptor encryption: SALT | ENCRYPTED | MAC.
fn decrypt_layer(
    blob: &[u8],
    secret_data: &[u8],
    subcredential: &[u8; 32],
    revision: u64,
    constant: &[u8],
) -> Option<Vec<u8>> {
    if blob.len() < 16 + 32 {
        return None;
    }
    let (salt, rest) = blob.split_at(16);
    let (encrypted, tag) = rest.split_at(rest.len() - 32);
    let mut keys = [0u8; 32 + 16 + 32];
    shake256(
        &[
            secret_data,
            subcredential,
            &revision.to_be_bytes(),
            salt,
            constant,
        ],
        &mut keys,
    );
    let (key, rest) = keys.split_at(32);
    let (iv, mac_key) = rest.split_at(16);
    let expected = sha3_256(&[
        &32u64.to_be_bytes(),
        mac_key,
        &16u64.to_be_bytes(),
        salt,
        encrypted,
    ]);
    if expected[..] != *tag {
        return None;
    }
    let mut plaintext = encrypted.to_vec();
    aes256_ctr(key, iv.try_into().ok()?, &mut plaintext);
    Some(plaintext)
}

/// The base64 body of the `-----BEGIN X-----` block after `keyword`.
fn block_after(text: &str, keyword: &str) -> Option<Vec<u8>> {
    let start = text.find(&format!("{keyword}\n-----BEGIN "))?;
    let rest = &text[start..];
    let begin = rest.find('\n')? + 1;
    let body_start = begin + rest[begin..].find('\n')? + 1;
    let end = body_start + rest[body_start..].find("-----END ")?;
    let body = rest[body_start..end].lines().collect::<String>();
    decode_base64(&body)
}

/// An introduction point from a descriptor.
#[derive(Debug, Clone)]
pub struct IntroPoint {
    pub target: RelayTarget,
    pub ntor_key: [u8; 32],
    /// The introduction point's authentication key, KP_hs_ipt_sid.
    pub auth_key: [u8; 32],
    /// The service's encryption key for this point, KP_hss_ntor.
    pub encryption_key: [u8; 32],
}

/// Reads a link specifier block into the relay it names.
pub fn parse_link_specifiers(bytes: &[u8]) -> Option<RelayTarget> {
    let count = *bytes.first()?;
    let mut at = 1;
    let (mut address, mut rsa, mut ed25519) = (None, None, None);
    for _ in 0..count {
        let kind = *bytes.get(at)?;
        let length = usize::from(*bytes.get(at + 1)?);
        let data = bytes.get(at + 2..at + 2 + length)?;
        match (kind, length) {
            (0, 6) => {
                let ip = std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                let port = u16::from_be_bytes([data[4], data[5]]);
                address = Some(std::net::SocketAddr::from((ip, port)));
            }
            (2, 20) => rsa = Some(data.try_into().ok()?),
            (3, 32) => ed25519 = Some(data.try_into().ok()?),
            _ => {}
        }
        at += 2 + length;
    }
    Some(RelayTarget {
        address: address?,
        rsa_identity: rsa?,
        ed25519_identity: ed25519,
    })
}

/// Checks a descriptor fetched for `identity` in a period and returns its
/// introduction points.
pub fn open_descriptor(
    text: &str,
    identity: &[u8; 32],
    blinded: &[u8; 32],
    now_seconds: u64,
) -> Result<Vec<IntroPoint>, String> {
    if !text.starts_with("hs-descriptor 3\n") {
        return Err("not a v3 descriptor".to_owned());
    }
    let certificate = block_after(text, "descriptor-signing-key-cert")
        .and_then(|bytes| Ed25519Cert::parse(&bytes))
        .ok_or("no descriptor signing key certificate")?;
    if certificate.cert_type != DESCRIPTOR_SIGNING
        || !certificate.verify(blinded)
        || certificate.is_expired(now_seconds)
    {
        return Err("the signing key certificate does not verify".to_owned());
    }
    let signature_at = text.rfind("\nsignature ").ok_or("no signature")? + 1;
    let signature = decode_base64(text[signature_at + "signature ".len()..].trim())
        .ok_or("bad signature encoding")?;
    let signed = [
        &b"Tor onion service descriptor sig v3"[..],
        &text.as_bytes()[..signature_at],
    ]
    .concat();
    let signature: [u8; 64] = signature.try_into().map_err(|_| "bad signature length")?;
    axon_addons::sign::VerifyingKey(certificate.certified)
        .verify(&signed, &axon_addons::sign::Signature(signature))
        .map_err(|_| "the descriptor signature does not verify")?;
    let revision = text
        .lines()
        .find_map(|line| line.strip_prefix("revision-counter "))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .ok_or("no revision counter")?;
    let subcredential = subcredential(identity, blinded);
    let outer = block_after(text, "superencrypted").ok_or("no superencrypted layer")?;
    let first = decrypt_layer(
        &outer,
        blinded,
        &subcredential,
        revision,
        b"hsdir-superencrypted-data",
    )
    .ok_or("the outer layer does not decrypt")?;
    let first = String::from_utf8_lossy(&first);
    let inner = block_after(&first, "encrypted").ok_or("no encrypted layer")?;
    let second = decrypt_layer(
        &inner,
        blinded,
        &subcredential,
        revision,
        b"hsdir-encrypted-data",
    )
    .ok_or("the inner layer does not decrypt (client authorization?)")?;
    let second = String::from_utf8_lossy(&second);
    let mut points = Vec::new();
    for section in second.split("\nintroduction-point ").skip(1) {
        let mut lines = section.lines();
        let specifiers = lines
            .next()
            .and_then(decode_base64)
            .ok_or("bad link specifiers")?;
        let Some(target) = parse_link_specifiers(&specifiers) else {
            continue;
        };
        let key_after = |prefix: &str| {
            section
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .and_then(decode_base64)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        };
        let auth = block_after(section, "auth-key").and_then(|bytes| Ed25519Cert::parse(&bytes));
        let (Some(ntor_key), Some(encryption_key), Some(auth)) = (
            key_after("onion-key ntor "),
            key_after("enc-key ntor "),
            auth,
        ) else {
            continue;
        };
        points.push(IntroPoint {
            target,
            ntor_key,
            auth_key: auth.certified,
            encryption_key,
        });
    }
    Ok(points)
}

/// Link specifiers for a relay: IPv4 address, RSA and Ed25519 identities.
pub fn link_specifiers(target: &RelayTarget) -> Vec<u8> {
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
    let mut out = vec![specifiers.len() as u8];
    for (kind, data) in specifiers {
        out.push(kind);
        out.push(data.len() as u8);
        out.extend_from_slice(&data);
    }
    out
}

/// The client's state between INTRODUCE1 and RENDEZVOUS2.
pub struct Introduction {
    secret: ExchangeSecret,
    public: [u8; 32],
    auth_key: [u8; 32],
    encryption_key: [u8; 32],
}

/// Builds an INTRODUCE1 message for `point` that asks the service to meet
/// at the rendezvous point `rendezvous` (with its ntor key) under `cookie`.
pub fn introduce1(
    point: &IntroPoint,
    subcredential: &[u8; 32],
    cookie: &[u8; 20],
    rendezvous: &RelayTarget,
    rendezvous_ntor_key: &[u8; 32],
) -> (Introduction, Vec<u8>) {
    let mut cell = vec![0u8; 20];
    cell.push(2);
    cell.extend_from_slice(&32u16.to_be_bytes());
    cell.extend_from_slice(&point.auth_key);
    cell.push(0);

    let mut plaintext = cookie.to_vec();
    plaintext.push(0);
    plaintext.push(1);
    plaintext.extend_from_slice(&32u16.to_be_bytes());
    plaintext.extend_from_slice(rendezvous_ntor_key);
    plaintext.extend_from_slice(&link_specifiers(rendezvous));
    // Pad like tor does, so all introductions look alike.
    const MINIMUM: usize = 246;
    let encrypted_len = 32 + plaintext.len() + 32;
    if cell.len() + encrypted_len < MINIMUM {
        plaintext.resize(MINIMUM - cell.len() - 64, 0);
    }

    let secret = ExchangeSecret::generate().expect("system random source");
    let public = secret.public().0;
    let shared = secret
        .agree(&ExchangePublic(point.encryption_key))
        .unwrap_or([0; 32]);
    let secret_input = [
        &shared[..],
        &point.auth_key,
        &public,
        &point.encryption_key,
        PROTOID,
    ]
    .concat();
    let mut keys = [0u8; 64];
    shake256(
        &[&secret_input, T_HSENC, M_HSEXPAND, subcredential],
        &mut keys,
    );
    let mut encrypted = plaintext;
    aes256_ctr(&keys[..32], &[0; 16], &mut encrypted);
    let tag = mac(&keys[32..], &[&cell, &public, &encrypted]);
    cell.extend_from_slice(&public);
    cell.extend_from_slice(&encrypted);
    cell.extend_from_slice(&tag);
    (
        Introduction {
            secret,
            public,
            auth_key: point.auth_key,
            encryption_key: point.encryption_key,
        },
        cell,
    )
}

impl Introduction {
    /// Completes the handshake from the RENDEZVOUS2 payload and returns the
    /// keys of the service's hop.
    pub fn finish(self, rendezvous2: &[u8]) -> Option<HopKeys> {
        let server: [u8; 32] = rendezvous2.get(..32)?.try_into().ok()?;
        let auth = rendezvous2.get(32..64)?;
        let first = self.secret.agree(&ExchangePublic(server)).ok()?;
        let second = self
            .secret
            .agree(&ExchangePublic(self.encryption_key))
            .ok()?;
        let secret_input = [
            &first[..],
            &second,
            &self.auth_key,
            &self.encryption_key,
            &self.public,
            &server,
            PROTOID,
        ]
        .concat();
        let seed = mac(&secret_input, &[T_HSENC]);
        let verify = mac(&secret_input, &[T_HSVERIFY]);
        let auth_input = [
            &verify[..],
            &self.auth_key,
            &self.encryption_key,
            &server,
            &self.public,
            PROTOID,
            b"Server",
        ]
        .concat();
        if mac(&auth_input, &[T_HSMAC])[..] != *auth {
            return None;
        }
        let mut material = [0u8; 128];
        shake256(&[&seed, M_HSEXPAND], &mut material);
        Some(HopKeys::from_onion_material(&material))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_check_their_checksum() {
        // The Tor Project's own onion site.
        let address = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        let key = parse_address(address).unwrap();
        assert_eq!(parse_address(&format!("www.{address}")), Some(key));
        let mut broken = address.to_owned();
        broken.replace_range(0..1, "3");
        assert_eq!(parse_address(&broken), None);
    }

    #[test]
    fn blinding_matches_the_blinded_secret_key() {
        // A' = h·A must equal (h·a)·B for the key pair (a, A).
        let base = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let secret = Scalar::from_bytes_mod_order([7u8; 32]);
        let identity = (base * secret).compress().to_bytes();
        let factor =
            Scalar::from_bytes_mod_order(blinding_factor(&identity, 20_000, DEFAULT_PERIOD_LENGTH));
        let blinded = blind(&identity, 20_000, DEFAULT_PERIOD_LENGTH).unwrap();
        assert_eq!(blinded, (base * (factor * secret)).compress().to_bytes());
        assert_ne!(
            blinded,
            blind(&identity, 20_001, DEFAULT_PERIOD_LENGTH).unwrap()
        );
    }

    #[test]
    fn the_ring_takes_distinct_directories_after_each_replica() {
        let hsdirs = (0..20).map(|i| (i, [i as u8; 32])).collect::<Vec<_>>();
        let chosen = responsible_directories(&[9; 32], &hsdirs, &[1; 32], 5, 1440, 2, 3);
        assert_eq!(chosen.len(), 6);
        let mut unique = chosen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 6);
    }
}
