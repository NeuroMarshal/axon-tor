//! The directory: the authorities a client trusts, the consensus they sign
//! and the microdescriptors that complete it.

use std::net::SocketAddr;

/// A directory authority: where its relay listens, its relay identity, and
/// the v3 identity it signs consensus documents with.
#[derive(Debug, Clone, Copy)]
pub struct Authority {
    pub name: &'static str,
    pub address: &'static str,
    /// SHA-1 of the relay's RSA identity key, in hex.
    pub fingerprint: &'static str,
    /// SHA-1 of the authority's v3 identity key, in hex.
    pub v3_identity: &'static str,
}

/// The authorities of the public Tor network.
pub const AUTHORITIES: [Authority; 9] = [
    Authority {
        name: "moria1",
        address: "128.31.0.39:9201",
        fingerprint: "1A25C6358DB91342AA51720A5038B72742732498",
        v3_identity: "F533C81CEF0BC0267857C99B2F471ADF249FA232",
    },
    Authority {
        name: "tor26",
        address: "217.196.147.77:443",
        fingerprint: "FAA4BCA4A6AC0CB4F2EEC88A1F35F4AE6EF794A5",
        v3_identity: "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C",
    },
    Authority {
        name: "dizum",
        address: "45.66.35.11:443",
        fingerprint: "7EA6EAD6FD83083C538F44038BBFA077587DD755",
        v3_identity: "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
    },
    Authority {
        name: "gabelmoo",
        address: "131.188.40.189:443",
        fingerprint: "F2044413DAC2E02E3D6BCF4735A19BCA1DE97281",
        v3_identity: "ED03BB616EB2F60BEC80151114BB25CEF515B226",
    },
    Authority {
        name: "dannenberg",
        address: "193.23.244.244:443",
        fingerprint: "7BE683E65D48141321C5ED92F075C55364AC7123",
        v3_identity: "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
    },
    Authority {
        name: "maatuska",
        address: "171.25.193.9:80",
        fingerprint: "BD6A829255CB08E66FBE7D3748363586E46B3810",
        v3_identity: "49015F787433103580E3B66A1707A00E60F2D15B",
    },
    Authority {
        name: "longclaw",
        address: "199.58.81.140:443",
        fingerprint: "74A910646BCEEFBCD2E874FC1DC997430F968145",
        v3_identity: "23D15D965BC35114467363C165C4F724B64B4F66",
    },
    Authority {
        name: "bastet",
        address: "204.13.164.118:443",
        fingerprint: "24E2F139121D4394C54B5BCC368B3B411857C413",
        v3_identity: "27102BC123E7AF1D4741AE047E160C91ADC76B21",
    },
    Authority {
        name: "faravahar",
        address: "216.218.219.41:443",
        fingerprint: "E3E42D35F801C9D5AB23584E0025D56FE2B33396",
        v3_identity: "70849B868D606BAECFB6128C5E3D782029AA394F",
    },
];

/// Parses a 40-digit hex fingerprint.
pub fn parse_fingerprint(hex: &str) -> Option<[u8; 20]> {
    data_encoding::HEXUPPER_PERMISSIVE
        .decode(hex.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

impl Authority {
    pub fn socket_address(&self) -> SocketAddr {
        self.address.parse().expect("valid authority address")
    }

    pub fn rsa_identity(&self) -> [u8; 20] {
        parse_fingerprint(self.fingerprint).expect("valid authority fingerprint")
    }
}

/// Seconds since the Unix epoch of a `YYYY-MM-DD HH:MM:SS` time.
pub fn parse_time(date: &str, time: &str) -> Option<u64> {
    let mut date = date.split('-').map(|part| part.parse::<i64>().ok());
    let (year, month, day) = (date.next()??, date.next()??, date.next()??);
    let mut time = time.split(':').map(|part| part.parse::<i64>().ok());
    let (hour, minute, second) = (time.next()??, time.next()??, time.next()??);
    // Days from the civil date (Howard Hinnant's algorithm).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

/// Base64 as directory documents write it, with or without padding.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim().trim_end_matches('=');
    data_encoding::BASE64_NOPAD.decode(trimmed.as_bytes()).ok()
}

/// The PEM block that starts on the line after `lines[at]`, decoded, and
/// the index of the line after it.
fn pem_block(lines: &[&str], at: usize) -> Option<(Vec<u8>, usize)> {
    let begin = at + 1;
    if !lines.get(begin)?.starts_with("-----BEGIN ") {
        return None;
    }
    let end = begin
        + lines[begin..]
            .iter()
            .position(|line| line.starts_with("-----END "))?;
    let body = lines[begin + 1..end].concat();
    Some((decode_base64(&body)?, end + 1))
}

/// Relay flags from the consensus.
pub mod flags {
    pub const EXIT: u16 = 1;
    pub const FAST: u16 = 2;
    pub const GUARD: u16 = 4;
    pub const HSDIR: u16 = 8;
    pub const RUNNING: u16 = 16;
    pub const STABLE: u16 = 32;
    pub const V2DIR: u16 = 64;
    pub const VALID: u16 = 128;
    pub const BAD_EXIT: u16 = 256;
    pub const MIDDLE_ONLY: u16 = 512;

    pub fn parse(names: &str) -> u16 {
        names.split_whitespace().fold(0, |flags, name| {
            flags
                | match name {
                    "Exit" => EXIT,
                    "Fast" => FAST,
                    "Guard" => GUARD,
                    "HSDir" => HSDIR,
                    "Running" => RUNNING,
                    "Stable" => STABLE,
                    "V2Dir" => V2DIR,
                    "Valid" => VALID,
                    "BadExit" => BAD_EXIT,
                    "MiddleOnly" => MIDDLE_ONLY,
                    _ => 0,
                }
        })
    }
}

/// A relay as the microdescriptor consensus lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub nickname: String,
    pub rsa_identity: [u8; 20],
    pub address: SocketAddr,
    pub dir_port: u16,
    /// SHA-256 of the relay's microdescriptor.
    pub microdescriptor: [u8; 32],
    pub flags: u16,
    /// Weight for path selection, in the consensus's bandwidth units.
    pub bandwidth: u64,
}

impl Relay {
    pub fn has(&self, flags: u16) -> bool {
        self.flags & flags == flags
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: String,
    pub v3_identity: [u8; 20],
    pub signing_key_digest: [u8; 20],
    pub signature: Vec<u8>,
}

/// A microdescriptor consensus.
#[derive(Debug, Clone)]
pub struct Consensus {
    pub valid_after: u64,
    pub fresh_until: u64,
    pub valid_until: u64,
    pub relays: Vec<Relay>,
    pub params: std::collections::BTreeMap<String, i64>,
    pub shared_rand_current: Option<[u8; 32]>,
    pub shared_rand_previous: Option<[u8; 32]>,
    pub signatures: Vec<Signature>,
    /// SHA-256 of the signed part: through the space after the first
    /// "directory-signature".
    pub signed_digest: [u8; 32],
}

fn shared_random(fields: &[&str]) -> Option<[u8; 32]> {
    decode_base64(fields.get(2)?)?.try_into().ok()
}

impl Consensus {
    pub fn parse(text: &str) -> Result<Self, String> {
        if !text.starts_with("network-status-version 3 microdesc") {
            return Err("not a microdescriptor consensus".to_owned());
        }
        let marker = "\ndirectory-signature ";
        let signed_end = text.find(marker).ok_or("no signatures")? + marker.len();
        let signed_digest = axon_addons::noise::sha256(&[&text.as_bytes()[..signed_end]]);
        let lines = text.lines().collect::<Vec<_>>();
        let mut consensus = Self {
            valid_after: 0,
            fresh_until: 0,
            valid_until: 0,
            relays: Vec::new(),
            params: Default::default(),
            shared_rand_current: None,
            shared_rand_previous: None,
            signatures: Vec::new(),
            signed_digest,
        };
        let mut at = 0;
        while at < lines.len() {
            let fields = lines[at].split_whitespace().collect::<Vec<_>>();
            at += 1;
            let time = || parse_time(fields.get(1)?, fields.get(2)?);
            match fields.first().copied() {
                Some("valid-after") => consensus.valid_after = time().ok_or("bad valid-after")?,
                Some("fresh-until") => consensus.fresh_until = time().ok_or("bad fresh-until")?,
                Some("valid-until") => consensus.valid_until = time().ok_or("bad valid-until")?,
                Some("params") => {
                    for pair in &fields[1..] {
                        if let Some((key, value)) = pair.split_once('=')
                            && let Ok(value) = value.parse()
                        {
                            consensus.params.insert(key.to_owned(), value);
                        }
                    }
                }
                Some("shared-rand-current-value") => {
                    consensus.shared_rand_current = shared_random(&fields);
                }
                Some("shared-rand-previous-value") => {
                    consensus.shared_rand_previous = shared_random(&fields);
                }
                Some("r") if fields.len() >= 8 => {
                    let rsa_identity = decode_base64(fields[2])
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or("bad relay identity")?;
                    let ip = fields[5].parse().map_err(|_| "bad relay address")?;
                    let port = fields[6].parse().map_err(|_| "bad relay port")?;
                    consensus.relays.push(Relay {
                        nickname: fields[1].to_owned(),
                        rsa_identity,
                        address: SocketAddr::new(ip, port),
                        dir_port: fields[7].parse().unwrap_or(0),
                        microdescriptor: [0; 32],
                        flags: 0,
                        bandwidth: 0,
                    });
                }
                Some("m") => {
                    if let (Some(relay), Some(digest)) =
                        (consensus.relays.last_mut(), fields.get(1))
                    {
                        relay.microdescriptor = decode_base64(digest)
                            .and_then(|bytes| bytes.try_into().ok())
                            .ok_or("bad microdescriptor digest")?;
                    }
                }
                Some("s") => {
                    if let Some(relay) = consensus.relays.last_mut() {
                        relay.flags = flags::parse(&lines[at - 1][1..]);
                    }
                }
                Some("w") => {
                    if let Some(relay) = consensus.relays.last_mut() {
                        relay.bandwidth = fields
                            .iter()
                            .find_map(|field| field.strip_prefix("Bandwidth="))
                            .and_then(|value| value.parse().ok())
                            .unwrap_or(0);
                    }
                }
                Some("directory-signature") => {
                    let (algorithm, identity, digest) = match fields.len() {
                        4 => (fields[1], fields[2], fields[3]),
                        3 => ("sha1", fields[1], fields[2]),
                        _ => return Err("bad directory-signature".to_owned()),
                    };
                    let (signature, next) =
                        pem_block(&lines, at - 1).ok_or("bad signature block")?;
                    at = next;
                    consensus.signatures.push(Signature {
                        algorithm: algorithm.to_owned(),
                        v3_identity: parse_fingerprint(identity).ok_or("bad signer")?,
                        signing_key_digest: parse_fingerprint(digest).ok_or("bad signing key")?,
                        signature,
                    });
                }
                _ => {}
            }
        }
        Ok(consensus)
    }

    /// The authorities among [`AUTHORITIES`] whose valid SHA-256 signature
    /// the consensus carries, checked with their signing key certificates.
    pub fn signed_by(&self, certificates: &[KeyCertificate]) -> Vec<&'static str> {
        AUTHORITIES
            .iter()
            .filter(|authority| {
                let identity = parse_fingerprint(authority.v3_identity).expect("valid identity");
                self.signatures.iter().any(|signature| {
                    signature.algorithm == "sha256"
                        && signature.v3_identity == identity
                        && certificates.iter().any(|certificate| {
                            certificate.v3_identity == identity
                                && certificate.signing_key_digest == signature.signing_key_digest
                                && certificate
                                    .signing_key
                                    .verify_pkcs1(&self.signed_digest, &signature.signature)
                        })
                })
            })
            .map(|authority| authority.name)
            .collect()
    }

    /// Whether more than half of the known authorities signed it.
    pub fn is_trusted(&self, certificates: &[KeyCertificate]) -> bool {
        self.signed_by(certificates).len() * 2 > AUTHORITIES.len()
    }

    pub fn param(&self, name: &str, default: i64) -> i64 {
        self.params.get(name).copied().unwrap_or(default)
    }
}

/// An authority's signing key, certified by its long-term v3 identity key.
#[derive(Debug, Clone)]
pub struct KeyCertificate {
    pub v3_identity: [u8; 20],
    pub signing_key: axon_addons::rsa::PublicKey,
    pub signing_key_digest: [u8; 20],
    pub expires: u64,
}

fn sha1(bytes: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    sha1::Sha1::digest(bytes).into()
}

/// Reads the key certificates in `text` and keeps those that are signed by
/// their identity key, cross-signed by their signing key and not expired.
pub fn parse_key_certificates(text: &str, now: u64) -> Vec<KeyCertificate> {
    let mut certificates = Vec::new();
    let start_marker = "dir-key-certificate-version 3";
    let end_marker = "\ndir-key-certification\n";
    let mut rest = text;
    while let Some(start) = rest.find(start_marker) {
        let document = &rest[start..];
        let Some(signed_len) = document.find(end_marker).map(|end| end + end_marker.len()) else {
            break;
        };
        let lines = document.lines().collect::<Vec<_>>();
        let mut fingerprint = None;
        let mut expires = None;
        let mut identity = None;
        let mut signing = None;
        let mut crosscert = None;
        let mut certification = None;
        let mut at = 0;
        while at < lines.len() {
            let fields = lines[at].split_whitespace().collect::<Vec<_>>();
            match fields.first().copied() {
                Some("fingerprint") => {
                    fingerprint = fields.get(1).and_then(|f| parse_fingerprint(f))
                }
                Some("dir-key-expires") => {
                    expires = fields
                        .get(1)
                        .zip(fields.get(2))
                        .and_then(|(d, t)| parse_time(d, t));
                }
                Some(
                    name @ ("dir-identity-key"
                    | "dir-signing-key"
                    | "dir-key-crosscert"
                    | "dir-key-certification"),
                ) => {
                    let Some((block, next)) = pem_block(&lines, at) else {
                        break;
                    };
                    match name {
                        "dir-identity-key" => identity = Some(block),
                        "dir-signing-key" => signing = Some(block),
                        "dir-key-crosscert" => crosscert = Some(block),
                        _ => certification = Some(block),
                    }
                    at = next;
                    if name == "dir-key-certification" {
                        break;
                    }
                    continue;
                }
                _ => {}
            }
            at += 1;
        }
        let consumed: usize = lines[..at.min(lines.len())]
            .iter()
            .map(|line| line.len() + 1)
            .sum();
        rest = &document[consumed.max(signed_len)..];
        let (
            Some(fingerprint),
            Some(expires),
            Some(identity),
            Some(signing),
            Some(crosscert),
            Some(certification),
        ) = (
            fingerprint,
            expires,
            identity,
            signing,
            crosscert,
            certification,
        )
        else {
            continue;
        };
        let (Some(identity_key), Some(signing_key)) = (
            axon_addons::rsa::PublicKey::from_pkcs1(&identity),
            axon_addons::rsa::PublicKey::from_pkcs1(&signing),
        ) else {
            continue;
        };
        let certified =
            identity_key.verify_pkcs1(&sha1(&document.as_bytes()[..signed_len]), &certification);
        let crossed = signing_key.verify_pkcs1(&sha1(&identity), &crosscert);
        if sha1(&identity) == fingerprint && certified && crossed && expires > now {
            certificates.push(KeyCertificate {
                v3_identity: fingerprint,
                signing_key_digest: sha1(&signing),
                signing_key,
                expires,
            });
        }
    }
    certificates
}

/// What a client takes from a relay's microdescriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Microdescriptor {
    pub digest: [u8; 32],
    pub ntor_onion_key: [u8; 32],
    pub ed25519_identity: Option<[u8; 32]>,
    /// Ports the relay exits to, from its policy summary.
    pub exit_ports: PortPolicy,
}

/// A policy summary: `accept` or `reject` and a list of port ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortPolicy {
    pub accept: bool,
    pub ranges: Vec<(u16, u16)>,
}

/// Relays without a summary exit nowhere.
impl Default for PortPolicy {
    fn default() -> Self {
        Self {
            accept: true,
            ranges: Vec::new(),
        }
    }
}

impl PortPolicy {
    pub fn parse(text: &str) -> Option<Self> {
        let (kind, list) = text.split_once(' ')?;
        let accept = match kind {
            "accept" => true,
            "reject" => false,
            _ => return None,
        };
        let ranges = list
            .split(',')
            .filter_map(|item| match item.split_once('-') {
                Some((low, high)) => Some((low.parse().ok()?, high.parse().ok()?)),
                None => item.parse().ok().map(|port| (port, port)),
            })
            .collect();
        Some(Self { accept, ranges })
    }

    pub fn allows(&self, port: u16) -> bool {
        let listed = self
            .ranges
            .iter()
            .any(|&(low, high)| (low..=high).contains(&port));
        listed == self.accept
    }
}

/// Splits a batch of microdescriptors and parses each. Each starts with
/// its "onion-key" item, or with "ntor-onion-key" once relays dropped the
/// older key.
pub fn parse_microdescriptors(text: &str) -> Vec<Microdescriptor> {
    let first_item = if text.starts_with("onion-key") || text.contains("\nonion-key\n") {
        "onion-key\n"
    } else {
        "ntor-onion-key "
    };
    let mut starts = text
        .match_indices(first_item)
        .map(|(index, _)| index)
        .filter(|&index| index == 0 || text.as_bytes()[index - 1] == b'\n')
        .collect::<Vec<_>>();
    starts.push(text.len());
    starts
        .windows(2)
        .filter_map(|bounds| {
            let body = &text[bounds[0]..bounds[1]];
            let mut ntor = None;
            let mut ed25519 = None;
            let mut exit_ports = PortPolicy::default();
            for line in body.lines() {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                match fields.as_slice() {
                    ["ntor-onion-key", key] => ntor = decode_base64(key)?.try_into().ok(),
                    ["id", "ed25519", key] => ed25519 = decode_base64(key)?.try_into().ok(),
                    ["p", ..] => exit_ports = PortPolicy::parse(&line[2..])?,
                    _ => {}
                }
            }
            Some(Microdescriptor {
                digest: axon_addons::noise::sha256(&[body.as_bytes()]),
                ntor_onion_key: ntor?,
                ed25519_identity: ed25519,
                exit_ports,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_convert_to_unix_seconds() {
        assert_eq!(parse_time("1970-01-01", "00:00:00"), Some(0));
        assert_eq!(parse_time("2026-10-17", "12:00:00"), Some(1_792_238_400));
        assert_eq!(parse_time("2024-02-29", "23:59:59"), Some(1_709_251_199));
    }

    #[test]
    fn microdescriptors_split_and_parse() {
        let text = "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----\n\
                    ntor-onion-key AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\n\
                    p accept 80,443,8000-8100\nid ed25519 AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI\n\
                    onion-key\n-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----\n\
                    ntor-onion-key AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\n";
        let parsed = parse_microdescriptors(text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].ntor_onion_key, [1; 32]);
        assert_eq!(parsed[0].ed25519_identity, Some([2; 32]));
        assert!(parsed[0].exit_ports.allows(443) && parsed[0].exit_ports.allows(8050));
        assert!(!parsed[0].exit_ports.allows(22));
        assert_eq!(parsed[1].ntor_onion_key, [3; 32]);
        assert!(!parsed[1].exit_ports.allows(80));
        let second_start = text.rfind("onion-key\n").unwrap();
        assert_eq!(
            parsed[1].digest,
            axon_addons::noise::sha256(&[&text.as_bytes()[second_start..]])
        );
    }
}
