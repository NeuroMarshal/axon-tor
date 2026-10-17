//! Tor's Ed25519 certificates and the RSA to Ed25519 cross-certificate, as
//! relays send them in CERTS cells and onion services in descriptors.

use axon_addons::{
    noise::sha256,
    rsa::PublicKey,
    sign::{Signature, VerifyingKey},
};

pub const SIGNING_KEY: u8 = 4;
pub const TLS_LINK: u8 = 5;
pub const DESCRIPTOR_SIGNING: u8 = 8;
pub const INTRO_AUTH: u8 = 9;
pub const INTRO_ENCRYPTION: u8 = 11;

const SIGNED_WITH_KEY: u8 = 4;
const AFFECTS_VALIDATION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Cert {
    pub cert_type: u8,
    /// Hours since the Unix epoch.
    pub expires: u32,
    /// An Ed25519 key, or for TLS link certificates a SHA-256 digest.
    pub certified: [u8; 32],
    /// The key that signed the certificate, if the certificate names it.
    pub signed_with: Option<[u8; 32]>,
    raw: Vec<u8>,
}

fn ed25519_verify(key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    VerifyingKey(*key)
        .verify(message, &Signature(signature))
        .is_ok()
}

impl Ed25519Cert {
    /// Parses a certificate. Unknown extensions that affect validation make
    /// it invalid.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 + 64 || bytes[0] != 1 {
            return None;
        }
        let cert_type = bytes[1];
        let expires = u32::from_be_bytes(bytes[2..6].try_into().ok()?);
        let certified = bytes[7..39].try_into().ok()?;
        let count = bytes[39];
        let mut at = 40;
        let mut signed_with = None;
        for _ in 0..count {
            let header = bytes.get(at..at + 4)?;
            let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let (kind, flags) = (header[2], header[3]);
            let data = bytes.get(at + 4..at + 4 + length)?;
            match kind {
                SIGNED_WITH_KEY if length == 32 => signed_with = Some(data.try_into().ok()?),
                _ if flags & AFFECTS_VALIDATION != 0 => return None,
                _ => {}
            }
            at += 4 + length;
        }
        if bytes.len() != at + 64 {
            return None;
        }
        Some(Self {
            cert_type,
            expires,
            certified,
            signed_with,
            raw: bytes.to_vec(),
        })
    }

    /// Whether `key` signed the certificate. When the certificate names its
    /// signer, the name must match too.
    pub fn verify(&self, key: &[u8; 32]) -> bool {
        if self.signed_with.is_some_and(|named| named != *key) {
            return false;
        }
        let (signed, signature) = self.raw.split_at(self.raw.len() - 64);
        ed25519_verify(key, signed, signature)
    }

    /// Verifies against the key the certificate names as its signer.
    pub fn verify_self_named(&self) -> Option<[u8; 32]> {
        let key = self.signed_with?;
        self.verify(&key).then_some(key)
    }

    pub fn is_expired(&self, now_seconds: u64) -> bool {
        u64::from(self.expires) * 3600 < now_seconds
    }
}

/// Checks an RSA to Ed25519 cross-certificate with the relay's RSA
/// identity key and returns the Ed25519 identity it certifies.
pub fn rsa_cross_certificate(bytes: &[u8], rsa: &PublicKey, now_seconds: u64) -> Option<[u8; 32]> {
    let key: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
    let expires = u32::from_be_bytes(bytes.get(32..36)?.try_into().ok()?);
    let length = usize::from(*bytes.get(36)?);
    let signature = bytes.get(37..37 + length)?;
    if u64::from(expires) * 3600 < now_seconds {
        return None;
    }
    let digest = sha256(&[b"Tor TLS RSA/Ed25519 cross-certificate", &bytes[..36]]);
    rsa.verify_pkcs1(&digest, signature).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axon_addons::sign::SigningKey;

    fn certificate(
        signer: &SigningKey,
        cert_type: u8,
        certified: [u8; 32],
        name_signer: bool,
    ) -> Vec<u8> {
        let mut bytes = vec![1, cert_type];
        bytes.extend_from_slice(&500_000u32.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&certified);
        if name_signer {
            bytes.push(1);
            bytes.extend_from_slice(&32u16.to_be_bytes());
            bytes.extend_from_slice(&[SIGNED_WITH_KEY, 0]);
            bytes.extend_from_slice(&signer.verifying_key().0);
        } else {
            bytes.push(0);
        }
        let signature = signer.sign(&bytes).0;
        bytes.extend_from_slice(&signature);
        bytes
    }

    #[test]
    fn certificates_verify_against_their_signer_only() {
        let identity = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let bytes = certificate(&identity, SIGNING_KEY, [3; 32], true);
        let cert = Ed25519Cert::parse(&bytes).unwrap();
        assert_eq!(cert.certified, [3; 32]);
        assert_eq!(cert.verify_self_named(), Some(identity.verifying_key().0));
        assert!(!cert.verify(&other.verifying_key().0));
        assert!(!cert.is_expired(400_000 * 3600));
        assert!(cert.is_expired(600_000 * 3600));
        let plain = Ed25519Cert::parse(&certificate(&identity, TLS_LINK, [4; 32], false)).unwrap();
        assert!(plain.verify(&identity.verifying_key().0));
        assert_eq!(plain.verify_self_named(), None);
        let mut tampered = bytes.clone();
        tampered[10] ^= 1;
        assert!(
            !Ed25519Cert::parse(&tampered)
                .unwrap()
                .verify(&identity.verifying_key().0)
        );
    }
}
