//! The ntor handshake (tor-spec 5.1.4), the client's half: it proves that
//! only the relay with the given identity and onion key can derive the
//! circuit keys.

use axon_addons::{
    keys::{ExchangePublic, ExchangeSecret},
    noise::hmac_sha256,
};

use crate::crypto::hkdf_expand;

const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:verify";
const M_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";

/// Handshake type of ntor in CREATE2 and EXTEND2.
pub const NTOR: u16 = 2;
/// Key material taken from ntor: Df, Db, Kf, Kb.
pub const KEY_MATERIAL_LEN: usize = 72;

pub struct NtorClient {
    secret: ExchangeSecret,
    public: [u8; 32],
    identity: [u8; 20],
    onion_key: [u8; 32],
}

impl NtorClient {
    /// Starts a handshake with the relay whose RSA identity digest and ntor
    /// onion key are given. Returns the client state and the 84 bytes of
    /// handshake data.
    pub fn start(identity: [u8; 20], onion_key: [u8; 32]) -> (Self, Vec<u8>) {
        let secret = ExchangeSecret::generate().expect("system random source");
        let public = secret.public().0;
        let mut data = identity.to_vec();
        data.extend_from_slice(&onion_key);
        data.extend_from_slice(&public);
        (
            Self {
                secret,
                public,
                identity,
                onion_key,
            },
            data,
        )
    }

    /// Checks the relay's reply (Y and AUTH) and returns the key material.
    pub fn finish(self, reply: &[u8]) -> Option<[u8; KEY_MATERIAL_LEN]> {
        let server: [u8; 32] = reply.get(..32)?.try_into().ok()?;
        let auth = reply.get(32..64)?;
        let first = self.secret.agree(&ExchangePublic(server)).ok()?;
        let second = self.secret.agree(&ExchangePublic(self.onion_key)).ok()?;
        let secret_input = [
            &first[..],
            &second,
            &self.identity,
            &self.onion_key,
            &self.public,
            &server,
            PROTOID,
        ]
        .concat();
        let key_seed = hmac_sha256(T_KEY, &[&secret_input]);
        let verify = hmac_sha256(T_VERIFY, &[&secret_input]);
        let expected = hmac_sha256(
            T_MAC,
            &[
                &verify,
                &self.identity,
                &self.onion_key,
                &server,
                &self.public,
                PROTOID,
                b"Server",
            ],
        );
        if expected != *auth {
            return None;
        }
        hkdf_expand(&key_seed, M_EXPAND, KEY_MATERIAL_LEN)
            .try_into()
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays the relay with its onion key b.
    fn relay_reply(b: &ExchangeSecret, identity: [u8; 20], request: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let client: [u8; 32] = request[52..84].try_into().unwrap();
        let y = ExchangeSecret::generate().unwrap();
        let big_b = b.public().0;
        let big_y = y.public().0;
        let secret_input = [
            &y.agree(&ExchangePublic(client)).unwrap()[..],
            &b.agree(&ExchangePublic(client)).unwrap(),
            &identity,
            &big_b,
            &client,
            &big_y,
            PROTOID,
        ]
        .concat();
        let key_seed = hmac_sha256(T_KEY, &[&secret_input]);
        let verify = hmac_sha256(T_VERIFY, &[&secret_input]);
        let auth = hmac_sha256(
            T_MAC,
            &[
                &verify, &identity, &big_b, &big_y, &client, PROTOID, b"Server",
            ],
        );
        let mut reply = big_y.to_vec();
        reply.extend_from_slice(&auth);
        (reply, hkdf_expand(&key_seed, M_EXPAND, KEY_MATERIAL_LEN))
    }

    #[test]
    fn both_sides_derive_the_same_keys() {
        let onion_key = ExchangeSecret::generate().unwrap();
        let identity = [9u8; 20];
        let (client, request) = NtorClient::start(identity, onion_key.public().0);
        assert_eq!(request.len(), 84);
        let (reply, relay_keys) = relay_reply(&onion_key, identity, &request);
        assert_eq!(client.finish(&reply).unwrap().to_vec(), relay_keys);

        let (client, request) = NtorClient::start(identity, onion_key.public().0);
        let (mut reply, _) = relay_reply(&onion_key, identity, &request);
        reply[40] ^= 1;
        assert!(client.finish(&reply).is_none());
    }
}
