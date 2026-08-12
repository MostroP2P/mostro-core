//! Domain-separated chat key derivation (`K_conv` / `K_sign`).
//!
//! The ECDH shared secret between two trade keys (or admin ↔ party trade key)
//! is **not** used on the wire. ECDH itself is computed by the local
//! [`generate_shared_key`] helper (`nostr::util::generate_shared_key` is
//! crate-private in 0.45). HKDF-SHA256 then splits that secret into:
//!
//! * [`K_conv`](derive_chat_keys) — NIP-44 encryption and the outer `p` tag
//! * [`K_sign`](derive_chat_keys) — signs the outer kind 14 event (author filter)
//!
//! See <https://mostro.network/protocol/chat.html#key-derivation>.

// Leading `::` selects the `hkdf` crate: `nostr_sdk::prelude` also exports a
// module by that name, so a plain `use hkdf::Hkdf` is ambiguous.
use ::hkdf::Hkdf;
use nostr_sdk::prelude::*;
use secp256k1::{ecdh, PublicKey as Secp256k1PublicKey};
use sha2::Sha256;

use crate::error::{MostroError, ServiceError};

/// HKDF `info` for `K_conv`. Changing this value changes the wire format.
pub const CHAT_CONV_INFO: &[u8] = b"mostro:chat:conv:v1";
/// HKDF `info` for `K_sign`. Changing this value changes the wire format.
pub const CHAT_SIGN_INFO: &[u8] = b"mostro:chat:sign:v1";

/// Raw x25519-style ECDH shared secret (even-parity assumption, per NIP-04/44).
///
/// Replaces `nostr::util::generate_shared_key`, which is crate-private in 0.45.
pub(crate) fn generate_shared_key(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<[u8; 32], MostroError> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // assume even parity, as NIP-04/44 do
    compressed[1..].copy_from_slice(public_key.as_bytes());
    let normalized = Secp256k1PublicKey::from_slice(&compressed).map_err(|e| {
        MostroError::MostroInternalErr(ServiceError::EncryptionError(format!(
            "invalid peer pubkey: {e}"
        )))
    })?;

    let secret_key =
        secp256k1::SecretKey::from_byte_array(&secret_key.to_secret_bytes()).map_err(|e| {
            MostroError::MostroInternalErr(ServiceError::EncryptionError(format!(
                "invalid local secret key: {e}"
            )))
        })?;

    let point = ecdh::shared_secret_point(&normalized, &secret_key);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(&point[..32]);
    Ok(shared)
}

/// Derive `(K_conv, K_sign)` from a party's trade keys and the peer's trade pubkey.
///
/// Both peers obtain the same pair by swapping arguments
/// (`A.derive(a, B) == B.derive(b, A)`).
pub fn derive_chat_keys(
    own_trade: &Keys,
    peer_trade: &PublicKey,
) -> Result<(Keys, Keys), MostroError> {
    let shared = generate_shared_key(own_trade.secret_key(), peer_trade)?;
    derive_chat_keys_from_shared(&shared)
}

/// Derive `(K_conv, K_sign)` from an already-computed 32-byte ECDH secret.
///
/// Clients that persist the ECDH output (e.g. Mostrix `order_chat_shared_key_hex`)
/// call this on load instead of re-running ECDH.
pub fn derive_chat_keys_from_shared(shared: &[u8]) -> Result<(Keys, Keys), MostroError> {
    if shared.len() != 32 {
        return Err(MostroError::MostroInternalErr(
            ServiceError::EncryptionError(format!(
                "chat shared secret must be 32 bytes, got {}",
                shared.len()
            )),
        ));
    }
    let hkdf = Hkdf::<Sha256>::new(None, shared);

    let derive = |info: &[u8]| -> Result<Keys, MostroError> {
        // Retry with a counter byte on the negligible chance that the output
        // is not a valid secp256k1 secret key (spec requirement).
        for counter in 0u16..=255 {
            let mut labelled = info.to_vec();
            if counter > 0 {
                labelled.push(counter as u8);
            }
            let mut out = [0u8; 32];
            hkdf.expand(&labelled, &mut out).map_err(|e| {
                MostroError::MostroInternalErr(ServiceError::EncryptionError(format!(
                    "HKDF expand failed: {e}"
                )))
            })?;
            if let Ok(sk) = SecretKey::from_slice(&out) {
                return Ok(Keys::new(sk));
            }
        }
        Err(MostroError::MostroInternalErr(
            ServiceError::EncryptionError("HKDF failed to produce a valid secret key".to_string()),
        ))
    };

    Ok((derive(CHAT_CONV_INFO)?, derive(CHAT_SIGN_INFO)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Published test vector from <https://mostro.network/protocol/chat.html#test-vector>.
    #[test]
    fn protocol_test_vector_derived_pubkeys() {
        let alice = Keys::parse("548f68890c49fa42f104c60352395e60ff030b0b407e955f1eed1400d6c0347a")
            .unwrap();
        let bob = Keys::parse("f258e73f07386d37133718b6127f873dd7c391b8f43b331ff8254034a13d2943")
            .unwrap();

        assert_eq!(
            alice.public_key().to_hex(),
            "000053c3b4773182e7c4c1b72b272d34be01bf4414a6a25c998977c516a46a01"
        );
        assert_eq!(
            bob.public_key().to_hex(),
            "000009ae5cff9f6ba9b05159ec5ed58c187f5882ea77c81ed5dd19163272a5d7"
        );

        let shared = generate_shared_key(alice.secret_key(), &bob.public_key()).unwrap();
        let expected_shared =
            SecretKey::from_hex("def6633a53d07d1e829484c4d4bdbbeed2f4b14c21743e63871c174338e39475")
                .unwrap()
                .to_secret_bytes();
        assert_eq!(shared, expected_shared);

        let (alice_conv, alice_sign) = derive_chat_keys(&alice, &bob.public_key()).unwrap();
        let (bob_conv, bob_sign) = derive_chat_keys(&bob, &alice.public_key()).unwrap();

        assert_eq!(alice_conv.public_key(), bob_conv.public_key());
        assert_eq!(alice_sign.public_key(), bob_sign.public_key());
        assert_eq!(
            alice_conv.public_key().to_hex(),
            "bceb1cd2a8e98ee9729122a1693edcc39c3ace04582ff96a26705c5e4078a6f2"
        );
        assert_eq!(
            alice_sign.public_key().to_hex(),
            "1dba04571059183f76b148119cfa6f8004dad30cb4e810180a6df17386a7f0b4"
        );

        let from_shared = derive_chat_keys_from_shared(&shared).unwrap();
        assert_eq!(from_shared.0.public_key(), alice_conv.public_key());
        assert_eq!(from_shared.1.public_key(), alice_sign.public_key());
    }

    #[test]
    fn k_conv_cannot_derive_k_sign() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let (conv, sign) = derive_chat_keys(&alice, &bob.public_key()).unwrap();
        // Holding only K_conv must not yield K_sign (observer is read-only).
        assert_ne!(
            conv.secret_key().to_secret_bytes(),
            sign.secret_key().to_secret_bytes()
        );
        assert_ne!(conv.public_key(), sign.public_key());
    }

    #[test]
    fn derive_from_shared_rejects_wrong_length() {
        let err = derive_chat_keys_from_shared(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, MostroError::MostroInternalErr(_)));
    }
}
