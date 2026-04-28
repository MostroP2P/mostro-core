//! ECDH-derived shared key used as the addressable identity of a Mostro
//! P2P chat channel.
//!
//! The two parties of a chat (buyer/seller during a trade or admin/party
//! during a dispute) each compute the same `SharedKey` from their own trade
//! secret key and the counterparty's trade public key, so both can encrypt
//! and decrypt the conversation, and so relays can route gift wraps through
//! a `p` tag bound to the shared public key — without leaking either real
//! pubkey on the wire.

use nostr_sdk::prelude::*;

use crate::error::{MostroError, ServiceError};

/// Shared key derived via ECDH between two parties' trade keys.
///
/// Internally a `Keys` instance whose secret is the 32-byte ECDH output of
/// `(local_secret, counterparty_pubkey)`. Both sides of the conversation
/// derive an identical value and therefore an identical public key, which
/// is what gift wraps are addressed to.
#[derive(Debug, Clone)]
pub struct SharedKey(Keys);

impl SharedKey {
    /// Derive a shared key from a local secret key and the counterparty's
    /// public key using the secp256k1 ECDH primitive exposed by
    /// [`nostr_sdk::util::generate_shared_key`].
    ///
    /// Both peers obtain the same `SharedKey` by swapping arguments
    /// (`A.derive(a_sk, b_pk) == B.derive(b_sk, a_pk)`).
    pub fn derive(secret: &SecretKey, counterparty: &PublicKey) -> Result<Self, MostroError> {
        let bytes = nostr_sdk::util::generate_shared_key(secret, counterparty).map_err(|e| {
            MostroError::MostroInternalErr(ServiceError::EncryptionError(format!(
                "shared key derivation failed: {e}"
            )))
        })?;
        let secret = SecretKey::from_slice(&bytes).map_err(|e| {
            MostroError::MostroInternalErr(ServiceError::EncryptionError(format!(
                "invalid shared secret: {e}"
            )))
        })?;
        Ok(Self(Keys::new(secret)))
    }

    /// Build a `SharedKey` from an already-derived `Keys` value.
    ///
    /// Useful when a client persists a freshly-generated `Keys` instead of
    /// re-deriving it on every load.
    pub fn from_keys(keys: Keys) -> Self {
        Self(keys)
    }

    /// Borrow the underlying `Keys`.
    pub fn keys(&self) -> &Keys {
        &self.0
    }

    /// Public key of this shared key — the value used as the `p` tag on
    /// every gift wrap belonging to the channel.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// Borrow the underlying secret key.
    pub fn secret_key(&self) -> &SecretKey {
        self.0.secret_key()
    }

    /// Serialize the secret as a lower-case hex string suitable for client
    /// persistence. Pair with [`SharedKey::from_hex`] to round-trip.
    pub fn to_hex(&self) -> String {
        self.0.secret_key().to_secret_hex()
    }

    /// Rebuild a `SharedKey` from a hex-encoded secret previously produced
    /// by [`SharedKey::to_hex`].
    pub fn from_hex(hex: &str) -> Result<Self, MostroError> {
        let secret = SecretKey::from_hex(hex).map_err(|e| {
            MostroError::MostroInternalErr(ServiceError::EncryptionError(format!(
                "invalid shared key hex: {e}"
            )))
        })?;
        Ok(Self(Keys::new(secret)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_symmetric_between_peers() {
        let alice = Keys::generate();
        let bob = Keys::generate();

        let from_alice = SharedKey::derive(alice.secret_key(), &bob.public_key()).unwrap();
        let from_bob = SharedKey::derive(bob.secret_key(), &alice.public_key()).unwrap();

        assert_eq!(from_alice.public_key(), from_bob.public_key());
        assert_eq!(from_alice.to_hex(), from_bob.to_hex());
    }

    #[test]
    fn derive_shared_key_hex_roundtrip() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let derived = SharedKey::derive(alice.secret_key(), &bob.public_key()).unwrap();

        let hex = derived.to_hex();
        let restored = SharedKey::from_hex(&hex).unwrap();

        assert_eq!(derived.public_key(), restored.public_key());
        assert_eq!(derived.to_hex(), restored.to_hex());
    }

    #[test]
    fn derive_shared_key_different_peers_produce_different_keys() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let carol = Keys::generate();

        let with_bob = SharedKey::derive(alice.secret_key(), &bob.public_key()).unwrap();
        let with_carol = SharedKey::derive(alice.secret_key(), &carol.public_key()).unwrap();

        assert_ne!(with_bob.public_key(), with_carol.public_key());
    }

    #[test]
    fn from_hex_rejects_invalid_input() {
        let err = SharedKey::from_hex("not-a-hex-string").unwrap_err();
        assert!(matches!(err, MostroError::MostroInternalErr(_)));
    }
}
