//! ECDH shared secret used as IKM for Mostro P2P chat key derivation.
//!
//! The two parties of a chat (buyer/seller during a trade or admin/party
//! during a dispute) each compute the same 32-byte ECDH output from their
//! own secret key and the counterparty's public key. That output is the
//! input keying material for [`crate::chat::derive_chat_keys_from_shared`],
//! which produces `K_conv` and `K_sign`.
//!
//! Clients MAY persist the ECDH secret (via [`SharedKey::to_hex`]) and
//! re-derive chat keys on load. The ECDH secret itself is **not** the wire
//! address: `pub(K_conv)` is the `p` tag and `pub(K_sign)` is the author.

use nostr_sdk::prelude::*;

use crate::chat::keys::{derive_chat_keys_from_shared, generate_shared_key};
use crate::error::{MostroError, ServiceError};

/// Shared ECDH secret between two parties' trade (or admin) keys.
///
/// Internally a `Keys` instance whose secret is the 32-byte ECDH output of
/// `(local_secret, counterparty_pubkey)`. Prefer [`SharedKey::chat_keys`] for
/// the on-the-wire `K_conv` / `K_sign` pair.
#[derive(Debug, Clone)]
pub struct SharedKey(Keys);

impl SharedKey {
    /// Derive the ECDH shared secret from a local secret key and the
    /// counterparty's public key.
    ///
    /// Both peers obtain the same `SharedKey` by swapping arguments
    /// (`A.derive(a_sk, b_pk) == B.derive(b_sk, a_pk)`).
    pub fn derive(secret: &SecretKey, counterparty: &PublicKey) -> Result<Self, MostroError> {
        let bytes = generate_shared_key(secret, counterparty)?;
        let secret = SecretKey::from_slice(&bytes).map_err(|e| {
            MostroError::MostroInternalErr(ServiceError::EncryptionError(format!(
                "invalid shared secret: {e}"
            )))
        })?;
        Ok(Self(Keys::new(secret)))
    }

    /// Build a `SharedKey` from an already-derived `Keys` value.
    pub fn from_keys(keys: Keys) -> Self {
        Self(keys)
    }

    /// Borrow the underlying ECDH `Keys` (IKM as a keypair).
    ///
    /// For gift-wrap dual-read decrypt only. New envelopes use [`Self::chat_keys`].
    pub fn keys(&self) -> &Keys {
        &self.0
    }

    /// Public key of the raw ECDH secret interpreted as a keypair.
    ///
    /// This was the GiftWrap `p` tag under the superseded envelope. The new
    /// envelope uses `pub(K_conv)` from [`Self::chat_keys`] instead.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// Borrow the underlying ECDH secret key.
    pub fn secret_key(&self) -> &SecretKey {
        self.0.secret_key()
    }

    /// Derive `(K_conv, K_sign)` from this ECDH secret.
    pub fn chat_keys(&self) -> Result<(Keys, Keys), MostroError> {
        derive_chat_keys_from_shared(self.secret_key().as_secret_bytes())
    }

    /// Serialize the ECDH secret as lower-case hex for client persistence.
    pub fn to_hex(&self) -> String {
        self.0.secret_key().to_secret_hex()
    }

    /// Rebuild from hex previously produced by [`SharedKey::to_hex`].
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

        let (ac, as_) = from_alice.chat_keys().unwrap();
        let (bc, bs) = from_bob.chat_keys().unwrap();
        assert_eq!(ac.public_key(), bc.public_key());
        assert_eq!(as_.public_key(), bs.public_key());
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
