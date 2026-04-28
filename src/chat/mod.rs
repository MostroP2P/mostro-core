//! Mostro P2P chat protocol primitives.
//!
//! Mostro reuses the NIP-59 GiftWrap envelope to carry a second, lighter
//! channel: direct buyer/seller chat during a trade and admin/party chat
//! during a dispute. Unlike protocol messages — which are addressed to a
//! Mostro node and use the dual identity/trade key scheme of
//! [`crate::nip59`] — chat envelopes are addressed to a per-channel
//! **shared key** that both parties derive via ECDH from their trade keys.
//!
//! The on-the-wire shape is intentionally simple:
//!
//! ```text
//! Plain-text message
//!     -> kind 1 TextNote signed by sender_trade_keys (inner)
//!     -> NIP-44 v2 encrypt to shared_pubkey using an ephemeral key
//!     -> kind 1059 GiftWrap with `p` = shared_pubkey, signed ephemerally
//! ```
//!
//! Both parties can fetch and decrypt every wrap addressed to the shared
//! key, and the inner event's signature carries the real sender's trade
//! pubkey so each side can render the conversation correctly without
//! exchanging extra metadata.
//!
//! This module is **pure protocol**: it derives shared keys, builds and
//! parses envelopes, and constructs the relay filter. It does not manage
//! relays, subscriptions, persistence or higher-level workflows — those
//! belong to the client.
//!
//! ## Quick start
//!
//! ```no_run
//! # async fn run() -> Result<(), mostro_core::error::MostroError> {
//! use mostro_core::chat::{chat_filter, wrap_chat_message, unwrap_chat_message, SharedKey};
//! use nostr_sdk::prelude::*;
//!
//! let alice = Keys::generate();
//! let bob_pubkey = Keys::generate().public_key();
//!
//! let shared = SharedKey::derive(alice.secret_key(), &bob_pubkey)?;
//! let event = wrap_chat_message(&alice, &shared.public_key(), "hi bob").await?;
//!
//! // ...publish `event` to relays, fetch incoming wraps with `chat_filter(...)`,
//! // then on the receiving side:
//! let chat = unwrap_chat_message(shared.keys(), &event).await?;
//! assert_eq!(chat.content, "hi bob");
//! # Ok(()) }
//! ```

mod filter;
mod shared_key;
mod unwrap;
mod wrap;

pub use filter::{chat_filter, CHAT_DEFAULT_LOOKBACK_SECS};
pub use shared_key::SharedKey;
pub use unwrap::{unwrap_chat_message, ChatMessage};
pub use wrap::wrap_chat_message;

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::nips::nip44;
    use nostr_sdk::prelude::*;

    fn shared_pair() -> (Keys, Keys, SharedKey, SharedKey) {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let alice_shared = SharedKey::derive(alice.secret_key(), &bob.public_key()).unwrap();
        let bob_shared = SharedKey::derive(bob.secret_key(), &alice.public_key()).unwrap();
        (alice, bob, alice_shared, bob_shared)
    }

    #[tokio::test]
    async fn wrap_and_unwrap_roundtrip() {
        let (alice, _bob, alice_shared, bob_shared) = shared_pair();
        let body = "hello from alice";

        let event = wrap_chat_message(&alice, &alice_shared.public_key(), body)
            .await
            .expect("wrap");

        assert_eq!(event.kind, Kind::GiftWrap);
        assert!(event
            .tags
            .public_keys()
            .any(|pk| *pk == alice_shared.public_key()));

        let decoded = unwrap_chat_message(bob_shared.keys(), &event)
            .await
            .expect("unwrap");

        assert_eq!(decoded.content, body);
        assert_eq!(decoded.sender, alice.public_key());
    }

    #[tokio::test]
    async fn unwrap_with_wrong_shared_key_fails() {
        let (alice, _bob, alice_shared, _bob_shared) = shared_pair();
        let intruder = Keys::generate();
        let intruder_shared =
            SharedKey::derive(intruder.secret_key(), &Keys::generate().public_key()).unwrap();

        let event = wrap_chat_message(&alice, &alice_shared.public_key(), "for bob only")
            .await
            .expect("wrap");

        let err = unwrap_chat_message(intruder_shared.keys(), &event)
            .await
            .expect_err("must not decrypt with foreign shared key");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }

    #[tokio::test]
    async fn unwrap_tampered_event_fails() {
        let (_alice, _bob, alice_shared, bob_shared) = shared_pair();

        // Build a wrap whose inner ciphertext is the encryption of an event
        // signed by an *impostor*, not by `alice`. The outer envelope is
        // perfectly valid (ephemeral key signs it), but the inner signature
        // must not verify against the rumor pubkey.
        let impostor = Keys::generate();
        let inner = EventBuilder::text_note("forged")
            .build(impostor.public_key())
            .sign(&impostor)
            .await
            .unwrap();

        // Mutate the signed event JSON so the signature no longer matches
        // its content — `verify()` should reject it.
        let mut json: serde_json::Value = serde_json::from_str(&inner.as_json()).unwrap();
        json["content"] = serde_json::Value::String("tampered".to_string());
        let tampered_inner = json.to_string();

        let ephemeral = Keys::generate();
        let encrypted = nip44::encrypt(
            ephemeral.secret_key(),
            &alice_shared.public_key(),
            tampered_inner,
            nip44::Version::V2,
        )
        .unwrap();
        let event = EventBuilder::new(Kind::GiftWrap, encrypted)
            .tag(Tag::public_key(alice_shared.public_key()))
            .sign_with_keys(&ephemeral)
            .unwrap();

        let err = unwrap_chat_message(bob_shared.keys(), &event)
            .await
            .expect_err("tampered inner must not verify");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }

    #[tokio::test]
    async fn unwrap_rejects_non_giftwrap_event() {
        let alice = Keys::generate();
        let other = Keys::generate();
        let shared = SharedKey::derive(alice.secret_key(), &other.public_key()).unwrap();

        // A plain text note is the wrong kind for the outer envelope.
        let bogus = EventBuilder::text_note("not a wrap")
            .build(alice.public_key())
            .sign(&alice)
            .await
            .unwrap();

        let err = unwrap_chat_message(shared.keys(), &bogus)
            .await
            .expect_err("non-giftwrap must error");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }
}
