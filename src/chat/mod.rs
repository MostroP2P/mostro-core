//! Mostro P2P chat protocol primitives.
//!
//! Buyer/seller (and admin/party dispute) chat excludes the Mostro daemon.
//! Messages use a **kind 14** envelope signed by `K_sign`, carrying a NIP-44
//! encrypted kind 1 event signed by the sender's trade key. Keys are derived
//! from the parties' ECDH secret via HKDF domain separation into `K_conv`
//! (encrypt / `p` tag) and `K_sign` (outer author).
//!
//! ```text
//! Plain-text message
//!     -> kind 1 TextNote signed by sender_trade_keys (inner)
//!     -> NIP-44 v2 self-encrypt under K_conv
//!     -> kind 14, p = pub(K_conv), signed by K_sign (outer)
//! ```
//!
//! Clients MUST subscribe with `authors = [pub(K_sign)]` — see [`chat_filter`].
//! Filtering by `#p` alone is vulnerable to third-party flooding.
//!
//! Legacy gift-wrap helpers ([`wrap_giftwrap_chat_message`],
//! [`unwrap_giftwrap_chat_message`], [`giftwrap_chat_filter`]) remain for a
//! dual-read migration window.
//!
//! Spec: <https://mostro.network/protocol/chat.html>
//!
//! ## Quick start
//!
//! ```no_run
//! # async fn run() -> Result<(), mostro_core::error::MostroError> {
//! use mostro_core::chat::{
//!     chat_filter, derive_chat_keys, unwrap_chat_message, wrap_chat_message,
//! };
//! use nostr_sdk::prelude::*;
//!
//! let alice = Keys::generate();
//! let bob = Keys::generate();
//!
//! let (conv, sign) = derive_chat_keys(&alice, &bob.public_key())?;
//! let event = wrap_chat_message(&alice, &conv, &sign, "hi bob").await?;
//!
//! // Subscribe with chat_filter(sign.public_key()), then:
//! let allowed = [alice.public_key(), bob.public_key()];
//! let chat = unwrap_chat_message(
//!     &conv,
//!     &sign.public_key(),
//!     &allowed,
//!     &event,
//!     Timestamp::now(),
//! )?;
//! assert_eq!(chat.content, "hi bob");
//! # Ok(()) }
//! ```

mod filter;
mod keys;
mod shared_key;
mod unwrap;
mod wrap;

pub use filter::{chat_filter, giftwrap_chat_filter, CHAT_DEFAULT_LOOKBACK_SECS};
pub use keys::{derive_chat_keys, derive_chat_keys_from_shared, CHAT_CONV_INFO, CHAT_SIGN_INFO};
pub use shared_key::SharedKey;
pub use unwrap::{
    unwrap_chat_message, unwrap_giftwrap_chat_message, ChatMessage, CHAT_MAX_CLOCK_SKEW_SECS,
    CHAT_MAX_CONTENT_BYTES,
};
pub use wrap::{wrap_chat_message, wrap_chat_message_with_tags, wrap_giftwrap_chat_message};

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::nips::nip44;
    use nostr_sdk::prelude::*;

    fn chat_pair() -> (Keys, Keys, Keys, Keys) {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let (conv, sign) = derive_chat_keys(&alice, &bob.public_key()).unwrap();
        (alice, bob, conv, sign)
    }

    #[tokio::test]
    async fn wrap_and_unwrap_roundtrip() {
        let (alice, bob, conv, sign) = chat_pair();
        let body = "hello from alice";

        let event = wrap_chat_message(&alice, &conv, &sign, body)
            .await
            .expect("wrap");

        assert_eq!(event.kind, Kind::PrivateDirectMessage);
        assert_eq!(event.pubkey, sign.public_key());
        assert!(event.tags.public_keys().any(|pk| *pk == conv.public_key()));

        let allowed = [alice.public_key(), bob.public_key()];
        let decoded = unwrap_chat_message(
            &conv,
            &sign.public_key(),
            &allowed,
            &event,
            Timestamp::now(),
        )
        .expect("unwrap");

        assert_eq!(decoded.content, body);
        assert_eq!(decoded.sender, alice.public_key());
    }

    #[tokio::test]
    async fn unwrap_rejects_wrong_author() {
        let (alice, bob, conv, sign) = chat_pair();
        let event = wrap_chat_message(&alice, &conv, &sign, "hi").await.unwrap();

        let impostor = Keys::generate().public_key();
        let allowed = [alice.public_key(), bob.public_key()];
        let err = unwrap_chat_message(&conv, &impostor, &allowed, &event, Timestamp::now())
            .expect_err("wrong author");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }

    #[tokio::test]
    async fn unwrap_rejects_wrong_p_tag() {
        let (alice, bob, conv, sign) = chat_pair();
        let now = Timestamp::now();
        let inner = EventBuilder::text_note("hi")
            .custom_created_at(now)
            .build(alice.public_key())
            .sign(&alice)
            .await
            .unwrap();
        let content = nip44::encrypt(
            conv.secret_key(),
            &conv.public_key(),
            inner.as_json(),
            nip44::Version::V2,
        )
        .unwrap();
        let wrong_p = Keys::generate().public_key();
        let event = EventBuilder::new(Kind::PrivateDirectMessage, content)
            .tag(Tag::public_key(wrong_p))
            .custom_created_at(now)
            .sign_with_keys(&sign)
            .unwrap();

        let allowed = [alice.public_key(), bob.public_key()];
        let err = unwrap_chat_message(
            &conv,
            &sign.public_key(),
            &allowed,
            &event,
            Timestamp::now(),
        )
        .expect_err("wrong p");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }

    #[tokio::test]
    async fn unwrap_rejects_future_timestamp() {
        let (alice, bob, conv, sign) = chat_pair();
        let far_future = Timestamp::from_secs(Timestamp::now().as_secs() + 3600);
        let inner = EventBuilder::text_note("hi")
            .custom_created_at(far_future)
            .build(alice.public_key())
            .sign(&alice)
            .await
            .unwrap();
        let content = nip44::encrypt(
            conv.secret_key(),
            &conv.public_key(),
            inner.as_json(),
            nip44::Version::V2,
        )
        .unwrap();
        let event = EventBuilder::new(Kind::PrivateDirectMessage, content)
            .tag(Tag::public_key(conv.public_key()))
            .custom_created_at(far_future)
            .sign_with_keys(&sign)
            .unwrap();

        let allowed = [alice.public_key(), bob.public_key()];
        let err = unwrap_chat_message(
            &conv,
            &sign.public_key(),
            &allowed,
            &event,
            Timestamp::now(),
        )
        .expect_err("future");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }

    #[tokio::test]
    async fn unwrap_rejects_oversized_content() {
        let (alice, bob, conv, sign) = chat_pair();
        let now = Timestamp::now();
        let huge = "x".repeat(CHAT_MAX_CONTENT_BYTES + 1);
        let event = EventBuilder::new(Kind::PrivateDirectMessage, huge)
            .tag(Tag::public_key(conv.public_key()))
            .custom_created_at(now)
            .sign_with_keys(&sign)
            .unwrap();

        let allowed = [alice.public_key(), bob.public_key()];
        let err = unwrap_chat_message(
            &conv,
            &sign.public_key(),
            &allowed,
            &event,
            Timestamp::now(),
        )
        .expect_err("oversized");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
        // Author/p/size checks run before decrypt — bogus ciphertext is fine.
        let _ = alice;
    }

    #[tokio::test]
    async fn unwrap_rejects_non_party_inner_signer() {
        let (alice, bob, conv, sign) = chat_pair();
        let intruder = Keys::generate();
        let now = Timestamp::now();
        let inner = EventBuilder::text_note("forged")
            .custom_created_at(now)
            .build(intruder.public_key())
            .sign(&intruder)
            .await
            .unwrap();
        let content = nip44::encrypt(
            conv.secret_key(),
            &conv.public_key(),
            inner.as_json(),
            nip44::Version::V2,
        )
        .unwrap();
        let event = EventBuilder::new(Kind::PrivateDirectMessage, content)
            .tag(Tag::public_key(conv.public_key()))
            .custom_created_at(now)
            .sign_with_keys(&sign)
            .unwrap();

        let allowed = [alice.public_key(), bob.public_key()];
        let err = unwrap_chat_message(
            &conv,
            &sign.public_key(),
            &allowed,
            &event,
            Timestamp::now(),
        )
        .expect_err("non-party");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }

    #[tokio::test]
    async fn observer_with_k_conv_only_can_decrypt_but_not_sign() {
        let (alice, bob, conv, sign) = chat_pair();
        let event = wrap_chat_message(&alice, &conv, &sign, "evidence")
            .await
            .unwrap();

        // Observer holds K_conv only (e.g. Keys::new from disclosed secret).
        let observer_conv =
            Keys::new(SecretKey::from_slice(conv.secret_key().as_secret_bytes()).unwrap());
        let allowed = [alice.public_key(), bob.public_key()];
        let msg = unwrap_chat_message(
            &observer_conv,
            &sign.public_key(),
            &allowed,
            &event,
            Timestamp::now(),
        )
        .expect("observer decrypt");
        assert_eq!(msg.content, "evidence");

        // Without K_sign the observer cannot author a valid outer event.
        let forged = wrap_chat_message(&alice, &observer_conv, &observer_conv, "inject")
            .await
            .unwrap();
        assert_ne!(forged.pubkey, sign.public_key());
        let err = unwrap_chat_message(
            &conv,
            &sign.public_key(),
            &allowed,
            &forged,
            Timestamp::now(),
        )
        .expect_err("observer cannot forge author");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }

    #[tokio::test]
    async fn giftwrap_legacy_roundtrip_still_works() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let shared = SharedKey::derive(alice.secret_key(), &bob.public_key()).unwrap();

        let event = wrap_giftwrap_chat_message(&alice, &shared.public_key(), "legacy")
            .await
            .unwrap();
        assert_eq!(event.kind, Kind::GiftWrap);

        let decoded = unwrap_giftwrap_chat_message(shared.keys(), &event)
            .await
            .unwrap();
        assert_eq!(decoded.content, "legacy");
        assert_eq!(decoded.sender, alice.public_key());
    }

    #[tokio::test]
    async fn wrap_rejects_extra_p_tag() {
        let (alice, _bob, conv, sign) = chat_pair();
        let err = wrap_chat_message_with_tags(
            &alice,
            &conv,
            &sign,
            "hi",
            vec![Tag::public_key(Keys::generate().public_key())],
        )
        .await
        .expect_err("extra p");
        assert!(matches!(
            err,
            crate::error::MostroError::MostroInternalErr(_)
        ));
    }
}
