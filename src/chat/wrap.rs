//! Build a Mostro P2P chat envelope (kind 14 signed by `K_sign`).
//!
//! Wire format (see <https://mostro.network/protocol/chat.html>):
//!
//! ```text
//! Plain-text message
//!     -> kind 1 TextNote signed by sender trade key (inner)
//!     -> NIP-44 v2 self-encrypt under K_conv
//!     -> kind 14, p = pub(K_conv), signed by K_sign (outer)
//! ```
//!
//! Legacy gift-wrap producers remain available as
//! [`wrap_giftwrap_chat_message`] for dual-read migration windows.

use nostr_sdk::nips::{nip44, nip59};
use nostr_sdk::prelude::*;

use crate::error::{MostroError, ServiceError};

/// Wrap a plain-text chat message into a kind 14 event signed by `K_sign`.
///
/// * `sender_trade_keys` — signs the inner kind 1 (sender authentication).
/// * `conv` — `K_conv`; NIP-44 self-encryption and the sole outer `p` tag.
/// * `sign` — `K_sign`; signs the outer event (relay `authors` filter).
/// * `message` — plain-text body.
///
/// The inner and outer `created_at` share the same real timestamp (no NIP-59
/// tweak). Extra `p` tags are rejected so a dispute solver's `#p` query sees
/// every message the parties see.
pub async fn wrap_chat_message(
    sender_trade_keys: &Keys,
    conv: &Keys,
    sign: &Keys,
    message: &str,
) -> Result<Event, MostroError> {
    wrap_chat_message_with_tags(sender_trade_keys, conv, sign, message, Vec::new()).await
}

/// Like [`wrap_chat_message`], but allows additional outer tags that are **not**
/// `p` tags.
pub async fn wrap_chat_message_with_tags(
    sender_trade_keys: &Keys,
    conv: &Keys,
    sign: &Keys,
    message: &str,
    extra_tags: Vec<Tag>,
) -> Result<Event, MostroError> {
    if extra_tags.iter().any(|t| t.kind() == TagKind::p()) {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("extra_tags must not contain a p tag".to_string()),
        ));
    }

    // One timestamp for both events: recipients reject a mismatch (replay defense).
    let now = Timestamp::now();

    let inner = EventBuilder::text_note(message)
        .custom_created_at(now)
        .build(sender_trade_keys.public_key())
        .sign(sender_trade_keys)
        .await
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))?;

    // NIP-44 self-encryption: K_conv is both sides of the key exchange.
    let content = nip44::encrypt(
        conv.secret_key(),
        &conv.public_key(),
        inner.as_json(),
        nip44::Version::V2,
    )
    .map_err(|e| MostroError::MostroInternalErr(ServiceError::EncryptionError(e.to_string())))?;

    let mut tags = vec![Tag::public_key(conv.public_key())];
    tags.extend(extra_tags);

    EventBuilder::new(Kind::PrivateDirectMessage, content)
        .tags(tags)
        .custom_created_at(now)
        .sign_with_keys(sign)
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))
}

/// Legacy gift-wrap producer (kind 1059, ephemeral outer key).
///
/// Prefer [`wrap_chat_message`]. Kept for dual-read transition tests and any
/// client that still needs to emit the superseded envelope during migration.
pub async fn wrap_giftwrap_chat_message(
    sender_trade_keys: &Keys,
    shared_pubkey: &PublicKey,
    message: &str,
) -> Result<Event, MostroError> {
    let inner = EventBuilder::text_note(message)
        .build(sender_trade_keys.public_key())
        .sign(sender_trade_keys)
        .await
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))?;

    let ephemeral = Keys::generate();
    let encrypted = nip44::encrypt(
        ephemeral.secret_key(),
        shared_pubkey,
        inner.as_json(),
        nip44::Version::V2,
    )
    .map_err(|e| MostroError::MostroInternalErr(ServiceError::EncryptionError(e.to_string())))?;

    EventBuilder::new(Kind::GiftWrap, encrypted)
        .tag(Tag::public_key(*shared_pubkey))
        .custom_created_at(Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK))
        .sign_with_keys(&ephemeral)
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))
}
