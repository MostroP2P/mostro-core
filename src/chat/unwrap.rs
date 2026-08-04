//! Decrypt and validate a Mostro P2P chat envelope.
//!
//! [`unwrap_chat_message`] implements the mandatory cheapest-first checks from
//! <https://mostro.network/protocol/chat.html#client-security-requirements>,
//! except the caller-owned steps: rate-limit budget, outer-id LRU, and durable
//! inner-id deduplication.

use nostr_sdk::nips::nip44;
use nostr_sdk::prelude::*;

use crate::error::{MostroError, ServiceError};

/// Tolerance for clock skew between inner/outer `created_at` and against the
/// recipient's local clock (absolute future bound). Spec default: 60 seconds.
pub const CHAT_MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Upper bound on the encrypted outer `content`, enforced before decrypting.
/// Spec default: 64 KiB.
pub const CHAT_MAX_CONTENT_BYTES: usize = 64 * 1024;

/// A decrypted P2P chat message.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Plain-text body of the inner kind 1 event.
    pub content: String,
    /// Trade (or admin) public key of the sender — from the verified inner event.
    pub sender: PublicKey,
    /// `created_at` of the inner kind 1 event.
    pub created_at: Timestamp,
    /// Verified inner event id — retain durably for replay protection.
    pub inner_event_id: EventId,
    /// Outer event id — suitable for a bounded LRU against duplicate deliveries.
    pub outer_event_id: EventId,
}

/// Unwrap a kind 14 chat event signed by `K_sign`.
///
/// * `conv` — `K_conv` (decrypt).
/// * `sign_pubkey` — `pub(K_sign)` expected as outer author.
/// * `allowed_signers` — accepted inner pubkeys (buyer+seller trade keys, or
///   party trade key + admin pubkey for dispute chat).
/// * `outer` — received kind 14 event.
/// * `now` — recipient's clock for the absolute future bound.
///
/// Caller must still enforce rate limiting, outer-id LRU, and durable inner-id
/// dedup using [`ChatMessage::inner_event_id`] / [`ChatMessage::outer_event_id`].
pub fn unwrap_chat_message(
    conv: &Keys,
    sign_pubkey: &PublicKey,
    allowed_signers: &[PublicKey],
    outer: &Event,
    now: Timestamp,
) -> Result<ChatMessage, MostroError> {
    // 1. Author
    if outer.pubkey != *sign_pubkey {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError(
                "outer event is not authored by the conversation signing key".to_string(),
            ),
        ));
    }
    if outer.kind != Kind::PrivateDirectMessage {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("outer event is not kind 14".to_string()),
        ));
    }

    // 2. Exactly one `p` tag equal to pub(K_conv)
    let mut p_tags = outer.tags.iter().filter(|t| t.kind() == TagKind::p());
    match (p_tags.next().and_then(|t| t.content()), p_tags.next()) {
        (Some(pk), None) if pk == conv.public_key().to_hex() => {}
        _ => {
            return Err(MostroError::MostroInternalErr(
                ServiceError::UnexpectedError(
                    "outer event must carry exactly one p tag for this conversation".to_string(),
                ),
            ));
        }
    }

    // 3. Absolute timestamp bound against local clock
    if outer.created_at.as_secs() > now.as_secs().saturating_add(CHAT_MAX_CLOCK_SKEW_SECS) {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("outer event is dated too far in the future".to_string()),
        ));
    }

    // 4. Size before crypto
    if outer.content.len() > CHAT_MAX_CONTENT_BYTES {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError(
                "encrypted payload exceeds the accepted size".to_string(),
            ),
        ));
    }

    // 7. Outer signature (steps 5–6 are caller-owned)
    outer.verify().map_err(|e| {
        MostroError::MostroInternalErr(ServiceError::NostrError(format!(
            "invalid outer chat signature: {e}"
        )))
    })?;

    // 8. Decrypt
    let decrypted =
        nip44::decrypt(conv.secret_key(), &conv.public_key(), &outer.content).map_err(|e| {
            MostroError::MostroInternalErr(ServiceError::DecryptionError(format!(
                "K_conv decrypt failed: {e}"
            )))
        })?;

    let inner = Event::from_json(&decrypted).map_err(|e| {
        MostroError::MostroInternalErr(ServiceError::NostrError(format!(
            "malformed inner chat event: {e}"
        )))
    })?;

    // 9–11. Inner auth
    inner.verify().map_err(|e| {
        MostroError::MostroInternalErr(ServiceError::NostrError(format!(
            "invalid inner chat signature: {e}"
        )))
    })?;
    if !allowed_signers.contains(&inner.pubkey) {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError(
                "inner event is signed by a key that is not a party to this conversation"
                    .to_string(),
            ),
        ));
    }
    if inner.kind != Kind::TextNote {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("inner chat event is not a TextNote".to_string()),
        ));
    }

    // 13. Relative timestamp bound (step 12 = caller durable inner-id dedup)
    let skew = inner
        .created_at
        .as_secs()
        .abs_diff(outer.created_at.as_secs());
    if skew > CHAT_MAX_CLOCK_SKEW_SECS {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError(
                "inner and outer timestamps disagree — stale re-wrap".to_string(),
            ),
        ));
    }

    Ok(ChatMessage {
        content: inner.content.clone(),
        sender: inner.pubkey,
        created_at: inner.created_at,
        inner_event_id: inner.id,
        outer_event_id: outer.id,
    })
}

/// Legacy gift-wrap unwrap (kind 1059). Prefer [`unwrap_chat_message`].
///
/// Kept for dual-read migration: clients MAY accept both envelopes during the
/// transition window.
pub async fn unwrap_giftwrap_chat_message(
    shared_keys: &Keys,
    event: &Event,
) -> Result<ChatMessage, MostroError> {
    if event.kind != Kind::GiftWrap {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("event is not a GiftWrap".to_string()),
        ));
    }

    let decrypted = nip44::decrypt(shared_keys.secret_key(), &event.pubkey, &event.content)
        .map_err(|e| {
            MostroError::MostroInternalErr(ServiceError::DecryptionError(format!(
                "shared-key decrypt failed: {e}"
            )))
        })?;

    let inner = Event::from_json(&decrypted).map_err(|e| {
        MostroError::MostroInternalErr(ServiceError::NostrError(format!(
            "malformed inner chat event: {e}"
        )))
    })?;

    if inner.kind != Kind::TextNote {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("inner chat event is not a TextNote".to_string()),
        ));
    }

    inner.verify().map_err(|e| {
        MostroError::MostroInternalErr(ServiceError::NostrError(format!(
            "invalid inner chat signature: {e}"
        )))
    })?;

    Ok(ChatMessage {
        content: inner.content.clone(),
        sender: inner.pubkey,
        created_at: inner.created_at,
        inner_event_id: inner.id,
        outer_event_id: event.id,
    })
}
