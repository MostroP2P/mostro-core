//! Decrypt a Mostro P2P chat gift wrap and verify its inner signature.

use nostr_sdk::nips::nip44;
use nostr_sdk::prelude::*;

use crate::error::{MostroError, ServiceError};

/// A decrypted P2P chat message.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Plain-text body of the inner kind 1 event.
    pub content: String,
    /// Trade public key of the sender, taken from the inner event's
    /// signature — already verified by [`unwrap_chat_message`].
    pub sender: PublicKey,
    /// `created_at` of the inner kind 1 event.
    pub created_at: Timestamp,
}

/// Unwrap a Mostro P2P chat gift wrap.
///
/// * `shared_keys` — the `Keys` instance derived from the channel's
///   [`SharedKey`](super::SharedKey); the secret half is needed to NIP-44
///   decrypt the outer ciphertext.
/// * `event` — a kind 1059 event previously fetched from a relay.
///
/// On success the inner kind 1 event's signature is verified before
/// returning, so the [`ChatMessage::sender`] field can be trusted as the
/// authentic author of the message.
pub async fn unwrap_chat_message(
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
        content: inner.content,
        sender: inner.pubkey,
        created_at: inner.created_at,
    })
}
