//! Build a Mostro P2P chat gift wrap.
//!
//! The wire format is a non-standard NIP-59 envelope: a kind 1 text note
//! signed by the sender's trade key is encrypted with NIP-44 v2 using an
//! ephemeral key as the encryption side and the **shared key's public key**
//! as the recipient. The outer kind 1059 event carries that ciphertext, a
//! `p` tag pointing at the shared pubkey for relay routing, and is signed
//! with the same ephemeral key.
//!
//! See <https://mostro.network/protocol/chat.html> for the protocol spec.

use nostr_sdk::nips::{nip44, nip59};
use nostr_sdk::prelude::*;

use crate::error::{MostroError, ServiceError};

/// Wrap a plain-text chat message into a Mostro P2P gift wrap (kind 1059).
///
/// * `sender_trade_keys` — the sender's per-trade keys; sign the inner kind 1
///   so the receiver can verify authorship.
/// * `shared_pubkey` — public key of the [`SharedKey`](super::SharedKey)
///   shared by the two chat parties; used as the NIP-44 recipient and as
///   the value of the outer `p` tag.
/// * `message` — the chat content to deliver.
///
/// The outer `created_at` is randomized within
/// [`nip59::RANGE_RANDOM_TIMESTAMP_TWEAK`] to defeat timing correlation.
pub async fn wrap_chat_message(
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
