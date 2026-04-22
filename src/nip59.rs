//! NIP-59 GiftWrap transport for Mostro messages.
//!
//! Every message exchanged with a Mostro node travels through the same
//! pipeline:
//!
//! ```text
//! Message -> JSON((Message, Option<Signature>)) -> Rumor -> Seal -> GiftWrap
//! ```
//!
//! This module centralizes wrap/unwrap so clients do not need to reimplement
//! NIP-59 glue themselves. It does not manage relays, subscriptions, waiters
//! or persistence — the returned `Event` is ready to publish, and the caller
//! decides how to do so.

use std::str::FromStr;

use crate::message::{Action, Message, Payload};
use crate::prelude::{CantDoReason, MostroError, ServiceError};
use nostr_sdk::nips::{nip44, nip59};
use nostr_sdk::prelude::*;

/// Options controlling how a Mostro message is wrapped.
#[derive(Debug, Clone)]
pub struct WrapOptions {
    /// NIP-13 proof-of-work difficulty applied to the outer GiftWrap event.
    pub pow: u8,
    /// Optional expiration tag for the outer GiftWrap event.
    pub expiration: Option<Timestamp>,
    /// When true the inner rumor content is `(Message, Some(Signature))`,
    /// with the signature produced from the JSON of `Message` using
    /// `trade_keys`. When false the content is `(Message, None)`. Traffic
    /// to a Mostro node always uses `true`.
    pub signed: bool,
}

impl Default for WrapOptions {
    fn default() -> Self {
        Self {
            pow: 0,
            expiration: None,
            signed: true,
        }
    }
}

/// A Mostro message recovered from an incoming GiftWrap, plus metadata from
/// the outer envelopes.
#[derive(Debug, Clone)]
pub struct UnwrappedMessage {
    /// The logical Mostro message carried inside the rumor.
    pub message: Message,
    /// Signature of the JSON-serialized `Message`, produced with the sender's
    /// trade keys. Present only when the sender set `signed = true`.
    pub signature: Option<Signature>,
    /// Rumor author (the sender's trade public key).
    pub sender: PublicKey,
    /// Rumor `created_at` timestamp.
    pub created_at: Timestamp,
}

/// Build a GiftWrap event (`kind: 1059`) ready to be published to a relay.
///
/// * `message` — the Mostro message to send.
/// * `trade_keys` — per-trade keys. Author of the rumor, signer of the Seal,
///   and signer of the inner tuple signature when `opts.signed == true`.
/// * `receiver` — the Mostro node public key.
/// * `opts` — wrap options (PoW, expiration, signed).
///
/// `nostr-sdk` 0.44 enforces that the rumor author equals the seal signer
/// (NIP-59 `SenderMismatch`), so both layers are signed with `trade_keys`.
/// The inner tuple signature (produced with `trade_keys`) is what allows
/// Mostro to cryptographically bind the message to the trade identity.
pub async fn wrap_message(
    message: &Message,
    trade_keys: &Keys,
    receiver: PublicKey,
    opts: WrapOptions,
) -> Result<Event, MostroError> {
    let message_json = message.as_json().map_err(MostroError::MostroInternalErr)?;

    let content = if opts.signed {
        let sig = Message::sign(message_json, trade_keys);
        serde_json::to_string(&(message, Some(sig.to_string())))
            .map_err(|_| MostroError::MostroInternalErr(ServiceError::MessageSerializationError))?
    } else {
        serde_json::to_string(&(message, Option::<String>::None))
            .map_err(|_| MostroError::MostroInternalErr(ServiceError::MessageSerializationError))?
    };

    // PoW only applies to the outer GiftWrap (per WrapOptions docs); the
    // rumor is encrypted inside the seal and never published on its own,
    // so mining its event id would burn CPU for nothing.
    let rumor = EventBuilder::text_note(content).build(trade_keys.public_key());

    let seal: Event = EventBuilder::seal(trade_keys, &receiver, rumor)
        .await
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))?
        .sign(trade_keys)
        .await
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))?;

    gift_wrap_from_seal_with_pow(&seal, receiver, opts.pow, opts.expiration)
}

/// Wrap an already built Seal into a NIP-59 GiftWrap with optional PoW and
/// expiration. The outer event is signed with a freshly generated ephemeral
/// key and carries a mandatory `p` tag pointing at `receiver`.
fn gift_wrap_from_seal_with_pow(
    seal: &Event,
    receiver: PublicKey,
    pow: u8,
    expiration: Option<Timestamp>,
) -> Result<Event, MostroError> {
    if seal.kind != Kind::Seal {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("expected Seal kind".to_string()),
        ));
    }

    let ephemeral = Keys::generate();
    let encrypted = nip44::encrypt(
        ephemeral.secret_key(),
        &receiver,
        seal.as_json(),
        nip44::Version::default(),
    )
    .map_err(|e| MostroError::MostroInternalErr(ServiceError::EncryptionError(e.to_string())))?;

    let mut tags: Vec<Tag> = Vec::new();
    if let Some(exp) = expiration {
        tags.push(Tag::expiration(exp));
    }
    tags.push(Tag::public_key(receiver));

    EventBuilder::new(Kind::GiftWrap, encrypted)
        .tags(tags)
        .custom_created_at(Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK))
        .pow(pow)
        .sign_with_keys(&ephemeral)
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))
}

/// Try to open an incoming GiftWrap with the given `trade_keys`.
///
/// Returns `Ok(None)` only when the outer NIP-44 layer could not be
/// decrypted with `trade_keys` — the canonical "not addressed to me"
/// signal, so callers can try multiple trade keys without treating each
/// miss as fatal. Every other failure (corrupted seal, malformed rumor
/// JSON, seal/rumor pubkey mismatch, invalid signatures, etc.) yields
/// `Err` so callers can tell "not mine" apart from "broken".
pub async fn unwrap_message(
    event: &Event,
    trade_keys: &Keys,
) -> Result<Option<UnwrappedMessage>, MostroError> {
    if event.kind != Kind::GiftWrap {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("event is not a GiftWrap".to_string()),
        ));
    }

    let unwrapped = match nip59::extract_rumor(trade_keys, event).await {
        Ok(u) => u,
        // Outer NIP-44 decrypt failed — wrap was not for us.
        Err(nip59::Error::Signer(_)) => return Ok(None),
        Err(e) => {
            return Err(MostroError::MostroInternalErr(ServiceError::NostrError(
                e.to_string(),
            )));
        }
    };

    let (message, sig_str): (Message, Option<String>) =
        serde_json::from_str(&unwrapped.rumor.content)
            .map_err(|_| MostroError::MostroInternalErr(ServiceError::MessageSerializationError))?;

    let signature = match sig_str {
        Some(s) => {
            let sig = Signature::from_str(&s).map_err(|e| {
                MostroError::MostroInternalErr(ServiceError::UnexpectedError(format!(
                    "malformed rumor signature: {e}"
                )))
            })?;
            let message_json = message.as_json().map_err(MostroError::MostroInternalErr)?;
            if !Message::verify_signature(message_json, unwrapped.sender, sig) {
                return Err(MostroError::MostroInternalErr(
                    ServiceError::UnexpectedError(
                        "rumor signature does not verify against sender".to_string(),
                    ),
                ));
            }
            Some(sig)
        }
        None => None,
    };

    Ok(Some(UnwrappedMessage {
        message,
        signature,
        sender: unwrapped.sender,
        created_at: unwrapped.rumor.created_at,
    }))
}

/// Validate a response received from a Mostro node.
///
/// * Returns `Err(MostroCantDo(reason))` when the payload is `CantDo`.
/// * Returns `Err(MostroInternalErr(...))` when `expected_request_id` is
///   provided and the inner message carries a different id, or no id at all
///   on an action that requires one.
/// * Otherwise returns `Ok(())`.
///
/// The allow-list of actions that may arrive without a `request_id` (server
/// push messages such as state transitions, DMs, payment failures, etc.) is
/// intentionally kept on the caller side, because the exact set depends on
/// the client flow; this function only enforces the universal rules.
pub fn validate_response(
    message: &Message,
    expected_request_id: Option<u64>,
) -> Result<(), MostroError> {
    let inner = message.get_inner_message_kind();

    if let Some(Payload::CantDo(reason)) = &inner.payload {
        return Err(MostroError::MostroCantDo(
            reason.clone().unwrap_or(CantDoReason::InvalidAction),
        ));
    }

    if let Some(expected) = expected_request_id {
        match inner.request_id {
            Some(got) if got == expected => {}
            Some(_) => {
                return Err(MostroError::MostroInternalErr(
                    ServiceError::UnexpectedError("mismatched request_id".to_string()),
                ));
            }
            None => {
                if !action_accepts_missing_request_id(&inner.action) {
                    return Err(MostroError::MostroInternalErr(
                        ServiceError::UnexpectedError(
                            "missing request_id on a response that requires one".to_string(),
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Actions that may legitimately arrive without a `request_id` even when the
/// caller was waiting on one (unsolicited server-initiated events).
fn action_accepts_missing_request_id(action: &Action) -> bool {
    matches!(
        action,
        Action::BuyerTookOrder
            | Action::HoldInvoicePaymentAccepted
            | Action::HoldInvoicePaymentSettled
            | Action::HoldInvoicePaymentCanceled
            | Action::WaitingSellerToPay
            | Action::WaitingBuyerInvoice
            | Action::BuyerInvoiceAccepted
            | Action::PurchaseCompleted
            | Action::Released
            | Action::FiatSentOk
            | Action::Canceled
            | Action::CooperativeCancelInitiatedByPeer
            | Action::CooperativeCancelAccepted
            | Action::DisputeInitiatedByPeer
            | Action::AdminSettled
            | Action::AdminCanceled
            | Action::AdminTookDispute
            | Action::PaymentFailed
            | Action::InvoiceUpdated
            | Action::Rate
            | Action::RateReceived
            | Action::SendDm
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Action, MessageKind, Payload};
    use uuid::uuid;

    fn sample_order_message(request_id: Option<u64>) -> Message {
        let peer = crate::message::Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            None,
        );
        Message::Order(MessageKind::new(
            Some(uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")),
            request_id,
            Some(1),
            Action::FiatSentOk,
            Some(Payload::Peer(peer)),
        ))
    }

    #[tokio::test]
    async fn wrap_then_unwrap_roundtrip() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();

        let message = sample_order_message(Some(42));

        let wrapped = wrap_message(
            &message,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .await
        .expect("wrap");

        assert_eq!(wrapped.kind, Kind::GiftWrap);
        assert!(wrapped
            .tags
            .iter()
            .any(|t| t.as_slice().first().map(|s| s.as_str()) == Some("p")));

        let unwrapped = unwrap_message(&wrapped, &receiver_keys)
            .await
            .expect("unwrap result")
            .expect("unwrap some");

        assert_eq!(unwrapped.sender, trade_keys.public_key());
        assert_eq!(
            unwrapped.message.as_json().unwrap(),
            message.as_json().unwrap()
        );
        assert!(unwrapped.signature.is_some());
    }

    #[tokio::test]
    async fn unwrap_with_corrupted_seal_returns_err() {
        let receiver_keys = Keys::generate();
        let ephemeral = Keys::generate();

        // GiftWrap addressed to `receiver_keys` whose outer ciphertext
        // decrypts successfully but yields a string that is not a valid
        // seal Event JSON. `extract_rumor` must surface this as an error,
        // not be silently absorbed as `Ok(None)`.
        let encrypted = nip44::encrypt(
            ephemeral.secret_key(),
            &receiver_keys.public_key(),
            "not a seal",
            nip44::Version::default(),
        )
        .expect("encrypt");

        let corrupted = EventBuilder::new(Kind::GiftWrap, encrypted)
            .tags([Tag::public_key(receiver_keys.public_key())])
            .sign_with_keys(&ephemeral)
            .expect("sign");

        let result = unwrap_message(&corrupted, &receiver_keys).await;
        assert!(
            matches!(result, Err(MostroError::MostroInternalErr(_))),
            "expected Err for corrupted gift wrap, got {result:?}",
        );
    }

    // Build a GiftWrap by hand with a custom inner rumor tuple so tests
    // can inject a malformed or wrong-signature payload that `wrap_message`
    // would never emit.
    async fn wrap_with_raw_inner(
        trade_keys: &Keys,
        receiver: PublicKey,
        inner: (&Message, Option<String>),
    ) -> Event {
        let content = serde_json::to_string(&inner).unwrap();
        let rumor = EventBuilder::text_note(content).build(trade_keys.public_key());
        let seal = EventBuilder::seal(trade_keys, &receiver, rumor)
            .await
            .unwrap()
            .sign(trade_keys)
            .await
            .unwrap();
        gift_wrap_from_seal_with_pow(&seal, receiver, 0, None).unwrap()
    }

    #[tokio::test]
    async fn unwrap_with_malformed_signature_errors() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let msg = sample_order_message(Some(1));

        let wrapped = wrap_with_raw_inner(
            &trade_keys,
            receiver_keys.public_key(),
            (&msg, Some("not-a-hex-signature".to_string())),
        )
        .await;

        let result = unwrap_message(&wrapped, &receiver_keys).await;
        assert!(
            matches!(result, Err(MostroError::MostroInternalErr(_))),
            "malformed signature must surface as Err, got {result:?}",
        );
    }

    #[tokio::test]
    async fn unwrap_with_signature_for_other_content_errors() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let msg = sample_order_message(Some(1));
        // Well-formed signature, but over a completely different payload.
        let bogus = Message::sign("not the real message".to_string(), &trade_keys);

        let wrapped = wrap_with_raw_inner(
            &trade_keys,
            receiver_keys.public_key(),
            (&msg, Some(bogus.to_string())),
        )
        .await;

        let result = unwrap_message(&wrapped, &receiver_keys).await;
        assert!(
            matches!(result, Err(MostroError::MostroInternalErr(_))),
            "non-verifying signature must surface as Err, got {result:?}",
        );
    }

    #[tokio::test]
    async fn unwrap_with_wrong_trade_keys_returns_none() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let stranger_keys = Keys::generate();

        let wrapped = wrap_message(
            &sample_order_message(Some(1)),
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .await
        .expect("wrap");

        let result = unwrap_message(&wrapped, &stranger_keys)
            .await
            .expect("call should not error");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn signature_is_verifiable_with_trade_pubkey() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let message = sample_order_message(Some(7));

        let wrapped = wrap_message(
            &message,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .await
        .unwrap();

        let unwrapped = unwrap_message(&wrapped, &receiver_keys)
            .await
            .unwrap()
            .unwrap();

        let sig = unwrapped.signature.expect("signed");
        let json = unwrapped.message.as_json().unwrap();
        assert!(Message::verify_signature(
            json,
            trade_keys.public_key(),
            sig
        ));
    }

    #[tokio::test]
    async fn unsigned_wrap_has_no_signature() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();

        let wrapped = wrap_message(
            &sample_order_message(Some(3)),
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions {
                signed: false,
                ..WrapOptions::default()
            },
        )
        .await
        .expect("wrap");

        let unwrapped = unwrap_message(&wrapped, &receiver_keys)
            .await
            .unwrap()
            .unwrap();
        assert!(unwrapped.signature.is_none());
    }

    #[tokio::test]
    async fn expiration_tag_is_set_when_provided() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let exp = Timestamp::from_secs(Timestamp::now().as_secs() + 3600);

        let wrapped = wrap_message(
            &sample_order_message(Some(1)),
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions {
                expiration: Some(exp),
                ..WrapOptions::default()
            },
        )
        .await
        .expect("wrap");

        let has_expiration = wrapped
            .tags
            .iter()
            .any(|t| t.as_slice().first().map(|s| s.as_str()) == Some("expiration"));
        assert!(has_expiration);
    }

    #[test]
    fn validate_response_cant_do_short_circuits() {
        let msg = Message::cant_do(
            Some(uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")),
            Some(5),
            Some(Payload::CantDo(Some(CantDoReason::NotAuthorized))),
        );
        let err = validate_response(&msg, Some(5)).unwrap_err();
        match err {
            MostroError::MostroCantDo(CantDoReason::NotAuthorized) => {}
            _ => panic!("expected CantDo(NotAuthorized)"),
        }
    }

    #[test]
    fn validate_response_request_id_match() {
        let msg = sample_order_message(Some(9));
        validate_response(&msg, Some(9)).unwrap();
    }

    #[test]
    fn validate_response_request_id_mismatch_errors() {
        let msg = sample_order_message(Some(9));
        let err = validate_response(&msg, Some(10)).unwrap_err();
        assert!(matches!(err, MostroError::MostroInternalErr(_)));
    }

    #[test]
    fn validate_response_allows_unsolicited_actions_without_request_id() {
        let msg = Message::Order(MessageKind::new(
            Some(uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")),
            None,
            None,
            Action::BuyerTookOrder,
            None,
        ));
        validate_response(&msg, Some(1)).unwrap();
    }

    #[test]
    fn validate_response_with_no_expected_id_is_ok() {
        let msg = sample_order_message(None);
        validate_response(&msg, None).unwrap();
    }
}
