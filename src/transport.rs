//! Transport selection for Mostro protocol messages.
//!
//! Mostro supports two wire transports for the same logical
//! [`Message`](crate::message::Message):
//!
//! * **Protocol v1 — NIP-59 GiftWrap** (`kind: 1059`, see [`crate::nip59`]):
//!   fully opaque envelopes. Strong metadata privacy, but relays cannot
//!   rate-limit by sender, which makes the node spam-prone.
//! * **Protocol v2 — NIP-44 direct** (`kind: 14`): a *signed* event authored
//!   by the per-trade key, whose `content` is the NIP-44 encryption of a
//!   3-element JSON tuple:
//!
//!   ```text
//!   [Message, trade_sig | null, [identity_pubkey, identity_sig] | null]
//!   ```
//!
//!   The visible sender lets relays and the daemon rate-limit and
//!   pre-filter cheaply, while the identity key — and its proof of
//!   possession — stays inside the ciphertext, exactly as private as the
//!   seal makes it in v1. Both signatures are produced with
//!   [`Message::sign`] over the JSON of the first tuple element; the
//!   co-signature is what binds the identity key to the trade key for that
//!   message. A `null` third element is full-privacy mode: the identity is
//!   the trade key itself.
//!
//! Note the deliberate deviation from NIP-17: there, `kind: 14` is an
//! *unsigned* rumor that only travels inside a gift wrap. Mostro publishes
//! it signed because the author is an ephemeral, single-trade key, so the
//! association the NIP-17 rule protects against is intentional and bounded.
//!
//! Both transports unwrap into the same [`UnwrappedMessage`], so consumers
//! never need to know which envelope a message arrived in:
//! [`unwrap_incoming`] dispatches on the event kind.

use std::str::FromStr;

use crate::message::Message;
use crate::nip59::{self, UnwrappedMessage, WrapOptions};
use crate::prelude::{MostroError, ServiceError};
use nostr_sdk::nips::nip44;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

/// Inner content of a v2 event, before NIP-44 encryption:
/// `[Message, trade_sig, [identity_pubkey, identity_sig]]`.
type DirectTuple = (Message, Option<String>, Option<(String, String)>);

/// A concrete wire transport for Mostro protocol messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    /// Protocol v1 — NIP-59 GiftWrap (`kind: 1059`).
    #[serde(rename = "gift-wrap")]
    GiftWrap,
    /// Protocol v2 — NIP-44 direct message (`kind: 14`).
    #[serde(rename = "nip44")]
    Nip44Direct,
}

impl Transport {
    /// The Nostr event kind this transport publishes.
    pub fn event_kind(&self) -> Kind {
        match self {
            Transport::GiftWrap => Kind::GiftWrap,
            Transport::Nip44Direct => Kind::PrivateDirectMessage,
        }
    }
}

/// The transport a received event arrived on, if it is a Mostro transport
/// kind at all. Lets a daemon record the inbound transport per message so
/// replies can mirror it.
pub fn transport_for_kind(kind: Kind) -> Option<Transport> {
    match kind {
        Kind::GiftWrap => Some(Transport::GiftWrap),
        Kind::PrivateDirectMessage => Some(Transport::Nip44Direct),
        _ => None,
    }
}

/// Operator-facing transport policy: which transports a node speaks.
///
/// Serializes to the `transport` settings values `"gift-wrap"`, `"nip44"`
/// and `"dual"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TransportMode {
    /// Accept and send v1 gift wraps only (legacy behavior).
    #[default]
    #[serde(rename = "gift-wrap")]
    GiftWrap,
    /// Accept and send v2 NIP-44 direct messages only.
    #[serde(rename = "nip44")]
    Nip44Direct,
    /// Accept both; replies mirror the transport each message arrived on.
    #[serde(rename = "dual")]
    Dual,
}

impl TransportMode {
    /// Event kinds a node running this mode must subscribe to.
    pub fn subscription_kinds(&self) -> Vec<Kind> {
        match self {
            TransportMode::GiftWrap => vec![Kind::GiftWrap],
            TransportMode::Nip44Direct => vec![Kind::PrivateDirectMessage],
            TransportMode::Dual => vec![Kind::GiftWrap, Kind::PrivateDirectMessage],
        }
    }

    /// Whether events of `kind` are accepted under this mode.
    pub fn accepts(&self, kind: Kind) -> bool {
        self.subscription_kinds().contains(&kind)
    }

    /// The transport to reply on for a message that arrived via `inbound`.
    ///
    /// Single-transport modes always answer on their own transport; `Dual`
    /// mirrors the inbound one, which is mandatory for backwards
    /// compatibility — a v1 client that sent a gift wrap can only see
    /// gift-wrapped replies.
    pub fn reply_transport(&self, inbound: Transport) -> Transport {
        match self {
            TransportMode::GiftWrap => Transport::GiftWrap,
            TransportMode::Nip44Direct => Transport::Nip44Direct,
            TransportMode::Dual => inbound,
        }
    }

    /// Protocol versions accepted under this mode, for capability
    /// advertisement (the `protocol_versions` tag of the node info event).
    pub fn protocol_versions(&self) -> &'static str {
        match self {
            TransportMode::GiftWrap => "1",
            TransportMode::Nip44Direct => "2",
            TransportMode::Dual => "1,2",
        }
    }
}

impl FromStr for TransportMode {
    type Err = MostroError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gift-wrap" => Ok(TransportMode::GiftWrap),
            "nip44" => Ok(TransportMode::Nip44Direct),
            "dual" => Ok(TransportMode::Dual),
            other => Err(MostroError::MostroInternalErr(
                ServiceError::UnexpectedError(format!(
                    "unknown transport mode {other:?}; expected \"gift-wrap\", \"nip44\" or \"dual\""
                )),
            )),
        }
    }
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TransportMode::GiftWrap => "gift-wrap",
            TransportMode::Nip44Direct => "nip44",
            TransportMode::Dual => "dual",
        };
        write!(f, "{s}")
    }
}

/// Build a protocol-v2 direct message event (`kind: 14`) ready to publish.
///
/// * `message` — the Mostro message to send.
/// * `identity_keys` — long-lived identity keys. When they differ from
///   `trade_keys` (reputation mode) the encrypted tuple carries an identity
///   proof: the identity pubkey plus its [`Message::sign`] signature over
///   the message JSON. Pass the same value as `trade_keys` for full-privacy
///   mode — the proof is then omitted and the receiver treats the trade key
///   as the identity.
/// * `trade_keys` — per-trade keys. They author and sign the event (the
///   visible, rate-limitable sender) and produce the inner tuple signature
///   when `opts.signed` is `true`.
/// * `receiver` — the counterparty (Mostro node, or a client's trade key
///   for node-originated messages). The NIP-44 conversation key is derived
///   from `trade_keys` and `receiver`, so only those two parties can
///   decrypt the content.
/// * `opts` — PoW difficulty, NIP-40 expiration and inner-signature flag,
///   same semantics as the gift-wrap transport.
pub fn wrap_message_nip44(
    message: &Message,
    identity_keys: &Keys,
    trade_keys: &Keys,
    receiver: PublicKey,
    opts: WrapOptions,
) -> Result<Event, MostroError> {
    let message_json = message.as_json().map_err(MostroError::MostroInternalErr)?;

    let trade_sig = opts
        .signed
        .then(|| Message::sign(message_json.clone(), trade_keys).to_string());

    let identity_proof = (identity_keys.public_key() != trade_keys.public_key()).then(|| {
        (
            identity_keys.public_key().to_hex(),
            Message::sign(message_json.clone(), identity_keys).to_string(),
        )
    });

    let tuple: (&Message, Option<String>, Option<(String, String)>) =
        (message, trade_sig, identity_proof);
    let content = serde_json::to_string(&tuple)
        .map_err(|_| MostroError::MostroInternalErr(ServiceError::MessageSerializationError))?;

    let encrypted = nip44::encrypt(
        trade_keys.secret_key(),
        &receiver,
        content,
        nip44::Version::default(),
    )
    .map_err(|e| MostroError::MostroInternalErr(ServiceError::EncryptionError(e.to_string())))?;

    let mut tags: Vec<Tag> = vec![Tag::public_key(receiver)];
    if let Some(exp) = opts.expiration {
        tags.push(Tag::expiration(exp));
    }

    EventBuilder::new(Kind::PrivateDirectMessage, encrypted)
        .tags(tags)
        .pow(opts.pow)
        .sign_with_keys(trade_keys)
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))
}

/// Try to open an incoming protocol-v2 direct message (`kind: 14`) with the
/// given `receiver_keys`.
///
/// Returns `Ok(None)` only when the NIP-44 content could not be decrypted
/// with `receiver_keys` — the "not addressed to me" signal, mirroring
/// [`nip59::unwrap_message`]. Every other failure (invalid event signature,
/// malformed tuple, non-verifying inner signatures) yields `Err`.
///
/// On success, [`UnwrappedMessage::sender`] is the event author (the trade
/// key) and [`UnwrappedMessage::identity`] is the proven identity pubkey
/// from the tuple, or the trade key itself when no proof was attached
/// (full-privacy mode).
pub fn unwrap_message_nip44(
    event: &Event,
    receiver_keys: &Keys,
) -> Result<Option<UnwrappedMessage>, MostroError> {
    if event.kind != Kind::PrivateDirectMessage {
        return Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError("event is not a direct message".to_string()),
        ));
    }

    // The event signature is the trade-key authorship proof — unlike the
    // gift wrap's outer layer (signed by a throwaway ephemeral key), it
    // must be valid before anything in the content is trusted.
    event.verify().map_err(|_| {
        MostroError::MostroInternalErr(ServiceError::NostrError(
            "invalid event signature".to_string(),
        ))
    })?;

    // Decrypt using (receiver_secret, trade_pubkey). Failure here is the
    // "not addressed to me" signal.
    let plaintext = match nip44::decrypt(receiver_keys.secret_key(), &event.pubkey, &event.content)
    {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };

    let (message, trade_sig, identity_proof): DirectTuple = serde_json::from_str(&plaintext)
        .map_err(|_| MostroError::MostroInternalErr(ServiceError::MessageSerializationError))?;

    let message_json = message.as_json().map_err(MostroError::MostroInternalErr)?;

    let signature = match trade_sig {
        Some(s) => {
            let sig = Signature::from_str(&s).map_err(|e| {
                MostroError::MostroInternalErr(ServiceError::UnexpectedError(format!(
                    "malformed trade signature: {e}"
                )))
            })?;
            if !Message::verify_signature(message_json.clone(), event.pubkey, sig) {
                return Err(MostroError::MostroInternalErr(
                    ServiceError::UnexpectedError(
                        "trade signature does not verify against event author".to_string(),
                    ),
                ));
            }
            Some(sig)
        }
        None => None,
    };

    let identity = match identity_proof {
        Some((pubkey, sig)) => {
            let identity_pubkey = PublicKey::from_str(&pubkey).map_err(|e| {
                MostroError::MostroInternalErr(ServiceError::UnexpectedError(format!(
                    "malformed identity pubkey: {e}"
                )))
            })?;
            let identity_sig = Signature::from_str(&sig).map_err(|e| {
                MostroError::MostroInternalErr(ServiceError::UnexpectedError(format!(
                    "malformed identity signature: {e}"
                )))
            })?;
            if !Message::verify_signature(message_json, identity_pubkey, identity_sig) {
                return Err(MostroError::MostroInternalErr(
                    ServiceError::UnexpectedError(
                        "identity signature does not verify against identity pubkey".to_string(),
                    ),
                ));
            }
            identity_pubkey
        }
        None => event.pubkey,
    };

    Ok(Some(UnwrappedMessage {
        message,
        signature,
        sender: event.pubkey,
        identity,
        created_at: event.created_at,
    }))
}

/// Wrap `message` for the given `transport`. Thin dispatcher over
/// [`nip59::wrap_message`] and [`wrap_message_nip44`] so senders hold a
/// single code path.
pub async fn wrap_message_with(
    transport: Transport,
    message: &Message,
    identity_keys: &Keys,
    trade_keys: &Keys,
    receiver: PublicKey,
    opts: WrapOptions,
) -> Result<Event, MostroError> {
    match transport {
        Transport::GiftWrap => {
            nip59::wrap_message(message, identity_keys, trade_keys, receiver, opts).await
        }
        Transport::Nip44Direct => {
            wrap_message_nip44(message, identity_keys, trade_keys, receiver, opts)
        }
    }
}

/// Try to open an incoming event on whichever Mostro transport matches its
/// kind, returning the transport-agnostic [`UnwrappedMessage`].
///
/// * `kind: 1059` → the v1 gift-wrap path ([`nip59::unwrap_message`]).
/// * `kind: 14` → the v2 direct path ([`unwrap_message_nip44`]).
/// * anything else → `Err` (the caller subscribed to a kind no Mostro
///   transport speaks).
///
/// `Ok(None)` keeps its "not addressed to me" meaning on both paths.
pub async fn unwrap_incoming(
    event: &Event,
    receiver_keys: &Keys,
) -> Result<Option<UnwrappedMessage>, MostroError> {
    match event.kind {
        Kind::GiftWrap => nip59::unwrap_message(event, receiver_keys).await,
        Kind::PrivateDirectMessage => unwrap_message_nip44(event, receiver_keys),
        other => Err(MostroError::MostroInternalErr(
            ServiceError::UnexpectedError(format!("no Mostro transport for event kind {other}")),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Action, MessageKind, Payload, Peer};
    use crate::nip59::wrap_message;
    use uuid::uuid;

    fn sample_order_message(request_id: Option<u64>) -> Message {
        let peer = Peer::new(
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

    // Build a kind-14 event with an arbitrary plaintext tuple so tests can
    // inject payloads `wrap_message_nip44` would never emit.
    fn wrap_raw_nip44(trade_keys: &Keys, receiver: PublicKey, plaintext: &str) -> Event {
        let encrypted = nip44::encrypt(
            trade_keys.secret_key(),
            &receiver,
            plaintext,
            nip44::Version::default(),
        )
        .expect("encrypt");
        EventBuilder::new(Kind::PrivateDirectMessage, encrypted)
            .tags([Tag::public_key(receiver)])
            .sign_with_keys(trade_keys)
            .expect("sign")
    }

    #[test]
    fn nip44_roundtrip_reputation_mode() {
        let identity_keys = Keys::generate();
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let message = sample_order_message(Some(42));

        let event = wrap_message_nip44(
            &message,
            &identity_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .expect("wrap");

        assert_eq!(event.kind, Kind::PrivateDirectMessage);
        assert_eq!(event.pubkey, trade_keys.public_key());
        assert!(event
            .tags
            .iter()
            .any(|t| t.as_slice().first().map(|s| s.as_str()) == Some("p")));

        let unwrapped = unwrap_message_nip44(&event, &receiver_keys)
            .expect("unwrap result")
            .expect("unwrap some");

        assert_eq!(unwrapped.sender, trade_keys.public_key());
        assert_eq!(unwrapped.identity, identity_keys.public_key());
        assert!(unwrapped.signature.is_some());
        assert_eq!(
            unwrapped.message.as_json().unwrap(),
            message.as_json().unwrap()
        );
    }

    #[test]
    fn nip44_full_privacy_identity_equals_sender() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();

        let event = wrap_message_nip44(
            &sample_order_message(Some(1)),
            &trade_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions {
                signed: false,
                ..WrapOptions::default()
            },
        )
        .expect("wrap");

        let unwrapped = unwrap_message_nip44(&event, &receiver_keys)
            .expect("unwrap")
            .expect("some");

        assert_eq!(unwrapped.sender, trade_keys.public_key());
        assert_eq!(unwrapped.identity, trade_keys.public_key());
        assert!(unwrapped.signature.is_none());
    }

    #[test]
    fn nip44_messages_are_stamped_protocol_v2() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();

        let event = wrap_message_nip44(
            &sample_order_message(Some(1)),
            &trade_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .expect("wrap");

        let unwrapped = unwrap_message_nip44(&event, &receiver_keys)
            .expect("unwrap")
            .expect("some");
        assert_eq!(unwrapped.message.get_inner_message_kind().version, 2);
    }

    #[test]
    fn nip44_wrong_receiver_returns_none() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let stranger_keys = Keys::generate();

        let event = wrap_message_nip44(
            &sample_order_message(Some(1)),
            &trade_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .expect("wrap");

        let result = unwrap_message_nip44(&event, &stranger_keys).expect("call should not error");
        assert!(result.is_none());
    }

    #[test]
    fn nip44_forged_identity_proof_errors() {
        let identity_keys = Keys::generate();
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let message = sample_order_message(Some(1));

        // Identity signature over a different payload must be rejected.
        let bogus_sig = Message::sign("not the real message".to_string(), &identity_keys);
        let tuple: (&Message, Option<String>, Option<(String, String)>) = (
            &message,
            None,
            Some((identity_keys.public_key().to_hex(), bogus_sig.to_string())),
        );
        let plaintext = serde_json::to_string(&tuple).unwrap();
        let event = wrap_raw_nip44(&trade_keys, receiver_keys.public_key(), &plaintext);

        let result = unwrap_message_nip44(&event, &receiver_keys);
        assert!(
            matches!(result, Err(MostroError::MostroInternalErr(_))),
            "forged identity proof must surface as Err, got {result:?}",
        );
    }

    #[test]
    fn nip44_trade_sig_from_other_key_errors() {
        let trade_keys = Keys::generate();
        let other_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let message = sample_order_message(Some(1));
        let message_json = message.as_json().unwrap();

        // Inner signature produced by a key other than the event author.
        let foreign_sig = Message::sign(message_json, &other_keys);
        let tuple: (&Message, Option<String>, Option<(String, String)>) =
            (&message, Some(foreign_sig.to_string()), None);
        let plaintext = serde_json::to_string(&tuple).unwrap();
        let event = wrap_raw_nip44(&trade_keys, receiver_keys.public_key(), &plaintext);

        let result = unwrap_message_nip44(&event, &receiver_keys);
        assert!(
            matches!(result, Err(MostroError::MostroInternalErr(_))),
            "foreign trade signature must surface as Err, got {result:?}",
        );
    }

    #[test]
    fn nip44_malformed_tuple_errors() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();

        // Decrypts fine but is not a valid 3-element tuple.
        let event = wrap_raw_nip44(&trade_keys, receiver_keys.public_key(), "not a tuple");

        let result = unwrap_message_nip44(&event, &receiver_keys);
        assert!(
            matches!(result, Err(MostroError::MostroInternalErr(_))),
            "malformed tuple must surface as Err, got {result:?}",
        );
    }

    #[test]
    fn nip44_expiration_tag_is_set_when_provided() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let exp = Timestamp::from_secs(Timestamp::now().as_secs() + 3600);

        let event = wrap_message_nip44(
            &sample_order_message(Some(1)),
            &trade_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions {
                expiration: Some(exp),
                ..WrapOptions::default()
            },
        )
        .expect("wrap");

        let has_expiration = event
            .tags
            .iter()
            .any(|t| t.as_slice().first().map(|s| s.as_str()) == Some("expiration"));
        assert!(has_expiration);
    }

    #[test]
    fn nip44_pow_is_applied() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();

        let event = wrap_message_nip44(
            &sample_order_message(Some(1)),
            &trade_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions {
                pow: 8,
                ..WrapOptions::default()
            },
        )
        .expect("wrap");

        assert!(event.check_pow(8));
    }

    #[tokio::test]
    async fn unwrap_incoming_dispatches_both_transports() {
        let identity_keys = Keys::generate();
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let message = sample_order_message(Some(7));

        let wrapped = wrap_message(
            &message,
            &identity_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .await
        .expect("gift wrap");
        let direct = wrap_message_nip44(
            &message,
            &identity_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .expect("nip44 wrap");

        for event in [wrapped, direct] {
            let unwrapped = unwrap_incoming(&event, &receiver_keys)
                .await
                .expect("unwrap")
                .expect("some");
            assert_eq!(unwrapped.sender, trade_keys.public_key());
            assert_eq!(unwrapped.identity, identity_keys.public_key());
            assert_eq!(
                unwrapped.message.as_json().unwrap(),
                message.as_json().unwrap()
            );
        }
    }

    #[tokio::test]
    async fn unwrap_incoming_rejects_unknown_kind() {
        let keys = Keys::generate();
        let event = EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .expect("sign");

        let result = unwrap_incoming(&event, &keys).await;
        assert!(matches!(result, Err(MostroError::MostroInternalErr(_))));
    }

    #[tokio::test]
    async fn wrap_message_with_dispatches_by_transport() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let message = sample_order_message(Some(1));

        let gift = wrap_message_with(
            Transport::GiftWrap,
            &message,
            &trade_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .await
        .expect("gift wrap");
        let direct = wrap_message_with(
            Transport::Nip44Direct,
            &message,
            &trade_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .await
        .expect("nip44");

        assert_eq!(gift.kind, Kind::GiftWrap);
        assert_eq!(direct.kind, Kind::PrivateDirectMessage);
    }

    #[test]
    fn transport_mode_subscription_kinds() {
        assert_eq!(
            TransportMode::GiftWrap.subscription_kinds(),
            vec![Kind::GiftWrap]
        );
        assert_eq!(
            TransportMode::Nip44Direct.subscription_kinds(),
            vec![Kind::PrivateDirectMessage]
        );
        assert_eq!(
            TransportMode::Dual.subscription_kinds(),
            vec![Kind::GiftWrap, Kind::PrivateDirectMessage]
        );
        assert!(TransportMode::Dual.accepts(Kind::GiftWrap));
        assert!(!TransportMode::GiftWrap.accepts(Kind::PrivateDirectMessage));
    }

    #[test]
    fn transport_mode_reply_mirroring() {
        assert_eq!(
            TransportMode::Dual.reply_transport(Transport::GiftWrap),
            Transport::GiftWrap
        );
        assert_eq!(
            TransportMode::Dual.reply_transport(Transport::Nip44Direct),
            Transport::Nip44Direct
        );
        // Single-transport modes never mirror.
        assert_eq!(
            TransportMode::GiftWrap.reply_transport(Transport::Nip44Direct),
            Transport::GiftWrap
        );
        assert_eq!(
            TransportMode::Nip44Direct.reply_transport(Transport::GiftWrap),
            Transport::Nip44Direct
        );
    }

    #[test]
    fn transport_mode_config_parsing() {
        for (s, expected) in [
            ("gift-wrap", TransportMode::GiftWrap),
            ("nip44", TransportMode::Nip44Direct),
            ("dual", TransportMode::Dual),
        ] {
            assert_eq!(s.parse::<TransportMode>().unwrap(), expected);
            let from_serde: TransportMode = serde_json::from_str(&format!("{s:?}")).unwrap();
            assert_eq!(from_serde, expected);
            assert_eq!(expected.to_string(), s);
        }
        assert!("bogus".parse::<TransportMode>().is_err());
        assert_eq!(TransportMode::default(), TransportMode::GiftWrap);
    }

    #[test]
    fn transport_for_kind_mapping() {
        assert_eq!(
            transport_for_kind(Kind::GiftWrap),
            Some(Transport::GiftWrap)
        );
        assert_eq!(
            transport_for_kind(Kind::PrivateDirectMessage),
            Some(Transport::Nip44Direct)
        );
        assert_eq!(transport_for_kind(Kind::TextNote), None);
    }

    #[test]
    fn transport_mode_protocol_versions() {
        assert_eq!(TransportMode::GiftWrap.protocol_versions(), "1");
        assert_eq!(TransportMode::Nip44Direct.protocol_versions(), "2");
        assert_eq!(TransportMode::Dual.protocol_versions(), "1,2");
    }
}
