//! Transport for Mostro protocol messages.
//!
//! Mostro messages travel as **protocol v2 — NIP-44 direct** (`kind: 14`):
//! a *signed* event authored by the per-trade key, whose `content` is the
//! NIP-44 encryption of a 3-element JSON tuple:
//!
//! ```text
//! [Message, trade_sig | null, [identity_pubkey, identity_sig] | null]
//! ```
//!
//! The visible sender lets relays and the daemon rate-limit and pre-filter
//! cheaply, while the identity key — and its proof of possession — stays
//! inside the ciphertext. `trade_sig` is [`Message::sign`] over the JSON of
//! the first tuple element; `identity_sig` signs a domain-tagged payload
//! that includes the trade pubkey
//! (`mostro-transport-v2-identity:<trade_pubkey>:<message_json>`), so the
//! proof binds the identity to the specific trade key authoring the event
//! and cannot be grafted onto another sender. A `null` third element is
//! full-privacy mode: the identity is the trade key itself.
//!
//! Note the deliberate deviation from NIP-17: there, `kind: 14` is an
//! *unsigned* rumor that only travels inside a gift wrap. Mostro publishes
//! it signed because the author is an ephemeral, single-trade key, so the
//! association the NIP-17 rule protects against is intentional and bounded.
//!
//! Protocol v1 (NIP-59 gift wrap, `kind: 1059`) was removed in 0.16.0
//! (mostro#786). The [`Transport`] enum and the [`wrap_message_with`] /
//! [`unwrap_incoming`] dispatchers are kept even with a single transport:
//! they are what let v2 be introduced next to v1 without touching message
//! handlers, and every transport yields the same [`UnwrappedMessage`].

use std::str::FromStr;

use crate::message::Message;
use crate::prelude::{MostroError, ServiceError};
use nostr::nips::nip44;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

/// Options controlling how a Mostro message is wrapped.
#[derive(Debug, Clone)]
pub struct WrapOptions {
    /// NIP-13 proof-of-work difficulty applied to the outer event.
    pub pow: u8,
    /// Optional NIP-40 expiration tag for the outer event.
    pub expiration: Option<Timestamp>,
    /// When true the tuple carries the trade key's signature over the JSON
    /// of `Message`. When false that element is `null`. Traffic to a Mostro
    /// node always uses `true`.
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

/// A Mostro message recovered from an incoming event, plus the sender and
/// identity it proves.
#[derive(Debug, Clone)]
pub struct UnwrappedMessage {
    /// The logical Mostro message.
    pub message: Message,
    /// Signature of the JSON-serialized `Message`, produced with the sender's
    /// trade keys. Present only when the sender set `signed = true`.
    pub signature: Option<Signature>,
    /// Event author — the sender's trade public key.
    pub sender: PublicKey,
    /// The sender's long-lived identity public key, proven inside the
    /// ciphertext. In full-privacy mode this equals `sender`.
    pub identity: PublicKey,
    /// Event `created_at` timestamp.
    pub created_at: Timestamp,
}

/// Inner content of a v2 event, before NIP-44 encryption:
/// `[Message, trade_sig, [identity_pubkey, identity_sig]]`.
type DirectTuple = (Message, Option<String>, Option<(String, String)>);

/// Payload the identity key signs for the v2 identity proof.
///
/// It is domain-tagged and includes the trade pubkey, so the proof binds
/// the identity to *both* the message and the trade key that authored the
/// event. Signing the message
/// JSON alone would let any party that sees the plaintext tuple graft the
/// proof onto an event authored by a different trade key.
fn identity_proof_payload(trade_pubkey: &PublicKey, message_json: &str) -> String {
    format!(
        "mostro-transport-v2-identity:{}:{}",
        trade_pubkey.to_hex(),
        message_json
    )
}

/// The wire transport a node speaks, selected by the `transport` setting.
///
/// Protocol v2 is the only transport. The enum stays so that the kind, the
/// envelope and the advertised `protocol_version` keep coming from one
/// place, as they did while v1 and v2 coexisted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    /// Protocol v2 — NIP-44 direct message (`kind: 14`).
    #[default]
    #[serde(rename = "nip44")]
    Nip44Direct,
}

impl Transport {
    /// The Nostr event kind this transport publishes and subscribes to.
    pub fn event_kind(&self) -> Kind {
        match self {
            Transport::Nip44Direct => Kind::PrivateDirectMessage,
        }
    }

    /// The Mostro protocol version this transport carries, for capability
    /// advertisement (the `protocol_version` tag of the node info event).
    pub fn protocol_version(&self) -> u8 {
        match self {
            Transport::Nip44Direct => 2,
        }
    }
}

impl FromStr for Transport {
    type Err = MostroError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "nip44" => Ok(Transport::Nip44Direct),
            other => Err(MostroError::MostroInternalErr(
                ServiceError::UnexpectedError(format!(
                    "unknown transport {other:?}; expected \"nip44\""
                )),
            )),
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Transport::Nip44Direct => "nip44",
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
///   the domain-tagged payload binding the trade pubkey to the message
///   JSON (see [`identity_proof_payload`]). Pass the same value as
///   `trade_keys` for full-privacy mode — the proof is then omitted and
///   the receiver treats the trade key as the identity.
/// * `trade_keys` — per-trade keys. They author and sign the event (the
///   visible, rate-limitable sender) and produce the inner tuple signature
///   when `opts.signed` is `true`.
/// * `receiver` — the counterparty (Mostro node, or a client's trade key
///   for node-originated messages). The NIP-44 conversation key is derived
///   from `trade_keys` and `receiver`, so only those two parties can
///   decrypt the content.
/// * `opts` — PoW difficulty, NIP-40 expiration and inner-signature flag.
///   When `opts.pow > 0`, PoW is
///   mined on the unsigned event via `UnsignedEvent::mine(&SingleThreadPow, …)`
///   before signing with `finalize` (nostr 0.45; replaces `EventBuilder::pow`
///   / `sign_with_keys`).
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
        let payload = identity_proof_payload(&trade_keys.public_key(), &message_json);
        (
            identity_keys.public_key().to_hex(),
            Message::sign(payload, identity_keys).to_string(),
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

    let unsigned = EventBuilder::new(Kind::PrivateDirectMessage, encrypted)
        .tags(tags)
        .finalize_unsigned(trade_keys.public_key());

    let unsigned = match core::num::NonZeroU8::new(opts.pow) {
        Some(pow) => unsigned
            .mine(&SingleThreadPow, pow)
            .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))?,
        None => unsigned,
    };

    unsigned
        .finalize(trade_keys)
        .map_err(|e| MostroError::MostroInternalErr(ServiceError::NostrError(e.to_string())))
}

/// Try to open an incoming protocol-v2 direct message (`kind: 14`) with the
/// given `receiver_keys`.
///
/// Returns `Ok(None)` only when the NIP-44 content could not be decrypted
/// with `receiver_keys` — the "not addressed to me" signal. Every other failure (invalid event signature,
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

    // The event signature is the trade-key authorship proof: it must be
    // valid before anything in the content is trusted.
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
            let payload = identity_proof_payload(&event.pubkey, &message_json);
            if !Message::verify_signature(payload, identity_pubkey, identity_sig) {
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

/// Wrap `message` for the given `transport`, so senders hold a single code
/// path whatever transport the node speaks.
pub async fn wrap_message_with(
    transport: Transport,
    message: &Message,
    identity_keys: &Keys,
    trade_keys: &Keys,
    receiver: PublicKey,
    opts: WrapOptions,
) -> Result<Event, MostroError> {
    match transport {
        Transport::Nip44Direct => {
            wrap_message_nip44(message, identity_keys, trade_keys, receiver, opts)
        }
    }
}

/// Try to open an incoming event on the Mostro transport that matches its
/// kind, returning the transport-agnostic [`UnwrappedMessage`].
///
/// * `kind: 14` → [`unwrap_message_nip44`]; `Ok(None)` means "not
///   addressed to me".
/// * anything else, including the removed protocol-v1 gift wrap
///   (`kind: 1059`) → `Err`.
pub async fn unwrap_incoming(
    event: &Event,
    receiver_keys: &Keys,
) -> Result<Option<UnwrappedMessage>, MostroError> {
    match event.kind {
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
            .finalize(trade_keys)
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
    fn nip44_identity_proof_grafted_onto_other_trade_key_errors() {
        // A valid identity proof produced for trade key T must not verify
        // when replayed inside an event authored by another trade key T',
        // even with the identical Message — the proof payload includes the
        // trade pubkey precisely to prevent this grafting.
        let identity_keys = Keys::generate();
        let trade_keys = Keys::generate();
        let attacker_trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let message = sample_order_message(Some(1));
        let message_json = message.as_json().unwrap();

        // Legitimate proof, bound to the victim's trade key.
        let payload = identity_proof_payload(&trade_keys.public_key(), &message_json);
        let legit_sig = Message::sign(payload, &identity_keys);

        // Attacker replays it under their own trade key.
        let tuple: (&Message, Option<String>, Option<(String, String)>) = (
            &message,
            None,
            Some((identity_keys.public_key().to_hex(), legit_sig.to_string())),
        );
        let plaintext = serde_json::to_string(&tuple).unwrap();
        let event = wrap_raw_nip44(&attacker_trade_keys, receiver_keys.public_key(), &plaintext);

        let result = unwrap_message_nip44(&event, &receiver_keys);
        assert!(
            matches!(result, Err(MostroError::MostroInternalErr(_))),
            "grafted identity proof must surface as Err, got {result:?}",
        );

        // Sanity check: the same proof under the right trade key verifies.
        let event = wrap_raw_nip44(&trade_keys, receiver_keys.public_key(), &plaintext);
        let unwrapped = unwrap_message_nip44(&event, &receiver_keys)
            .expect("unwrap")
            .expect("some");
        assert_eq!(unwrapped.identity, identity_keys.public_key());
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
    async fn unwrap_incoming_opens_nip44() {
        let identity_keys = Keys::generate();
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let message = sample_order_message(Some(7));

        let event = wrap_message_nip44(
            &message,
            &identity_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .expect("nip44 wrap");

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

    #[test]
    fn gift_wrap_is_not_a_transport() {
        assert!("gift-wrap".parse::<Transport>().is_err());
        assert!(serde_json::from_str::<Transport>("\"gift-wrap\"").is_err());
        assert_eq!(Transport::default(), Transport::Nip44Direct);
    }

    #[tokio::test]
    async fn unwrap_incoming_rejects_gift_wrap() {
        // A kind-1059 event addressed to the receiver is no longer a Mostro
        // transport: it must be an error, not the "not addressed to me"
        // `Ok(None)` a v1 unwrap returned when decryption failed.
        let receiver_keys = Keys::generate();
        let event = EventBuilder::new(Kind::GiftWrap, "ciphertext")
            .tags([Tag::public_key(receiver_keys.public_key())])
            .finalize(&Keys::generate())
            .expect("sign");

        let result = unwrap_incoming(&event, &receiver_keys).await;
        assert!(
            matches!(result, Err(MostroError::MostroInternalErr(_))),
            "a gift wrap must be rejected, got {result:?}",
        );
    }

    #[tokio::test]
    async fn unwrap_incoming_rejects_unknown_kind() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "hello")
            .finalize(&keys)
            .expect("sign");

        let result = unwrap_incoming(&event, &keys).await;
        assert!(matches!(result, Err(MostroError::MostroInternalErr(_))));
    }

    #[tokio::test]
    async fn wrap_message_with_uses_nip44() {
        let trade_keys = Keys::generate();
        let receiver_keys = Keys::generate();

        let event = wrap_message_with(
            Transport::Nip44Direct,
            &sample_order_message(Some(1)),
            &trade_keys,
            &trade_keys,
            receiver_keys.public_key(),
            WrapOptions::default(),
        )
        .await
        .expect("nip44");

        assert_eq!(event.kind, Kind::PrivateDirectMessage);
    }

    #[test]
    fn transport_config_parsing() {
        assert_eq!(
            "nip44".parse::<Transport>().unwrap(),
            Transport::Nip44Direct
        );
        let from_serde: Transport = serde_json::from_str("\"nip44\"").unwrap();
        assert_eq!(from_serde, Transport::Nip44Direct);
        assert_eq!(Transport::Nip44Direct.to_string(), "nip44");
        assert!("dual".parse::<Transport>().is_err());
        assert!("bogus".parse::<Transport>().is_err());
    }

    #[test]
    fn transport_kind_and_version() {
        assert_eq!(
            Transport::Nip44Direct.event_kind(),
            Kind::PrivateDirectMessage
        );
        assert_eq!(Transport::Nip44Direct.protocol_version(), 2);
    }
}
