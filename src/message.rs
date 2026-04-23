//! Protocol message envelope exchanged between clients and a Mostro node.
//!
//! The top-level type is [`Message`], a tagged union that carries a
//! [`MessageKind`] together with a discriminator (order, dispute, DM, rate,
//! can't-do, restore). [`MessageKind`] holds the shared fields present on
//! every request/response: protocol version, optional identifier, trade
//! index, [`Action`] and [`Payload`].
//!
//! In transit, messages are serialized to JSON, optionally signed with the
//! sender's trade keys using [`Message::sign`], and wrapped in a NIP-59
//! envelope by [`crate::nip59::wrap_message`].

use crate::prelude::*;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Message as BitcoinMessage;
use nostr_sdk::prelude::*;
#[cfg(feature = "sqlx")]
use sqlx::FromRow;
#[cfg(feature = "sqlx")]
use sqlx_crud::SqlxCrud;

use std::fmt;
use uuid::Uuid;

/// Identity of a counterpart in a trade.
///
/// `Peer` bundles the counterpart's trade public key with an optional
/// [`UserInfo`] snapshot so it can be embedded into messages that need to
/// surface reputation (for example the peer disclosure sent with
/// [`Action::FiatSentOk`]).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Peer {
    /// Trade public key of the peer (hex or npub).
    pub pubkey: String,
    /// Optional reputation snapshot. Absent when the peer operates in full
    /// privacy mode.
    pub reputation: Option<UserInfo>,
}

impl Peer {
    /// Create a new [`Peer`].
    pub fn new(pubkey: String, reputation: Option<UserInfo>) -> Self {
        Self { pubkey, reputation }
    }

    /// Parse a [`Peer`] from its JSON representation.
    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Serialize the peer to a JSON string.
    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }
}

/// Discriminator describing the verb of a Mostro message.
///
/// `Action` values are serialized in `kebab-case`. Each action has its own
/// expected [`Payload`] shape — see [`MessageKind::verify`] for the full
/// matrix.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Publish a new order. Payload: [`Payload::Order`].
    NewOrder,
    /// Take an existing `sell` order. Payload: optional
    /// [`Payload::PaymentRequest`] or [`Payload::Amount`].
    TakeSell,
    /// Take an existing `buy` order. Payload: optional [`Payload::Amount`].
    TakeBuy,
    /// Request the taker to pay a Lightning invoice.
    /// Payload: [`Payload::PaymentRequest`].
    PayInvoice,
    /// Buyer notifies Mostro that fiat was sent.
    FiatSent,
    /// Mostro acknowledges the fiat-sent notification to the seller.
    FiatSentOk,
    /// Seller releases the hold invoice funds.
    Release,
    /// Mostro confirms that the funds have been released.
    Released,
    /// Cancel an order.
    Cancel,
    /// Mostro confirms that the order was canceled.
    Canceled,
    /// Local side started a cooperative cancel.
    CooperativeCancelInitiatedByYou,
    /// Remote side started a cooperative cancel.
    CooperativeCancelInitiatedByPeer,
    /// Local side opened a dispute.
    DisputeInitiatedByYou,
    /// Remote side opened a dispute.
    DisputeInitiatedByPeer,
    /// Both sides agreed on the cooperative cancel.
    CooperativeCancelAccepted,
    /// Mostro accepted the buyer's payout invoice.
    BuyerInvoiceAccepted,
    /// Trade completed successfully.
    PurchaseCompleted,
    /// Mostro saw the hold-invoice payment accepted by the node.
    HoldInvoicePaymentAccepted,
    /// Mostro saw the hold-invoice payment settled.
    HoldInvoicePaymentSettled,
    /// Mostro saw the hold-invoice payment canceled.
    HoldInvoicePaymentCanceled,
    /// Informational: waiting for the seller to pay the hold invoice.
    WaitingSellerToPay,
    /// Informational: waiting for the buyer's payout invoice.
    WaitingBuyerInvoice,
    /// Buyer sends/updates its payout invoice.
    /// Payload: [`Payload::PaymentRequest`].
    AddInvoice,
    /// Informational: a buyer has taken a sell order.
    BuyerTookOrder,
    /// Server-initiated rating request.
    Rate,
    /// Client-initiated rate. Payload: [`Payload::RatingUser`].
    RateUser,
    /// Acknowledgement of a received rating.
    RateReceived,
    /// Mostro returns a structured refusal. Payload: [`Payload::CantDo`].
    CantDo,
    /// Client-initiated dispute.
    Dispute,
    /// Admin cancels a trade.
    AdminCancel,
    /// Admin cancel acknowledged.
    AdminCanceled,
    /// Admin settles the hold invoice.
    AdminSettle,
    /// Admin settle acknowledged.
    AdminSettled,
    /// Admin registers a new dispute solver.
    AdminAddSolver,
    /// Solver takes a dispute.
    AdminTakeDispute,
    /// Solver took the dispute acknowledged.
    AdminTookDispute,
    /// Notification that a Lightning payment failed.
    /// Payload: [`Payload::PaymentFailed`].
    PaymentFailed,
    /// Invoice associated with the order was updated.
    InvoiceUpdated,
    /// Direct message between users. Payload: [`Payload::TextMessage`].
    SendDm,
    /// Disclosure of a counterpart's trade pubkey. Payload: [`Payload::Peer`].
    TradePubkey,
    /// Client asks Mostro to restore its session state. Payload must be `None`.
    RestoreSession,
    /// Client asks Mostro for its last known trade index. Payload must be
    /// `None`.
    LastTradeIndex,
    /// Listing of orders in response to a query.
    /// Payload: [`Payload::Ids`] or [`Payload::Orders`].
    Orders,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Top-level Mostro message exchanged between users and Mostro.
///
/// `Message` is a tagged union: every variant carries the shared
/// [`MessageKind`] body, while the variant itself tells the receiver which
/// channel the message belongs to (orders, disputes, DMs, rating, can't-do,
/// session restore). Serializes as `kebab-case` JSON.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Message {
    /// Order-channel message.
    Order(MessageKind),
    /// Dispute-channel message.
    Dispute(MessageKind),
    /// "Can't do" response returned by the Mostro node.
    CantDo(MessageKind),
    /// Rating message (server-initiated rate request or client rate).
    Rate(MessageKind),
    /// Direct message between users.
    Dm(MessageKind),
    /// Session restore request/response.
    Restore(MessageKind),
}

impl Message {
    /// Build a new `Message::Order` wrapping a freshly constructed
    /// [`MessageKind`].
    pub fn new_order(
        id: Option<Uuid>,
        request_id: Option<u64>,
        trade_index: Option<i64>,
        action: Action,
        payload: Option<Payload>,
    ) -> Self {
        let kind = MessageKind::new(id, request_id, trade_index, action, payload);
        Self::Order(kind)
    }

    /// Build a new `Message::Dispute` wrapping a freshly constructed
    /// [`MessageKind`].
    pub fn new_dispute(
        id: Option<Uuid>,
        request_id: Option<u64>,
        trade_index: Option<i64>,
        action: Action,
        payload: Option<Payload>,
    ) -> Self {
        let kind = MessageKind::new(id, request_id, trade_index, action, payload);

        Self::Dispute(kind)
    }

    /// Build a new `Message::Restore` with [`Action::RestoreSession`].
    ///
    /// According to [`MessageKind::verify`], the payload for a restore
    /// request must be `None`. Any other payload yields an invalid message.
    pub fn new_restore(payload: Option<Payload>) -> Self {
        let kind = MessageKind::new(None, None, None, Action::RestoreSession, payload);
        Self::Restore(kind)
    }

    /// Build a new `Message::CantDo` message (a structured refusal sent by
    /// Mostro when a request cannot be fulfilled).
    pub fn cant_do(id: Option<Uuid>, request_id: Option<u64>, payload: Option<Payload>) -> Self {
        let kind = MessageKind::new(id, request_id, None, Action::CantDo, payload);

        Self::CantDo(kind)
    }

    /// Build a new `Message::Dm` carrying a direct message between users.
    pub fn new_dm(
        id: Option<Uuid>,
        request_id: Option<u64>,
        action: Action,
        payload: Option<Payload>,
    ) -> Self {
        let kind = MessageKind::new(id, request_id, None, action, payload);

        Self::Dm(kind)
    }

    /// Parse a [`Message`] from its JSON representation.
    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Serialize the message to a JSON string.
    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Borrow the inner [`MessageKind`] regardless of the variant.
    pub fn get_inner_message_kind(&self) -> &MessageKind {
        match self {
            Message::Dispute(k)
            | Message::Order(k)
            | Message::CantDo(k)
            | Message::Rate(k)
            | Message::Dm(k)
            | Message::Restore(k) => k,
        }
    }

    /// Return the [`Action`] of the inner [`MessageKind`].
    ///
    /// Always returns `Some` for the current variant set; the `Option` is
    /// kept for API stability.
    pub fn inner_action(&self) -> Option<Action> {
        match self {
            Message::Dispute(a)
            | Message::Order(a)
            | Message::CantDo(a)
            | Message::Rate(a)
            | Message::Dm(a)
            | Message::Restore(a) => Some(a.get_action()),
        }
    }

    /// Validate that the inner [`MessageKind`] is consistent with its
    /// [`Action`]. Delegates to [`MessageKind::verify`].
    pub fn verify(&self) -> bool {
        match self {
            Message::Order(m)
            | Message::Dispute(m)
            | Message::CantDo(m)
            | Message::Rate(m)
            | Message::Dm(m)
            | Message::Restore(m) => m.verify(),
        }
    }

    /// Produce a Schnorr signature over the SHA-256 digest of `message`
    /// using `keys`.
    ///
    /// This is the signature embedded in the rumor tuple when
    /// [`crate::nip59::wrap_message`] is called with
    /// [`WrapOptions::signed`](crate::nip59::WrapOptions::signed) set to
    /// `true`. It binds a message to the sender's trade keys without
    /// relying on the outer Nostr event signature.
    pub fn sign(message: String, keys: &Keys) -> Signature {
        let hash: Sha256Hash = Sha256Hash::hash(message.as_bytes());
        let hash = hash.to_byte_array();
        let message: BitcoinMessage = BitcoinMessage::from_digest(hash);

        keys.sign_schnorr(&message)
    }

    /// Verify a signature previously produced by [`Message::sign`].
    ///
    /// Returns `true` when `sig` is a valid Schnorr signature of the
    /// SHA-256 digest of `message` under `pubkey`, `false` otherwise
    /// (including when `pubkey` has no x-only representation).
    pub fn verify_signature(message: String, pubkey: PublicKey, sig: Signature) -> bool {
        // Create payload hash
        let hash: Sha256Hash = Sha256Hash::hash(message.as_bytes());
        let hash = hash.to_byte_array();
        let message: BitcoinMessage = BitcoinMessage::from_digest(hash);

        // Create a verification-only context for better performance
        let secp = Secp256k1::verification_only();
        // Verify signature
        if let Ok(xonlykey) = pubkey.xonly() {
            xonlykey.verify(&secp, &message, &sig).is_ok()
        } else {
            false
        }
    }
}

/// Body shared by every [`Message`] variant.
///
/// All Mostro protocol messages share this envelope: a protocol version,
/// an optional client-chosen request id for correlation, a trade index used
/// to enforce strictly increasing sequences per user, an optional
/// order/dispute id, an [`Action`] and an optional [`Payload`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessageKind {
    /// Mostro protocol version. Set to
    /// `PROTOCOL_VER` by [`MessageKind::new`].
    pub version: u8,
    /// Client-chosen correlation id, echoed back on responses so the client
    /// can match them to in-flight requests.
    pub request_id: Option<u64>,
    /// Trade index attached to this message. Must be strictly greater than
    /// the last trade index Mostro has seen for the sender.
    pub trade_index: Option<i64>,
    /// Optional target identifier (usually the id of an [`crate::order::Order`]
    /// or [`crate::dispute::Dispute`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Verb of the message.
    pub action: Action,
    /// Payload attached to the action. The allowed shape for a given action
    /// is enforced by [`MessageKind::verify`].
    pub payload: Option<Payload>,
}

/// Alias for a signed integer amount in satoshis.
type Amount = i64;

/// Retry configuration for a failed Lightning payment.
///
/// Sent inside a [`Payload::PaymentFailed`] so the client knows how many
/// retries to expect and how long to wait between them.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PaymentFailedInfo {
    /// Maximum number of payment attempts Mostro will perform.
    pub payment_attempts: u32,
    /// Delay in seconds between two retry attempts.
    pub payment_retries_interval: u32,
}

/// Row-mapper used by `mostrod` when fetching metadata for session restore.
///
/// Not intended as a general-purpose order representation — field names are
/// chosen to match the SQL `SELECT` aliases used by the server query.
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud))]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestoredOrderHelper {
    /// Order id.
    pub id: Uuid,
    /// Order status, serialized as kebab-case.
    pub status: String,
    /// Master identity pubkey of the buyer, if any.
    pub master_buyer_pubkey: Option<String>,
    /// Master identity pubkey of the seller, if any.
    pub master_seller_pubkey: Option<String>,
    /// Trade index the buyer used on this order.
    pub trade_index_buyer: Option<i64>,
    /// Trade index the seller used on this order.
    pub trade_index_seller: Option<i64>,
}

/// Row-mapper used by `mostrod` when fetching disputes for session restore.
///
/// Field names are chosen to match the SQL `SELECT` aliases in the restore
/// query (in particular `status` is aliased as `dispute_status`).
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud))]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestoredDisputeHelper {
    /// Dispute id.
    pub dispute_id: Uuid,
    /// Order id the dispute is attached to.
    pub order_id: Uuid,
    /// Dispute status, serialized as kebab-case.
    pub dispute_status: String,
    /// Master identity pubkey of the buyer, if any.
    pub master_buyer_pubkey: Option<String>,
    /// Master identity pubkey of the seller, if any.
    pub master_seller_pubkey: Option<String>,
    /// Trade index the buyer used on the parent order.
    pub trade_index_buyer: Option<i64>,
    /// Trade index the seller used on the parent order.
    pub trade_index_seller: Option<i64>,
    /// Whether the buyer has initiated a dispute for this order.
    /// Combined with [`Self::seller_dispute`] to derive
    /// [`RestoredDisputesInfo::initiator`].
    pub buyer_dispute: bool,
    /// Whether the seller has initiated a dispute for this order.
    /// Combined with [`Self::buyer_dispute`] to derive
    /// [`RestoredDisputesInfo::initiator`].
    pub seller_dispute: bool,
    /// Public key of the solver assigned to the dispute, `None` if no
    /// solver has taken it.
    pub solver_pubkey: Option<String>,
}

/// Minimal per-order information returned to a client on session restore.
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud))]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestoredOrdersInfo {
    /// Id of the order.
    pub order_id: Uuid,
    /// Trade index of the order as seen by the requesting user.
    pub trade_index: i64,
    /// Current status of the order, serialized as kebab-case.
    pub status: String,
}

/// Identifies which party of an order opened a dispute.
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "TEXT", rename_all = "lowercase"))]
pub enum DisputeInitiator {
    /// The buyer opened the dispute.
    Buyer,
    /// The seller opened the dispute.
    Seller,
}

/// Minimal per-dispute information returned to a client on session restore.
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud))]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestoredDisputesInfo {
    /// Id of the dispute.
    pub dispute_id: Uuid,
    /// Id of the order the dispute is attached to.
    pub order_id: Uuid,
    /// Trade index of the dispute as seen by the requesting user.
    pub trade_index: i64,
    /// Current status of the dispute, serialized as kebab-case.
    pub status: String,
    /// Who initiated the dispute: [`DisputeInitiator::Buyer`],
    /// [`DisputeInitiator::Seller`], or `None` when unknown.
    pub initiator: Option<DisputeInitiator>,
    /// Public key of the solver assigned to the dispute, `None` if no
    /// solver has taken it yet.
    pub solver_pubkey: Option<String>,
}

/// Bundle of orders and disputes returned on a session restore.
///
/// Carried inside [`Payload::RestoreData`]. The server typically sends this
/// struct in the response to a [`Action::RestoreSession`] request.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RestoreSessionInfo {
    /// Orders associated with the requesting user.
    #[serde(rename = "orders")]
    pub restore_orders: Vec<RestoredOrdersInfo>,
    /// Disputes associated with the requesting user.
    #[serde(rename = "disputes")]
    pub restore_disputes: Vec<RestoredDisputesInfo>,
}

/// Typed payload attached to a [`MessageKind`].
///
/// Each variant corresponds to a set of [`Action`] values that can legally
/// carry it (see [`MessageKind::verify`]). Serialized in `snake_case` so
/// that the variant name is the JSON discriminator.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    /// A compact representation of an order used by [`Action::NewOrder`].
    Order(SmallOrder),
    /// Lightning payment request plus optional amount override.
    ///
    /// Used by [`Action::PayInvoice`], [`Action::AddInvoice`] and
    /// [`Action::TakeSell`]. The [`SmallOrder`] carries the matching order
    /// when relevant; the `String` is a BOLT-11 invoice.
    PaymentRequest(Option<SmallOrder>, String, Option<Amount>),
    /// Free-form text message used by DMs.
    TextMessage(String),
    /// Peer disclosure (trade pubkey and optional reputation).
    Peer(Peer),
    /// Rating value the user wants to attach to a completed trade.
    RatingUser(u8),
    /// Raw amount in satoshis (for actions that accept an amount override).
    Amount(Amount),
    /// Dispute context: the dispute id plus optional
    /// [`SolverDisputeInfo`] bundle sent to solvers.
    Dispute(Uuid, Option<SolverDisputeInfo>),
    /// Reason carried by a [`Action::CantDo`] response.
    CantDo(Option<CantDoReason>),
    /// Next trade key and index announced by the maker of a range order
    /// when it emits [`Action::Release`] or [`Action::FiatSent`].
    NextTrade(String, u32),
    /// Retry configuration surfaced by [`Action::PaymentFailed`].
    PaymentFailed(PaymentFailedInfo),
    /// Payload returned by the server on a session restore.
    RestoreData(RestoreSessionInfo),
    /// Vector of order ids (lightweight listing).
    Ids(Vec<Uuid>),
    /// Vector of [`SmallOrder`] values (full listing).
    Orders(Vec<SmallOrder>),
}

#[allow(dead_code)]
impl MessageKind {
    /// Build a new [`MessageKind`] stamped with the current protocol
    /// version (`PROTOCOL_VER`).
    pub fn new(
        id: Option<Uuid>,
        request_id: Option<u64>,
        trade_index: Option<i64>,
        action: Action,
        payload: Option<Payload>,
    ) -> Self {
        Self {
            version: PROTOCOL_VER,
            request_id,
            trade_index,
            id,
            action,
            payload,
        }
    }
    /// Parse a [`MessageKind`] from its JSON representation.
    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }
    /// Serialize the [`MessageKind`] to a JSON string.
    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Return a clone of the [`Action`] carried by this message.
    pub fn get_action(&self) -> Action {
        self.action.clone()
    }

    /// Extract the `(next_trade_pubkey, next_trade_index)` pair from a
    /// [`Payload::NextTrade`] payload.
    ///
    /// Returns `Ok(None)` when there is no payload at all and
    /// [`ServiceError::InvalidPayload`] when the payload is present but of
    /// a different variant.
    pub fn get_next_trade_key(&self) -> Result<Option<(String, u32)>, ServiceError> {
        match &self.payload {
            Some(Payload::NextTrade(key, index)) => Ok(Some((key.to_string(), *index))),
            None => Ok(None),
            _ => Err(ServiceError::InvalidPayload),
        }
    }

    /// Extract the rating value from a [`Payload::RatingUser`] payload,
    /// validating it against
    /// [`MIN_RATING`]`..=`[`MAX_RATING`].
    ///
    /// Returns [`ServiceError::InvalidRating`] when the payload shape is
    /// wrong and [`ServiceError::InvalidRatingValue`] when the value is out
    /// of range.
    pub fn get_rating(&self) -> Result<u8, ServiceError> {
        if let Some(Payload::RatingUser(v)) = self.payload.to_owned() {
            if !(MIN_RATING..=MAX_RATING).contains(&v) {
                return Err(ServiceError::InvalidRatingValue);
            }
            Ok(v)
        } else {
            Err(ServiceError::InvalidRating)
        }
    }

    /// Check that the payload, id and trade index are consistent with the
    /// action carried by this message.
    ///
    /// Returns `true` when the combination is well-formed and `false`
    /// otherwise; Mostro uses this method to reject malformed requests
    /// before processing them.
    pub fn verify(&self) -> bool {
        match &self.action {
            Action::NewOrder => matches!(&self.payload, Some(Payload::Order(_))),
            Action::PayInvoice | Action::AddInvoice => {
                if self.id.is_none() {
                    return false;
                }
                matches!(&self.payload, Some(Payload::PaymentRequest(_, _, _)))
            }
            Action::TakeSell
            | Action::TakeBuy
            | Action::FiatSent
            | Action::FiatSentOk
            | Action::Release
            | Action::Released
            | Action::Dispute
            | Action::AdminCancel
            | Action::AdminCanceled
            | Action::AdminSettle
            | Action::AdminSettled
            | Action::Rate
            | Action::RateReceived
            | Action::AdminTakeDispute
            | Action::AdminTookDispute
            | Action::DisputeInitiatedByYou
            | Action::DisputeInitiatedByPeer
            | Action::WaitingBuyerInvoice
            | Action::PurchaseCompleted
            | Action::HoldInvoicePaymentAccepted
            | Action::HoldInvoicePaymentSettled
            | Action::HoldInvoicePaymentCanceled
            | Action::WaitingSellerToPay
            | Action::BuyerTookOrder
            | Action::BuyerInvoiceAccepted
            | Action::CooperativeCancelInitiatedByYou
            | Action::CooperativeCancelInitiatedByPeer
            | Action::CooperativeCancelAccepted
            | Action::Cancel
            | Action::InvoiceUpdated
            | Action::AdminAddSolver
            | Action::SendDm
            | Action::TradePubkey
            | Action::Canceled => {
                if self.id.is_none() {
                    return false;
                }
                true
            }
            Action::LastTradeIndex | Action::RestoreSession => self.payload.is_none(),
            Action::PaymentFailed => {
                if self.id.is_none() {
                    return false;
                }
                matches!(&self.payload, Some(Payload::PaymentFailed(_)))
            }
            Action::RateUser => {
                matches!(&self.payload, Some(Payload::RatingUser(_)))
            }
            Action::CantDo => {
                matches!(&self.payload, Some(Payload::CantDo(_)))
            }
            Action::Orders => {
                matches!(
                    &self.payload,
                    Some(Payload::Ids(_)) | Some(Payload::Orders(_))
                )
            }
        }
    }

    /// Return the [`SmallOrder`] carried by a [`Action::NewOrder`] message.
    ///
    /// Yields `None` if the action is not `NewOrder` or the payload is of a
    /// different variant.
    pub fn get_order(&self) -> Option<&SmallOrder> {
        if self.action != Action::NewOrder {
            return None;
        }
        match &self.payload {
            Some(Payload::Order(o)) => Some(o),
            _ => None,
        }
    }

    /// Return the Lightning payment request embedded in a message.
    ///
    /// Valid only for [`Action::TakeSell`], [`Action::AddInvoice`] and
    /// [`Action::NewOrder`]. For `NewOrder`, the invoice is read from the
    /// [`SmallOrder::buyer_invoice`] field. Returns `None` otherwise.
    pub fn get_payment_request(&self) -> Option<String> {
        if self.action != Action::TakeSell
            && self.action != Action::AddInvoice
            && self.action != Action::NewOrder
        {
            return None;
        }
        match &self.payload {
            Some(Payload::PaymentRequest(_, pr, _)) => Some(pr.to_owned()),
            Some(Payload::Order(ord)) => ord.buyer_invoice.to_owned(),
            _ => None,
        }
    }

    /// Return the amount override embedded in a [`Action::TakeSell`] or
    /// [`Action::TakeBuy`] message, either from a [`Payload::Amount`] or
    /// from the third element of a [`Payload::PaymentRequest`].
    pub fn get_amount(&self) -> Option<Amount> {
        if self.action != Action::TakeSell && self.action != Action::TakeBuy {
            return None;
        }
        match &self.payload {
            Some(Payload::PaymentRequest(_, _, amount)) => *amount,
            Some(Payload::Amount(amount)) => Some(*amount),
            _ => None,
        }
    }

    /// Borrow the optional payload.
    pub fn get_payload(&self) -> Option<&Payload> {
        self.payload.as_ref()
    }

    /// Return `(true, index)` when the message carries a trade index,
    /// `(false, 0)` otherwise.
    pub fn has_trade_index(&self) -> (bool, i64) {
        if let Some(index) = self.trade_index {
            return (true, index);
        }
        (false, 0)
    }

    /// Return the trade index carried by the message, or `0` when absent.
    pub fn trade_index(&self) -> i64 {
        if let Some(index) = self.trade_index {
            return index;
        }
        0
    }
}

#[cfg(test)]
mod test {
    use crate::message::{Action, Message, MessageKind, Payload, Peer};
    use crate::user::UserInfo;
    use nostr_sdk::Keys;
    use uuid::uuid;

    #[test]
    fn test_peer_with_reputation() {
        // Test creating a Peer with reputation information
        let reputation = UserInfo {
            rating: 4.5,
            reviews: 10,
            operating_days: 30,
        };
        let peer = Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            Some(reputation.clone()),
        );

        // Assert the fields are set correctly
        assert_eq!(
            peer.pubkey,
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8"
        );
        assert!(peer.reputation.is_some());
        let peer_reputation = peer.reputation.clone().unwrap();
        assert_eq!(peer_reputation.rating, 4.5);
        assert_eq!(peer_reputation.reviews, 10);
        assert_eq!(peer_reputation.operating_days, 30);

        // Test JSON serialization and deserialization
        let json = peer.as_json().unwrap();
        let deserialized_peer = Peer::from_json(&json).unwrap();
        assert_eq!(deserialized_peer.pubkey, peer.pubkey);
        assert!(deserialized_peer.reputation.is_some());
        let deserialized_reputation = deserialized_peer.reputation.unwrap();
        assert_eq!(deserialized_reputation.rating, 4.5);
        assert_eq!(deserialized_reputation.reviews, 10);
        assert_eq!(deserialized_reputation.operating_days, 30);
    }

    #[test]
    fn test_peer_without_reputation() {
        // Test creating a Peer without reputation information
        let peer = Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            None,
        );

        // Assert the reputation field is None
        assert_eq!(
            peer.pubkey,
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8"
        );
        assert!(peer.reputation.is_none());

        // Test JSON serialization and deserialization
        let json = peer.as_json().unwrap();
        let deserialized_peer = Peer::from_json(&json).unwrap();
        assert_eq!(deserialized_peer.pubkey, peer.pubkey);
        assert!(deserialized_peer.reputation.is_none());
    }

    #[test]
    fn test_peer_in_message() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");

        // Test with reputation
        let reputation = UserInfo {
            rating: 4.5,
            reviews: 10,
            operating_days: 30,
        };
        let peer_with_reputation = Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            Some(reputation),
        );
        let payload_with_reputation = Payload::Peer(peer_with_reputation);
        let message_with_reputation = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::FiatSentOk,
            Some(payload_with_reputation),
        ));

        // Verify message with reputation
        assert!(message_with_reputation.verify());
        let message_json = message_with_reputation.as_json().unwrap();
        let deserialized_message = Message::from_json(&message_json).unwrap();
        assert!(deserialized_message.verify());

        // Test without reputation
        let peer_without_reputation = Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            None,
        );
        let payload_without_reputation = Payload::Peer(peer_without_reputation);
        let message_without_reputation = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::FiatSentOk,
            Some(payload_without_reputation),
        ));

        // Verify message without reputation
        assert!(message_without_reputation.verify());
        let message_json = message_without_reputation.as_json().unwrap();
        let deserialized_message = Message::from_json(&message_json).unwrap();
        assert!(deserialized_message.verify());
    }

    #[test]
    fn test_payment_failed_payload() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");

        // Test PaymentFailedInfo serialization and deserialization
        let payment_failed_info = crate::message::PaymentFailedInfo {
            payment_attempts: 3,
            payment_retries_interval: 60,
        };

        let payload = Payload::PaymentFailed(payment_failed_info);
        let message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::PaymentFailed,
            Some(payload),
        ));

        // Verify message validation
        assert!(message.verify());

        // Test JSON serialization
        let message_json = message.as_json().unwrap();

        // Test deserialization
        let deserialized_message = Message::from_json(&message_json).unwrap();
        assert!(deserialized_message.verify());

        // Verify the payload contains correct values
        if let Message::Order(kind) = deserialized_message {
            if let Some(Payload::PaymentFailed(info)) = kind.payload {
                assert_eq!(info.payment_attempts, 3);
                assert_eq!(info.payment_retries_interval, 60);
            } else {
                panic!("Expected PaymentFailed payload");
            }
        } else {
            panic!("Expected Order message");
        }
    }

    #[test]
    fn test_message_payload_signature() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let peer = Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            None, // Add None for the reputation parameter
        );
        let payload = Payload::Peer(peer);
        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::FiatSentOk,
            Some(payload),
        ));
        assert!(test_message.verify());
        let test_message_json = test_message.as_json().unwrap();
        // Message should be signed with the trade keys
        let trade_keys =
            Keys::parse("110e43647eae221ab1da33ddc17fd6ff423f2b2f49d809b9ffa40794a2ab996c")
                .unwrap();
        let sig = Message::sign(test_message_json.clone(), &trade_keys);

        assert!(Message::verify_signature(
            test_message_json,
            trade_keys.public_key(),
            sig
        ));
    }

    #[test]
    fn test_restore_session_message() {
        // Test RestoreSession request (payload = None)
        let restore_request_message = Message::Restore(MessageKind::new(
            None,
            None,
            None,
            Action::RestoreSession,
            None,
        ));

        // Verify message validation
        assert!(restore_request_message.verify());
        assert_eq!(
            restore_request_message.inner_action(),
            Some(Action::RestoreSession)
        );

        // Test JSON serialization and deserialization for RestoreRequest
        let message_json = restore_request_message.as_json().unwrap();
        let deserialized_message = Message::from_json(&message_json).unwrap();
        assert!(deserialized_message.verify());
        assert_eq!(
            deserialized_message.inner_action(),
            Some(Action::RestoreSession)
        );

        // Test RestoreSession with RestoreData payload
        let restored_orders = vec![
            crate::message::RestoredOrdersInfo {
                order_id: uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23"),
                trade_index: 1,
                status: "active".to_string(),
            },
            crate::message::RestoredOrdersInfo {
                order_id: uuid!("408e1272-d5f4-47e6-bd97-3504baea9c24"),
                trade_index: 2,
                status: "success".to_string(),
            },
        ];

        let restored_disputes = vec![
            crate::message::RestoredDisputesInfo {
                dispute_id: uuid!("508e1272-d5f4-47e6-bd97-3504baea9c25"),
                order_id: uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23"),
                trade_index: 1,
                status: "initiated".to_string(),
                initiator: Some(crate::message::DisputeInitiator::Buyer),
                solver_pubkey: None,
            },
            crate::message::RestoredDisputesInfo {
                dispute_id: uuid!("608e1272-d5f4-47e6-bd97-3504baea9c26"),
                order_id: uuid!("408e1272-d5f4-47e6-bd97-3504baea9c24"),
                trade_index: 2,
                status: "in-progress".to_string(),
                initiator: None,
                solver_pubkey: Some(
                    "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344".to_string(),
                ),
            },
            crate::message::RestoredDisputesInfo {
                dispute_id: uuid!("708e1272-d5f4-47e6-bd97-3504baea9c27"),
                order_id: uuid!("508e1272-d5f4-47e6-bd97-3504baea9c25"),
                trade_index: 3,
                status: "initiated".to_string(),
                initiator: Some(crate::message::DisputeInitiator::Seller),
                solver_pubkey: None,
            },
        ];

        let restore_session_info = crate::message::RestoreSessionInfo {
            restore_orders: restored_orders.clone(),
            restore_disputes: restored_disputes.clone(),
        };

        let restore_data_payload = Payload::RestoreData(restore_session_info);
        let restore_data_message = Message::Restore(MessageKind::new(
            None,
            None,
            None,
            Action::RestoreSession,
            Some(restore_data_payload),
        ));

        // With new logic, any payload for RestoreSession is invalid (must be None)
        assert!(!restore_data_message.verify());

        // Verify serialization/deserialization of RestoreData payload with all initiator cases
        let message_json = restore_data_message.as_json().unwrap();
        let deserialized_restore_message = Message::from_json(&message_json).unwrap();

        if let Message::Restore(kind) = deserialized_restore_message {
            if let Some(Payload::RestoreData(session_info)) = kind.payload {
                assert_eq!(session_info.restore_disputes.len(), 3);
                assert_eq!(
                    session_info.restore_disputes[0].initiator,
                    Some(crate::message::DisputeInitiator::Buyer)
                );
                assert!(session_info.restore_disputes[0].solver_pubkey.is_none());
                assert_eq!(session_info.restore_disputes[1].initiator, None);
                assert_eq!(
                    session_info.restore_disputes[1].solver_pubkey,
                    Some(
                        "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
                            .to_string()
                    )
                );
                assert_eq!(
                    session_info.restore_disputes[2].initiator,
                    Some(crate::message::DisputeInitiator::Seller)
                );
                assert!(session_info.restore_disputes[2].solver_pubkey.is_none());
            } else {
                panic!("Expected RestoreData payload");
            }
        } else {
            panic!("Expected Restore message");
        }
    }

    #[test]
    fn test_restore_session_message_validation() {
        // Test that RestoreSession action accepts only payload=None or RestoreData
        let restore_request_message = Message::Restore(MessageKind::new(
            None,
            None,
            None,
            Action::RestoreSession,
            None, // Missing payload
        ));

        // Verify restore request message
        assert!(restore_request_message.verify());

        // Test with wrong payload type
        let wrong_payload = Payload::TextMessage("wrong payload".to_string());
        let wrong_message = Message::Restore(MessageKind::new(
            None,
            None,
            None,
            Action::RestoreSession,
            Some(wrong_payload),
        ));

        // Should fail validation because RestoreSession only accepts None
        assert!(!wrong_message.verify());

        // With new logic, presence of id/request_id/trade_index is allowed
        let with_id = Message::Restore(MessageKind::new(
            Some(uuid!("00000000-0000-0000-0000-000000000001")),
            None,
            None,
            Action::RestoreSession,
            None,
        ));
        assert!(with_id.verify());

        let with_request_id = Message::Restore(MessageKind::new(
            None,
            Some(42),
            None,
            Action::RestoreSession,
            None,
        ));
        assert!(with_request_id.verify());

        let with_trade_index = Message::Restore(MessageKind::new(
            None,
            None,
            Some(7),
            Action::RestoreSession,
            None,
        ));
        assert!(with_trade_index.verify());
    }

    #[test]
    fn test_restore_session_message_constructor() {
        // Test the new_restore constructor
        let restore_request_message = Message::new_restore(None);

        assert!(matches!(restore_request_message, Message::Restore(_)));
        assert!(restore_request_message.verify());
        assert_eq!(
            restore_request_message.inner_action(),
            Some(Action::RestoreSession)
        );

        // Test with RestoreData payload should be invalid now
        let restore_session_info = crate::message::RestoreSessionInfo {
            restore_orders: vec![],
            restore_disputes: vec![],
        };
        let restore_data_message =
            Message::new_restore(Some(Payload::RestoreData(restore_session_info)));

        assert!(matches!(restore_data_message, Message::Restore(_)));
        assert!(!restore_data_message.verify());
    }

    #[test]
    fn test_last_trade_index_valid_message() {
        let kind = MessageKind::new(None, None, Some(7), Action::LastTradeIndex, None);
        let msg = Message::Restore(kind);

        assert!(msg.verify());

        // roundtrip
        let json = msg.as_json().unwrap();
        let decoded = Message::from_json(&json).unwrap();
        assert!(decoded.verify());

        // ensure the trade index is propagated
        let inner = decoded.get_inner_message_kind();
        assert_eq!(inner.trade_index(), 7);
        assert_eq!(inner.has_trade_index(), (true, 7));
    }

    #[test]
    fn test_last_trade_index_without_id_is_valid() {
        // With new logic, id is not required; only payload must be None
        let kind = MessageKind::new(None, None, Some(5), Action::LastTradeIndex, None);
        let msg = Message::Restore(kind);
        assert!(msg.verify());
    }

    #[test]
    fn test_last_trade_index_with_payload_fails_validation() {
        // LastTradeIndex does not accept payload
        let kind = MessageKind::new(
            None,
            None,
            Some(3),
            Action::LastTradeIndex,
            Some(Payload::TextMessage("ignored".to_string())),
        );
        let msg = Message::Restore(kind);
        assert!(!msg.verify());
    }

    #[test]
    fn test_restored_dispute_helper_serialization_roundtrip() {
        use crate::message::RestoredDisputeHelper;

        let helper = RestoredDisputeHelper {
            dispute_id: uuid!("508e1272-d5f4-47e6-bd97-3504baea9c25"),
            order_id: uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23"),
            dispute_status: "initiated".to_string(),
            master_buyer_pubkey: Some("npub1buyerkey".to_string()),
            master_seller_pubkey: Some("npub1sellerkey".to_string()),
            trade_index_buyer: Some(1),
            trade_index_seller: Some(2),
            buyer_dispute: true,
            seller_dispute: false,
            solver_pubkey: None,
        };

        let json = serde_json::to_string(&helper).unwrap();
        let deserialized: RestoredDisputeHelper = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.dispute_id, helper.dispute_id);
        assert_eq!(deserialized.order_id, helper.order_id);
        assert_eq!(deserialized.dispute_status, helper.dispute_status);
        assert_eq!(deserialized.master_buyer_pubkey, helper.master_buyer_pubkey);
        assert_eq!(
            deserialized.master_seller_pubkey,
            helper.master_seller_pubkey
        );
        assert_eq!(deserialized.trade_index_buyer, helper.trade_index_buyer);
        assert_eq!(deserialized.trade_index_seller, helper.trade_index_seller);
        assert_eq!(deserialized.buyer_dispute, helper.buyer_dispute);
        assert_eq!(deserialized.seller_dispute, helper.seller_dispute);
        assert_eq!(deserialized.solver_pubkey, helper.solver_pubkey);

        let helper_seller_dispute = RestoredDisputeHelper {
            dispute_id: uuid!("608e1272-d5f4-47e6-bd97-3504baea9c26"),
            order_id: uuid!("408e1272-d5f4-47e6-bd97-3504baea9c24"),
            dispute_status: "in-progress".to_string(),
            master_buyer_pubkey: None,
            master_seller_pubkey: None,
            trade_index_buyer: None,
            trade_index_seller: None,
            buyer_dispute: false,
            seller_dispute: true,
            solver_pubkey: Some(
                "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344".to_string(),
            ),
        };

        let json_seller = serde_json::to_string(&helper_seller_dispute).unwrap();
        let deserialized_seller: RestoredDisputeHelper =
            serde_json::from_str(&json_seller).unwrap();

        assert_eq!(
            deserialized_seller.dispute_id,
            helper_seller_dispute.dispute_id
        );
        assert_eq!(deserialized_seller.order_id, helper_seller_dispute.order_id);
        assert_eq!(
            deserialized_seller.dispute_status,
            helper_seller_dispute.dispute_status
        );
        assert_eq!(deserialized_seller.master_buyer_pubkey, None);
        assert_eq!(deserialized_seller.master_seller_pubkey, None);
        assert_eq!(deserialized_seller.trade_index_buyer, None);
        assert_eq!(deserialized_seller.trade_index_seller, None);
        assert!(!deserialized_seller.buyer_dispute);
        assert!(deserialized_seller.seller_dispute);
        assert_eq!(
            deserialized_seller.solver_pubkey,
            helper_seller_dispute.solver_pubkey
        );
    }
}
