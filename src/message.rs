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

/// One party of the trade
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Peer {
    pub pubkey: String,
    pub reputation: Option<UserInfo>,
}

impl Peer {
    pub fn new(pubkey: String, reputation: Option<UserInfo>) -> Self {
        Self { pubkey, reputation }
    }

    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }

    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }
}

/// Action is used to identify each message between Mostro and users
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    NewOrder,
    TakeSell,
    TakeBuy,
    PayInvoice,
    FiatSent,
    FiatSentOk,
    Release,
    Released,
    Cancel,
    Canceled,
    CooperativeCancelInitiatedByYou,
    CooperativeCancelInitiatedByPeer,
    DisputeInitiatedByYou,
    DisputeInitiatedByPeer,
    CooperativeCancelAccepted,
    BuyerInvoiceAccepted,
    PurchaseCompleted,
    HoldInvoicePaymentAccepted,
    HoldInvoicePaymentSettled,
    HoldInvoicePaymentCanceled,
    WaitingSellerToPay,
    WaitingBuyerInvoice,
    AddInvoice,
    BuyerTookOrder,
    Rate,
    RateUser,
    RateReceived,
    CantDo,
    Dispute,
    AdminCancel,
    AdminCanceled,
    AdminSettle,
    AdminSettled,
    AdminAddSolver,
    AdminTakeDispute,
    AdminTookDispute,
    PaymentFailed,
    InvoiceUpdated,
    SendDm,
    TradePubkey,
    RestoreSession,
    LastTradeIndex,
    Orders,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Use this Message to establish communication between users and Mostro
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Message {
    Order(MessageKind),
    Dispute(MessageKind),
    CantDo(MessageKind),
    Rate(MessageKind),
    Dm(MessageKind),
    Restore(MessageKind),
}

impl Message {
    /// New order message
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

    /// New dispute message
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

    pub fn new_restore(payload: Option<Payload>) -> Self {
        let kind = MessageKind::new(None, None, None, Action::RestoreSession, payload);
        Self::Restore(kind)
    }

    /// New can't do template message message
    pub fn cant_do(id: Option<Uuid>, request_id: Option<u64>, payload: Option<Payload>) -> Self {
        let kind = MessageKind::new(id, request_id, None, Action::CantDo, payload);

        Self::CantDo(kind)
    }

    /// New DM message
    pub fn new_dm(
        id: Option<Uuid>,
        request_id: Option<u64>,
        action: Action,
        payload: Option<Payload>,
    ) -> Self {
        let kind = MessageKind::new(id, request_id, None, action, payload);

        Self::Dm(kind)
    }

    /// Get message from json string
    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Get message as json string
    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }

    // Get inner message kind
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

    // Get action from the inner message
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

    /// Verify if is valid the inner message
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

    pub fn sign(message: String, keys: &Keys) -> Signature {
        let hash: Sha256Hash = Sha256Hash::hash(message.as_bytes());
        let hash = hash.to_byte_array();
        let message: BitcoinMessage = BitcoinMessage::from_digest(hash);

        keys.sign_schnorr(&message)
    }

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

/// Use this Message to establish communication between users and Mostro
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessageKind {
    /// Message version
    pub version: u8,
    /// Request_id for test on client
    pub request_id: Option<u64>,
    /// Trade key index
    pub trade_index: Option<i64>,
    /// Message id is not mandatory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Action to be taken
    pub action: Action,
    /// Payload of the Message
    pub payload: Option<Payload>,
}

type Amount = i64;

/// Payment failure retry information
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PaymentFailedInfo {
    /// Maximum number of payment attempts
    pub payment_attempts: u32,
    /// Retry interval in seconds between payment attempts
    pub payment_retries_interval: u32,
}

/// Helper struct for faster order-restore queries (used by mostrod).
/// Intended as a lightweight row-mapper when fetching restore metadata.
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud))]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestoredOrderHelper {
    pub id: Uuid,
    pub status: String,
    pub master_buyer_pubkey: Option<String>,
    pub master_seller_pubkey: Option<String>,
    pub trade_index_buyer: Option<i64>,
    pub trade_index_seller: Option<i64>,
}

/// Information about the dispute to be restored in the new client.
/// Helper struct to decrypt the dispute information in case of encrypted database.
/// Note: field names are chosen to match expected SQL SELECT aliases in mostrod (e.g. `status` aliased as `dispute_status`).
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud))]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestoredDisputeHelper {
    pub dispute_id: Uuid,
    pub order_id: Uuid,
    pub dispute_status: String,
    pub master_buyer_pubkey: Option<String>,
    pub master_seller_pubkey: Option<String>,
    pub trade_index_buyer: Option<i64>,
    pub trade_index_seller: Option<i64>,
}

/// Information about the order to be restored in the new client
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud))]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestoredOrdersInfo {
    /// Id of the order
    pub order_id: Uuid,
    /// Trade index of the order
    pub trade_index: i64,
    /// Status of the order
    pub status: String,
}

/// Information about the dispute to be restored in the new client
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud))]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestoredDisputesInfo {
    /// Id of the dispute
    pub dispute_id: Uuid,
    /// Order id of the dispute
    pub order_id: Uuid,
    /// Trade index of the dispute
    pub trade_index: i64,
    /// Status of the dispute
    pub status: String,
}

/// Restore session user info
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RestoreSessionInfo {
    /// Vector of orders of the user requesting the restore of data
    #[serde(rename = "orders")]
    pub restore_orders: Vec<RestoredOrdersInfo>,
    /// Vector of disputes of the user requesting the restore of data
    #[serde(rename = "disputes")]
    pub restore_disputes: Vec<RestoredDisputesInfo>,
}

/// Message payload
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    /// Order
    Order(SmallOrder),
    /// Payment request
    PaymentRequest(Option<SmallOrder>, String, Option<Amount>),
    /// Use to send a message to another user
    TextMessage(String),
    /// Peer information
    Peer(Peer),
    /// Used to rate a user
    RatingUser(u8),
    /// In some cases we need to send an amount
    Amount(Amount),
    /// Dispute
    Dispute(Uuid, Option<SolverDisputeInfo>),
    /// Here the reason why we can't do the action
    CantDo(Option<CantDoReason>),
    /// This is used by the maker of a range order only on
    /// messages with action release and fiat-sent
    /// to inform the next trade pubkey and trade index
    NextTrade(String, u32),
    /// Payment failure retry configuration information
    PaymentFailed(PaymentFailedInfo),
    /// Restore session data with orders and disputes
    RestoreData(RestoreSessionInfo),
    /// IDs array
    Ids(Vec<Uuid>),
    /// Orders array
    Orders(Vec<SmallOrder>),
}

#[allow(dead_code)]
impl MessageKind {
    /// New message
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
    /// Get message from json string
    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }
    /// Get message as json string
    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }

    // Get action from the inner message
    pub fn get_action(&self) -> Action {
        self.action.clone()
    }

    /// Get the next trade keys when order is settled
    pub fn get_next_trade_key(&self) -> Result<Option<(String, u32)>, ServiceError> {
        match &self.payload {
            Some(Payload::NextTrade(key, index)) => Ok(Some((key.to_string(), *index))),
            None => Ok(None),
            _ => Err(ServiceError::InvalidPayload),
        }
    }

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

    /// Verify if is valid message
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
            Action::RestoreSession => {
                if self.id.is_some() || self.request_id.is_some() || self.trade_index.is_some() {
                    return false;
                }
                matches!(&self.payload, None | Some(Payload::RestoreData(_)))
            }
            Action::LastTradeIndex => {
                if self.id.is_none() || self.request_id.is_some() {
                    return false;
                }
                self.payload.is_none()
            }
            Action::Orders => {
                matches!(
                    &self.payload,
                    Some(Payload::Ids(_)) | Some(Payload::Orders(_))
                )
            }
        }
    }

    pub fn get_order(&self) -> Option<&SmallOrder> {
        if self.action != Action::NewOrder {
            return None;
        }
        match &self.payload {
            Some(Payload::Order(o)) => Some(o),
            _ => None,
        }
    }

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

    pub fn get_payload(&self) -> Option<&Payload> {
        self.payload.as_ref()
    }

    pub fn has_trade_index(&self) -> (bool, i64) {
        if let Some(index) = self.trade_index {
            return (true, index);
        }
        (false, 0)
    }

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

        let restored_disputes = vec![crate::message::RestoredDisputesInfo {
            dispute_id: uuid!("508e1272-d5f4-47e6-bd97-3504baea9c25"),
            order_id: uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23"),
            trade_index: 1,
            status: "initiated".to_string(),
        }];

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

        // Verify message validation
        assert!(restore_data_message.verify());
        assert_eq!(
            restore_data_message.inner_action(),
            Some(Action::RestoreSession)
        );

        // Test JSON serialization and deserialization for RestoreData
        let message_json = restore_data_message.as_json().unwrap();
        let deserialized_message = Message::from_json(&message_json).unwrap();
        assert!(deserialized_message.verify());
        assert_eq!(
            deserialized_message.inner_action(),
            Some(Action::RestoreSession)
        );

        // Verify the payload contains correct data
        if let Message::Restore(kind) = deserialized_message {
            if let Some(Payload::RestoreData(info)) = kind.payload {
                assert_eq!(info.restore_orders.len(), 2);
                assert_eq!(info.restore_disputes.len(), 1);

                // Check first order
                assert_eq!(
                    info.restore_orders[0].order_id,
                    uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")
                );
                assert_eq!(info.restore_orders[0].trade_index, 1);
                assert_eq!(info.restore_orders[0].status, "active");

                // Check second order
                assert_eq!(
                    info.restore_orders[1].order_id,
                    uuid!("408e1272-d5f4-47e6-bd97-3504baea9c24")
                );
                assert_eq!(info.restore_orders[1].trade_index, 2);
                assert_eq!(info.restore_orders[1].status, "success");

                // Check dispute
                assert_eq!(
                    info.restore_disputes[0].dispute_id,
                    uuid!("508e1272-d5f4-47e6-bd97-3504baea9c25")
                );
                assert_eq!(
                    info.restore_disputes[0].order_id,
                    uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")
                );
                assert_eq!(info.restore_disputes[0].trade_index, 1);
                assert_eq!(info.restore_disputes[0].status, "initiated");
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

        // Should fail validation because RestoreSession only accepts None or RestoreData
        assert!(!wrong_message.verify());

        // Id presence should make it invalid
        let with_id = Message::Restore(MessageKind::new(
            Some(uuid!("00000000-0000-0000-0000-000000000001")),
            None,
            None,
            Action::RestoreSession,
            None,
        ));
        assert!(!with_id.verify());

        // request_id presence should make it invalid
        let with_request_id = Message::Restore(MessageKind::new(
            None,
            Some(42),
            None,
            Action::RestoreSession,
            None,
        ));
        assert!(!with_request_id.verify());

        // trade_index presence should make it invalid
        let with_trade_index = Message::Restore(MessageKind::new(
            None,
            None,
            Some(7),
            Action::RestoreSession,
            None,
        ));
        assert!(!with_trade_index.verify());
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

        // Test with RestoreData payload
        let restore_session_info = crate::message::RestoreSessionInfo {
            restore_orders: vec![],
            restore_disputes: vec![],
        };
        let restore_data_message =
            Message::new_restore(Some(Payload::RestoreData(restore_session_info)));

        assert!(matches!(restore_data_message, Message::Restore(_)));
        assert!(restore_data_message.verify());
        assert_eq!(
            restore_data_message.inner_action(),
            Some(Action::RestoreSession)
        );
    }

    #[test]
    fn test_last_trade_index_valid_message() {
        let uuid = uuid!("11111111-2222-3333-4444-555555555555");
        let kind = MessageKind::new(Some(uuid), None, Some(7), Action::LastTradeIndex, None);
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
    fn test_last_trade_index_requires_id() {
        // Missing id must fail validation for LastTradeIndex
        let kind = MessageKind::new(None, Some(1), Some(5), Action::LastTradeIndex, None);
        let msg = Message::Restore(kind);
        assert!(!msg.verify());
    }

    #[test]
    fn test_last_trade_index_with_payload_is_still_valid() {
        // For this action, payload is not accepted
        let uuid = uuid!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        let kind = MessageKind::new(
            Some(uuid),
            None,
            Some(3),
            Action::LastTradeIndex,
            Some(Payload::TextMessage("ignored".to_string())),
        );
        let msg = Message::Restore(kind);
        assert!(!msg.verify());
    }
}
