use crate::dispute::SolverDisputeInfo;
use crate::dispute::UserDisputeInfo;
use crate::error::ServiceError;
use crate::PROTOCOL_VER;
use crate::{error::CantDoReason, order::SmallOrder};
use anyhow::Result;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Message as BitcoinMessage;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// Max rating
pub const MAX_RATING: u8 = 5;
// Min rating
pub const MIN_RATING: u8 = 1;

/// One party of the trade
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Peer {
    pub pubkey: String,
    pub reputation: Option<UserDisputeInfo>,
}

impl Peer {
    pub fn new(pubkey: String, reputation: Option<UserDisputeInfo>) -> Self {
        Self { pubkey, reputation }
    }

    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn as_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
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
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Get message as json string
    pub fn as_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    // Get inner message kind
    pub fn get_inner_message_kind(&self) -> &MessageKind {
        match self {
            Message::Dispute(k)
            | Message::Order(k)
            | Message::CantDo(k)
            | Message::Rate(k)
            | Message::Dm(k) => k,
        }
    }

    // Get action from the inner message
    pub fn inner_action(&self) -> Option<Action> {
        match self {
            Message::Dispute(a)
            | Message::Order(a)
            | Message::CantDo(a)
            | Message::Rate(a)
            | Message::Dm(a) => Some(a.get_action()),
        }
    }

    /// Verify if is valid the inner message
    pub fn verify(&self) -> bool {
        match self {
            Message::Order(m)
            | Message::Dispute(m)
            | Message::CantDo(m)
            | Message::Rate(m)
            | Message::Dm(m) => m.verify(),
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
    Dispute(Uuid, Option<u16>, Option<SolverDisputeInfo>),
    /// Here the reason why we can't do the action
    CantDo(Option<CantDoReason>),
    /// This is used by the maker of a range order only on
    /// messages with action release and fiat-sent
    /// to inform the next trade pubkey and trade index
    NextTrade(String, u32),
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
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
    /// Get message as json string
    pub fn as_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
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
            | Action::PaymentFailed
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
            Action::RateUser => {
                matches!(&self.payload, Some(Payload::RatingUser(_)))
            }
            Action::CantDo => {
                matches!(&self.payload, Some(Payload::CantDo(_)))
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
    use crate::dispute::UserDisputeInfo;
    use crate::message::{Action, Message, MessageKind, Payload, Peer};
    use nostr_sdk::Keys;
    use uuid::uuid;

    #[test]
    fn test_peer_with_reputation() {
        // Test creating a Peer with reputation information
        let reputation = UserDisputeInfo {
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
        let reputation = UserDisputeInfo {
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
}
