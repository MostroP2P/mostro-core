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
}

impl Peer {
    pub fn new(pubkey: String) -> Self {
        Self { pubkey }
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
    Dispute(Uuid, Option<u16>),
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

    pub fn get_rating(&self) -> Result<u8, ServiceError> {
        if let Some(Payload::RatingUser(v)) = self.payload.to_owned() {
            if !(MIN_RATING..=MAX_RATING).contains(&v) {
                return Err(ServiceError::InvalidRatingValue);
            }
            return Ok(v);
        } else {
            return Err(ServiceError::InvalidRating);
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

    pub fn sign(&self, keys: &Keys) -> Signature {
        let message = self.as_json().unwrap();
        let hash: Sha256Hash = Sha256Hash::hash(message.as_bytes());
        let hash = hash.to_byte_array();
        let message: BitcoinMessage = BitcoinMessage::from_digest(hash);

        keys.sign_schnorr(&message)
    }

    pub fn verify_signature(&self, pubkey: PublicKey, sig: Signature) -> bool {
        // Create message hash
        let message = self.as_json().unwrap();
        let hash: Sha256Hash = Sha256Hash::hash(message.as_bytes());
        let hash = hash.to_byte_array();
        let message: BitcoinMessage = BitcoinMessage::from_digest(hash);
        // Create a verification-only context for better performance
        let secp = Secp256k1::verification_only();
        // Verify signature
        pubkey.verify(&secp, &message, &sig).is_ok()
    }
}
