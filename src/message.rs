use crate::order::SmallOrder;
use crate::PROTOCOL_VER;
use anyhow::{Ok, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

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
pub enum Action {
    NewOrder,
    TakeSell,
    TakeBuy,
    PayInvoice,
    FiatSent,
    Release,
    Cancel,
    CooperativeCancelInitiatedByYou,
    CooperativeCancelInitiatedByPeer,
    DisputeInitiatedByYou,
    DisputeInitiatedByPeer,
    CooperativeCancelAccepted,
    BuyerInvoiceAccepted,
    SaleCompleted,
    PurchaseCompleted,
    HoldInvoicePaymentAccepted,
    HoldInvoicePaymentSettled,
    HoldInvoicePaymentCanceled,
    WaitingSellerToPay,
    WaitingBuyerInvoice,
    AddInvoice,
    BuyerTookOrder,
    RateUser,
    CantDo,
    RateReceived,
    Dispute,
    AdminCancel,
    AdminSettle,
    AdminAddSolver,
    AdminTakeDispute,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Use this Message to establish communication between users and Mostro
#[derive(Debug, Deserialize, Serialize)]
pub enum Message {
    Order(MessageKind),
    Dispute(MessageKind),
    CantDo(MessageKind),
    Rate(MessageKind),
}

impl Message {
    /// New order message
    pub fn new_order(
        id: Option<Uuid>,
        pubkey: Option<String>,
        action: Action,
        content: Option<Content>,
    ) -> Self {
        let kind = MessageKind::new(id, pubkey, action, content);

        Self::Order(kind)
    }

    /// New dispute message
    pub fn new_dispute(
        id: Option<Uuid>,
        pubkey: Option<String>,
        action: Action,
        content: Option<Content>,
    ) -> Self {
        let kind = MessageKind::new(id, pubkey, action, content);

        Self::Dispute(kind)
    }

    /// New can't do template message message
    pub fn cant_do(id: Option<Uuid>, pubkey: Option<String>, content: Option<Content>) -> Self {
        let kind = MessageKind::new(id, pubkey, Action::CantDo, content);

        Self::CantDo(kind)
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
            Message::Dispute(k) => k,
            Message::Order(k) => k,
            Message::CantDo(k) => k,
            Message::Rate(k) => k,
        }
    }

    // Get action from the inner message
    pub fn inner_action(&self) -> Option<Action> {
        match self {
            Message::Dispute(a) => Some(a.get_action()),
            Message::Order(a) => Some(a.get_action()),
            Message::CantDo(a) => Some(a.get_action()),
            Message::Rate(a) => Some(a.get_action()),
        }
    }

    /// Verify if is valid the inner message
    pub fn verify(&self) -> bool {
        match self {
            Message::Order(m) => m.verify(),
            Message::Dispute(m) => m.verify(),
            Message::CantDo(m) => m.verify(),
            Message::Rate(m) => m.verify(),
        }
    }
}

/// Use this Message to establish communication between users and Mostro
#[derive(Debug, Deserialize, Serialize)]
pub struct MessageKind {
    /// Message version
    pub version: u8,
    /// Message id is not mandatory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Real pubkey of the user hidden in the encrypted message,
    /// used with ephemeral identities
    pub pubkey: Option<String>,
    /// Action to be taken
    pub action: Action,
    /// Message content
    pub content: Option<Content>,
}

/// Message content
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum Content {
    Order(SmallOrder),
    PaymentRequest(Option<SmallOrder>, String),
    TextMessage(String),
    Peer(Peer),
    RatingUser(u8),
    Dispute(Uuid),
}

#[allow(dead_code)]
impl MessageKind {
    /// New message
    pub fn new(
        id: Option<Uuid>,
        pubkey: Option<String>,
        action: Action,
        content: Option<Content>,
    ) -> Self {
        Self {
            version: PROTOCOL_VER,
            id,
            pubkey,
            action,
            content,
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

    /// Verify if is valid message
    pub fn verify(&self) -> bool {
        match &self.action {
            Action::NewOrder => matches!(&self.content, Some(Content::Order(_))),
            Action::PayInvoice | Action::AddInvoice => {
                if self.id.is_none() {
                    return false;
                }
                matches!(&self.content, Some(Content::PaymentRequest(_, _)))
            }
            Action::TakeSell
            | Action::TakeBuy
            | Action::FiatSent
            | Action::Release
            | Action::Dispute
            | Action::AdminCancel
            | Action::AdminSettle
            | Action::Cancel => {
                if self.id.is_none() {
                    return false;
                }
                true
            }
            Action::AdminAddSolver => {
                if self.pubkey.is_none() {
                    return false;
                }
                true
            }
            Action::AdminTakeDispute => {
                matches!(&self.content, Some(Content::Dispute(_)))
            }
            Action::RateUser => {
                matches!(&self.content, Some(Content::RatingUser(_)))
            }
            Action::BuyerInvoiceAccepted
            | Action::SaleCompleted
            | Action::PurchaseCompleted
            | Action::HoldInvoicePaymentAccepted
            | Action::HoldInvoicePaymentSettled
            | Action::HoldInvoicePaymentCanceled
            | Action::WaitingSellerToPay
            | Action::BuyerTookOrder
            | Action::WaitingBuyerInvoice
            | Action::CooperativeCancelInitiatedByYou
            | Action::CooperativeCancelInitiatedByPeer
            | Action::DisputeInitiatedByYou
            | Action::DisputeInitiatedByPeer
            | Action::CooperativeCancelAccepted
            | Action::RateReceived
            | Action::CantDo => {
                matches!(&self.content, Some(Content::TextMessage(_)))
            }
        }
    }

    pub fn get_order(&self) -> Option<&SmallOrder> {
        if self.action != Action::NewOrder {
            return None;
        }
        match &self.content {
            Some(Content::Order(o)) => Some(o),
            _ => None,
        }
    }

    pub fn get_payment_request(&self) -> Option<String> {
        if self.action != Action::TakeSell && self.action != Action::AddInvoice {
            return None;
        }
        match &self.content {
            Some(Content::PaymentRequest(_, pr)) => Some(pr.to_owned()),
            _ => None,
        }
    }

    pub fn get_content(&self) -> Option<&Content> {
        self.content.as_ref()
    }
}
