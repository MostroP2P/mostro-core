pub mod dispute;
pub mod order;
pub mod rating;
pub mod user;

use anyhow::{Ok, Result};
use order::{NewOrder, SmallOrder};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

pub const NOSTR_REPLACEABLE_EVENT_KIND: u64 = 30078;

/// Action is used to identify each message between Mostro and users
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub enum Action {
    Order,
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
    Received,
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
pub struct Message {
    pub version: u8,
    /// Most of the times messages are related to an order
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<Uuid>,
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
    Order(NewOrder),
    PaymentRequest(Option<NewOrder>, String),
    SmallOrder(SmallOrder),
    TextMessage(String),
    Peer(Peer),
    RatingUser(u8),
    Dispute(Uuid),
}

#[allow(dead_code)]
impl Message {
    /// New message
    pub fn new(
        version: u8,
        order_id: Option<Uuid>,
        pubkey: Option<String>,
        action: Action,
        content: Option<Content>,
    ) -> Self {
        Self {
            version,
            order_id,
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

    /// Verify if is valid message
    pub fn verify(&self) -> bool {
        match &self.action {
            Action::Order => matches!(&self.content, Some(Content::Order(_))),
            Action::PayInvoice | Action::AddInvoice => {
                if self.order_id.is_none() {
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
                if self.order_id.is_none() {
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
            | Action::Received
            | Action::CantDo => {
                matches!(&self.content, Some(Content::TextMessage(_)))
            }
        }
    }

    pub fn get_order(&self) -> Option<&NewOrder> {
        if self.action != Action::Order {
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
}

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
