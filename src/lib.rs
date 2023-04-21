pub mod order;

use anyhow::{Ok, Result};
use clap::ValueEnum;
use order::{NewOrder, SmallOrder};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Orders can be only Buy or Sell
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Kind {
    Buy,
    Sell,
}

impl FromStr for Kind {
    type Err = ();

    fn from_str(kind: &str) -> std::result::Result<Self, Self::Err> {
        match kind {
            "Buy" => std::result::Result::Ok(Self::Buy),
            "Sell" => std::result::Result::Ok(Self::Sell),
            _ => Err(()),
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Each status that an order can have
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Status {
    Active,
    Canceled,
    CanceledByAdmin,
    CompletedByAdmin,
    Dispute,
    Expired,
    FiatSent,
    SettledHoldInvoice,
    Pending,
    Success,
    WaitingBuyerInvoice,
    WaitingPayment,
    CooperativelyCanceled,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for Status {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Active" => std::result::Result::Ok(Self::Active),
            "Canceled" => std::result::Result::Ok(Self::Canceled),
            "CanceledByAdmin" => std::result::Result::Ok(Self::CanceledByAdmin),
            "CompletedByAdmin" => std::result::Result::Ok(Self::CompletedByAdmin),
            "Dispute" => std::result::Result::Ok(Self::Dispute),
            "Expired" => std::result::Result::Ok(Self::Expired),
            "FiatSent" => std::result::Result::Ok(Self::FiatSent),
            "SettledHoldInvoice" => std::result::Result::Ok(Self::SettledHoldInvoice),
            "Pending" => std::result::Result::Ok(Self::Pending),
            "Success" => std::result::Result::Ok(Self::Success),
            "WaitingBuyerInvoice" => std::result::Result::Ok(Self::WaitingBuyerInvoice),
            "WaitingPayment" => std::result::Result::Ok(Self::WaitingPayment),
            "CooperativelyCanceled" => std::result::Result::Ok(Self::CooperativelyCanceled),
            _ => Err(()),
        }
    }
}

/// Action is used to identify each message between Mostro and users
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone, ValueEnum)]
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
    VoteUser,
    CantDo,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<Uuid>,
    pub action: Action,
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
}

#[allow(dead_code)]
impl Message {
    /// New message
    pub fn new(
        version: u8,
        order_id: Option<Uuid>,
        action: Action,
        content: Option<Content>,
    ) -> Self {
        Self {
            version,
            order_id,
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
            Action::PayInvoice => {
                if self.order_id.is_none() {
                    return false;
                }
                matches!(&self.content, Some(Content::PaymentRequest(_, _)))
            }
            Action::TakeSell
            | Action::TakeBuy
            | Action::FiatSent
            | Action::Release
            | Action::Cancel => {
                if self.order_id.is_none() {
                    return false;
                }
                true
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
            | Action::AddInvoice
            | Action::CooperativeCancelInitiatedByYou
            | Action::CooperativeCancelInitiatedByPeer
            | Action::CooperativeCancelAccepted
            | Action::VoteUser
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
/// We use this struct to create a user reputation
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Review{
    pub total_reviews: u64,
    pub total_rating: u64,
    pub last_rating: u64,
    pub max_rate: u64,
    pub min_rate: u64,
}

impl Review{
    pub fn new(
        total_reviews :u64,
        total_rating :u64,
        last_rating  :u64,
        min_rate: u64,
        max_rate: u64,
    ) ->Self {
        Self { 
            total_reviews,
            total_rating,
            last_rating,
            min_rate,
            max_rate,
        }
    }

     /// New order from json string
     pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Get order as json string
    pub fn as_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }
}