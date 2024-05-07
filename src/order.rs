use anyhow::{Ok, Result};
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;
#[cfg(feature = "sqlx")]
use sqlx_crud::SqlxCrud;
use std::str::FromStr;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

/// Orders can be only Buy or Sell
#[wasm_bindgen]
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Buy,
    Sell,
}

impl FromStr for Kind {
    type Err = ();

    fn from_str(kind: &str) -> std::result::Result<Self, Self::Err> {
        match kind.to_lowercase().as_str() {
            "buy" => std::result::Result::Ok(Self::Buy),
            "sell" => std::result::Result::Ok(Self::Sell),
            _ => Err(()),
        }
    }
}

impl ToString for Kind {
    fn to_string(&self) -> String {
        match self {
            Kind::Sell => String::from("sell"),
            Kind::Buy => String::from("buy"),
        }
    }
}

/// Each status that an order can have
#[wasm_bindgen]
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Active,
    Canceled,
    CanceledByAdmin,
    SettledByAdmin,
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

impl ToString for Status {
    fn to_string(&self) -> String {
        match self {
            Status::Active => String::from("active"),
            Status::Canceled => String::from("canceled"),
            Status::CanceledByAdmin => String::from("canceled-by-admin"),
            Status::SettledByAdmin => String::from("settled-by-admin"),
            Status::CompletedByAdmin => String::from("completed-by-admin"),
            Status::Dispute => String::from("dispute"),
            Status::Expired => String::from("expired"),
            Status::FiatSent => String::from("fiat-sent"),
            Status::SettledHoldInvoice => String::from("settled-hold-invoice"),
            Status::Pending => String::from("pending"),
            Status::Success => String::from("success"),
            Status::WaitingBuyerInvoice => String::from("waiting-buyer-invoice"),
            Status::WaitingPayment => String::from("waiting-payment"),
            Status::CooperativelyCanceled => String::from("cooperatively-canceled"),
        }
    }
}

impl FromStr for Status {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => std::result::Result::Ok(Self::Active),
            "canceled" => std::result::Result::Ok(Self::Canceled),
            "canceled-by-admin" => std::result::Result::Ok(Self::CanceledByAdmin),
            "settled-by-admin" => std::result::Result::Ok(Self::SettledByAdmin),
            "completed-by-admin" => std::result::Result::Ok(Self::CompletedByAdmin),
            "dispute" => std::result::Result::Ok(Self::Dispute),
            "expired" => std::result::Result::Ok(Self::Expired),
            "fiat-sent" => std::result::Result::Ok(Self::FiatSent),
            "settled-hold-invoice" => std::result::Result::Ok(Self::SettledHoldInvoice),
            "pending" => std::result::Result::Ok(Self::Pending),
            "success" => std::result::Result::Ok(Self::Success),
            "waiting-buyer-invoice" => std::result::Result::Ok(Self::WaitingBuyerInvoice),
            "waiting-payment" => std::result::Result::Ok(Self::WaitingPayment),
            "cooperatively-canceled" => std::result::Result::Ok(Self::CooperativelyCanceled),
            _ => Err(()),
        }
    }
}

/// Database representation of an order
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud), external_id)]
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Order {
    pub id: Uuid,
    pub kind: String,
    pub event_id: String,
    pub hash: Option<String>,
    pub preimage: Option<String>,
    pub creator_pubkey: String,
    pub cancel_initiator_pubkey: Option<String>,
    pub buyer_pubkey: Option<String>,
    pub master_buyer_pubkey: Option<String>,
    pub seller_pubkey: Option<String>,
    pub master_seller_pubkey: Option<String>,
    pub status: String,
    pub price_from_api: bool,
    pub premium: i64,
    pub payment_method: String,
    pub amount: i64,
    pub min_amount: i64,
    pub max_amount: i64,
    pub buyer_dispute: bool,
    pub seller_dispute: bool,
    pub buyer_cooperativecancel: bool,
    pub seller_cooperativecancel: bool,
    pub fee: i64,
    pub routing_fee: i64,
    pub fiat_code: String,
    pub fiat_amount: i64,
    pub buyer_invoice: Option<String>,
    pub range_parent_id: Option<Uuid>,
    pub invoice_held_at: i64,
    pub taken_at: i64,
    pub created_at: i64,
    pub buyer_sent_rate: bool,
    pub seller_sent_rate: bool,
    pub failed_payment: bool,
    pub payment_attempts: i64,
    pub expires_at: i64,
}

impl Order {
    pub fn as_new_order(&self) -> SmallOrder {
        SmallOrder::new(
            Some(self.id),
            Some(Kind::from_str(&self.kind).unwrap()),
            Some(Status::from_str(&self.status).unwrap()),
            self.amount,
            self.fiat_code.clone(),
            self.fiat_amount,
            self.payment_method.clone(),
            self.premium,
            None,
            None,
            self.buyer_invoice.clone(),
            Some(self.created_at),
            Some(self.expires_at),
        )
    }
}

/// We use this struct to create a new order
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SmallOrder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    pub kind: Option<Kind>,
    pub status: Option<Status>,
    pub amount: i64,
    pub fiat_code: String,
    pub fiat_amount: i64,
    pub payment_method: String,
    pub premium: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_buyer_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_seller_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_invoice: Option<String>,
    pub created_at: Option<i64>,
    pub expires_at: Option<i64>,
}

#[allow(dead_code)]
impl SmallOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Option<Uuid>,
        kind: Option<Kind>,
        status: Option<Status>,
        amount: i64,
        fiat_code: String,
        fiat_amount: i64,
        payment_method: String,
        premium: i64,
        master_buyer_pubkey: Option<String>,
        master_seller_pubkey: Option<String>,
        buyer_invoice: Option<String>,
        created_at: Option<i64>,
        expires_at: Option<i64>,
    ) -> Self {
        Self {
            id,
            kind,
            status,
            amount,
            fiat_code,
            fiat_amount,
            payment_method,
            premium,
            master_buyer_pubkey,
            master_seller_pubkey,
            buyer_invoice,
            created_at,
            expires_at,
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
