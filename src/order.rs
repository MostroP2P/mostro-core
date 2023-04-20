use std::str::FromStr;

use crate::{Kind, Status};
use anyhow::{Ok, Result};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx_crud::SqlxCrud;
use uuid::Uuid;

/// Database representation of an order
#[derive(Debug, FromRow, SqlxCrud, Deserialize, Serialize, Clone)]
pub struct Order {
    pub id: Uuid,
    pub kind: String,
    pub event_id: String,
    pub hash: Option<String>,
    pub preimage: Option<String>,
    pub creator_pubkey: String,
    pub cancel_initiator_pubkey: Option<String>,
    pub buyer_pubkey: Option<String>,
    pub seller_pubkey: Option<String>,
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
}

impl Order {
    pub fn as_new_order(&self) -> NewOrder {
        NewOrder::new(
            Some(self.id),
            Kind::from_str(&self.kind).unwrap(),
            Status::from_str(&self.status).unwrap(),
            self.amount,
            self.fiat_code.clone(),
            self.fiat_amount,
            self.payment_method.clone(),
            self.premium,
            self.buyer_invoice.clone(),
            Some(self.created_at),
        )
    }
}

/// Small representation of an order
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SmallOrder {
    pub id: Uuid,
    pub amount: i64,
    pub fiat_code: String,
    pub fiat_amount: i64,
    pub payment_method: String,
    pub premium: i64,
    pub buyer_pubkey: Option<String>,
    pub seller_pubkey: Option<String>,
}

#[allow(dead_code)]
impl SmallOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        amount: i64,
        fiat_code: String,
        fiat_amount: i64,
        payment_method: String,
        premium: i64,
        buyer_pubkey: Option<String>,
        seller_pubkey: Option<String>,
    ) -> Self {
        Self {
            id,
            amount,
            fiat_code,
            fiat_amount,
            payment_method,
            premium,
            buyer_pubkey,
            seller_pubkey,
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

/// We use this struct to create a new order
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NewOrder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    pub kind: Kind,
    pub status: Status,
    pub amount: i64,
    pub fiat_code: String,
    pub fiat_amount: i64,
    pub payment_method: String,
    pub premium: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_invoice: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
}

#[allow(dead_code)]
impl NewOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Option<Uuid>,
        kind: Kind,
        status: Status,
        amount: i64,
        fiat_code: String,
        fiat_amount: i64,
        payment_method: String,
        premium: i64,
        buyer_invoice: Option<String>,
        created_at: Option<i64>,
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
            buyer_invoice,
            created_at,
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

