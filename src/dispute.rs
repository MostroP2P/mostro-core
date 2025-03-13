use crate::order::Order;
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{FromRow, Type};
#[cfg(feature = "sqlx")]
use sqlx_crud::SqlxCrud;
use std::{fmt::Display, str::FromStr};
use uuid::Uuid;

const TOKEN_MIN: u16 = 100;
const TOKEN_MAX: u16 = 999;

/// Each status that a dispute can have
#[cfg_attr(feature = "sqlx", derive(Type))]
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Dispute initiated and waiting to be taken by a solver
    #[default]
    Initiated,
    /// Taken by a solver
    InProgress,
    /// Canceled by admin/solver and refunded to seller
    SellerRefunded,
    /// Settled seller's invoice by admin/solver and started to pay sats to buyer
    Settled,
    /// Released by the seller
    Released,
}

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Initiated => write!(f, "initiated"),
            Status::InProgress => write!(f, "in-progress"),
            Status::SellerRefunded => write!(f, "seller-refunded"),
            Status::Settled => write!(f, "settled"),
            Status::Released => write!(f, "released"),
        }
    }
}

impl FromStr for Status {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "initiated" => std::result::Result::Ok(Self::Initiated),
            "in-progress" => std::result::Result::Ok(Self::InProgress),
            "seller-refunded" => std::result::Result::Ok(Self::SellerRefunded),
            "settled" => std::result::Result::Ok(Self::Settled),
            "released" => std::result::Result::Ok(Self::Released),
            _ => Err(()),
        }
    }
}

/// Database representation of a dispute
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud), external_id)]
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Dispute {
    pub id: Uuid,
    pub order_id: Uuid,
    pub status: String,
    pub solver_pubkey: Option<String>,
    pub created_at: i64,
    pub taken_at: i64,
    pub buyer_token: Option<u16>,
    pub seller_token: Option<u16>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SolverDisputeInfo {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    pub hash: Option<String>,
    pub preimage: Option<String>,
    pub buyer_pubkey: Option<String>,
    pub buyer_token: Option<u16>,
    pub seller_pubkey: Option<String>,
    pub seller_token: Option<u16>,
    pub counterpart_rating: f64,
    pub initiator_rating: f64,
    pub initiator_operating_days: u64,
    pub counterpart_operating_days: u64,
    pub premium: i64,
    pub payment_method: String,
    pub amount: i64,
    pub fiat_amount: i64,
    pub fee: i64,
    pub routing_fee: i64,
    pub buyer_invoice: Option<String>,
    pub invoice_held_at: i64,
    pub taken_at: i64,
    pub created_at: i64,
}

impl SolverDisputeInfo {
    pub fn new(
        order: &Order,
        dispute: &Dispute,
        counterpart_rating: f64,
        initiator_rating: f64,
        initiator_operating_days: u64,
        counterpart_operating_days: u64,
    ) -> Self {
        Self {
            id: order.id,
            kind: order.kind.clone(),
            status: order.status.clone(),
            hash: order.hash.clone(),
            preimage: order.preimage.clone(),
            buyer_pubkey: order.buyer_pubkey.clone(),
            buyer_token: dispute.buyer_token,
            seller_pubkey: order.seller_pubkey.clone(),
            seller_token: dispute.seller_token,
            counterpart_rating,
            initiator_rating,
            initiator_operating_days,
            counterpart_operating_days,
            premium: order.premium,
            payment_method: order.payment_method.clone(),
            amount: order.amount,
            fiat_amount: order.fiat_amount,
            fee: order.fee,
            routing_fee: order.routing_fee,
            buyer_invoice: order.buyer_invoice.clone(),
            invoice_held_at: order.invoice_held_at,
            taken_at: order.taken_at,
            created_at: order.created_at,
        }
    }
}

impl Dispute {
    pub fn new(order_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            order_id,
            status: Status::Initiated.to_string(),
            solver_pubkey: None,
            created_at: Utc::now().timestamp(),
            taken_at: 0,
            buyer_token: None,
            seller_token: None,
        }
    }

    /// Create new dispute record and generate security tokens
    /// Returns a tuple of the initiator's token and the counterpart's token
    pub fn create_tokens(&mut self, is_buyer_dispute: bool) -> (Option<u16>, Option<u16>) {
        let mut rng = rand::thread_rng();
        let mut buyer_token;
        let mut seller_token;

        // Ensure tokens are unique
        loop {
            buyer_token = rng.gen_range(TOKEN_MIN..=TOKEN_MAX);
            seller_token = rng.gen_range(TOKEN_MIN..=TOKEN_MAX);
            if buyer_token != seller_token {
                break;
            }
        }

        self.buyer_token = Some(buyer_token);
        self.seller_token = Some(seller_token);

        let (initiator_token, counterpart_token) = match is_buyer_dispute {
            true => (self.buyer_token, self.seller_token),
            false => (self.seller_token, self.buyer_token),
        };

        (initiator_token, counterpart_token)
    }
}
