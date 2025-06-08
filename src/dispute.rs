use crate::{order::Order, user::User, user::UserInfo};
use chrono::Utc;
use nostr_sdk::Timestamp;
use rand::Rng;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{FromRow, Type};
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
#[cfg_attr(feature = "sqlx", derive(FromRow))]
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Dispute {
    pub id: String,
    pub order_id: String,
    pub status: String,
    pub order_previous_status: String,
    pub solver_pubkey: Option<String>,
    pub created_at: i64,
    pub taken_at: Option<i64>,
    pub buyer_token: i64,
    pub seller_token: i64,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SolverDisputeInfo {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub hash: Option<String>,
    pub preimage: Option<String>,
    pub order_previous_status: String,
    pub initiator_pubkey: String,
    pub buyer_pubkey: Option<String>,
    pub buyer_token: i64,
    pub seller_pubkey: Option<String>,
    pub seller_token: i64,
    pub initiator_full_privacy: bool,
    pub counterpart_full_privacy: bool,
    pub initiator_info: Option<UserInfo>,
    pub counterpart_info: Option<UserInfo>,
    pub premium: i64,
    pub payment_method: String,
    pub amount: i64,
    pub fiat_amount: i64,
    pub fee: Option<i64>,
    pub routing_fee: Option<i64>,
    pub buyer_invoice: Option<String>,
    pub invoice_held_at: Option<i64>,
    pub taken_at: Option<i64>,
    pub created_at: i64,
}

impl SolverDisputeInfo {
    pub fn new(
        order: &Order,
        dispute: &Dispute,
        initiator_tradekey: String,
        counterpart: Option<User>,
        initiator: Option<User>,
    ) -> Self {
        // Get initiator and counterpart info if not in full privacy mode
        let mut initiator_info = None;
        let mut counterpart_info = None;
        let mut initiator_full_privacy = true;
        let mut counterpart_full_privacy = true;

        if let Some(initiator) = initiator {
            let now = Timestamp::now();
            let initiator_operating_days = (now.as_u64() - initiator.created_at as u64) / 86400;
            initiator_info = Some(UserInfo {
                rating: initiator.total_rating,
                reviews: initiator.total_reviews,
                operating_days: initiator_operating_days,
            });
            initiator_full_privacy = false;
        }
        if let Some(counterpart) = counterpart {
            let now = Timestamp::now();
            let couterpart_operating_days = (now.as_u64() - counterpart.created_at as u64) / 86400;
            counterpart_info = Some(UserInfo {
                rating: counterpart.total_rating,
                reviews: counterpart.total_reviews,
                operating_days: couterpart_operating_days,
            });
            counterpart_full_privacy = false;
        }

        Self {
            id: order.id.clone(),
            kind: order.kind.clone(),
            status: order.status.clone(),
            hash: order.hash.clone(),
            preimage: order.preimage.clone(),
            order_previous_status: dispute.order_previous_status.clone(),
            initiator_pubkey: initiator_tradekey,
            buyer_pubkey: order.buyer_pubkey.clone(),
            buyer_token: dispute.buyer_token,
            seller_pubkey: order.seller_pubkey.clone(),
            seller_token: dispute.seller_token,
            initiator_full_privacy,
            counterpart_full_privacy,
            counterpart_info,
            initiator_info,
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
    pub fn new(order_id: Uuid, order_status: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            order_id: order_id.to_string(),
            status: Status::Initiated.to_string(),
            order_previous_status: order_status,
            solver_pubkey: None,
            created_at: Utc::now().timestamp(),
            taken_at: None,
            buyer_token: 0,
            seller_token: 0,
        }
    }

    /// Create new dispute record and generate security tokens
    /// Returns a tuple of the initiator's token and the counterpart's token
    pub fn create_tokens(&mut self, is_buyer_dispute: bool) -> (Option<u16>, Option<u16>) {
        let mut rng = rand::rng();
        let mut buyer_token;
        let mut seller_token;

        // Ensure tokens are unique
        loop {
            buyer_token = rng.random_range(TOKEN_MIN..=TOKEN_MAX);
            seller_token = rng.random_range(TOKEN_MIN..=TOKEN_MAX);
            if buyer_token != seller_token {
                break;
            }
        }

        self.buyer_token = buyer_token as i64;
        self.seller_token = seller_token as i64;

        let (initiator_token, counterpart_token) = match is_buyer_dispute {
            true => (Some(buyer_token), Some(seller_token)),
            false => (Some(seller_token), Some(buyer_token)),
        };

        (initiator_token, counterpart_token)
    }
}
