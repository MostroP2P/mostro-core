//! Dispute representation and lifecycle states.
//!
//! A [`Dispute`] is opened when one of the counterparts of a trade asks
//! Mostro to involve a solver. The dispute moves through a small state
//! machine described by [`Status`] until it is either settled, refunded or
//! released.
//!
//! [`SolverDisputeInfo`] is the payload surfaced to solvers with all the
//! trade details they need to render the dispute in their UI without
//! loading additional data.

use crate::{order::Order, user::User, user::UserInfo};
use chrono::Utc;
use nostr_sdk::Timestamp;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{FromRow, Type};
#[cfg(feature = "sqlx")]
use sqlx_crud::SqlxCrud;
use std::{fmt::Display, str::FromStr};
use uuid::Uuid;

/// Lifecycle status of a [`Dispute`].
#[cfg_attr(feature = "sqlx", derive(Type))]
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Dispute has been initiated and is waiting to be taken by a solver.
    #[default]
    Initiated,
    /// A solver has taken the dispute and is working on it.
    InProgress,
    /// Admin/solver canceled the trade and refunded the seller.
    SellerRefunded,
    /// Admin/solver settled the seller's hold invoice and initiated payment
    /// to the buyer.
    Settled,
    /// The seller released the funds before the dispute was resolved.
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

    /// Parse a [`Status`] from its kebab-case string representation.
    ///
    /// Returns `Err(())` if `s` does not match a known variant.
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

/// Database representation of a dispute.
///
/// Disputes are always bound to a parent [`Order`]; `order_previous_status`
/// preserves the status the order had before the dispute was filed so that
/// it can be restored if the dispute is dismissed.
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud), external_id)]
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Dispute {
    /// Unique identifier for the dispute.
    pub id: Uuid,
    /// Id of the order the dispute is attached to.
    pub order_id: Uuid,
    /// Current [`Status`] of the dispute, serialized as kebab-case.
    pub status: String,
    /// The status the underlying order had before the dispute was opened.
    pub order_previous_status: String,
    /// Public key of the solver that has taken the dispute, if any.
    pub solver_pubkey: Option<String>,
    /// Unix timestamp (seconds) when the dispute was created.
    pub created_at: i64,
    /// Unix timestamp (seconds) when the dispute was taken by a solver.
    /// `0` when it has not been taken yet.
    pub taken_at: i64,
}

/// Extended dispute view for solvers.
///
/// Bundles the [`Dispute`] together with the key fields of its parent
/// [`Order`] so a solver UI can render everything needed without additional
/// database lookups, while still respecting the `full privacy` setting of
/// each counterpart.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SolverDisputeInfo {
    /// Order id the dispute is attached to.
    pub id: Uuid,
    /// Order kind (`buy` or `sell`), serialized as kebab-case.
    pub kind: String,
    /// Order status at the time the dispute view was built.
    pub status: String,
    /// Payment hash of the hold invoice.
    pub hash: Option<String>,
    /// Preimage revealed once the hold invoice is settled.
    pub preimage: Option<String>,
    /// Status the order had immediately before the dispute was opened.
    pub order_previous_status: String,
    /// Trade public key of the dispute initiator.
    pub initiator_pubkey: String,
    /// Buyer's trade public key, if available.
    pub buyer_pubkey: Option<String>,
    /// Seller's trade public key, if available.
    pub seller_pubkey: Option<String>,
    /// `true` when the initiator is operating in full privacy mode, hiding
    /// its reputation.
    pub initiator_full_privacy: bool,
    /// `true` when the counterpart is operating in full privacy mode.
    pub counterpart_full_privacy: bool,
    /// Reputation snapshot of the initiator, when privacy allows it.
    pub initiator_info: Option<UserInfo>,
    /// Reputation snapshot of the counterpart, when privacy allows it.
    pub counterpart_info: Option<UserInfo>,
    /// Premium percentage applied to the order price.
    pub premium: i64,
    /// Payment method agreed upon for the fiat leg.
    pub payment_method: String,
    /// Sats amount of the trade.
    pub amount: i64,
    /// Fiat amount of the trade.
    pub fiat_amount: i64,
    /// Mostro fee charged for the trade.
    pub fee: i64,
    /// Lightning routing fee paid when settling the trade.
    pub routing_fee: i64,
    /// Buyer's Lightning invoice, if already provided.
    pub buyer_invoice: Option<String>,
    /// Unix timestamp (seconds) when the hold invoice was locked in.
    pub invoice_held_at: i64,
    /// Unix timestamp (seconds) when the order was taken.
    pub taken_at: i64,
    /// Unix timestamp (seconds) when the order was created.
    pub created_at: i64,
}

impl SolverDisputeInfo {
    /// Build a [`SolverDisputeInfo`] from an order, its dispute and the
    /// optional [`User`] records of both counterparts.
    ///
    /// When a [`User`] is provided, the corresponding privacy flag is set to
    /// `false` and a [`UserInfo`] snapshot is included (rating, reviews,
    /// operating days computed from `created_at`). When a [`User`] is `None`,
    /// the party is considered to be operating in full privacy mode.
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
            let initiator_operating_days = (now.as_secs() - initiator.created_at as u64) / 86400;
            initiator_info = Some(UserInfo {
                rating: initiator.total_rating,
                reviews: initiator.total_reviews,
                operating_days: initiator_operating_days,
            });
            initiator_full_privacy = false;
        }
        if let Some(counterpart) = counterpart {
            let now = Timestamp::now();
            let couterpart_operating_days = (now.as_secs() - counterpart.created_at as u64) / 86400;
            counterpart_info = Some(UserInfo {
                rating: counterpart.total_rating,
                reviews: counterpart.total_reviews,
                operating_days: couterpart_operating_days,
            });
            counterpart_full_privacy = false;
        }

        Self {
            id: order.id,
            kind: order.kind.clone(),
            status: order.status.clone(),
            hash: order.hash.clone(),
            preimage: order.preimage.clone(),
            order_previous_status: dispute.order_previous_status.clone(),
            initiator_pubkey: initiator_tradekey,
            buyer_pubkey: order.buyer_pubkey.clone(),
            seller_pubkey: order.seller_pubkey.clone(),
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
    /// Create a new dispute for an order.
    ///
    /// The dispute starts in [`Status::Initiated`] with a fresh UUID, the
    /// current timestamp as `created_at`, no solver assigned and `taken_at`
    /// set to `0`. `order_status` should be the current status of the order
    /// at the moment the dispute is filed; it is preserved in
    /// `order_previous_status`.
    pub fn new(order_id: Uuid, order_status: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            order_id,
            status: Status::Initiated.to_string(),
            order_previous_status: order_status,
            solver_pubkey: None,
            created_at: Utc::now().timestamp(),
            taken_at: 0,
        }
    }
}
