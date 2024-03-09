use serde::{Deserialize, Serialize};
use sqlx::types::chrono::Utc;
use sqlx::FromRow;
use sqlx::Type;
use sqlx_crud::SqlxCrud;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Each status that a dispute can have
#[derive(Debug, Default, Deserialize, Serialize, Type, Clone, PartialEq, Eq)]
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

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
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
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq, FromRow, SqlxCrud)]
#[external_id]
pub struct Dispute {
    pub id: Uuid,
    pub order_id: Uuid,
    pub status: Status,
    pub solver_pubkey: Option<String>,
    pub created_at: i64,
    pub taken_at: i64,
}

impl Dispute {
    pub fn new(order_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            order_id,
            status: Status::Initiated,
            solver_pubkey: None,
            created_at: Utc::now().timestamp(),
            taken_at: 0,
        }
    }
}
