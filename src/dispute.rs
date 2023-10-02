use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::Type;
use sqlx_crud::SqlxCrud;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Each status that a dispute can have
#[derive(Debug, Deserialize, Serialize, Type, Clone, PartialEq, Eq)]
pub enum Status {
    /// Dispute initiated and waiting to be taken by a solver
    Pending,
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
            "Pending" => std::result::Result::Ok(Self::Pending),
            "InProgress" => std::result::Result::Ok(Self::InProgress),
            "SellerRefunded" => std::result::Result::Ok(Self::SellerRefunded),
            "Settled" => std::result::Result::Ok(Self::Settled),
            "Released" => std::result::Result::Ok(Self::Released),
            _ => Err(()),
        }
    }
}

/// Database representation of a dispute
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, FromRow, SqlxCrud)]
pub struct Dispute {
    pub order_id: Uuid,
    pub status: Status,
    pub solver_pubkey: Option<String>,
    pub created_at: i64,
    pub taken_at: i64,
}
