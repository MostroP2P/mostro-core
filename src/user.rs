use chrono::Utc;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;
#[cfg(feature = "sqlx")]
use sqlx_crud::SqlxCrud;
use uuid::Uuid;

/// Database representation of an user
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud), external_id)]
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub pubkey: String,
    pub is_admin: i64,
    pub is_solver: i64,
    pub is_banned: i64,
    pub category: i64,
    pub created_at: i64,
    pub trade_index: i64,
}

impl User {
    pub fn new(
        pubkey: String,
        is_admin: i64,
        is_solver: i64,
        is_banned: i64,
        category: i64,
        trade_index: i64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            pubkey,
            is_admin,
            is_solver,
            is_banned,
            category,
            created_at: Utc::now().timestamp(),
            trade_index,
        }
    }
}
