use serde::{Deserialize, Serialize};
use sqlx::types::chrono::Utc;
use sqlx::FromRow;
use sqlx_crud::SqlxCrud;
use uuid::Uuid;

/// Database representation of an user
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, FromRow, SqlxCrud)]
pub struct User {
    pub id: Uuid,
    pub pubkey: String,
    pub is_admin: i64,
    pub is_solver: i64,
    pub is_banned: i64,
    pub category: i64,
    pub created_at: i64,
}

impl User {
    pub fn new(
        pubkey: String,
        is_admin: i64,
        is_solver: i64,
        is_banned: i64,
        category: i64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            pubkey,
            is_admin,
            is_solver,
            is_banned,
            category,
            created_at: Utc::now().timestamp(),
        }
    }
}
