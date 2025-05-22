use chrono::Utc;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;

#[derive(Debug, Default, Deserialize, Serialize, Clone)]

pub struct UserInfo {
    /// User's rating
    pub rating: f64,
    /// User's total reviews
    pub reviews: i64,
    /// User's operating days
    pub operating_days: u64,
}

/// Database representation of an user
#[cfg_attr(feature = "sqlx", derive(FromRow))]
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct User {
    pub pubkey: String,
    pub is_admin: i64,
    pub admin_password: Option<String>,
    pub is_solver: i64,
    pub is_banned: i64,
    pub category: i64,
    /// We have to be sure that when a user creates a new order (or takes an order),
    /// the trade_index is greater than the one we have in database
    pub last_trade_index: i64,
    pub total_reviews: i64,
    pub total_rating: f64,
    pub last_rating: i64,
    pub max_rating: i64,
    pub min_rating: i64,
    pub created_at: i64,
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
            pubkey,
            is_admin,
            admin_password: None,
            is_solver,
            is_banned,
            category,
            last_trade_index: trade_index,
            total_reviews: 0,
            total_rating: 0.0,
            last_rating: 0,
            max_rating: 0,
            min_rating: 0,
            created_at: Utc::now().timestamp(),
        }
    }

    /// Update user rating
    pub fn update_rating(&mut self, rating: u8) {
        // Update user reputation
        // increment first
        self.total_reviews += 1;
        let old_rating = self.total_rating;
        // recompute new rating
        if self.total_reviews <= 1 {
            self.max_rating = rating.into();
            self.min_rating = rating.into();
        } else {
            self.total_rating =
                old_rating + ((self.last_rating as f64) - old_rating) / (self.total_reviews as f64);
            if self.max_rating < rating.into() {
                self.max_rating = rating.into();
            }
            if self.min_rating > rating.into() {
                self.min_rating = rating.into();
            }
        }
        // Store last rating
        self.last_rating = rating.into();
    }
}
