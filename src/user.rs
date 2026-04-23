//! Persistent user representation and reputation helpers.
//!
//! The [`User`] struct is the database-backed record Mostro keeps for every
//! identity that has interacted with the system. It tracks rating aggregates,
//! administrative flags and the last trade index used by the user, which is
//! required so that new orders always carry a strictly increasing trade index.
//!
//! [`UserInfo`] is a lightweight view of the same data that can safely be
//! shared with a counterpart during a trade without leaking internals.

use chrono::Utc;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;

/// Public snapshot of a user's reputation shared with peers during a trade.
///
/// Unlike [`User`], `UserInfo` contains only the values a counterpart needs
/// to decide whether to trade: aggregated rating, number of reviews and how
/// many days the user has been operating on Mostro.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]

pub struct UserInfo {
    /// Aggregated rating value for the user (see [`crate::rating::Rating`]).
    pub rating: f64,
    /// Total number of ratings received.
    pub reviews: i64,
    /// Number of days since the user account was created.
    pub operating_days: u64,
}

/// Database representation of a Mostro user.
///
/// This is the canonical row stored on the Mostro node. It tracks identity
/// data (`pubkey`), administrative role flags, the last trade index used by
/// the user and rating aggregates used to compute reputation.
#[cfg_attr(feature = "sqlx", derive(FromRow))]
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct User {
    /// Master public key of the user, hex encoded.
    pub pubkey: String,
    /// `1` when the user has admin privileges, `0` otherwise. Stored as
    /// `i64` to match the underlying SQLite representation.
    pub is_admin: i64,
    /// Optional password used to authenticate privileged admin actions.
    pub admin_password: Option<String>,
    /// `1` when the user is a dispute solver, `0` otherwise.
    pub is_solver: i64,
    /// `1` when the user is banned from the platform, `0` otherwise.
    pub is_banned: i64,
    /// Free-form category bucket. Reserved for future segmentation.
    pub category: i64,
    /// Last trade index used by this user. When a user creates a new order
    /// (or takes one) the incoming trade index must be strictly greater than
    /// this value, or the request is rejected.
    pub last_trade_index: i64,
    /// Total number of ratings the user has received.
    pub total_reviews: i64,
    /// Weighted rating average computed from all received ratings.
    pub total_rating: f64,
    /// Most recent rating received, in the `MIN_RATING..=MAX_RATING` range.
    pub last_rating: i64,
    /// Highest rating ever received.
    pub max_rating: i64,
    /// Lowest rating ever received.
    pub min_rating: i64,
    /// Unix timestamp (seconds) when the user record was created.
    pub created_at: i64,
}

impl User {
    /// Create a new [`User`] with fresh rating aggregates.
    ///
    /// `trade_index` becomes the user's `last_trade_index`. The `created_at`
    /// timestamp is set to the current system time.
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

    /// Record a new rating for the user and refresh the aggregates.
    ///
    /// The first vote is weighted by `1/2` so that a single review cannot
    /// anchor a perfect or disastrous reputation. Subsequent votes update
    /// `total_rating` with an incremental running-average formula.
    /// `min_rating` and `max_rating` are tightened as new extremes arrive.
    ///
    /// # Example
    ///
    /// ```
    /// use mostro_core::user::User;
    ///
    /// let mut user = User::new("pubkey".into(), 0, 0, 0, 0, 0);
    /// user.update_rating(5);
    /// assert_eq!(user.total_reviews, 1);
    /// assert_eq!(user.max_rating, 5);
    /// ```
    pub fn update_rating(&mut self, rating: u8) {
        // Update user reputation
        // increment first
        self.total_reviews += 1;
        let old_rating = self.total_rating;
        // recompute new rating
        if self.total_reviews <= 1 {
            // New logic with weight 1/2 for first vote.
            let first_rating = rating as f64;
            self.total_rating = first_rating / 2.0;
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
