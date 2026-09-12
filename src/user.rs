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

/// Seconds in a day, the granularity every published first-trade date uses.
const SECONDS_PER_DAY: u64 = 86_400;

/// Truncate a Unix timestamp to the start of its UTC day.
///
/// Every published first-trade date goes through this. The rounding is not
/// cosmetic: the value travels on every order and every peer message of the
/// same user, so a second-precision timestamp would be a fingerprint that ties
/// their otherwise unlinkable trade pubkeys together. A day carries exactly
/// the information the old `operating_days` count carried.
///
/// Timestamps before the epoch clamp to `0` rather than wrap.
pub fn day_truncate(timestamp: i64) -> u64 {
    let seconds = timestamp.max(0) as u64;
    seconds - seconds % SECONDS_PER_DAY
}

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
    ///
    /// Superseded by [`UserInfo::since`], which carries the same information
    /// as a date instead of a count derived when the message was built. Kept
    /// for one deprecation window so old and new peers interoperate.
    pub operating_days: u64,
    /// Unix timestamp of the user's first trade, truncated to the start of its
    /// UTC day, or `None` from a peer that does not send it yet.
    ///
    /// Clients compute the age at display time, so it does not go stale the
    /// way `operating_days` does. Skipped when absent, so a `UserInfo` that
    /// never sets it serializes exactly as it did before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
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
                old_rating + ((rating as f64) - old_rating) / (self.total_reviews as f64);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-01-01T00:00:00Z, and the same instant plus most of a day.
    const DAY_START: i64 = 1_767_225_600;
    const LATE_IN_DAY: i64 = DAY_START + 86_399;

    #[test]
    fn day_truncate_lands_on_the_start_of_the_utc_day() {
        // Arrange / Act / Assert — anywhere inside a day maps to its start, so
        // the value cannot change while the user is mid-session.
        assert_eq!(day_truncate(DAY_START), DAY_START as u64);
        assert_eq!(day_truncate(LATE_IN_DAY), DAY_START as u64);
        assert_eq!(
            day_truncate(DAY_START + 86_400),
            (DAY_START + 86_400) as u64
        );
    }

    #[test]
    fn day_truncate_clamps_a_pre_epoch_timestamp_instead_of_wrapping() {
        // Arrange / Act / Assert — a negative cast to u64 would produce a date
        // far in the future, which reads as a user who has not started trading.
        assert_eq!(day_truncate(-1), 0);
        assert_eq!(day_truncate(0), 0);
    }

    #[test]
    fn user_info_omits_since_when_unset() {
        // Arrange
        let info = UserInfo {
            rating: 4.5,
            reviews: 10,
            operating_days: 30,
            since: None,
        };

        // Act
        let json = serde_json::to_string(&info).expect("serializes");

        // Assert — a peer that has not adopted the field must see the exact
        // payload it saw before.
        assert!(!json.contains("since"), "{json}");
    }

    #[test]
    fn user_info_round_trips_with_since() {
        // Arrange
        let info = UserInfo {
            rating: 4.5,
            reviews: 10,
            operating_days: 30,
            since: Some(DAY_START as u64),
        };

        // Act
        let parsed: UserInfo =
            serde_json::from_str(&serde_json::to_string(&info).expect("serializes"))
                .expect("parses");

        // Assert
        assert_eq!(parsed.since, Some(DAY_START as u64));
        assert_eq!(parsed.operating_days, 30);
    }

    #[test]
    fn user_info_from_a_peer_without_since_parses() {
        // Arrange — what every daemon sends today.
        let json = r#"{"rating":4.5,"reviews":10,"operating_days":30}"#;

        // Act
        let parsed: UserInfo = serde_json::from_str(json).expect("parses");

        // Assert
        assert_eq!(parsed.since, None);
        assert_eq!(parsed.operating_days, 30);
    }

    #[test]
    fn first_vote_is_weighted_by_half() {
        let mut user = User::default();

        user.update_rating(5);

        assert_eq!(user.total_reviews, 1);
        assert_eq!(user.total_rating, 2.5);
        assert_eq!(user.last_rating, 5);
        assert_eq!(user.max_rating, 5);
        assert_eq!(user.min_rating, 5);
    }

    #[test]
    fn second_vote_is_folded_into_the_average() {
        let mut user = User::default();
        user.update_rating(5);

        user.update_rating(1);

        // First vote weighted 1/2 -> 2.5, then incremental average with the
        // new vote: 2.5 + (1 - 2.5) / 2 = 1.75
        assert_eq!(user.total_reviews, 2);
        assert!((user.total_rating - 1.75).abs() < 1e-9);
        assert_eq!(user.last_rating, 1);
    }

    #[test]
    fn low_vote_lowers_a_high_average() {
        let mut user = User::default();
        for _ in 0..10 {
            user.update_rating(5);
        }
        let farmed_average = user.total_rating;
        assert!((farmed_average - 4.75).abs() < 1e-9);

        user.update_rating(1);

        // Correct running average: (2.5 + 9 * 5 + 1) / 11 = 48.5 / 11
        let expected = 48.5 / 11.0;
        assert!(
            user.total_rating < farmed_average,
            "a 1-star review must lower the average, got {} (was {})",
            user.total_rating,
            farmed_average
        );
        assert!((user.total_rating - expected).abs() < 1e-9);
        assert_eq!(user.last_rating, 1);
        assert_eq!(user.min_rating, 1);
        assert_eq!(user.max_rating, 5);
    }

    #[test]
    fn high_vote_raises_a_low_average() {
        let mut user = User::default();
        user.update_rating(1);
        user.update_rating(1);
        let low_average = user.total_rating;

        user.update_rating(5);

        assert!(
            user.total_rating > low_average,
            "a 5-star review must raise the average, got {} (was {})",
            user.total_rating,
            low_average
        );
        // (0.5 + 1 + 5) / 3
        assert!((user.total_rating - 6.5 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn min_and_max_track_extremes() {
        let mut user = User::default();
        user.update_rating(3);
        user.update_rating(5);
        user.update_rating(1);

        assert_eq!(user.max_rating, 5);
        assert_eq!(user.min_rating, 1);
    }
}
