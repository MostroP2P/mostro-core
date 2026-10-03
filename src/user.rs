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
use serde::{Deserialize, Serialize, Serializer};
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
    truncate_since(timestamp.max(0) as u64)
}

/// [`day_truncate`] for a value that is already a `since`. Idempotent, so it
/// is safe on every path a `since` takes out of the crate.
pub(crate) fn truncate_since(since: u64) -> u64 {
    since - since % SECONDS_PER_DAY
}

/// `serialize_with` for a `since` field: the field is public, so rounding at
/// the serialization boundary is the only place that covers every producer.
pub(crate) fn serialize_since<S: Serializer>(
    since: &Option<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    since.map(truncate_since).serialize(serializer)
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
    /// Always serialized truncated to its UTC day, however it was set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_since"
    )]
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
    /// Unix timestamp (seconds) the user's age is shown from: when the
    /// record was created, moved back by an imported reputation's earlier
    /// first-trade date.
    pub created_at: i64,
    /// Ratings received through imported reputation, never natively.
    /// Internal only. See [`crate::reputation`].
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    #[serde(default)]
    pub seeded_reviews: i64,
    /// Sum of `rating × reviews` over every imported reputation. Internal
    /// only.
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    #[serde(default)]
    pub seeded_rating_sum: f64,
    /// Sum of the raw ratings received natively, with no first-vote
    /// damping, so the native average is exact. Internal only.
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    #[serde(default)]
    pub native_rating_sum: f64,
    /// When the record was created, which an import never moves: what
    /// `created_at` goes back to when an import is reversed. Read it through
    /// [`User::native_created_at`].
    ///
    /// An `Option` on purpose: a database that predates the column reads it
    /// as `None`, and the accessor falls back to `created_at`; a plain `i64`
    /// would default to `0` and place every such user in 1970.
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    #[serde(default)]
    pub native_created_at: Option<i64>,
    /// The identity this account's reputation is bound to, as an issuer:
    /// the only identity an export may name without a rebind authorisation.
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    #[serde(default)]
    pub reputation_exported_to: Option<String>,
    /// UTC day start of the last export. Day precision, so the record cannot
    /// time-correlate an export with an import elsewhere.
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    #[serde(default)]
    pub reputation_exported_at: Option<i64>,
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
        let created_at = Utc::now().timestamp();
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
            created_at,
            native_created_at: Some(created_at),
            ..Self::default()
        }
    }

    /// When the record was created, which no import ever moves.
    ///
    /// Falls back to `created_at` for a record whose database predates the
    /// `native_created_at` column, never to `0`.
    pub fn native_created_at(&self) -> i64 {
        self.native_created_at.unwrap_or(self.created_at)
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

    #[test]
    fn a_new_user_records_its_creation_as_the_native_date() {
        let user = User::new("pubkey".into(), 0, 0, 0, 0, 0);
        assert_eq!(user.native_created_at, Some(user.created_at));
        assert_eq!(user.native_created_at(), user.created_at);
        assert_eq!((user.seeded_reviews, user.seeded_rating_sum), (0, 0.0));
        assert_eq!(user.native_rating_sum, 0.0);
        assert_eq!(user.reputation_exported_to, None);
        assert_eq!(user.reputation_exported_at, None);
    }

    #[test]
    fn a_record_without_a_native_date_falls_back_to_created_at_never_zero() {
        let user = User {
            created_at: 1_700_000_000,
            native_created_at: None,
            ..User::default()
        };
        assert_eq!(user.native_created_at(), 1_700_000_000);
    }

    #[test]
    fn a_serialised_user_from_before_the_new_fields_still_deserialises() {
        let json = r#"{"pubkey":"p","is_admin":0,"admin_password":null,"is_solver":0,
            "is_banned":0,"category":0,"last_trade_index":3,"total_reviews":2,
            "total_rating":4.5,"last_rating":5,"max_rating":5,"min_rating":4,
            "created_at":1700000000}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.native_created_at(), 1_700_000_000);
        assert_eq!(user.seeded_reviews, 0);
    }

    /// A daemon whose database predates the migration still reads its rows
    /// with `SELECT *`, and the native date of such a row is its
    /// `created_at`, not 1970.
    #[cfg(feature = "sqlx")]
    #[tokio::test]
    async fn a_row_without_the_new_columns_loads_with_their_defaults() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(":memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE users (pubkey char(64) primary key, is_admin integer not null default 0, \
             admin_password char(64), is_solver integer not null default 0, \
             is_banned integer not null default 0, category integer not null default 0, \
             last_trade_index integer not null default 0, total_reviews integer not null default 0, \
             total_rating real not null default 0.0, last_rating integer not null default 0, \
             max_rating integer not null default 0, min_rating integer not null default 0, \
             created_at integer not null)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users (pubkey, total_reviews, total_rating, created_at) \
             VALUES ('p', 2, 4.5, 1700000000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let user: User = sqlx::query_as("SELECT * FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(user.native_created_at, None);
        assert_eq!(user.native_created_at(), 1_700_000_000);
        assert_eq!((user.seeded_reviews, user.native_rating_sum), (0, 0.0));
        assert_eq!(user.reputation_exported_to, None);
    }

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
    fn user_info_truncates_since_on_serialization() {
        // Arrange — built directly, bypassing any helper that would round it.
        let info = UserInfo {
            rating: 4.5,
            reviews: 10,
            operating_days: 30,
            since: Some(LATE_IN_DAY as u64),
        };

        // Act
        let json = serde_json::to_string(&info).expect("serializes");

        // Assert — the peer sees the day, never the second.
        assert!(json.contains(&format!("\"since\":{DAY_START}")), "{json}");
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
