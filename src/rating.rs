//! Encoding of user reputation as Nostr event tags.
//!
//! Mostro publishes user reputation as addressable Nostr events of kind
//! [`NOSTR_RATING_EVENT_KIND`](crate::prelude::NOSTR_RATING_EVENT_KIND). The
//! [`Rating`] struct in this module mirrors the tag set used on those events
//! and provides helpers to serialize to / deserialize from both JSON and
//! `nostr_sdk::Tags`.

use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::ServiceError;

/// User reputation snapshot, suitable for publishing as Nostr tags.
///
/// The fields are the same aggregates stored on [`crate::user::User`], but
/// typed for transport (unsigned integers for counts, `u8` for rating values).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rating {
    /// Total number of ratings received.
    pub total_reviews: u64,
    /// Weighted rating average across all reviews.
    pub total_rating: f64,
    /// Most recent rating, in the `MIN_RATING..=MAX_RATING` range.
    pub last_rating: u8,
    /// Highest rating ever received.
    pub max_rate: u8,
    /// Lowest rating ever received.
    pub min_rate: u8,
}

impl Rating {
    /// Construct a new [`Rating`] from its individual components.
    pub fn new(
        total_reviews: u64,
        total_rating: f64,
        last_rating: u8,
        min_rate: u8,
        max_rate: u8,
    ) -> Self {
        Self {
            total_reviews,
            total_rating,
            last_rating,
            min_rate,
            max_rate,
        }
    }

    /// Parse a [`Rating`] from its JSON representation.
    ///
    /// Returns [`ServiceError::MessageSerializationError`] if `json` is not a
    /// valid serialization of this type.
    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Serialize the rating to a JSON string.
    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Encode the rating as a set of Nostr tags, ready to attach to an event.
    ///
    /// The returned [`Tags`] value contains one entry per numeric field plus
    /// a `z` marker tag identifying the payload as a rating.
    pub fn to_tags(&self) -> Result<Tags> {
        let tags = vec![
            Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("total_reviews")),
                vec![self.total_reviews.to_string()],
            ),
            Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("total_rating")),
                vec![self.total_rating.to_string()],
            ),
            Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("last_rating")),
                vec![self.last_rating.to_string()],
            ),
            Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("max_rate")),
                vec![self.max_rate.to_string()],
            ),
            Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("min_rate")),
                vec![self.min_rate.to_string()],
            ),
            Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("z")),
                vec!["rating".to_string()],
            ),
        ];

        let tags = Tags::from_list(tags);

        Ok(tags)
    }

    /// Rebuild a [`Rating`] from a set of Nostr tags previously produced by
    /// [`Rating::to_tags`].
    ///
    /// Unknown tag keys are ignored so that the function keeps working if the
    /// server adds new metadata fields. Returns a [`ServiceError`] if a
    /// required key carries a non-parseable value.
    pub fn from_tags(tags: Tags) -> Result<Self, ServiceError> {
        let mut total_reviews = 0;
        let mut total_rating = 0.0;
        let mut last_rating = 0;
        let mut max_rate = 0;
        let mut min_rate = 0;

        for tag in tags.into_iter() {
            let t = tag.to_vec();
            let key = t
                .first()
                .ok_or_else(|| ServiceError::NostrError("Missing tag key".to_string()))?;
            let value = t
                .get(1)
                .ok_or_else(|| ServiceError::NostrError("Missing tag value".to_string()))?;
            match key.as_str() {
                "total_reviews" => {
                    total_reviews = value
                        .parse::<u64>()
                        .map_err(|_| ServiceError::ParsingNumberError)?
                }
                "total_rating" => {
                    total_rating = value
                        .parse::<f64>()
                        .map_err(|_| ServiceError::ParsingNumberError)?
                }
                "last_rating" => {
                    last_rating = value
                        .parse::<u8>()
                        .map_err(|_| ServiceError::ParsingNumberError)?
                }
                "max_rate" => {
                    max_rate = value
                        .parse::<u8>()
                        .map_err(|_| ServiceError::ParsingNumberError)?
                }
                "min_rate" => {
                    min_rate = value
                        .parse::<u8>()
                        .map_err(|_| ServiceError::ParsingNumberError)?
                }
                _ => {}
            }
        }

        Ok(Self {
            total_reviews,
            total_rating,
            last_rating,
            max_rate,
            min_rate,
        })
    }
}
