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
    /// Unix timestamp of the user's first trade, truncated to the start of its
    /// UTC day, or `None` from a peer that does not publish it yet.
    ///
    /// Supersedes the `days` count the daemon publishes alongside it. A day
    /// count is derived when the event is written, so it is stale on any event
    /// that sits on relays for a while, and it cannot be merged when
    /// reputation is imported from another venue; a date can be.
    ///
    /// Day precision is deliberate rather than incidental. This value travels
    /// on every order of the same user, so a second-precision timestamp would
    /// be a fingerprint linking their trade pubkeys together.
    ///
    /// Skipped when absent, so a `Rating` that never sets it serializes
    /// exactly as it did before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

impl Rating {
    /// Construct a new [`Rating`] from its individual components.
    ///
    /// Leaves [`Rating::since`] unset; add it with [`Rating::with_since`].
    /// The signature is deliberately unchanged so no caller has to move.
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
            since: None,
        }
    }

    /// Attach the date of the user's first trade.
    ///
    /// `since` is expected already truncated to the start of its UTC day; this
    /// does not round it, because the caller owns the clock and a helper here
    /// would quietly disagree with the one the daemon uses.
    pub fn with_since(mut self, since: u64) -> Self {
        self.since = Some(since);
        self
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
    /// Returns a [`Tags`] value with one entry per numeric field plus a `z`
    /// marker tag identifying the payload as a rating. Encoding is infallible
    /// (nostr 0.45 `Tag::custom` takes string kind keys directly).
    pub fn to_tags(&self) -> Tags {
        let mut tags = vec![
            Tag::custom("total_reviews", vec![self.total_reviews.to_string()]),
            Tag::custom("total_rating", vec![self.total_rating.to_string()]),
            Tag::custom("last_rating", vec![self.last_rating.to_string()]),
            Tag::custom("max_rate", vec![self.max_rate.to_string()]),
            Tag::custom("min_rate", vec![self.min_rate.to_string()]),
        ];

        // Only when set: an absent `since` must leave the tag list exactly as
        // it was before this field existed.
        if let Some(since) = self.since {
            tags.push(Tag::custom("since", vec![since.to_string()]));
        }

        tags.push(Tag::custom("z", vec!["rating".to_string()]));

        Tags::from_list(tags)
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
        let mut since = None;

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
                "since" => {
                    since = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| ServiceError::ParsingNumberError)?,
                    )
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
            since,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A day-truncated timestamp: 2026-01-01T00:00:00Z.
    const SINCE: u64 = 1_767_225_600;

    fn sample() -> Rating {
        Rating::new(7, 4.5, 5, 1, 5)
    }

    fn tag_value(tags: &Tags, key: &str) -> Option<String> {
        tags.iter().find_map(|tag| {
            let t = tag.clone().to_vec();
            (t.first().map(String::as_str) == Some(key)).then(|| t.get(1).cloned())?
        })
    }

    #[test]
    fn new_leaves_since_unset_and_json_omits_it() {
        // Arrange
        let rating = sample();

        // Act
        let json = rating.as_json().expect("serializes");

        // Assert — a Rating that never sets it must serialize exactly as it
        // did before the field existed, or every existing consumer sees a new
        // key appear.
        assert_eq!(rating.since, None);
        assert!(!json.contains("since"), "{json}");
    }

    #[test]
    fn with_since_sets_it_and_json_carries_it() {
        // Arrange / Act
        let rating = sample().with_since(SINCE);
        let json = rating.as_json().expect("serializes");

        // Assert
        assert_eq!(rating.since, Some(SINCE));
        assert!(json.contains(&format!("\"since\":{SINCE}")), "{json}");
    }

    #[test]
    fn json_without_since_still_parses() {
        // Arrange — the shape every daemon published before this field.
        let json =
            r#"{"total_reviews":7,"total_rating":4.5,"last_rating":5,"max_rate":5,"min_rate":1}"#;

        // Act
        let rating = Rating::from_json(json).expect("parses");

        // Assert
        assert_eq!(rating.since, None);
        assert_eq!(rating.total_reviews, 7);
    }

    #[test]
    fn json_round_trips_with_since() {
        // Arrange
        let original = sample().with_since(SINCE);

        // Act
        let parsed = Rating::from_json(&original.as_json().expect("serializes")).expect("parses");

        // Assert
        assert_eq!(parsed.since, Some(SINCE));
        assert_eq!(parsed.total_rating, original.total_rating);
    }

    #[test]
    fn tags_omit_since_when_unset() {
        // Arrange / Act
        let tags = sample().to_tags();

        // Assert — same reasoning as the JSON case: no new tag on an event
        // built by a caller that has not adopted the field.
        assert_eq!(tag_value(&tags, "since"), None);
        assert_eq!(tag_value(&tags, "z"), Some("rating".to_string()));
    }

    #[test]
    fn tags_carry_since_when_set() {
        // Arrange / Act
        let tags = sample().with_since(SINCE).to_tags();

        // Assert
        assert_eq!(tag_value(&tags, "since"), Some(SINCE.to_string()));
        // The marker stays last, after the field that was inserted before it.
        assert_eq!(tag_value(&tags, "z"), Some("rating".to_string()));
    }

    #[test]
    fn tags_round_trip_with_since() {
        // Arrange
        let original = sample().with_since(SINCE);

        // Act
        let parsed = Rating::from_tags(original.to_tags()).expect("parses");

        // Assert
        assert_eq!(parsed.since, Some(SINCE));
        assert_eq!(parsed.total_reviews, original.total_reviews);
        assert_eq!(parsed.min_rate, original.min_rate);
    }

    #[test]
    fn tags_without_since_parse_as_none() {
        // Arrange — an event from a daemon that has not shipped the field.
        let tags = sample().to_tags();

        // Act
        let parsed = Rating::from_tags(tags).expect("parses");

        // Assert
        assert_eq!(parsed.since, None);
    }

    #[test]
    fn an_unparseable_since_is_an_error_not_a_silent_zero() {
        // Arrange — 1970 is a real date, so falling back to it would read as a
        // user who has been trading for fifty years.
        let tags = Tags::from_list(vec![
            Tag::custom("total_reviews", vec!["7".to_string()]),
            Tag::custom("since", vec!["yesterday".to_string()]),
        ]);

        // Act
        let parsed = Rating::from_tags(tags);

        // Assert
        assert!(parsed.is_err());
    }
}
