use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::ServiceError;

/// We use this struct to create a user reputation
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rating {
    pub total_reviews: u64,
    pub total_rating: f64,
    pub last_rating: u8,
    pub max_rate: u8,
    pub min_rate: u8,
}

impl Rating {
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

    /// New order from json string
    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Get order as json string
    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Transform Rating struct to tuple vector to easily interact with Nostr
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

    /// Transform tuple vector to Rating struct
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
