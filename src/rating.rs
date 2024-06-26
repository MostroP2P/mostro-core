use anyhow::{Ok, Result};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

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
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Get order as json string
    pub fn as_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    /// Transform Rating struct to tuple vector to easily interact with Nostr
    pub fn to_tags(&self) -> Result<Vec<Tag>> {
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

        Ok(tags)
    }

    /// Transform tuple vector to Rating struct
    pub fn from_tags(tags: Vec<Tag>) -> Result<Self> {
        let mut total_reviews = 0;
        let mut total_rating = 0.0;
        let mut last_rating = 0;
        let mut max_rate = 0;
        let mut min_rate = 0;

        for tag in tags {
            let t = tag.to_vec();
            match t.first().unwrap().as_str() {
                "total_reviews" => total_reviews = t.get(1).unwrap().parse::<u64>().unwrap(),
                "total_rating" => total_rating = t.get(1).unwrap().parse::<f64>().unwrap(),
                "last_rating" => last_rating = t.get(1).unwrap().parse::<u8>().unwrap(),
                "max_rate" => max_rate = t.get(1).unwrap().parse::<u8>().unwrap(),
                "min_rate" => min_rate = t.get(1).unwrap().parse::<u8>().unwrap(),
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
