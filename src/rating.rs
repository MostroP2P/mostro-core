use anyhow::{Ok, Result};
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
    pub fn to_tags(&self) -> Result<Vec<(String, String)>> {
        let tags = vec![
            ("total_reviews".to_string(), self.total_reviews.to_string()),
            ("total_rating".to_string(), self.total_rating.to_string()),
            ("last_rating".to_string(), self.last_rating.to_string()),
            ("max_rate".to_string(), self.max_rate.to_string()),
            ("min_rate".to_string(), self.min_rate.to_string()),
            ("data_label".to_string(), "rating".to_string()),
        ];

        Ok(tags)
    }

    /// Transform tuple vector to Rating struct
    pub fn from_tags(tags: Vec<(String, String)>) -> Result<Self> {
        let mut total_reviews = 0;
        let mut total_rating = 0.0;
        let mut last_rating = 0;
        let mut max_rate = 0;
        let mut min_rate = 0;

        for tag in tags {
            match tag.0.as_str() {
                "total_reviews" => total_reviews = tag.1.parse::<u64>().unwrap(),
                "total_rating" => total_rating = tag.1.parse::<f64>().unwrap(),
                "last_rating" => last_rating = tag.1.parse::<u8>().unwrap(),
                "max_rate" => max_rate = tag.1.parse::<u8>().unwrap(),
                "min_rate" => min_rate = tag.1.parse::<u8>().unwrap(),
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
