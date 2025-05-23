use crate::prelude::*;
use nostr_sdk::{PublicKey, Timestamp};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;
#[cfg(feature = "sqlx")]
use sqlx_crud::SqlxCrud;
use std::{fmt::Display, str::FromStr};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

/// Orders can be only Buy or Sell
#[wasm_bindgen]
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Buy,
    Sell,
}

impl FromStr for Kind {
    type Err = ();

    fn from_str(kind: &str) -> std::result::Result<Self, Self::Err> {
        match kind.to_lowercase().as_str() {
            "buy" => std::result::Result::Ok(Self::Buy),
            "sell" => std::result::Result::Ok(Self::Sell),
            _ => Err(()),
        }
    }
}

impl Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::Sell => write!(f, "sell"),
            Kind::Buy => write!(f, "buy"),
        }
    }
}

/// Each status that an order can have
#[wasm_bindgen]
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Active,
    Canceled,
    CanceledByAdmin,
    SettledByAdmin,
    CompletedByAdmin,
    Dispute,
    Expired,
    FiatSent,
    SettledHoldInvoice,
    Pending,
    Success,
    WaitingBuyerInvoice,
    WaitingPayment,
    CooperativelyCanceled,
    InProgress,
}

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Active => write!(f, "active"),
            Status::Canceled => write!(f, "canceled"),
            Status::CanceledByAdmin => write!(f, "canceled-by-admin"),
            Status::SettledByAdmin => write!(f, "settled-by-admin"),
            Status::CompletedByAdmin => write!(f, "completed-by-admin"),
            Status::Dispute => write!(f, "dispute"),
            Status::Expired => write!(f, "expired"),
            Status::FiatSent => write!(f, "fiat-sent"),
            Status::SettledHoldInvoice => write!(f, "settled-hold-invoice"),
            Status::Pending => write!(f, "pending"),
            Status::Success => write!(f, "success"),
            Status::WaitingBuyerInvoice => write!(f, "waiting-buyer-invoice"),
            Status::WaitingPayment => write!(f, "waiting-payment"),
            Status::CooperativelyCanceled => write!(f, "cooperatively-canceled"),
            Status::InProgress => write!(f, "in-progress"),
        }
    }
}

impl FromStr for Status {
    type Err = ();
    /// Convert a string to a status
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => std::result::Result::Ok(Self::Active),
            "canceled" => std::result::Result::Ok(Self::Canceled),
            "canceled-by-admin" => std::result::Result::Ok(Self::CanceledByAdmin),
            "settled-by-admin" => std::result::Result::Ok(Self::SettledByAdmin),
            "completed-by-admin" => std::result::Result::Ok(Self::CompletedByAdmin),
            "dispute" => std::result::Result::Ok(Self::Dispute),
            "expired" => std::result::Result::Ok(Self::Expired),
            "fiat-sent" => std::result::Result::Ok(Self::FiatSent),
            "settled-hold-invoice" => std::result::Result::Ok(Self::SettledHoldInvoice),
            "pending" => std::result::Result::Ok(Self::Pending),
            "success" => std::result::Result::Ok(Self::Success),
            "waiting-buyer-invoice" => std::result::Result::Ok(Self::WaitingBuyerInvoice),
            "waiting-payment" => std::result::Result::Ok(Self::WaitingPayment),
            "cooperatively-canceled" => std::result::Result::Ok(Self::CooperativelyCanceled),
            "in-progress" => std::result::Result::Ok(Self::InProgress),
            _ => Err(()),
        }
    }
}
/// Database representation of an order
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud), external_id)]
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Order {
    pub id: Uuid,
    pub kind: String,
    pub event_id: String,
    pub hash: Option<String>,
    pub preimage: Option<String>,
    pub creator_pubkey: String,
    pub cancel_initiator_pubkey: Option<String>,
    pub buyer_pubkey: Option<String>,
    pub master_buyer_pubkey: Option<String>,
    pub seller_pubkey: Option<String>,
    pub master_seller_pubkey: Option<String>,
    pub status: String,
    pub price_from_api: bool,
    pub premium: i64,
    pub payment_method: String,
    pub amount: i64,
    pub min_amount: Option<i64>,
    pub max_amount: Option<i64>,
    pub buyer_dispute: bool,
    pub seller_dispute: bool,
    pub buyer_cooperativecancel: bool,
    pub seller_cooperativecancel: bool,
    pub fee: i64,
    pub routing_fee: i64,
    pub fiat_code: String,
    pub fiat_amount: i64,
    pub buyer_invoice: Option<String>,
    pub range_parent_id: Option<Uuid>,
    pub invoice_held_at: i64,
    pub taken_at: i64,
    pub created_at: i64,
    pub buyer_sent_rate: bool,
    pub seller_sent_rate: bool,
    pub failed_payment: bool,
    pub payment_attempts: i64,
    pub expires_at: i64,
    pub trade_index_seller: Option<i64>,
    pub trade_index_buyer: Option<i64>,
    pub next_trade_pubkey: Option<String>,
    pub next_trade_index: Option<i64>,
}

impl From<SmallOrder> for Order {
    fn from(small_order: SmallOrder) -> Self {
        Self {
            id: Uuid::new_v4(),
            // order will be overwritten with the real one before publishing
            kind: small_order
                .kind
                .map_or_else(|| Kind::Buy.to_string(), |k| k.to_string()),
            status: small_order
                .status
                .map_or_else(|| Status::Active.to_string(), |s| s.to_string()),
            amount: small_order.amount,
            fiat_code: small_order.fiat_code,
            min_amount: small_order.min_amount,
            max_amount: small_order.max_amount,
            fiat_amount: small_order.fiat_amount,
            payment_method: small_order.payment_method,
            premium: small_order.premium,
            event_id: String::new(),
            creator_pubkey: String::new(),
            price_from_api: false,
            fee: 0,
            routing_fee: 0,
            invoice_held_at: 0,
            taken_at: 0,
            created_at: small_order.created_at.unwrap_or(0),
            expires_at: small_order.expires_at.unwrap_or(0),
            payment_attempts: 0,
            ..Default::default()
        }
    }
}

impl Order {
    /// Convert an order to a small order
    pub fn as_new_order(&self) -> SmallOrder {
        SmallOrder::new(
            Some(self.id),
            Some(Kind::from_str(&self.kind).unwrap()),
            Some(Status::from_str(&self.status).unwrap()),
            self.amount,
            self.fiat_code.clone(),
            self.min_amount,
            self.max_amount,
            self.fiat_amount,
            self.payment_method.clone(),
            self.premium,
            None,
            None,
            self.buyer_invoice.clone(),
            Some(self.created_at),
            Some(self.expires_at),
            None,
            None,
        )
    }
    /// Get the kind of the order
    pub fn get_order_kind(&self) -> Result<Kind, ServiceError> {
        if let Ok(kind) = Kind::from_str(&self.kind) {
            Ok(kind)
        } else {
            Err(ServiceError::InvalidOrderKind)
        }
    }

    /// Get the status of the order in case
    pub fn get_order_status(&self) -> Result<Status, ServiceError> {
        if let Ok(status) = Status::from_str(&self.status) {
            Ok(status)
        } else {
            Err(ServiceError::InvalidOrderStatus)
        }
    }

    /// Compare the status of the order
    pub fn check_status(&self, status: Status) -> Result<(), CantDoReason> {
        match Status::from_str(&self.status) {
            Ok(s) => match s == status {
                true => Ok(()),
                false => Err(CantDoReason::InvalidOrderStatus),
            },
            Err(_) => Err(CantDoReason::InvalidOrderStatus),
        }
    }

    /// Check if the order is a buy order
    pub fn is_buy_order(&self) -> Result<(), CantDoReason> {
        if self.kind != Kind::Buy.to_string() {
            return Err(CantDoReason::InvalidOrderKind);
        }
        Ok(())
    }
    /// Check if the order is a sell order
    pub fn is_sell_order(&self) -> Result<(), CantDoReason> {
        if self.kind != Kind::Sell.to_string() {
            return Err(CantDoReason::InvalidOrderKind);
        }
        Ok(())
    }

    /// Check if the sender is the creator of the order
    pub fn sent_from_maker(&self, sender: PublicKey) -> Result<(), CantDoReason> {
        let sender = sender.to_string();
        if self.creator_pubkey != sender {
            return Err(CantDoReason::InvalidPubkey);
        }
        Ok(())
    }

    /// Check if the sender is the creator of the order
    pub fn not_sent_from_maker(&self, sender: PublicKey) -> Result<(), CantDoReason> {
        let sender = sender.to_string();
        if self.creator_pubkey == sender {
            return Err(CantDoReason::InvalidPubkey);
        }
        Ok(())
    }

    /// Get the creator pubkey
    pub fn get_creator_pubkey(&self) -> Result<PublicKey, ServiceError> {
        match PublicKey::from_str(self.creator_pubkey.as_ref()) {
            Ok(pk) => Ok(pk),
            Err(_) => Err(ServiceError::InvalidPubkey),
        }
    }

    /// Get the buyer pubkey
    pub fn get_buyer_pubkey(&self) -> Result<PublicKey, ServiceError> {
        if let Some(pk) = self.buyer_pubkey.as_ref() {
            PublicKey::from_str(pk).map_err(|_| ServiceError::InvalidPubkey)
        } else {
            Err(ServiceError::InvalidPubkey)
        }
    }
    /// Get the seller pubkey
    pub fn get_seller_pubkey(&self) -> Result<PublicKey, ServiceError> {
        if let Some(pk) = self.seller_pubkey.as_ref() {
            PublicKey::from_str(pk).map_err(|_| ServiceError::InvalidPubkey)
        } else {
            Err(ServiceError::InvalidPubkey)
        }
    }
    /// Get the master buyer pubkey
    pub fn get_master_buyer_pubkey(
        &self,
        password: Option<&SecretString>,
    ) -> Result<String, ServiceError> {
        if let Some(pk) = self.master_buyer_pubkey.as_ref() {
            CryptoUtils::decrypt_data(pk.clone(), password).map_err(|_| ServiceError::InvalidPubkey)
        } else {
            Err(ServiceError::InvalidPubkey)
        }
    }
    /// Get the master seller pubkey
    pub fn get_master_seller_pubkey(
        &self,
        password: Option<&SecretString>,
    ) -> Result<String, ServiceError> {
        if let Some(pk) = self.master_seller_pubkey.as_ref() {
            CryptoUtils::decrypt_data(pk.clone(), password).map_err(|_| ServiceError::InvalidPubkey)
        } else {
            Err(ServiceError::InvalidPubkey)
        }
    }

    /// Check if the order is a range order
    pub fn is_range_order(&self) -> bool {
        self.min_amount.is_some() && self.max_amount.is_some()
    }

    pub fn count_failed_payment(&mut self, retries_number: i64) {
        if !self.failed_payment {
            self.failed_payment = true;
            self.payment_attempts = 0;
        } else if self.payment_attempts < retries_number {
            self.payment_attempts += 1;
        }
    }

    /// Check if the order has no amount
    pub fn has_no_amount(&self) -> bool {
        self.amount == 0
    }

    /// Set the timestamp to now
    pub fn set_timestamp_now(&mut self) {
        self.taken_at = Timestamp::now().as_u64() as i64
    }

    /// Check if a user is creating a full privacy order so he doesn't to have reputation
    /// compare master keys with the order keys if they are the same the user is in full privacy mode
    /// otherwise the user is not in normal mode and has a reputation
    pub fn is_full_privacy_order(
        &self,
        password: Option<&SecretString>,
    ) -> Result<(Option<String>, Option<String>), ServiceError> {
        let (mut normal_buyer_idkey, mut normal_seller_idkey) = (None, None);

        // Get master pubkeys to get users data from db
        let master_buyer_pubkey = self.get_master_buyer_pubkey(password).ok();
        let master_seller_pubkey = self.get_master_seller_pubkey(password).ok();

        // Check if the buyer is in full privacy mode
        if self.buyer_pubkey.as_ref() != master_buyer_pubkey.as_ref() {
            normal_buyer_idkey = master_buyer_pubkey;
        }

        // Check if the seller is in full privacy mode
        if self.seller_pubkey.as_ref() != master_seller_pubkey.as_ref() {
            normal_seller_idkey = master_seller_pubkey;
        }

        Ok((normal_buyer_idkey, normal_seller_idkey))
    }
    /// Setup the dispute status
    ///
    /// If the pubkey is the buyer, set the buyer dispute to true
    /// If the pubkey is the seller, set the seller dispute to true
    pub fn setup_dispute(&mut self, is_buyer_dispute: bool) -> Result<(), CantDoReason> {
        // Get the opposite dispute status
        let is_seller_dispute = !is_buyer_dispute;

        // Update dispute flags based on who initiated
        let mut update_seller_dispute = false;
        let mut update_buyer_dispute = false;

        if is_seller_dispute && !self.seller_dispute {
            update_seller_dispute = true;
            self.seller_dispute = update_seller_dispute;
        } else if is_buyer_dispute && !self.buyer_dispute {
            update_buyer_dispute = true;
            self.buyer_dispute = update_buyer_dispute;
        };
        // Set the status to dispute
        self.status = Status::Dispute.to_string();

        // Update the database with dispute information
        // Save the dispute to DB
        if !update_buyer_dispute && !update_seller_dispute {
            return Err(CantDoReason::DisputeCreationError);
        }

        Ok(())
    }
}

/// We use this struct to create a new order
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SmallOrder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    pub kind: Option<Kind>,
    pub status: Option<Status>,
    pub amount: i64,
    pub fiat_code: String,
    pub min_amount: Option<i64>,
    pub max_amount: Option<i64>,
    pub fiat_amount: i64,
    pub payment_method: String,
    pub premium: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_trade_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seller_trade_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_invoice: Option<String>,
    pub created_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub buyer_token: Option<u16>,
    pub seller_token: Option<u16>,
}

#[allow(dead_code)]
impl SmallOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Option<Uuid>,
        kind: Option<Kind>,
        status: Option<Status>,
        amount: i64,
        fiat_code: String,
        min_amount: Option<i64>,
        max_amount: Option<i64>,
        fiat_amount: i64,
        payment_method: String,
        premium: i64,
        buyer_trade_pubkey: Option<String>,
        seller_trade_pubkey: Option<String>,
        buyer_invoice: Option<String>,
        created_at: Option<i64>,
        expires_at: Option<i64>,
        buyer_token: Option<u16>,
        seller_token: Option<u16>,
    ) -> Self {
        Self {
            id,
            kind,
            status,
            amount,
            fiat_code,
            min_amount,
            max_amount,
            fiat_amount,
            payment_method,
            premium,
            buyer_trade_pubkey,
            seller_trade_pubkey,
            buyer_invoice,
            created_at,
            expires_at,
            buyer_token,
            seller_token,
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

    /// Get the amount of sats or the string "Market price"
    pub fn sats_amount(&self) -> String {
        if self.amount == 0 {
            "Market price".to_string()
        } else {
            self.amount.to_string()
        }
    }
    /// Check if the order has a zero amount and a premium or fiat amount
    pub fn check_zero_amount_with_premium(&self) -> Result<(), CantDoReason> {
        let premium = (self.premium != 0).then_some(self.premium);
        let sats_amount = (self.amount != 0).then_some(self.amount);

        if premium.is_some() && sats_amount.is_some() {
            return Err(CantDoReason::InvalidParameters);
        }
        Ok(())
    }
    /// Check if the order is a range order and if the amount is zero
    pub fn check_range_order_limits(&self, amounts: &mut Vec<i64>) -> Result<(), CantDoReason> {
        // Check if the min and max amount are valid and update the vector
        if let (Some(min), Some(max)) = (self.min_amount, self.max_amount) {
            if min < 0 || max < 0 {
                return Err(CantDoReason::InvalidAmount);
            }
            if min >= max {
                return Err(CantDoReason::InvalidAmount);
            }
            if self.amount != 0 {
                return Err(CantDoReason::InvalidAmount);
            }
            amounts.clear();
            amounts.push(min);
            amounts.push(max);
        }
        Ok(())
    }
}

impl From<Order> for SmallOrder {
    fn from(order: Order) -> Self {
        let id = Some(order.id);
        let kind = Kind::from_str(&order.kind).unwrap();
        let status = Status::from_str(&order.status).unwrap();
        let amount = order.amount;
        let fiat_code = order.fiat_code.clone();
        let min_amount = order.min_amount;
        let max_amount = order.max_amount;
        let fiat_amount = order.fiat_amount;
        let payment_method = order.payment_method.clone();
        let premium = order.premium;
        let buyer_trade_pubkey = order.buyer_pubkey.clone();
        let seller_trade_pubkey = order.seller_pubkey.clone();
        let buyer_invoice = order.buyer_invoice.clone();

        Self {
            id,
            kind: Some(kind),
            status: Some(status),
            amount,
            fiat_code,
            min_amount,
            max_amount,
            fiat_amount,
            payment_method,
            premium,
            buyer_trade_pubkey,
            seller_trade_pubkey,
            buyer_invoice,
            created_at: None,
            expires_at: None,
            buyer_token: None,
            seller_token: None,
        }
    }
}
