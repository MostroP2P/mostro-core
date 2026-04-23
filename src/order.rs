//! Orders and their lifecycle.
//!
//! [`Order`] is the database-backed record for a trade between a buyer and a
//! seller on Mostro. Orders have a [`Kind`] (buy or sell) and a [`Status`]
//! that evolves through a small state machine as the trade progresses.
//!
//! [`SmallOrder`] is a compact, wire-friendly view of an order used when
//! broadcasting via Nostr or surfacing minimal information to clients.

use crate::prelude::*;
use nostr_sdk::{PublicKey, Timestamp};
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::FromRow;
#[cfg(feature = "sqlx")]
use sqlx_crud::SqlxCrud;
use std::{fmt::Display, str::FromStr};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

/// Direction of an order: the maker wants to buy or sell sats.
#[wasm_bindgen]
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// The maker wants to buy sats in exchange for fiat.
    Buy,
    /// The maker wants to sell sats in exchange for fiat.
    Sell,
}

impl FromStr for Kind {
    type Err = ();

    /// Parse a [`Kind`] from `"buy"` or `"sell"` (case-insensitive).
    ///
    /// Returns `Err(())` for any other input.
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

/// Lifecycle status of an [`Order`].
///
/// Values are serialized in `kebab-case`, matching the representation stored
/// in the database and sent over the wire.
#[wasm_bindgen]
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Order is published and available to be taken.
    Active,
    /// Order was canceled by the maker or the taker.
    Canceled,
    /// Order was canceled by an admin.
    CanceledByAdmin,
    /// Order was settled by an admin (solver) after a dispute.
    SettledByAdmin,
    /// Order was completed by an admin after a dispute.
    CompletedByAdmin,
    /// Order is currently in dispute.
    Dispute,
    /// Order expired before being taken or completed.
    Expired,
    /// Buyer has marked fiat as sent; waiting for the seller to release.
    FiatSent,
    /// Hold invoice has been settled; payment to the buyer is in flight.
    SettledHoldInvoice,
    /// Order has been created but not yet published.
    Pending,
    /// Trade completed successfully.
    Success,
    /// Waiting for the buyer's payout invoice.
    WaitingBuyerInvoice,
    /// Waiting for the seller to pay the hold invoice.
    WaitingPayment,
    /// Both parties agreed to cooperatively cancel the trade.
    CooperativelyCanceled,
    /// Order has been taken and the trade is in progress.
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
/// Persistent representation of a Mostro order.
///
/// This is the canonical on-disk record kept by a Mostro node. All fields
/// are stored so an order can be recomputed / restarted from its row alone;
/// clients usually work with the lighter [`SmallOrder`] view.
///
/// Timestamps are Unix seconds; `hash` / `preimage` refer to the hold
/// invoice used to lock the seller's funds.
#[cfg_attr(feature = "sqlx", derive(FromRow, SqlxCrud), external_id)]
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Order {
    /// Unique order identifier.
    pub id: Uuid,
    /// Order kind ([`Kind::Buy`] or [`Kind::Sell`]), serialized as
    /// kebab-case.
    pub kind: String,
    /// Nostr event id of the order publication.
    pub event_id: String,
    /// Payment hash of the seller's hold invoice, once generated.
    pub hash: Option<String>,
    /// Preimage revealed when the hold invoice is settled.
    pub preimage: Option<String>,
    /// Trade public key of the order creator (maker).
    pub creator_pubkey: String,
    /// Trade public key of the party who initiated a cancel, if any.
    pub cancel_initiator_pubkey: Option<String>,
    /// Buyer trade public key.
    pub buyer_pubkey: Option<String>,
    /// Buyer master identity pubkey. Equal to `buyer_pubkey` when the
    /// buyer operates in full-privacy mode.
    pub master_buyer_pubkey: Option<String>,
    /// Seller trade public key.
    pub seller_pubkey: Option<String>,
    /// Seller master identity pubkey. Equal to `seller_pubkey` when the
    /// seller operates in full-privacy mode.
    pub master_seller_pubkey: Option<String>,
    /// Current [`Status`] of the order, serialized as kebab-case.
    pub status: String,
    /// `true` if the sats amount was computed from a live market price.
    pub price_from_api: bool,
    /// Premium percentage applied on top of the spot price.
    pub premium: i64,
    /// Free-form payment method description (e.g. "SEPA,Bank transfer").
    pub payment_method: String,
    /// Sats amount. `0` means the amount is computed at take-time from the
    /// fiat amount and the current market price.
    pub amount: i64,
    /// Lower bound of a range order (fiat amount). `None` for fixed orders.
    pub min_amount: Option<i64>,
    /// Upper bound of a range order (fiat amount). `None` for fixed orders.
    pub max_amount: Option<i64>,
    /// `true` when the buyer has initiated a dispute on this order.
    pub buyer_dispute: bool,
    /// `true` when the seller has initiated a dispute on this order.
    pub seller_dispute: bool,
    /// `true` when the buyer has initiated a cooperative cancel.
    pub buyer_cooperativecancel: bool,
    /// `true` when the seller has initiated a cooperative cancel.
    pub seller_cooperativecancel: bool,
    /// Mostro fee charged for this trade, in sats.
    pub fee: i64,
    /// Lightning routing fee observed when paying the buyer.
    pub routing_fee: i64,
    /// Optional developer-fee portion of `fee`.
    pub dev_fee: i64,
    /// `true` once the developer fee has been paid out.
    pub dev_fee_paid: bool,
    /// Payment hash of the developer-fee payment, when available.
    pub dev_fee_payment_hash: Option<String>,
    /// Fiat currency code (e.g. "EUR", "USD").
    pub fiat_code: String,
    /// Fiat amount of the trade.
    pub fiat_amount: i64,
    /// Buyer's Lightning payout invoice, once provided.
    pub buyer_invoice: Option<String>,
    /// Parent order id for orders derived from a range parent.
    pub range_parent_id: Option<Uuid>,
    /// Unix timestamp (seconds) when the hold invoice was locked in.
    pub invoice_held_at: i64,
    /// Unix timestamp (seconds) when the order was taken.
    pub taken_at: i64,
    /// Unix timestamp (seconds) when the order was created.
    pub created_at: i64,
    /// `true` once the buyer has rated the counterpart.
    pub buyer_sent_rate: bool,
    /// `true` once the seller has rated the counterpart.
    pub seller_sent_rate: bool,
    /// `true` if the latest payment attempt to the buyer failed.
    pub failed_payment: bool,
    /// Number of payment attempts performed so far.
    pub payment_attempts: i64,
    /// Unix timestamp (seconds) when the order expires automatically.
    pub expires_at: i64,
    /// Trade index used by the seller when creating / taking the order.
    pub trade_index_seller: Option<i64>,
    /// Trade index used by the buyer when creating / taking the order.
    pub trade_index_buyer: Option<i64>,
    /// Trade public key announced by a range-order maker for the next
    /// trade in the same range.
    pub next_trade_pubkey: Option<String>,
    /// Trade index announced by a range-order maker for the next trade.
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
            dev_fee: 0,
            dev_fee_paid: false,
            dev_fee_payment_hash: None,
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
    /// Build a [`SmallOrder`] suitable for broadcasting as a new order event.
    ///
    /// Copies the tradable fields (amounts, payment method, premium, etc.)
    /// from `self`. Trade pubkeys are left unset because a new order is
    /// published before a counterpart is assigned.
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
        )
    }
    /// Parse the order kind from the string-encoded field.
    ///
    /// Returns [`ServiceError::InvalidOrderKind`] when `self.kind` does not
    /// match a known [`Kind`] variant.
    pub fn get_order_kind(&self) -> Result<Kind, ServiceError> {
        if let Ok(kind) = Kind::from_str(&self.kind) {
            Ok(kind)
        } else {
            Err(ServiceError::InvalidOrderKind)
        }
    }

    /// Parse the order status from the string-encoded field.
    ///
    /// Returns [`ServiceError::InvalidOrderStatus`] when `self.status` does
    /// not match a known [`Status`] variant.
    pub fn get_order_status(&self) -> Result<Status, ServiceError> {
        if let Ok(status) = Status::from_str(&self.status) {
            Ok(status)
        } else {
            Err(ServiceError::InvalidOrderStatus)
        }
    }

    /// Check that the order is currently in a specific [`Status`].
    ///
    /// Returns `Ok(())` on match and [`CantDoReason::InvalidOrderStatus`]
    /// either on mismatch or when the stored status cannot be parsed.
    pub fn check_status(&self, status: Status) -> Result<(), CantDoReason> {
        match Status::from_str(&self.status) {
            Ok(s) => match s == status {
                true => Ok(()),
                false => Err(CantDoReason::InvalidOrderStatus),
            },
            Err(_) => Err(CantDoReason::InvalidOrderStatus),
        }
    }

    /// Assert that the order is a [`Kind::Buy`] order.
    pub fn is_buy_order(&self) -> Result<(), CantDoReason> {
        if self.kind != Kind::Buy.to_string() {
            return Err(CantDoReason::InvalidOrderKind);
        }
        Ok(())
    }
    /// Assert that the order is a [`Kind::Sell`] order.
    pub fn is_sell_order(&self) -> Result<(), CantDoReason> {
        if self.kind != Kind::Sell.to_string() {
            return Err(CantDoReason::InvalidOrderKind);
        }
        Ok(())
    }

    /// Assert that `sender` is the maker (creator) of the order.
    ///
    /// Returns [`CantDoReason::InvalidPubkey`] when the pubkeys differ.
    pub fn sent_from_maker(&self, sender: PublicKey) -> Result<(), CantDoReason> {
        let sender = sender.to_string();
        if self.creator_pubkey != sender {
            return Err(CantDoReason::InvalidPubkey);
        }
        Ok(())
    }

    /// Assert that `sender` is **not** the maker of the order.
    ///
    /// Returns [`CantDoReason::InvalidPubkey`] when `sender` matches
    /// `self.creator_pubkey`.
    pub fn not_sent_from_maker(&self, sender: PublicKey) -> Result<(), CantDoReason> {
        let sender = sender.to_string();
        if self.creator_pubkey == sender {
            return Err(CantDoReason::InvalidPubkey);
        }
        Ok(())
    }

    /// Parse the maker's public key as a Nostr [`PublicKey`].
    pub fn get_creator_pubkey(&self) -> Result<PublicKey, ServiceError> {
        match PublicKey::from_str(self.creator_pubkey.as_ref()) {
            Ok(pk) => Ok(pk),
            Err(_) => Err(ServiceError::InvalidPubkey),
        }
    }

    /// Parse the buyer trade public key.
    ///
    /// Returns [`ServiceError::InvalidPubkey`] when the field is absent or
    /// cannot be parsed.
    pub fn get_buyer_pubkey(&self) -> Result<PublicKey, ServiceError> {
        if let Some(pk) = self.buyer_pubkey.as_ref() {
            PublicKey::from_str(pk).map_err(|_| ServiceError::InvalidPubkey)
        } else {
            Err(ServiceError::InvalidPubkey)
        }
    }
    /// Parse the seller trade public key.
    ///
    /// Returns [`ServiceError::InvalidPubkey`] when the field is absent or
    /// cannot be parsed.
    pub fn get_seller_pubkey(&self) -> Result<PublicKey, ServiceError> {
        if let Some(pk) = self.seller_pubkey.as_ref() {
            PublicKey::from_str(pk).map_err(|_| ServiceError::InvalidPubkey)
        } else {
            Err(ServiceError::InvalidPubkey)
        }
    }
    /// Parse the buyer master identity public key.
    pub fn get_master_buyer_pubkey(&self) -> Result<PublicKey, ServiceError> {
        if let Some(pk) = self.master_buyer_pubkey.as_ref() {
            PublicKey::from_str(pk).map_err(|_| ServiceError::InvalidPubkey)
        } else {
            Err(ServiceError::InvalidPubkey)
        }
    }
    /// Parse the seller master identity public key.
    pub fn get_master_seller_pubkey(&self) -> Result<PublicKey, ServiceError> {
        if let Some(pk) = self.master_seller_pubkey.as_ref() {
            PublicKey::from_str(pk).map_err(|_| ServiceError::InvalidPubkey)
        } else {
            Err(ServiceError::InvalidPubkey)
        }
    }

    /// `true` when both `min_amount` and `max_amount` are set, i.e. this is
    /// a range order.
    pub fn is_range_order(&self) -> bool {
        self.min_amount.is_some() && self.max_amount.is_some()
    }

    /// Increment the payment-failure counter.
    ///
    /// On the first failure, sets [`Self::failed_payment`] to `true` and
    /// [`Self::payment_attempts`] to `1`. On subsequent failures the counter
    /// is bumped, capped at `retries_number`.
    pub fn count_failed_payment(&mut self, retries_number: i64) {
        if !self.failed_payment {
            self.failed_payment = true;
            self.payment_attempts = 1;
        } else if self.payment_attempts < retries_number {
            self.payment_attempts += 1;
        }
    }

    /// `true` when `amount == 0`, meaning the sats amount is not fixed and
    /// will be computed from the fiat amount and market price.
    pub fn has_no_amount(&self) -> bool {
        self.amount == 0
    }

    /// Set [`Self::taken_at`] to the current Unix timestamp.
    pub fn set_timestamp_now(&mut self) {
        self.taken_at = Timestamp::now().as_secs() as i64
    }

    /// Compare the trade pubkeys against the master pubkeys to detect which
    /// sides of the trade are operating in full privacy mode.
    ///
    /// Returns a `(buyer_normal_idkey, seller_normal_idkey)` tuple. Each
    /// value is `Some(master_pubkey)` when that side is running in normal
    /// mode (trade key differs from master key, so the user is willing to
    /// associate the trade with its reputation); `None` when the side is in
    /// full privacy mode.
    pub fn is_full_privacy_order(&self) -> Result<(Option<String>, Option<String>), ServiceError> {
        let (mut normal_buyer_idkey, mut normal_seller_idkey) = (None, None);

        // Get master pubkeys to get users data from db
        let master_buyer_pubkey = self.get_master_buyer_pubkey().ok();
        let master_seller_pubkey = self.get_master_seller_pubkey().ok();

        // Check if the buyer is in full privacy mode
        if self.buyer_pubkey != master_buyer_pubkey.map(|pk| pk.to_string()) {
            normal_buyer_idkey = master_buyer_pubkey.map(|pk| pk.to_string());
        }

        // Check if the seller is in full privacy mode
        if self.seller_pubkey != master_seller_pubkey.map(|pk| pk.to_string()) {
            normal_seller_idkey = master_seller_pubkey.map(|pk| pk.to_string());
        }

        Ok((normal_buyer_idkey, normal_seller_idkey))
    }
    /// Mark the order as in dispute and record which side initiated it.
    ///
    /// When `is_buyer_dispute` is `true` the buyer flag is set, otherwise
    /// the seller flag. The order status is then transitioned to
    /// [`Status::Dispute`]. Returns
    /// [`CantDoReason::DisputeCreationError`] when the appropriate flag was
    /// already set (avoids registering the same dispute twice).
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

/// Compact, wire-friendly view of an order.
///
/// `SmallOrder` carries the fields needed to publish a new order or to show
/// a listing entry to a client, without the bookkeeping fields kept in
/// [`Order`] (hold invoice hash, fees, dispute flags, etc.). It is the shape
/// used by [`Payload::Order`] and siblings.
///
/// Unknown fields are rejected at deserialization time (`deny_unknown_fields`).
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SmallOrder {
    /// Order id. `None` for orders that have not been persisted yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Order kind.
    pub kind: Option<Kind>,
    /// Current status.
    pub status: Option<Status>,
    /// Sats amount. `0` when the sats amount is derived from the fiat
    /// amount and live market price.
    pub amount: i64,
    /// Fiat currency code (e.g. "EUR").
    pub fiat_code: String,
    /// Lower bound of a range order (fiat amount).
    pub min_amount: Option<i64>,
    /// Upper bound of a range order (fiat amount).
    pub max_amount: Option<i64>,
    /// Fiat amount of the trade.
    pub fiat_amount: i64,
    /// Free-form payment method description.
    pub payment_method: String,
    /// Premium percentage applied on top of the spot price.
    pub premium: i64,
    /// Buyer trade public key, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_trade_pubkey: Option<String>,
    /// Seller trade public key, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seller_trade_pubkey: Option<String>,
    /// Buyer's Lightning payout invoice, when already provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_invoice: Option<String>,
    /// Unix timestamp (seconds) when the order was created.
    pub created_at: Option<i64>,
    /// Unix timestamp (seconds) when the order expires automatically.
    pub expires_at: Option<i64>,
}

#[allow(dead_code)]
impl SmallOrder {
    /// Construct a new [`SmallOrder`] from all of its fields.
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
        }
    }
    /// Parse a [`SmallOrder`] from its JSON representation.
    pub fn from_json(json: &str) -> Result<Self, ServiceError> {
        serde_json::from_str(json).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Serialize the order to a JSON string.
    pub fn as_json(&self) -> Result<String, ServiceError> {
        serde_json::to_string(&self).map_err(|_| ServiceError::MessageSerializationError)
    }

    /// Return the sats amount as a string, or the literal `"Market price"`
    /// when the amount is `0` (to be computed at take-time).
    pub fn sats_amount(&self) -> String {
        if self.amount == 0 {
            "Market price".to_string()
        } else {
            self.amount.to_string()
        }
    }
    /// Assert that the fiat amount is strictly positive.
    ///
    /// Returns [`CantDoReason::InvalidAmount`] otherwise.
    pub fn check_fiat_amount(&self) -> Result<(), CantDoReason> {
        if self.fiat_amount <= 0 {
            return Err(CantDoReason::InvalidAmount);
        }
        Ok(())
    }

    /// Assert that the sats amount is non-negative.
    ///
    /// A value of `0` is explicitly accepted because it signals that the
    /// sats amount will be derived from the fiat amount and the market
    /// price at take-time. Returns [`CantDoReason::InvalidAmount`] when the
    /// amount is negative.
    pub fn check_amount(&self) -> Result<(), CantDoReason> {
        if self.amount < 0 {
            return Err(CantDoReason::InvalidAmount);
        }
        Ok(())
    }

    /// Reject orders that set both `amount` and `premium` at the same time.
    ///
    /// A premium only makes sense when the sats amount is market-priced;
    /// combining a fixed sats amount with a premium is ambiguous and
    /// returns [`CantDoReason::InvalidParameters`].
    pub fn check_zero_amount_with_premium(&self) -> Result<(), CantDoReason> {
        let premium = (self.premium != 0).then_some(self.premium);
        let sats_amount = (self.amount != 0).then_some(self.amount);

        if premium.is_some() && sats_amount.is_some() {
            return Err(CantDoReason::InvalidParameters);
        }
        Ok(())
    }

    /// Validate the bounds of a range order and push them into `amounts`.
    ///
    /// When both `min_amount` and `max_amount` are set, they must be
    /// non-negative, `min < max`, and `amount` must be `0` (range orders
    /// cannot fix the sats amount). On success, `amounts` is cleared and
    /// replaced with `[min, max]`. On failure returns
    /// [`CantDoReason::InvalidAmount`].
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

    /// Verify that the order's fiat code appears in the list of accepted
    /// currencies.
    ///
    /// An empty allowlist disables the check (every currency is accepted).
    /// Returns [`CantDoReason::InvalidFiatCurrency`] when the currency is
    /// not allowed.
    pub fn check_fiat_currency(
        &self,
        fiat_currencies_accepted: &[String],
    ) -> Result<(), CantDoReason> {
        if !fiat_currencies_accepted.contains(&self.fiat_code)
            && !fiat_currencies_accepted.is_empty()
        {
            return Err(CantDoReason::InvalidFiatCurrency);
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
            created_at: Some(order.created_at),
            expires_at: Some(order.expires_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CantDoReason;
    use nostr_sdk::Keys;
    use uuid::uuid;

    #[test]
    fn test_status_string() {
        assert_eq!(Status::Active.to_string(), "active");
        assert_eq!(Status::CompletedByAdmin.to_string(), "completed-by-admin");
        assert_eq!(Status::FiatSent.to_string(), "fiat-sent");
        assert_ne!(Status::Pending.to_string(), "Pending");
    }

    #[test]
    fn test_kind_string() {
        assert_ne!(Kind::Sell.to_string(), "active");
        assert_eq!(Kind::Sell.to_string(), "sell");
        assert_eq!(Kind::Buy.to_string(), "buy");
        assert_ne!(Kind::Buy.to_string(), "active");
    }

    #[test]
    fn test_order_message() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let payment_methods = "SEPA,Bank transfer".to_string();
        let payload = Payload::Order(SmallOrder::new(
            Some(uuid),
            Some(Kind::Sell),
            Some(Status::Pending),
            100,
            "eur".to_string(),
            None,
            None,
            100,
            payment_methods,
            1,
            None,
            None,
            None,
            Some(1627371434),
            None,
        ));

        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::NewOrder,
            Some(payload),
        ));
        let test_message_json = test_message.as_json().unwrap();
        let sample_message = r#"{"order":{"version":1,"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","request_id":1,"trade_index":2,"action":"new-order","payload":{"order":{"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","kind":"sell","status":"pending","amount":100,"fiat_code":"eur","fiat_amount":100,"payment_method":"SEPA,Bank transfer","premium":1,"created_at":1627371434}}}}"#;
        let message = Message::from_json(sample_message).unwrap();
        assert!(message.verify());
        let message_json = message.as_json().unwrap();
        assert_eq!(message_json, test_message_json);
    }

    #[test]
    fn test_payment_request_payload_message() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(3),
            Action::PayInvoice,
            Some(Payload::PaymentRequest(
                Some(SmallOrder::new(
                    Some(uuid),
                    Some(Kind::Sell),
                    Some(Status::WaitingPayment),
                    100,
                    "eur".to_string(),
                    None,
                    None,
                    100,
                    "Face to face".to_string(),
                    1,
                    None,
                    None,
                    None,
                    Some(1627371434),
                    None,
                )),
                "lnbcrt78510n1pj59wmepp50677g8tffdqa2p8882y0x6newny5vtz0hjuyngdwv226nanv4uzsdqqcqzzsxqyz5vqsp5skn973360gp4yhlpmefwvul5hs58lkkl3u3ujvt57elmp4zugp4q9qyyssqw4nzlr72w28k4waycf27qvgzc9sp79sqlw83j56txltz4va44j7jda23ydcujj9y5k6k0rn5ms84w8wmcmcyk5g3mhpqepf7envhdccp72nz6e".to_string(),
                None,
            )),
        ));
        let sample_message = r#"{"order":{"version":1,"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","request_id":1,"trade_index":3,"action":"pay-invoice","payload":{"payment_request":[{"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","kind":"sell","status":"waiting-payment","amount":100,"fiat_code":"eur","fiat_amount":100,"payment_method":"Face to face","premium":1,"created_at":1627371434},"lnbcrt78510n1pj59wmepp50677g8tffdqa2p8882y0x6newny5vtz0hjuyngdwv226nanv4uzsdqqcqzzsxqyz5vqsp5skn973360gp4yhlpmefwvul5hs58lkkl3u3ujvt57elmp4zugp4q9qyyssqw4nzlr72w28k4waycf27qvgzc9sp79sqlw83j56txltz4va44j7jda23ydcujj9y5k6k0rn5ms84w8wmcmcyk5g3mhpqepf7envhdccp72nz6e",null]}}}"#;
        let message = Message::from_json(sample_message).unwrap();
        assert!(message.verify());
        let message_json = message.as_json().unwrap();
        let test_message_json = test_message.as_json().unwrap();
        assert_eq!(message_json, test_message_json);
    }

    #[test]
    fn test_message_payload_signature() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let peer = Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            None,
        );
        let payload = Payload::Peer(peer);
        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::FiatSentOk,
            Some(payload),
        ));
        assert!(test_message.verify());
        let test_message_json = test_message.as_json().unwrap();
        // Message should be signed with the trade keys
        let trade_keys =
            Keys::parse("110e43647eae221ab1da33ddc17fd6ff423f2b2f49d809b9ffa40794a2ab996c")
                .unwrap();
        let sig = Message::sign(test_message_json.clone(), &trade_keys);

        assert!(Message::verify_signature(
            test_message_json,
            trade_keys.public_key(),
            sig
        ));
    }

    #[test]
    fn test_cant_do_message_serialization() {
        // Test all CantDoReason variants
        let reasons = vec![
            CantDoReason::InvalidSignature,
            CantDoReason::InvalidTradeIndex,
            CantDoReason::InvalidAmount,
            CantDoReason::InvalidInvoice,
            CantDoReason::InvalidPaymentRequest,
            CantDoReason::InvalidPeer,
            CantDoReason::InvalidRating,
            CantDoReason::InvalidTextMessage,
            CantDoReason::InvalidOrderStatus,
            CantDoReason::InvalidPubkey,
            CantDoReason::InvalidParameters,
            CantDoReason::OrderAlreadyCanceled,
            CantDoReason::CantCreateUser,
            CantDoReason::IsNotYourOrder,
            CantDoReason::NotAllowedByStatus,
            CantDoReason::OutOfRangeFiatAmount,
            CantDoReason::OutOfRangeSatsAmount,
            CantDoReason::IsNotYourDispute,
            CantDoReason::NotFound,
            CantDoReason::InvalidFiatCurrency,
            CantDoReason::TooManyRequests,
        ];

        for reason in reasons {
            let cant_do = Message::CantDo(MessageKind::new(
                None,
                None,
                None,
                Action::CantDo,
                Some(Payload::CantDo(Some(reason.clone()))),
            ));
            let message = Message::from_json(&cant_do.as_json().unwrap()).unwrap();
            assert!(message.verify());
            assert_eq!(message.as_json().unwrap(), cant_do.as_json().unwrap());
        }

        // Test None case
        let cant_do = Message::CantDo(MessageKind::new(
            None,
            None,
            None,
            Action::CantDo,
            Some(Payload::CantDo(None)),
        ));
        let message = Message::from_json(&cant_do.as_json().unwrap()).unwrap();
        assert!(message.verify());
        assert_eq!(message.as_json().unwrap(), cant_do.as_json().unwrap());
    }

    // === check_fiat_amount tests ===

    #[test]
    fn test_check_fiat_amount_valid() {
        // id, kind, status, amount, fiat_code, min_amount, max_amount, fiat_amount, payment_method, premium, buyer_pubkey, seller_pubkey, buyer_invoice, created_at, expires_at
        let order = SmallOrder::new(
            None,
            None,
            None,
            100,
            "VES".to_string(),
            None,
            None,
            500,
            "Bank".to_string(),
            1,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(order.check_fiat_amount().is_ok());
    }

    #[test]
    fn test_check_fiat_amount_zero() {
        let order = SmallOrder::new(
            None,
            None,
            None,
            100,
            "VES".to_string(),
            None,
            None,
            0,
            "Bank".to_string(),
            1,
            None,
            None,
            None,
            None,
            None,
        );
        let result = order.check_fiat_amount();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CantDoReason::InvalidAmount);
    }

    #[test]
    fn test_check_fiat_amount_negative() {
        let order = SmallOrder::new(
            None,
            None,
            None,
            100,
            "VES".to_string(),
            None,
            None,
            -100,
            "Bank".to_string(),
            1,
            None,
            None,
            None,
            None,
            None,
        );
        let result = order.check_fiat_amount();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CantDoReason::InvalidAmount);
    }

    // === check_amount tests ===

    #[test]
    fn test_check_amount_valid() {
        // amount = 100000 (positive, valid sats)
        let order = SmallOrder::new(
            None,
            None,
            None,
            100000,
            "VES".to_string(),
            None,
            None,
            500,
            "Bank".to_string(),
            0,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(order.check_amount().is_ok());
    }

    #[test]
    fn test_check_amount_zero() {
        // amount = 0 is valid (seller sets exact sats amount)
        let order = SmallOrder::new(
            None,
            None,
            None,
            0,
            "VES".to_string(),
            None,
            None,
            500,
            "Bank".to_string(),
            0,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(order.check_amount().is_ok());
    }

    #[test]
    fn test_check_amount_negative() {
        // amount = -1000 (negative, invalid)
        let order = SmallOrder::new(
            None,
            None,
            None,
            -1000,
            "VES".to_string(),
            None,
            None,
            500,
            "Bank".to_string(),
            0,
            None,
            None,
            None,
            None,
            None,
        );
        let result = order.check_amount();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CantDoReason::InvalidAmount);
    }
}
