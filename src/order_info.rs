//! Snapshot of one order for the admin and the solvers of a node.
//!
//! [`OrderInfo`] is the reply to [`Action::AdminOrderInfo`]: the real
//! state of an order as the node sees it, taken from its database and from
//! its Lightning node at the same moment. Database and Lightning values are
//! reported side by side and never merged, because the point of the query is
//! to see when they disagree.
//!
//! This module only models the answer. Deciding who may ask, when the
//! Lightning node is asked and which case applies is the daemon's job.
//!
//! # What it never carries
//!
//! [`OrderInfo`] is a dedicated struct. It does not embed [`SmallOrder`] or
//! [`SolverDisputeInfo`], and it has no field for a preimage, the buyer's
//! invoice, a bond payout invoice, a Cashu token or a master (identity)
//! pubkey, so a daemon cannot leak one by mistake.
//!
//! # Compatibility
//!
//! Every enum here has an `unknown` fallback, so a value added by a newer
//! daemon does not break an older client. Unknown JSON fields are ignored for
//! the same reason; new fields must be added with `#[serde(default)]`.

use crate::prelude::*;
use uuid::Uuid;

/// The real state of one order, carried by [`Payload::OrderInfo`].
///
/// The order fields come from the database and are always answered.
/// [`hold_invoice`](Self::hold_invoice) and [`payout`](Self::payout) come
/// from the Lightning node and are absent (`null`) when the order has no hash
/// to ask about. At most one of [`hold_invoice`](Self::hold_invoice) and
/// [`cashu_escrow`](Self::cashu_escrow) is present.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct OrderInfo {
    /// Order id.
    pub id: Uuid,
    /// Order kind, `buy` or `sell`. A string rather than [`Kind`] so the
    /// payload never fails on a value this build does not know.
    pub kind: String,
    /// Status stored in the database, in kebab-case. This is the real one,
    /// not the reduced status of the public order event. A string rather
    /// than [`Status`] so a status added later does not break older clients:
    /// parse it with `Status::from_str` and show the raw text when that
    /// fails.
    pub status: String,
    /// Sats amount.
    pub amount: i64,
    /// Mostro fee charged for this trade, in sats.
    pub fee: i64,
    /// Lightning routing fee observed when paying the buyer, in sats.
    pub routing_fee: i64,
    /// Fiat currency code (e.g. "EUR").
    pub fiat_code: String,
    /// Fiat amount of the trade.
    pub fiat_amount: i64,
    /// Lower bound of a range order (fiat amount). `None` for fixed orders.
    pub min_amount: Option<i64>,
    /// Upper bound of a range order (fiat amount). `None` for fixed orders.
    pub max_amount: Option<i64>,
    /// Free-form payment method description.
    pub payment_method: String,
    /// Premium percentage applied on top of the spot price.
    pub premium: i64,
    /// Parent order id when this order is a slice of a range order.
    pub range_parent_id: Option<Uuid>,
    /// Unix timestamp (seconds) when the order was created.
    pub created_at: i64,
    /// Unix timestamp (seconds) when the order was taken. `None` while
    /// nobody has taken it.
    pub taken_at: Option<i64>,
    /// Unix timestamp (seconds) when the order expires automatically.
    pub expires_at: i64,
    /// Buyer trade public key, when known. Never the master pubkey.
    pub buyer_trade_pubkey: Option<String>,
    /// Seller trade public key, when known. Never the master pubkey.
    pub seller_trade_pubkey: Option<String>,
    /// `true` when the buyer has initiated a dispute on this order.
    pub buyer_dispute: bool,
    /// `true` when the seller has initiated a dispute on this order.
    pub seller_dispute: bool,
    /// `true` when the buyer has initiated a cooperative cancel.
    pub buyer_cooperativecancel: bool,
    /// `true` when the seller has initiated a cooperative cancel.
    pub seller_cooperativecancel: bool,
    /// `true` if the latest payment attempt to the buyer failed. From the
    /// database, so it is answered even when [`payout`](Self::payout) is
    /// absent.
    pub failed_payment: bool,
    /// Number of payment attempts performed so far. From the database.
    pub payment_attempts: i64,
    /// Unix timestamp (seconds) when the seller's hold invoice was settled,
    /// from the database: since when the node holds the sats owed to the
    /// buyer. `None` while the escrow is not settled, and on orders settled
    /// by a daemon that did not record it yet.
    #[serde(default)]
    pub hold_settled_at: Option<i64>,
    /// The seller's hold invoice. `None` when the order has no hold invoice
    /// hash (none created yet, or a Cashu order).
    pub hold_invoice: Option<HoldInvoiceInfo>,
    /// The Cashu escrow, on a Cashu order. `None` on a Lightning order.
    pub cashu_escrow: Option<CashuEscrowInfo>,
    /// The payment to the buyer. `None` when there is no payment hash to ask
    /// the Lightning node about.
    pub payout: Option<PayoutInfo>,
    /// One entry per bond row of the order. Empty when the order has none.
    #[serde(default)]
    pub bonds: Vec<BondInfo>,
}

/// The seller's hold invoice, as the Lightning node reports it.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct HoldInvoiceInfo {
    /// State of the hold invoice at the Lightning node.
    pub state: HoldInvoiceState,
    /// Unix timestamp (seconds) when the hold invoice was locked in, from
    /// the database. `None` while the seller has not paid it.
    pub held_at: Option<i64>,
}

/// State of a hold invoice at the Lightning node.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HoldInvoiceState {
    /// Created and not paid yet.
    Open,
    /// The seller paid it: the funds are locked.
    Accepted,
    /// Settled: the funds were claimed.
    Settled,
    /// Canceled: the funds went back to the seller.
    Canceled,
    /// The Lightning node has no record of this hash.
    NotFound,
    /// The Lightning node could not be asked (error or timeout). The state
    /// is not known to the daemon.
    Unavailable,
    /// Catch-all for states this build of `mostro-core` does not know yet.
    /// Unlike [`HoldInvoiceState::Unavailable`], the daemon did answer.
    /// Never emitted by a daemon on purpose.
    #[serde(other)]
    Unknown,
}

/// The Cashu escrow of an order. Never carries the token.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct CashuEscrowInfo {
    /// URL of the Cashu mint hosting the escrow.
    pub mint_url: String,
    /// Unix timestamp (seconds) when the escrow token was validated and
    /// locked in. `None` until the escrow is locked.
    pub locked_at: Option<i64>,
}

/// The payment to the buyer, as the Lightning node reports it.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct PayoutInfo {
    /// State of the payment at the Lightning node.
    pub state: PayoutState,
    /// Why the payment failed, when the Lightning node reports a reason.
    pub failure_reason: Option<PayoutFailureReason>,
    /// Unix timestamp (seconds) when the payment reached its final state,
    /// when the Lightning node reports it.
    pub resolved_at: Option<i64>,
}

/// State of a payment at the Lightning node.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PayoutState {
    /// The payment is on its way and has no final result yet.
    InFlight,
    /// The buyer was paid.
    Succeeded,
    /// The payment failed. See [`PayoutInfo::failure_reason`].
    Failed,
    /// The Lightning node has no record of this hash.
    NotFound,
    /// The Lightning node could not be asked (error or timeout). The state
    /// is not known to the daemon.
    Unavailable,
    /// Catch-all for states this build of `mostro-core` does not know yet.
    /// Unlike [`PayoutState::Unavailable`], the daemon did answer. Never
    /// emitted by a daemon on purpose.
    #[serde(other)]
    Unknown,
}

/// Why a payment to the buyer failed, as the Lightning node reports it.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PayoutFailureReason {
    /// The payment timed out.
    Timeout,
    /// No route to the buyer was found.
    NoRoute,
    /// A non-recoverable error occurred.
    Error,
    /// The payment details were wrong (unknown hash, bad amount or bad
    /// final CLTV delta).
    IncorrectPaymentDetails,
    /// The node did not have enough balance to pay.
    InsufficientBalance,
    /// The payment was canceled.
    Canceled,
    /// A reason this build of `mostro-core` does not know yet, or one the
    /// daemon could not map to the reasons above.
    #[serde(other)]
    Unknown,
}

/// One bond row of an order.
///
/// A range order has a single maker bond, on the root order. A maker slash on
/// a slice and the refund of the unslashed remainder are separate rows; see
/// [`BondKind`].
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct BondInfo {
    /// Which side of the trade posted the bond.
    pub role: BondRole,
    /// Amount of this row, in sats.
    pub amount: i64,
    /// Current state of the row.
    pub state: BondState,
    /// Why the bond was slashed. `None` when it was not.
    pub slash_reason: Option<BondSlashReason>,
    /// Which kind of row this is.
    pub kind: BondKind,
    /// Id of the root order, when this bond belongs to the root of a range
    /// order and the requested order is one of its slices. `None` when the
    /// row belongs to the requested order itself.
    pub root_order_id: Option<Uuid>,
}

/// Which side of a trade a bond row represents.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BondRole {
    /// The order creator.
    Maker,
    /// The party who took the order.
    Taker,
    /// Catch-all for roles this build of `mostro-core` does not know yet.
    /// Never emitted by a daemon on purpose.
    #[serde(other)]
    Unknown,
}

/// Lifecycle state of a bond row.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BondState {
    /// The bond hold invoice was created and is waiting to be paid.
    Requested,
    /// The bonded party paid: the bond is locked.
    Locked,
    /// The bond went back to the bonded party.
    Released,
    /// The bond was slashed and its payout to the counterparty is pending.
    PendingPayout,
    /// The bond was slashed and paid out.
    Slashed,
    /// The bond was slashed and the counterparty never claimed the payout.
    Forfeited,
    /// The payout of a slashed bond failed and needs operator attention.
    Failed,
    /// Catch-all for states this build of `mostro-core` does not know yet.
    /// Never emitted by a daemon on purpose.
    #[serde(other)]
    Unknown,
}

/// Why a bond was slashed.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BondSlashReason {
    /// The bonded party lost a dispute.
    LostDispute,
    /// The bonded party let a waiting-state timeout elapse.
    Timeout,
    /// Catch-all for reasons this build of `mostro-core` does not know yet.
    /// Never emitted by a daemon on purpose.
    #[serde(other)]
    Unknown,
}

/// Which kind of bond row a [`BondInfo`] describes.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BondKind {
    /// The bond itself.
    Bond,
    /// A maker slash recorded against one slice of a range order.
    SliceSlash,
    /// The unslashed remainder returned to the maker of a range order.
    MakerRefund,
    /// Catch-all for kinds this build of `mostro-core` does not know yet.
    /// Never emitted by a daemon on purpose.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::{json, Value};
    use std::fmt::Debug;
    use uuid::uuid;

    /// A Lightning order with every part answered.
    fn full_order_info() -> OrderInfo {
        OrderInfo {
            id: uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23"),
            kind: "sell".to_string(),
            status: "settled-hold-invoice".to_string(),
            amount: 100_000,
            fee: 600,
            routing_fee: 12,
            fiat_code: "EUR".to_string(),
            fiat_amount: 50,
            min_amount: Some(10),
            max_amount: Some(100),
            payment_method: "SEPA".to_string(),
            premium: 1,
            range_parent_id: Some(uuid!("ede61c96-4c13-4519-bf3a-dcf7f1e9d842")),
            created_at: 1_700_000_000,
            taken_at: Some(1_700_000_100),
            expires_at: 1_700_086_400,
            buyer_trade_pubkey: Some("a".repeat(64)),
            seller_trade_pubkey: Some("b".repeat(64)),
            buyer_dispute: false,
            seller_dispute: true,
            buyer_cooperativecancel: false,
            seller_cooperativecancel: false,
            failed_payment: true,
            payment_attempts: 2,
            hold_settled_at: Some(1_700_000_250),
            hold_invoice: Some(HoldInvoiceInfo {
                state: HoldInvoiceState::Settled,
                held_at: Some(1_700_000_200),
            }),
            cashu_escrow: None,
            payout: Some(PayoutInfo {
                state: PayoutState::Failed,
                failure_reason: Some(PayoutFailureReason::NoRoute),
                resolved_at: Some(1_700_000_300),
            }),
            bonds: vec![
                BondInfo {
                    role: BondRole::Taker,
                    amount: 1_000,
                    state: BondState::PendingPayout,
                    slash_reason: Some(BondSlashReason::LostDispute),
                    kind: BondKind::Bond,
                    root_order_id: None,
                },
                BondInfo {
                    role: BondRole::Maker,
                    amount: 5_000,
                    state: BondState::Locked,
                    slash_reason: None,
                    kind: BondKind::Bond,
                    root_order_id: Some(uuid!("ede61c96-4c13-4519-bf3a-dcf7f1e9d842")),
                },
            ],
        }
    }

    /// Assert that each variant serializes to its wire name and parses back.
    fn assert_wire_names<T>(cases: &[(T, &str)])
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        for (variant, name) in cases {
            assert_eq!(serde_json::to_value(variant).unwrap(), json!(name));
            let back: T = serde_json::from_value(json!(name)).unwrap();
            assert_eq!(&back, variant);
        }
    }

    /// Collect every object key of a JSON value, at any depth.
    fn collect_keys(value: &Value, keys: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    keys.push(key.clone());
                    collect_keys(inner, keys);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| collect_keys(item, keys)),
            _ => {}
        }
    }

    #[test]
    fn test_order_info_full_roundtrip() {
        let info = full_order_info();
        let json = serde_json::to_string(&info).unwrap();
        let back: OrderInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn test_order_info_cashu_roundtrip() {
        let info = OrderInfo {
            hold_invoice: None,
            payout: None,
            cashu_escrow: Some(CashuEscrowInfo {
                mint_url: "https://mint.example".to_string(),
                locked_at: Some(1_700_000_200),
            }),
            ..full_order_info()
        };
        let value = serde_json::to_value(&info).unwrap();
        assert_eq!(
            value["cashu_escrow"],
            json!({ "mint_url": "https://mint.example", "locked_at": 1_700_000_200 })
        );
        let back: OrderInfo = serde_json::from_value(value).unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn test_order_info_absent_parts_roundtrip() {
        let info = OrderInfo {
            taken_at: None,
            hold_invoice: None,
            payout: None,
            bonds: Vec::new(),
            ..full_order_info()
        };
        let value = serde_json::to_value(&info).unwrap();
        // Absent parts are an explicit `null`, not a missing key.
        assert_eq!(value["hold_invoice"], Value::Null);
        assert_eq!(value["payout"], Value::Null);
        assert_eq!(value["taken_at"], Value::Null);
        // The database part is still answered.
        assert_eq!(value["failed_payment"], json!(true));
        assert_eq!(value["payment_attempts"], json!(2));

        let back: OrderInfo = serde_json::from_value(value).unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn test_order_info_absent_differs_from_not_found_and_unavailable() {
        let with_hold = |state| OrderInfo {
            hold_invoice: Some(HoldInvoiceInfo {
                state,
                held_at: None,
            }),
            ..full_order_info()
        };
        let with_payout = |state| OrderInfo {
            payout: Some(PayoutInfo {
                state,
                failure_reason: None,
                resolved_at: None,
            }),
            ..full_order_info()
        };

        let holds = [
            serde_json::to_value(OrderInfo {
                hold_invoice: None,
                ..full_order_info()
            })
            .unwrap()["hold_invoice"]
                .clone(),
            serde_json::to_value(with_hold(HoldInvoiceState::NotFound)).unwrap()["hold_invoice"]
                .clone(),
            serde_json::to_value(with_hold(HoldInvoiceState::Unavailable)).unwrap()["hold_invoice"]
                .clone(),
        ];
        assert_eq!(holds[0], Value::Null);
        assert_eq!(holds[1]["state"], json!("not-found"));
        assert_eq!(holds[2]["state"], json!("unavailable"));

        let payouts = [
            serde_json::to_value(OrderInfo {
                payout: None,
                ..full_order_info()
            })
            .unwrap()["payout"]
                .clone(),
            serde_json::to_value(with_payout(PayoutState::NotFound)).unwrap()["payout"].clone(),
            serde_json::to_value(with_payout(PayoutState::Unavailable)).unwrap()["payout"].clone(),
        ];
        assert_eq!(payouts[0], Value::Null);
        assert_eq!(payouts[1]["state"], json!("not-found"));
        assert_eq!(payouts[2]["state"], json!("unavailable"));
    }

    #[test]
    fn test_order_info_missing_optional_keys_deserialize() {
        // A daemon may omit the optional parts instead of sending `null`.
        let mut value = serde_json::to_value(full_order_info()).unwrap();
        let map = value.as_object_mut().unwrap();
        for key in [
            "min_amount",
            "max_amount",
            "range_parent_id",
            "taken_at",
            "hold_settled_at",
            "buyer_trade_pubkey",
            "seller_trade_pubkey",
            "hold_invoice",
            "cashu_escrow",
            "payout",
            "bonds",
        ] {
            map.remove(key);
        }
        let back: OrderInfo = serde_json::from_value(value).unwrap();
        assert_eq!(back.hold_invoice, None);
        assert_eq!(back.payout, None);
        assert_eq!(back.taken_at, None);
        assert_eq!(back.hold_settled_at, None);
        assert!(back.bonds.is_empty());
    }

    #[test]
    fn test_order_info_ignores_unknown_fields() {
        let mut value = serde_json::to_value(full_order_info()).unwrap();
        value["added_by_a_newer_daemon"] = json!({ "any": "thing" });
        value["hold_invoice"]["added_later"] = json!(1);
        value["bonds"][0]["added_later"] = json!("x");
        let back: OrderInfo = serde_json::from_value(value).unwrap();
        assert_eq!(back, full_order_info());
    }

    #[test]
    fn test_order_info_unknown_status_and_kind_are_kept_as_text() {
        let mut value = serde_json::to_value(full_order_info()).unwrap();
        value["status"] = json!("a-status-added-later");
        value["kind"] = json!("swap");
        let back: OrderInfo = serde_json::from_value(value).unwrap();
        assert_eq!(back.status, "a-status-added-later");
        assert_eq!(back.kind, "swap");
    }

    #[test]
    fn test_order_info_wire_shape() {
        let value = serde_json::to_value(full_order_info()).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut expected = vec![
            "id",
            "kind",
            "status",
            "amount",
            "fee",
            "routing_fee",
            "fiat_code",
            "fiat_amount",
            "min_amount",
            "max_amount",
            "payment_method",
            "premium",
            "range_parent_id",
            "created_at",
            "taken_at",
            "expires_at",
            "buyer_trade_pubkey",
            "seller_trade_pubkey",
            "buyer_dispute",
            "seller_dispute",
            "buyer_cooperativecancel",
            "seller_cooperativecancel",
            "failed_payment",
            "payment_attempts",
            "hold_settled_at",
            "hold_invoice",
            "cashu_escrow",
            "payout",
            "bonds",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);

        assert_eq!(
            value["hold_invoice"],
            json!({ "state": "settled", "held_at": 1_700_000_200 })
        );
        assert_eq!(
            value["payout"],
            json!({
                "state": "failed",
                "failure_reason": "no-route",
                "resolved_at": 1_700_000_300
            })
        );
        assert_eq!(
            value["bonds"][0],
            json!({
                "role": "taker",
                "amount": 1_000,
                "state": "pending-payout",
                "slash_reason": "lost-dispute",
                "kind": "bond",
                "root_order_id": null
            })
        );
    }

    #[test]
    fn test_order_info_has_no_secret_fields() {
        // Both escrow parts are filled so every nested struct is serialized.
        let info = OrderInfo {
            cashu_escrow: Some(CashuEscrowInfo {
                mint_url: "https://mint.example".to_string(),
                locked_at: None,
            }),
            ..full_order_info()
        };
        let mut keys = Vec::new();
        collect_keys(&serde_json::to_value(info).unwrap(), &mut keys);
        for key in keys {
            for forbidden in ["preimage", "invoice", "token", "master", "hash"] {
                // `hold_invoice` names the escrow part; it holds no invoice.
                if key == "hold_invoice" {
                    continue;
                }
                assert!(
                    !key.contains(forbidden),
                    "`{key}` looks like a field OrderInfo must never carry"
                );
            }
        }
    }

    #[test]
    fn test_hold_invoice_state_wire_names() {
        assert_wire_names(&[
            (HoldInvoiceState::Open, "open"),
            (HoldInvoiceState::Accepted, "accepted"),
            (HoldInvoiceState::Settled, "settled"),
            (HoldInvoiceState::Canceled, "canceled"),
            (HoldInvoiceState::NotFound, "not-found"),
            (HoldInvoiceState::Unavailable, "unavailable"),
            (HoldInvoiceState::Unknown, "unknown"),
        ]);
    }

    #[test]
    fn test_payout_state_wire_names() {
        assert_wire_names(&[
            (PayoutState::InFlight, "in-flight"),
            (PayoutState::Succeeded, "succeeded"),
            (PayoutState::Failed, "failed"),
            (PayoutState::NotFound, "not-found"),
            (PayoutState::Unavailable, "unavailable"),
            (PayoutState::Unknown, "unknown"),
        ]);
    }

    #[test]
    fn test_payout_failure_reason_wire_names() {
        assert_wire_names(&[
            (PayoutFailureReason::Timeout, "timeout"),
            (PayoutFailureReason::NoRoute, "no-route"),
            (PayoutFailureReason::Error, "error"),
            (
                PayoutFailureReason::IncorrectPaymentDetails,
                "incorrect-payment-details",
            ),
            (
                PayoutFailureReason::InsufficientBalance,
                "insufficient-balance",
            ),
            (PayoutFailureReason::Canceled, "canceled"),
            (PayoutFailureReason::Unknown, "unknown"),
        ]);
    }

    #[test]
    fn test_bond_enums_wire_names() {
        assert_wire_names(&[
            (BondRole::Maker, "maker"),
            (BondRole::Taker, "taker"),
            (BondRole::Unknown, "unknown"),
        ]);
        assert_wire_names(&[
            (BondState::Requested, "requested"),
            (BondState::Locked, "locked"),
            (BondState::Released, "released"),
            (BondState::PendingPayout, "pending-payout"),
            (BondState::Slashed, "slashed"),
            (BondState::Forfeited, "forfeited"),
            (BondState::Failed, "failed"),
            (BondState::Unknown, "unknown"),
        ]);
        assert_wire_names(&[
            (BondSlashReason::LostDispute, "lost-dispute"),
            (BondSlashReason::Timeout, "timeout"),
            (BondSlashReason::Unknown, "unknown"),
        ]);
        assert_wire_names(&[
            (BondKind::Bond, "bond"),
            (BondKind::SliceSlash, "slice-slash"),
            (BondKind::MakerRefund, "maker-refund"),
            (BondKind::Unknown, "unknown"),
        ]);
    }

    #[test]
    fn test_unknown_values_fall_back() {
        let later = json!("a-value-added-later");
        assert_eq!(
            serde_json::from_value::<HoldInvoiceState>(later.clone()).unwrap(),
            HoldInvoiceState::Unknown
        );
        assert_eq!(
            serde_json::from_value::<PayoutState>(later.clone()).unwrap(),
            PayoutState::Unknown
        );
        assert_eq!(
            serde_json::from_value::<PayoutFailureReason>(later.clone()).unwrap(),
            PayoutFailureReason::Unknown
        );
        assert_eq!(
            serde_json::from_value::<BondRole>(later.clone()).unwrap(),
            BondRole::Unknown
        );
        assert_eq!(
            serde_json::from_value::<BondState>(later.clone()).unwrap(),
            BondState::Unknown
        );
        assert_eq!(
            serde_json::from_value::<BondSlashReason>(later.clone()).unwrap(),
            BondSlashReason::Unknown
        );
        assert_eq!(
            serde_json::from_value::<BondKind>(later).unwrap(),
            BondKind::Unknown
        );
    }

    #[test]
    fn test_unknown_value_does_not_break_the_payload() {
        let mut value = serde_json::to_value(full_order_info()).unwrap();
        value["hold_invoice"]["state"] = json!("a-state-added-later");
        value["payout"]["state"] = json!("a-state-added-later");
        value["payout"]["failure_reason"] = json!("a-reason-added-later");
        value["bonds"][0]["state"] = json!("a-state-added-later");
        value["bonds"][0]["kind"] = json!("a-kind-added-later");
        let back: OrderInfo = serde_json::from_value(value).unwrap();
        assert_eq!(back.hold_invoice.unwrap().state, HoldInvoiceState::Unknown);
        let payout = back.payout.unwrap();
        assert_eq!(payout.state, PayoutState::Unknown);
        assert_eq!(payout.failure_reason, Some(PayoutFailureReason::Unknown));
        assert_eq!(back.bonds[0].state, BondState::Unknown);
        assert_eq!(back.bonds[0].kind, BondKind::Unknown);
    }
}
