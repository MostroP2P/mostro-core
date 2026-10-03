//! Payment-sender declaration and payment-account history (anti-triangulation).
//!
//! A buyer commits to the fiat account it will pay from by sending only a
//! hash of the canonicalised account details ([`PayerDeclaration`]); the
//! plaintext travels buyer → seller over the peer channel and never reaches
//! Mostro. Mostro answers the seller with aggregate counters for that
//! `(buyer, payment_hash)` pair ([`PaymentHistory`]).
//!
//! The canonicalisation rules are a client contract defined in the protocol
//! book (`payer_declaration.md`); this module only fixes the hash
//! construction so every client derives the same value from the same
//! canonical string.

use crate::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Domain-separation prefix hashed in front of the canonical payment data.
///
/// It makes the resulting value useless as an identifier outside this
/// protocol. Every client must use exactly this prefix, or the same account
/// yields different hashes and its history silently fragments.
pub const PAYMENT_HASH_DOMAIN: &str = "mostro-payer-v1|";

/// Length, in hex characters, of a valid [`PayerDeclaration::payment_hash`].
pub const PAYMENT_HASH_HEX_LEN: usize = 64;

/// Hash an already-canonicalised payment-data string.
///
/// Returns `sha256(PAYMENT_HASH_DOMAIN || canonical)` as 64 lowercase hex
/// characters. The caller is responsible for canonicalising first (method
/// prefix, Unicode NFKC, uppercase, separators stripped from identifiers);
/// see the protocol chapter for the per-method rules. The hash must never
/// include an order id, trade key, timestamp or salt, which would make it
/// unique per trade and defeat the history. This is the reputation-mode
/// construction; a full-privacy buyer uses [`order_bound_payment_hash`].
pub fn payment_hash(canonical: &str) -> String {
    lower_hex(
        Sha256::new()
            .chain_update(PAYMENT_HASH_DOMAIN.as_bytes())
            .chain_update(canonical.as_bytes())
            .finalize()
            .as_slice(),
    )
}

/// Domain-separation prefix of the order-bound declaration a full-privacy
/// buyer sends (see [`order_bound_payment_hash`]).
pub const PAYMENT_HASH_ORDER_DOMAIN: &str = "mostro-payer-order-v1|";

/// The declaration hash of a full-privacy buyer, bound to one order.
///
/// Returns `sha256(PAYMENT_HASH_ORDER_DOMAIN || order_id || "|" ||
/// canonical)` as 64 lowercase hex characters, with `order_id` in its
/// lowercase hyphenated form. A full-privacy buyer has no history to build,
/// and reusing [`payment_hash`] would give the same value on every order and
/// let the node link its trade keys. The value still commits the buyer to an
/// account for this order: the seller recomputes it from the plaintext.
pub fn order_bound_payment_hash(order_id: &Uuid, canonical: &str) -> String {
    lower_hex(
        Sha256::new()
            .chain_update(PAYMENT_HASH_ORDER_DOMAIN.as_bytes())
            .chain_update(order_id.hyphenated().to_string().as_bytes())
            .chain_update(b"|")
            .chain_update(canonical.as_bytes())
            .finalize()
            .as_slice(),
    )
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// `true` when `hash` is exactly 64 lowercase hexadecimal characters.
///
/// Uppercase hex is rejected on purpose: the protocol defines a single
/// encoding, so two spellings of the same digest can never become two
/// history rows.
pub fn is_valid_payment_hash(hash: &str) -> bool {
    hash.len() == PAYMENT_HASH_HEX_LEN
        && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Buyer's commitment to the fiat payer identity for one order.
///
/// Carried by [`crate::message::Action::DeclarePayer`] (buyer → Mostro) and
/// [`crate::message::Action::PayerDeclared`] (Mostro → buyer ack and
/// Mostro → seller forward). It holds only the hash; the plaintext goes
/// buyer → seller off-band.
///
/// Deserialization accepts any string: neither serde nor
/// [`crate::message::MessageKind::verify`] checks the hash format. A daemon
/// must call [`is_valid_payment_hash`] on receipt and answer
/// [`crate::error::CantDoReason::InvalidPaymentHash`] when it fails.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct PayerDeclaration {
    /// 64 lowercase hex characters. A reputation-mode buyer declares
    /// [`payment_hash`], `sha256("mostro-payer-v1|" || canonical)`, which is
    /// stable across orders and builds history. A full-privacy buyer declares
    /// [`order_bound_payment_hash`], `sha256("mostro-payer-order-v1|" ||
    /// order_id || "|" || canonical)`, so the node cannot link its orders. A
    /// seller checking the plaintext uses the construction that matches the
    /// `buyer_mode` reported in [`PaymentHistory`] (either one for a mode it
    /// does not know).
    pub payment_hash: String,
}

impl PayerDeclaration {
    /// Build a declaration from an already computed hash.
    pub fn new(payment_hash: String) -> Self {
        Self { payment_hash }
    }
}

/// Whether the buyer's history is meaningful for this order.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BuyerMode {
    /// The buyer trades with an identity key: the counters are meaningful.
    Reputation,
    /// The buyer trades in Full Privacy Mode: Mostro has no cross-trade
    /// continuity for it, so the counters are always zero. Clients must
    /// render this as "history unavailable", never as "new account".
    FullPrivacy,
    /// Catch-all for modes this build of `mostro-core` does not know yet,
    /// so a newer daemon cannot break the whole `PaymentHistory` payload.
    /// Clients should treat it like [`BuyerMode::FullPrivacy`]. Deserialize
    /// only in practice: it serializes as `"unknown"`, but a daemon never
    /// emits it on purpose.
    #[serde(other)]
    Unknown,
}

/// Aggregate, order-scoped history of a `(buyer, payment_hash)` pair.
///
/// Carried by [`crate::message::Action::PaymentHistory`], pushed by Mostro to
/// the seller right after `fiat-sent-ok` and returned on a seller query.
/// Counters only ever reflect trades that reached `success` without a
/// dispute.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct PaymentHistory {
    /// Echo of the buyer-committed hash, so the seller's client can compare
    /// it with the hash it computes from the plaintext it received: with
    /// [`payment_hash`] when `buyer_mode` is [`BuyerMode::Reputation`], with
    /// [`order_bound_payment_hash`] when it is [`BuyerMode::FullPrivacy`].
    /// For [`BuyerMode::Unknown`] the client cannot know which construction
    /// a newer buyer used: it accepts a match under either one rather than
    /// picking one and reporting a false mismatch.
    pub payment_hash: String,
    /// Whether the counters are meaningful. See [`BuyerMode`].
    pub buyer_mode: BuyerMode,
    /// Number of orders that reached `success` for `(buyer, payment_hash)`.
    pub successful_trades: u32,
    /// Number of distinct sellers among those orders.
    pub distinct_counterparties: u32,
    /// How many of those distinct counterparties were already *experienced*
    /// at the time of their successful trade with this pair. The thresholds
    /// are node policy, advertised on the info event.
    pub experienced_counterparties: u32,
    /// Unix seconds of the first successful trade; `None` when
    /// `successful_trades == 0`.
    pub first_success_at: Option<i64>,
    /// Unix seconds of the last successful trade; `None` when
    /// `successful_trades == 0`.
    pub last_success_at: Option<i64>,
}

impl PaymentHistory {
    /// History for a buyer in Full Privacy Mode: every counter is zero and
    /// [`buyer_mode`](Self::buyer_mode) says the history is unavailable.
    pub fn unavailable(payment_hash: String) -> Self {
        Self {
            payment_hash,
            buyer_mode: BuyerMode::FullPrivacy,
            successful_trades: 0,
            distinct_counterparties: 0,
            experienced_counterparties: 0,
            first_success_at: None,
            last_success_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_bound_hash_matches_the_protocol_vector() {
        // `printf '%s' 'mostro-payer-order-v1|ede61c96-4c13-4519-bf3a-dcf7f1e9d842|EU|SEPA|DE89370400440532013000|ALICE SMITH' | sha256sum`
        let order = Uuid::parse_str("EDE61C96-4C13-4519-BF3A-DCF7F1E9D842").unwrap();
        let canonical = "EU|SEPA|DE89370400440532013000|ALICE SMITH";
        let hash = order_bound_payment_hash(&order, canonical);
        assert_eq!(
            hash,
            "1f0616c3f355282b7fb73b54f172be84d023f1f63a8a7d7822c4d51f83528628"
        );
        assert!(is_valid_payment_hash(&hash));
        assert_ne!(hash, payment_hash(canonical), "never the reusable hash");
        assert_ne!(
            hash,
            order_bound_payment_hash(&Uuid::new_v4(), canonical),
            "different on every order"
        );
    }

    #[test]
    fn payment_hash_is_domain_separated_lowercase_sha256() {
        // Arrange: computed independently with
        // `printf '%s' 'mostro-payer-v1|EU|SEPA|DE89370400440532013000|ALICE SMITH' | sha256sum`.
        let expected = "ee06af92c95429e7cb0cf8428636199a71a01e32bab7a8526d226161f0de9903";
        // Act
        let hash = payment_hash("EU|SEPA|DE89370400440532013000|ALICE SMITH");
        // Assert
        assert_eq!(hash.len(), PAYMENT_HASH_HEX_LEN);
        assert!(is_valid_payment_hash(&hash));
        assert_eq!(hash, expected);
    }

    #[test]
    fn payment_hash_differs_without_the_domain_prefix() {
        let canonical = "AR|CVU|0000003100012345678901|27123456789";
        let bare: String = Sha256::digest(canonical.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(payment_hash(canonical), bare);
    }

    #[test]
    fn payment_hash_is_deterministic_and_input_sensitive() {
        let a = payment_hash("EU|SEPA|DE89370400440532013000|ALICE SMITH");
        assert_eq!(
            a,
            payment_hash("EU|SEPA|DE89370400440532013000|ALICE SMITH")
        );
        assert_ne!(a, payment_hash("EU|SEPA|DE89370400440532013000|BOB SMITH"));
    }

    #[test]
    fn is_valid_payment_hash_rejects_wrong_length_uppercase_and_non_hex() {
        let good = "a".repeat(64);
        assert!(is_valid_payment_hash(&good));
        assert!(!is_valid_payment_hash(&"a".repeat(63)));
        assert!(!is_valid_payment_hash(&"a".repeat(65)));
        assert!(!is_valid_payment_hash(&"A".repeat(64)));
        assert!(!is_valid_payment_hash(&"g".repeat(64)));
        assert!(!is_valid_payment_hash(""));
    }

    #[test]
    fn buyer_mode_serializes_to_snake_case() {
        for (mode, wire) in [
            (BuyerMode::Reputation, "\"reputation\""),
            (BuyerMode::FullPrivacy, "\"full_privacy\""),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), wire);
            assert_eq!(serde_json::from_str::<BuyerMode>(wire).unwrap(), mode);
        }
    }

    #[test]
    fn unknown_buyer_mode_does_not_break_the_history_payload() {
        let json = format!(
            r#"{{"payment_hash":"{}","buyer_mode":"mode_from_the_future",
               "successful_trades":1,"distinct_counterparties":1,
               "experienced_counterparties":0,"first_success_at":1,"last_success_at":1}}"#,
            "a".repeat(64)
        );
        let history: PaymentHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(history.buyer_mode, BuyerMode::Unknown);
    }

    #[test]
    fn unavailable_history_has_zero_counters_and_full_privacy_mode() {
        let h = PaymentHistory::unavailable("b".repeat(64));
        assert_eq!(h.buyer_mode, BuyerMode::FullPrivacy);
        assert_eq!(
            (
                h.successful_trades,
                h.distinct_counterparties,
                h.experienced_counterparties
            ),
            (0, 0, 0)
        );
        assert_eq!((h.first_success_at, h.last_success_at), (None, None));
    }

    #[test]
    fn payment_history_ignores_unknown_keys_from_newer_daemons() {
        let json = format!(
            r#"{{"payment_hash":"{}","buyer_mode":"reputation","successful_trades":2,
               "distinct_counterparties":2,"experienced_counterparties":1,
               "first_success_at":10,"last_success_at":20,"field_from_the_future":true}}"#,
            "c".repeat(64)
        );
        let h: PaymentHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(h.successful_trades, 2);
    }
}
