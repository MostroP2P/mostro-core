//! Build a Nostr relay filter for Mostro P2P chat gift wraps.
//!
//! Chat gift wraps are addressable by the shared key's public key (carried
//! in the outer `p` tag), so a single filter retrieves both directions of
//! the conversation regardless of which trade key authored each message.

use nostr_sdk::prelude::*;

/// Default lookback window applied by [`chat_filter`] (7 days).
///
/// Mostro chat sessions are short-lived (a trade lasts at most a few days),
/// so a one-week window covers active disputes without dragging back
/// arbitrarily old wraps.
pub const CHAT_DEFAULT_LOOKBACK_SECS: u64 = 7 * 24 * 60 * 60;

/// Create a Nostr relay filter for chat gift wraps addressed to a shared
/// public key.
///
/// The returned filter matches:
///
/// * `kind == 1059` ([`Kind::GiftWrap`]),
/// * presence of a `p` tag equal to `shared_pubkey`,
/// * `created_at >= now - CHAT_DEFAULT_LOOKBACK_SECS`.
///
/// Callers can chain extra constraints (e.g. `.limit(...)` or override
/// `.since(...)`) before subscribing.
pub fn chat_filter(shared_pubkey: PublicKey) -> Filter {
    let since = Timestamp::now()
        .as_secs()
        .saturating_sub(CHAT_DEFAULT_LOOKBACK_SECS);
    Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(shared_pubkey)
        .since(Timestamp::from_secs(since))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_targets_gift_wrap_kind_and_pubkey() {
        let pk = Keys::generate().public_key();
        let filter = chat_filter(pk);
        let json = serde_json::to_value(&filter).expect("filter json");

        let kinds = json.get("kinds").expect("kinds present");
        assert!(kinds
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k.as_u64() == Some(1059)));

        let p = json.get("#p").expect("#p tag present");
        assert!(p
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(&pk.to_hex())));

        assert!(json.get("since").is_some());
    }
}
