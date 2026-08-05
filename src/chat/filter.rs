//! Build Nostr relay filters for Mostro P2P chat.
//!
//! The gift-wrap-free envelope is addressable by **`authors = [pub(K_sign)]`**.
//! Filtering only by `#p` reintroduces third-party flooding — see
//! <https://mostro.network/protocol/chat.html#subscription>.

use nostr_sdk::prelude::*;

/// Default lookback window applied by [`chat_filter`] / [`giftwrap_chat_filter`]
/// (7 days).
pub const CHAT_DEFAULT_LOOKBACK_SECS: u64 = 7 * 24 * 60 * 60;

/// Relay filter for kind 14 chat events authored by `pub(K_sign)`.
///
/// Matches:
///
/// * `kind == 14` ([`Kind::PrivateDirectMessage`]),
/// * `authors = [sign_pubkey]`,
/// * `created_at >= now - CHAT_DEFAULT_LOOKBACK_SECS`.
///
/// Callers SHOULD also chain `.limit(...)` and may override `.since(...)` with
/// a persisted cursor (never advanced past local now).
pub fn chat_filter(sign_pubkey: PublicKey) -> Filter {
    let since = Timestamp::now()
        .as_secs()
        .saturating_sub(CHAT_DEFAULT_LOOKBACK_SECS);
    Filter::new()
        .kind(Kind::PrivateDirectMessage)
        .author(sign_pubkey)
        .since(Timestamp::from_secs(since))
}

/// Legacy gift-wrap filter (`kind: 1059`, `#p = shared_pubkey`).
///
/// Prefer [`chat_filter`]. Kept for dual-read hydration during migration.
pub fn giftwrap_chat_filter(shared_pubkey: PublicKey) -> Filter {
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
    fn filter_targets_kind14_and_author() {
        let pk = Keys::generate().public_key();
        let filter = chat_filter(pk);
        let json = serde_json::to_value(&filter).expect("filter json");

        let kinds = json.get("kinds").expect("kinds present");
        assert!(kinds
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k.as_u64() == Some(14)));

        let authors = json.get("authors").expect("authors present");
        assert!(authors
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(&pk.to_hex())));

        assert!(json.get("since").is_some());
        assert!(json.get("#p").is_none());
    }

    #[test]
    fn giftwrap_filter_targets_kind_and_pubkey() {
        let pk = Keys::generate().public_key();
        let filter = giftwrap_chat_filter(pk);
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
    }
}
