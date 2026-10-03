//! Convenience re-exports and shared constants.
//!
//! This module gathers the types you are most likely to need when building a
//! Mostro client or daemon so they can be imported in bulk:
//!
//! ```
//! use mostro_core::prelude::*;
//! ```
//!
//! It also defines the Nostr event kinds used by the protocol and the minimum
//! and maximum rating bounds.

pub use crate::chat::{
    chat_filter, derive_chat_keys, derive_chat_keys_from_shared, unwrap_chat_message,
    wrap_chat_message, ChatMessage, SharedKey, CHAT_DEFAULT_LOOKBACK_SECS,
    CHAT_MAX_CLOCK_SKEW_SECS, CHAT_MAX_CONTENT_BYTES,
};
#[cfg(feature = "sqlx")]
pub use crate::db::Crud;
pub use crate::dispute::{Dispute, SolverDisputeInfo, Status as DisputeStatus};
pub use crate::error::{CantDoReason, MostroError, ServiceError};
pub use crate::message::{
    Action, BondPayoutRequest, BondResolution, CashuLockProof, CashuProofSignature, Message,
    MessageKind, Payload, PaymentFailedInfo, Peer, ReputationExportRequest, RestoreSessionInfo,
    RestoredDisputeHelper, RestoredDisputesInfo, RestoredOrderHelper, RestoredOrdersInfo,
};
pub use crate::order::{Kind, Order, SmallOrder, Status};
pub use crate::rating::Rating;
pub use crate::reputation::{
    AttestationError, ReputationAttestation, ReputationImport, ReputationRebind,
};
pub use crate::response::validate_response;
pub use crate::transport::{
    unwrap_incoming, unwrap_message_nip44, wrap_message_nip44, wrap_message_with, Transport,
    UnwrappedMessage, WrapOptions,
};
pub use crate::user::{User, UserInfo};
pub(crate) use serde::{Deserialize, Serialize};
pub use MostroError::*;

/// Maximum rating value a user can receive.
pub const MAX_RATING: u8 = 5;
/// Minimum rating value a user can receive.
pub const MIN_RATING: u8 = 1;
/// Nostr event kind used by Mostro to publish orders.
///
/// Addressable event kinds are in the `30000..=39999` range (NIP-01).
pub const NOSTR_ORDER_EVENT_KIND: u16 = 38383;
/// Nostr event kind used to publish user ratings.
pub const NOSTR_RATING_EVENT_KIND: u16 = 38384;
/// Nostr event kind used to publish node information events.
pub const NOSTR_INFO_EVENT_KIND: u16 = 38385;
/// Nostr event kind used to publish disputes.
pub const NOSTR_DISPUTE_EVENT_KIND: u16 = 38386;
/// Nostr event kind of a reputation attestation and of a rebind
/// authorisation (see [`crate::reputation`]).
///
/// Unlike the kinds above it is never published to relays: the event travels
/// inside encrypted messages, so it carries no `d` tag although the number
/// sits in the addressable range.
pub const NOSTR_REPUTATION_ATTESTATION_KIND: u16 = 38388;
/// Current Mostro protocol version. Embedded in every outgoing
/// [`MessageKind`](crate::message::MessageKind).
///
/// Version 2 introduces the NIP-44 direct transport (`kind: 14`) and its
/// 3-element content tuple carrying an in-ciphertext identity proof — see
/// [`crate::transport`]. Version 1 (the gift-wrap 2-tuple format) was
/// removed in 0.16.0.
pub(crate) const PROTOCOL_VER: u8 = 2;
