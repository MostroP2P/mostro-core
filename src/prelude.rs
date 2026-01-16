// This module re-exports commonly used types and traits for convenience.
// It allows users to import everything they need from a single module
//
//! Prelude

pub use crate::crypto::*;
pub use crate::dispute::{Dispute, SolverDisputeInfo, Status as DisputeStatus};
pub use crate::error::{CantDoReason, MostroError, ServiceError};
pub use crate::message::{
    Action, Message, MessageKind, Payload, PaymentFailedInfo, Peer, RestoreSessionInfo,
    RestoredDisputeHelper, RestoredDisputesInfo, RestoredOrderHelper, RestoredOrdersInfo,
};
pub use crate::order::{Kind, Order, SmallOrder, Status};
pub use crate::rating::Rating;
pub use crate::user::{User, UserInfo};
pub(crate) use serde::{Deserialize, Serialize};
pub use MostroError::*;

/// CONSTANTS exported for convenience
// Max rating for a user
pub const MAX_RATING: u8 = 5;
// Min rating for a user
pub const MIN_RATING: u8 = 1;
// Addressable event kind must be between 30000 and 39999 (NIP-1)
pub const NOSTR_ORDER_EVENT_KIND: u16 = 38383;
pub const NOSTR_RATING_EVENT_KIND: u16 = 38384;
pub const NOSTR_INFO_EVENT_KIND: u16 = 38385;
pub const NOSTR_DISPUTE_EVENT_KIND: u16 = 38386;
pub(crate) const PROTOCOL_VER: u8 = 1;
