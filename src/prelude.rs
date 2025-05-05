// This module re-exports commonly used types and traits for convenience.
// It allows users to import everything they need from a single module
//
//! Prelude

pub use crate::dispute::{Dispute, SolverDisputeInfo, Status as DisputeStatus};
pub use crate::error::{CantDoReason, MostroError, ServiceError};
pub use crate::message::{
    Action, Message, MessageKind, Payload, Peer, MAX_RATING, MIN_RATING,
    NOSTR_REPLACEABLE_EVENT_KIND,
};
pub use crate::order::{Kind, Order, SmallOrder, Status};
pub use crate::rating::Rating;
pub use crate::user::{User, UserInfo};
pub use MostroError::*;
