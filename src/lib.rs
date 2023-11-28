pub mod dispute;
pub mod message;
pub mod order;
pub mod rating;
pub mod user;

/// All messages broadcasted by Mostro daemon are Parameterized Replaceable Events
/// and use 30078 as event kind
pub const NOSTR_REPLACEABLE_EVENT_KIND: u64 = 30078;
