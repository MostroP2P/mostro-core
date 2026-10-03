//! # Mostro Core
//!
//! `mostro-core` is the foundational library behind [Mostro](https://mostro.network),
//! a peer-to-peer Bitcoin/Lightning over Nostr marketplace. It contains the
//! protocol-level data types (orders, disputes, users, ratings and messages)
//! shared between the Mostro daemon and any client, together with the NIP-44
//! direct transport used to exchange them privately.
//!
//! ## Overview
//!
//! A typical Mostro flow involves two peers (a buyer and a seller) and a
//! Mostro node that coordinates the trade. All protocol-level communication is
//! expressed through [`message::Message`] values that travel inside encrypted
//! signed, NIP-44 encrypted `kind: 14` events built by
//! [`transport::wrap_message_with`]. The receiver uses
//! [`transport::unwrap_incoming`] to recover the original
//! [`message::Message`], the sender's trade key, its proven identity and,
//! optionally, the sender's signature.
//!
//! Persistent state (orders, disputes, users) is modelled by the [`order`],
//! [`dispute`] and [`user`] modules. With the `sqlx` feature enabled they
//! derive [`sqlx::FromRow`]; [`order::Order`] and [`dispute::Dispute`]
//! also implement [`db::Crud`] for SQLite persistence.
//!
//! ## Quick start
//!
//! The [`prelude`] module re-exports the most commonly used types:
//!
//! ```
//! use mostro_core::prelude::*;
//!
//! let order = SmallOrder::new(
//!     None,
//!     Some(Kind::Sell),
//!     Some(Status::Pending),
//!     100,
//!     "eur".to_string(),
//!     None,
//!     None,
//!     100,
//!     "SEPA".to_string(),
//!     1,
//!     None,
//!     None,
//!     None,
//!     None,
//!     None,
//! );
//! let message = Message::new_order(None, Some(1), Some(2), Action::NewOrder, Some(Payload::Order(order)));
//! assert!(message.verify());
//! ```
//!
//! ## Cargo features
//!
//! * `wasm` *(default)* — enables `wasm-bindgen` annotations on selected types
//!   so the crate can be used from JavaScript/WebAssembly contexts.
//! * `sqlx` — derives `FromRow` for persistent structs and exposes
//!   [`db::Crud`] for `Order` and `Dispute`. Implies `wasm`.
//!
//! ## Module map
//!
//! * [`message`] — protocol message envelope, actions and payloads.
//! * [`order`] — order types, states and helpers.
//! * [`dispute`] — dispute types and states.
//! * [`db`] — SQLite [`Crud`] trait (`sqlx` feature).
//! * [`user`] — persistent user representation and rating updates.
//! * [`rating`] — Nostr-tag-encoded reputation helper.
//! * [`error`] — unified error taxonomy ([`MostroError`], [`ServiceError`],
//!   [`CantDoReason`]).
//! * [`transport`] — the protocol v2 NIP-44 direct transport (`kind: 14`)
//!   and the transport-driven wrap/unwrap dispatchers.
//! * [`response`] — validation of the responses a client receives.
//! * [`chat`] — P2P buyer/seller and admin/party chat envelope.
//! * [`prelude`] — convenience re-exports.
//!
//! [`MostroError`]: crate::error::MostroError
//! [`ServiceError`]: crate::error::ServiceError
//! [`CantDoReason`]: crate::error::CantDoReason

#![doc(html_root_url = "https://docs.rs/mostro-core")]
#![warn(missing_docs)]

pub mod chat;
#[cfg(feature = "sqlx")]
pub mod db;
pub mod dispute;
pub mod error;
pub mod message;
pub mod order;
pub mod payer;
pub mod prelude;
pub mod rating;
pub mod reputation;
pub mod response;
pub mod transport;
pub mod user;
