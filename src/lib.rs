//! # Mostro Core
//!
//! `mostro-core` is the foundational library behind [Mostro](https://mostro.network),
//! a peer-to-peer Bitcoin/Lightning over Nostr marketplace. It contains the
//! protocol-level data types (orders, disputes, users, ratings and messages)
//! shared between the Mostro daemon and any client, together with the NIP-59
//! GiftWrap transport used to exchange them privately.
//!
//! ## Overview
//!
//! A typical Mostro flow involves two peers (a buyer and a seller) and a
//! Mostro node that coordinates the trade. All protocol-level communication is
//! expressed through [`message::Message`] values that travel inside encrypted
//! NIP-59 envelopes built by [`nip59::wrap_message`]. The receiver uses
//! [`nip59::unwrap_message`] to recover the original [`message::Message`] and,
//! optionally, the sender's signature.
//!
//! Persistent state (orders, disputes, users) is modelled by the [`order`],
//! [`dispute`] and [`user`] modules. They can optionally derive the
//! [`sqlx::FromRow`] and `sqlx_crud::SqlxCrud` traits by enabling the
//! `sqlx` feature.
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
//! * `sqlx` — derives `FromRow` and `SqlxCrud` for the persistent structs
//!   (`Order`, `User`, `Dispute`, `RestoredOrderHelper`, …). Implies `wasm`.
//!
//! ## Module map
//!
//! * [`message`] — protocol message envelope, actions and payloads.
//! * [`order`] — order types, states and helpers.
//! * [`dispute`] — dispute types and states.
//! * [`user`] — persistent user representation and rating updates.
//! * [`rating`] — Nostr-tag-encoded reputation helper.
//! * [`error`] — unified error taxonomy ([`MostroError`], [`ServiceError`],
//!   [`CantDoReason`]).
//! * [`nip59`] — GiftWrap wrap/unwrap transport.
//! * [`prelude`] — convenience re-exports.
//!
//! [`MostroError`]: crate::error::MostroError
//! [`ServiceError`]: crate::error::ServiceError
//! [`CantDoReason`]: crate::error::CantDoReason

#![doc(html_root_url = "https://docs.rs/mostro-core")]
#![warn(missing_docs)]

pub mod dispute;
pub mod error;
pub mod message;
pub mod nip59;
pub mod order;
pub mod prelude;
pub mod rating;
pub mod user;
