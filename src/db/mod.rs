//! SQLite persistence helpers for Mostro domain types.
//!
//! Enabled by the `sqlx` Cargo feature. The [`Crud`] trait is the local
//! replacement for the unmaintained `sqlx-crud` crate: it provides typed
//! `create`, `update`, and `by_id` operations against SQLite tables whose
//! rows map via [`sqlx::FromRow`].

use std::future::Future;

use sqlx::{Pool, Sqlite};
use uuid::Uuid;

mod dispute;
mod order;

#[cfg(all(test, feature = "sqlx"))]
mod test_support;

/// Create, read-by-id, and update operations for a single SQLite table row.
///
/// Implementors are expected to map one struct to one table (for example
/// [`crate::order::Order`] → `orders`). IDs are assigned in application code
/// before insert, matching the previous `#[external_id]` behaviour of
/// `sqlx-crud`.
///
/// # Example
///
/// ```ignore
/// use mostro_core::db::Crud;
/// use mostro_core::order::Order;
///
/// let order = Order::default();
/// let order = order.create(&pool).await?;
/// let order = order.update(&pool).await?;
/// let maybe = Order::by_id(&pool, order.id).await?;
/// ```
pub trait Crud: Sized + for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> {
    /// Insert `self` into the backing table and return the persisted row.
    fn create(self, pool: &Pool<Sqlite>) -> impl Future<Output = Result<Self, sqlx::Error>> + Send;

    /// Update the row identified by `self`'s primary key and return the new
    /// row as stored in the database.
    fn update(self, pool: &Pool<Sqlite>) -> impl Future<Output = Result<Self, sqlx::Error>> + Send;

    /// Load a row by primary key. Returns `None` when no matching row exists.
    fn by_id(
        pool: &Pool<Sqlite>,
        id: Uuid,
    ) -> impl Future<Output = Result<Option<Self>, sqlx::Error>> + Send;
}
