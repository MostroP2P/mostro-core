use std::future::Future;

use sqlx::{query_builder::Separated, Pool, QueryBuilder, Sqlite};

use crate::db::Crud;
use crate::order::Order;

/// Persisted `orders` columns, in [`Order`] field order. Keep in sync with
/// `mostrod` migrations and [`Order`]'s `FromRow` mapping.
const ORDER_INSERT_COLUMNS: &[&str] = &[
    "id",
    "kind",
    "event_id",
    "hash",
    "preimage",
    "creator_pubkey",
    "cancel_initiator_pubkey",
    "buyer_pubkey",
    "master_buyer_pubkey",
    "seller_pubkey",
    "master_seller_pubkey",
    "status",
    "price_from_api",
    "premium",
    "payment_method",
    "amount",
    "min_amount",
    "max_amount",
    "buyer_dispute",
    "seller_dispute",
    "buyer_cooperativecancel",
    "seller_cooperativecancel",
    "fee",
    "routing_fee",
    "dev_fee",
    "dev_fee_paid",
    "dev_fee_payment_hash",
    "fiat_code",
    "fiat_amount",
    "buyer_invoice",
    "range_parent_id",
    "invoice_held_at",
    "taken_at",
    "created_at",
    "buyer_sent_rate",
    "seller_sent_rate",
    "failed_payment",
    "payment_attempts",
    "expires_at",
    "trade_index_seller",
    "trade_index_buyer",
    "next_trade_pubkey",
    "next_trade_index",
    "cashu_mint_url",
    "cashu_escrow_token",
    "cashu_escrow_locked_at",
];

fn order_update_columns() -> &'static [&'static str] {
    &ORDER_INSERT_COLUMNS[1..]
}

#[derive(Copy, Clone)]
enum BindStyle {
    Insert,
    Update,
}

fn bind_order_column<'a>(
    sep: &mut Separated<'_, 'a, Sqlite, &'static str>,
    column: &str,
    order: &'a Order,
    style: BindStyle,
) {
    if matches!(style, BindStyle::Update) {
        sep.push(column);
        sep.push_unseparated(" = ");
    }

    match column {
        "id" => bind_column_value(sep, order.id, style),
        "kind" => bind_column_value(sep, &order.kind, style),
        "event_id" => bind_column_value(sep, &order.event_id, style),
        "hash" => bind_column_value(sep, &order.hash, style),
        "preimage" => bind_column_value(sep, &order.preimage, style),
        "creator_pubkey" => bind_column_value(sep, &order.creator_pubkey, style),
        "cancel_initiator_pubkey" => bind_column_value(sep, &order.cancel_initiator_pubkey, style),
        "buyer_pubkey" => bind_column_value(sep, &order.buyer_pubkey, style),
        "master_buyer_pubkey" => bind_column_value(sep, &order.master_buyer_pubkey, style),
        "seller_pubkey" => bind_column_value(sep, &order.seller_pubkey, style),
        "master_seller_pubkey" => bind_column_value(sep, &order.master_seller_pubkey, style),
        "status" => bind_column_value(sep, &order.status, style),
        "price_from_api" => bind_column_value(sep, order.price_from_api, style),
        "premium" => bind_column_value(sep, order.premium, style),
        "payment_method" => bind_column_value(sep, &order.payment_method, style),
        "amount" => bind_column_value(sep, order.amount, style),
        "min_amount" => bind_column_value(sep, order.min_amount, style),
        "max_amount" => bind_column_value(sep, order.max_amount, style),
        "buyer_dispute" => bind_column_value(sep, order.buyer_dispute, style),
        "seller_dispute" => bind_column_value(sep, order.seller_dispute, style),
        "buyer_cooperativecancel" => bind_column_value(sep, order.buyer_cooperativecancel, style),
        "seller_cooperativecancel" => bind_column_value(sep, order.seller_cooperativecancel, style),
        "fee" => bind_column_value(sep, order.fee, style),
        "routing_fee" => bind_column_value(sep, order.routing_fee, style),
        "dev_fee" => bind_column_value(sep, order.dev_fee, style),
        "dev_fee_paid" => bind_column_value(sep, order.dev_fee_paid, style),
        "dev_fee_payment_hash" => bind_column_value(sep, &order.dev_fee_payment_hash, style),
        "fiat_code" => bind_column_value(sep, &order.fiat_code, style),
        "fiat_amount" => bind_column_value(sep, order.fiat_amount, style),
        "buyer_invoice" => bind_column_value(sep, &order.buyer_invoice, style),
        "range_parent_id" => bind_column_value(sep, order.range_parent_id, style),
        "invoice_held_at" => bind_column_value(sep, order.invoice_held_at, style),
        "taken_at" => bind_column_value(sep, order.taken_at, style),
        "created_at" => bind_column_value(sep, order.created_at, style),
        "buyer_sent_rate" => bind_column_value(sep, order.buyer_sent_rate, style),
        "seller_sent_rate" => bind_column_value(sep, order.seller_sent_rate, style),
        "failed_payment" => bind_column_value(sep, order.failed_payment, style),
        "payment_attempts" => bind_column_value(sep, order.payment_attempts, style),
        "expires_at" => bind_column_value(sep, order.expires_at, style),
        "trade_index_seller" => bind_column_value(sep, order.trade_index_seller, style),
        "trade_index_buyer" => bind_column_value(sep, order.trade_index_buyer, style),
        "next_trade_pubkey" => bind_column_value(sep, &order.next_trade_pubkey, style),
        "next_trade_index" => bind_column_value(sep, order.next_trade_index, style),
        "cashu_mint_url" => bind_column_value(sep, &order.cashu_mint_url, style),
        "cashu_escrow_token" => bind_column_value(sep, &order.cashu_escrow_token, style),
        "cashu_escrow_locked_at" => bind_column_value(sep, order.cashu_escrow_locked_at, style),
        other => panic!("unmapped order column: {other}"),
    }
}

fn bind_column_value<'a, T>(
    sep: &mut Separated<'_, 'a, Sqlite, &'static str>,
    value: T,
    style: BindStyle,
) where
    T: 'a + sqlx::Encode<'a, Sqlite> + sqlx::Type<Sqlite> + Send,
{
    match style {
        BindStyle::Insert => {
            sep.push_bind(value);
        }
        BindStyle::Update => {
            sep.push_bind_unseparated(value);
        }
    }
}

fn push_order_insert_binds<'a>(b: &mut Separated<'_, 'a, Sqlite, &'static str>, order: &'a Order) {
    for &column in ORDER_INSERT_COLUMNS {
        bind_order_column(b, column, order, BindStyle::Insert);
    }
}

fn push_order_update_set<'a>(set: &mut Separated<'_, 'a, Sqlite, &'static str>, order: &'a Order) {
    for &column in order_update_columns() {
        bind_order_column(set, column, order, BindStyle::Update);
    }
}

impl Crud for Order {
    fn create(self, pool: &Pool<Sqlite>) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
        let pool = pool.clone();
        async move {
            let mut qb = QueryBuilder::new("INSERT INTO orders (");
            {
                let mut cols = qb.separated(", ");
                for &column in ORDER_INSERT_COLUMNS {
                    cols.push(column);
                }
            }
            qb.push(") ");
            qb.push_values(std::iter::once(&self), |mut binds, order| {
                push_order_insert_binds(&mut binds, order);
            });
            qb.push(" RETURNING *");
            qb.build_query_as::<Order>().fetch_one(&pool).await
        }
    }

    fn update(self, pool: &Pool<Sqlite>) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
        let pool = pool.clone();
        async move {
            let mut qb = QueryBuilder::new("UPDATE orders SET ");
            {
                let mut set = qb.separated(", ");
                push_order_update_set(&mut set, &self);
            }
            qb.push(" WHERE id = ");
            qb.push_bind(self.id);
            qb.push(" RETURNING *");
            qb.build_query_as::<Order>().fetch_one(&pool).await
        }
    }

    fn by_id(
        pool: &Pool<Sqlite>,
        id: uuid::Uuid,
    ) -> impl Future<Output = Result<Option<Self>, sqlx::Error>> + Send {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, Order>("SELECT * FROM orders WHERE id = ? LIMIT 1")
                .bind(id)
                .fetch_optional(&pool)
                .await
        }
    }
}

#[cfg(all(test, feature = "sqlx"))]
mod tests {
    use super::*;
    use crate::db::test_support::{sample_order, setup_pool};
    use crate::order::{Kind, Status};
    use uuid::Uuid;

    /// Mirrors the INSERT bind loop in [`push_order_insert_binds`].
    fn order_insert_bind_count() -> usize {
        ORDER_INSERT_COLUMNS.len()
    }

    #[test]
    fn insert_column_list_matches_bind_count() {
        assert_eq!(ORDER_INSERT_COLUMNS.len(), order_insert_bind_count());
        assert_eq!(ORDER_INSERT_COLUMNS.first(), Some(&"id"));
        assert_eq!(order_update_columns().len(), ORDER_INSERT_COLUMNS.len() - 1);
    }

    #[tokio::test]
    async fn create_by_id_roundtrip() {
        let pool = setup_pool().await;
        let id = Uuid::new_v4();
        let order = sample_order(id);

        let created = order.create(&pool).await.expect("create");
        assert_eq!(created.id, id);
        assert_eq!(created.kind, Kind::Sell.to_string());
        assert_eq!(created.dev_fee, 42);
        assert_eq!(
            created.cashu_mint_url.as_deref(),
            Some("https://mint.example")
        );

        let fetched = Order::by_id(&pool, id).await.expect("by_id").expect("row");
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.amount, created.amount);
    }

    #[tokio::test]
    async fn by_id_returns_none_for_missing_row() {
        let pool = setup_pool().await;
        let missing = Order::by_id(&pool, Uuid::new_v4()).await.expect("by_id");
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn update_persists_changes() {
        let pool = setup_pool().await;
        let id = Uuid::new_v4();
        let order = sample_order(id);
        let mut created = order.create(&pool).await.expect("create");
        assert_eq!(created.status, Status::Pending.to_string());

        created.status = Status::Active.to_string();
        created.amount = 99_999;
        let updated = created.update(&pool).await.expect("update");
        assert_eq!(updated.status, Status::Active.to_string());
        assert_eq!(updated.amount, 99_999);

        let fetched = Order::by_id(&pool, id).await.expect("by_id").expect("row");
        assert_eq!(fetched.status, Status::Active.to_string());
        assert_eq!(fetched.amount, 99_999);
    }
}
