use std::future::Future;

use sqlx::{query_builder::Separated, Pool, QueryBuilder, Sqlite};

use crate::db::Crud;
use crate::order::Order;

fn push_order_insert_binds<'a>(
    b: &mut Separated<'_, 'a, Sqlite, &'static str>,
    order: &'a Order,
) {
    b.push_bind(order.id)
        .push_bind(&order.kind)
        .push_bind(&order.event_id)
        .push_bind(&order.hash)
        .push_bind(&order.preimage)
        .push_bind(&order.creator_pubkey)
        .push_bind(&order.cancel_initiator_pubkey)
        .push_bind(&order.buyer_pubkey)
        .push_bind(&order.master_buyer_pubkey)
        .push_bind(&order.seller_pubkey)
        .push_bind(&order.master_seller_pubkey)
        .push_bind(&order.status)
        .push_bind(order.price_from_api)
        .push_bind(order.premium)
        .push_bind(&order.payment_method)
        .push_bind(order.amount)
        .push_bind(order.min_amount)
        .push_bind(order.max_amount)
        .push_bind(order.buyer_dispute)
        .push_bind(order.seller_dispute)
        .push_bind(order.buyer_cooperativecancel)
        .push_bind(order.seller_cooperativecancel)
        .push_bind(order.fee)
        .push_bind(order.routing_fee)
        .push_bind(order.dev_fee)
        .push_bind(order.dev_fee_paid)
        .push_bind(&order.dev_fee_payment_hash)
        .push_bind(&order.fiat_code)
        .push_bind(order.fiat_amount)
        .push_bind(&order.buyer_invoice)
        .push_bind(order.range_parent_id)
        .push_bind(order.invoice_held_at)
        .push_bind(order.taken_at)
        .push_bind(order.created_at)
        .push_bind(order.buyer_sent_rate)
        .push_bind(order.seller_sent_rate)
        .push_bind(order.failed_payment)
        .push_bind(order.payment_attempts)
        .push_bind(order.expires_at)
        .push_bind(order.trade_index_seller)
        .push_bind(order.trade_index_buyer)
        .push_bind(&order.next_trade_pubkey)
        .push_bind(order.next_trade_index)
        .push_bind(&order.cashu_mint_url)
        .push_bind(&order.cashu_escrow_token)
        .push_bind(order.cashu_escrow_locked_at);
}

fn push_order_update_set<'a>(
    set: &mut Separated<'_, 'a, Sqlite, &'static str>,
    order: &'a Order,
) {
    set.push("kind = ")
        .push_bind_unseparated(&order.kind);
    set.push("event_id = ")
        .push_bind_unseparated(&order.event_id);
    set.push("hash = ").push_bind_unseparated(&order.hash);
    set.push("preimage = ")
        .push_bind_unseparated(&order.preimage);
    set.push("creator_pubkey = ")
        .push_bind_unseparated(&order.creator_pubkey);
    set.push("cancel_initiator_pubkey = ")
        .push_bind_unseparated(&order.cancel_initiator_pubkey);
    set.push("buyer_pubkey = ")
        .push_bind_unseparated(&order.buyer_pubkey);
    set.push("master_buyer_pubkey = ")
        .push_bind_unseparated(&order.master_buyer_pubkey);
    set.push("seller_pubkey = ")
        .push_bind_unseparated(&order.seller_pubkey);
    set.push("master_seller_pubkey = ")
        .push_bind_unseparated(&order.master_seller_pubkey);
    set.push("status = ")
        .push_bind_unseparated(&order.status);
    set.push("price_from_api = ")
        .push_bind_unseparated(order.price_from_api);
    set.push("premium = ")
        .push_bind_unseparated(order.premium);
    set.push("payment_method = ")
        .push_bind_unseparated(&order.payment_method);
    set.push("amount = ")
        .push_bind_unseparated(order.amount);
    set.push("min_amount = ")
        .push_bind_unseparated(order.min_amount);
    set.push("max_amount = ")
        .push_bind_unseparated(order.max_amount);
    set.push("buyer_dispute = ")
        .push_bind_unseparated(order.buyer_dispute);
    set.push("seller_dispute = ")
        .push_bind_unseparated(order.seller_dispute);
    set.push("buyer_cooperativecancel = ")
        .push_bind_unseparated(order.buyer_cooperativecancel);
    set.push("seller_cooperativecancel = ")
        .push_bind_unseparated(order.seller_cooperativecancel);
    set.push("fee = ").push_bind_unseparated(order.fee);
    set.push("routing_fee = ")
        .push_bind_unseparated(order.routing_fee);
    set.push("dev_fee = ")
        .push_bind_unseparated(order.dev_fee);
    set.push("dev_fee_paid = ")
        .push_bind_unseparated(order.dev_fee_paid);
    set.push("dev_fee_payment_hash = ")
        .push_bind_unseparated(&order.dev_fee_payment_hash);
    set.push("fiat_code = ")
        .push_bind_unseparated(&order.fiat_code);
    set.push("fiat_amount = ")
        .push_bind_unseparated(order.fiat_amount);
    set.push("buyer_invoice = ")
        .push_bind_unseparated(&order.buyer_invoice);
    set.push("range_parent_id = ")
        .push_bind_unseparated(order.range_parent_id);
    set.push("invoice_held_at = ")
        .push_bind_unseparated(order.invoice_held_at);
    set.push("taken_at = ")
        .push_bind_unseparated(order.taken_at);
    set.push("created_at = ")
        .push_bind_unseparated(order.created_at);
    set.push("buyer_sent_rate = ")
        .push_bind_unseparated(order.buyer_sent_rate);
    set.push("seller_sent_rate = ")
        .push_bind_unseparated(order.seller_sent_rate);
    set.push("failed_payment = ")
        .push_bind_unseparated(order.failed_payment);
    set.push("payment_attempts = ")
        .push_bind_unseparated(order.payment_attempts);
    set.push("expires_at = ")
        .push_bind_unseparated(order.expires_at);
    set.push("trade_index_seller = ")
        .push_bind_unseparated(order.trade_index_seller);
    set.push("trade_index_buyer = ")
        .push_bind_unseparated(order.trade_index_buyer);
    set.push("next_trade_pubkey = ")
        .push_bind_unseparated(&order.next_trade_pubkey);
    set.push("next_trade_index = ")
        .push_bind_unseparated(order.next_trade_index);
    set.push("cashu_mint_url = ")
        .push_bind_unseparated(&order.cashu_mint_url);
    set.push("cashu_escrow_token = ")
        .push_bind_unseparated(&order.cashu_escrow_token);
    set.push("cashu_escrow_locked_at = ")
        .push_bind_unseparated(order.cashu_escrow_locked_at);
}

impl Crud for Order {
    fn create(
        self,
        pool: &Pool<Sqlite>,
    ) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
        let pool = pool.clone();
        async move {
            let mut qb = QueryBuilder::new("INSERT INTO orders (");
            {
                let mut cols = qb.separated(", ");
                cols.push("id");
                cols.push("kind");
                cols.push("event_id");
                cols.push("hash");
                cols.push("preimage");
                cols.push("creator_pubkey");
                cols.push("cancel_initiator_pubkey");
                cols.push("buyer_pubkey");
                cols.push("master_buyer_pubkey");
                cols.push("seller_pubkey");
                cols.push("master_seller_pubkey");
                cols.push("status");
                cols.push("price_from_api");
                cols.push("premium");
                cols.push("payment_method");
                cols.push("amount");
                cols.push("min_amount");
                cols.push("max_amount");
                cols.push("buyer_dispute");
                cols.push("seller_dispute");
                cols.push("buyer_cooperativecancel");
                cols.push("seller_cooperativecancel");
                cols.push("fee");
                cols.push("routing_fee");
                cols.push("dev_fee");
                cols.push("dev_fee_paid");
                cols.push("dev_fee_payment_hash");
                cols.push("fiat_code");
                cols.push("fiat_amount");
                cols.push("buyer_invoice");
                cols.push("range_parent_id");
                cols.push("invoice_held_at");
                cols.push("taken_at");
                cols.push("created_at");
                cols.push("buyer_sent_rate");
                cols.push("seller_sent_rate");
                cols.push("failed_payment");
                cols.push("payment_attempts");
                cols.push("expires_at");
                cols.push("trade_index_seller");
                cols.push("trade_index_buyer");
                cols.push("next_trade_pubkey");
                cols.push("next_trade_index");
                cols.push("cashu_mint_url");
                cols.push("cashu_escrow_token");
                cols.push("cashu_escrow_locked_at");
            }
            qb.push(") ");
            qb.push_values(std::iter::once(&self), |mut binds, order| {
                push_order_insert_binds(&mut binds, order);
            });
            qb.push(" RETURNING *");
            qb.build_query_as::<Order>().fetch_one(&pool).await
        }
    }

    fn update(
        self,
        pool: &Pool<Sqlite>,
    ) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
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
