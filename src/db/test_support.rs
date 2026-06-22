use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

use crate::order::{Kind, Order, Status};

pub(crate) const ORDERS_DDL: &str = r#"
CREATE TABLE orders (
  id char(36) primary key not null,
  kind varchar(4) not null,
  event_id char(64) not null,
  hash char(64),
  preimage char(64),
  creator_pubkey char(64),
  cancel_initiator_pubkey char(64),
  dispute_initiator_pubkey char(64),
  buyer_pubkey char(64),
  master_buyer_pubkey char(64),
  seller_pubkey char(64),
  master_seller_pubkey char(64),
  status varchar(10) not null,
  price_from_api integer not null default 0,
  premium integer not null,
  payment_method varchar(500) not null,
  amount integer not null,
  min_amount integer default 0,
  max_amount integer default 0,
  buyer_dispute integer not null default 0,
  seller_dispute integer not null default 0,
  buyer_cooperativecancel integer not null default 0,
  seller_cooperativecancel integer not null default 0,
  fee integer not null default 0,
  routing_fee integer not null default 0,
  fiat_code varchar(5) not null,
  fiat_amount integer not null,
  buyer_invoice text,
  range_parent_id char(36),
  invoice_held_at integer default 0,
  taken_at integer default 0,
  created_at integer not null,
  buyer_sent_rate integer default 0,
  seller_sent_rate integer default 0,
  payment_attempts integer default 0,
  failed_payment integer default 0,
  expires_at integer not null,
  trade_index_seller integer default 0,
  trade_index_buyer integer default 0,
  next_trade_pubkey char(64),
  next_trade_index integer default 0,
  dev_fee INTEGER DEFAULT 0,
  dev_fee_paid INTEGER NOT NULL DEFAULT 0,
  dev_fee_payment_hash CHAR(64),
  cashu_mint_url text,
  cashu_escrow_token text,
  cashu_escrow_locked_at integer
);
"#;

pub(crate) const DISPUTES_DDL: &str = r#"
CREATE TABLE disputes (
  id char(36) primary key not null,
  order_id char(36) unique not null,
  status varchar(10) not null,
  order_previous_status varchar(10) not null,
  solver_pubkey char(64),
  created_at integer not null,
  taken_at integer default 0
);
"#;

pub(crate) async fn setup_pool() -> Pool<Sqlite> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(":memory:")
        .await
        .expect("open in-memory sqlite");
    sqlx::query(ORDERS_DDL)
        .execute(&pool)
        .await
        .expect("orders ddl");
    sqlx::query(DISPUTES_DDL)
        .execute(&pool)
        .await
        .expect("disputes ddl");
    pool
}

pub(crate) fn sample_order(id: Uuid) -> Order {
    Order {
        id,
        kind: Kind::Sell.to_string(),
        event_id: "a".repeat(64),
        creator_pubkey: "b".repeat(64),
        status: Status::Pending.to_string(),
        premium: 5,
        payment_method: "SEPA".to_string(),
        amount: 10_000,
        fiat_code: "USD".to_string(),
        fiat_amount: 100,
        created_at: 1_700_000_000,
        expires_at: 1_700_086_400,
        dev_fee: 42,
        cashu_mint_url: Some("https://mint.example".to_string()),
        ..Default::default()
    }
}
