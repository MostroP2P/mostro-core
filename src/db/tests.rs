use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Pool;
use sqlx::Sqlite;
use uuid::Uuid;

use crate::db::Crud;
use crate::dispute::Dispute;
use crate::order::{Kind, Order, Status};

const ORDERS_DDL: &str = r#"
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

const DISPUTES_DDL: &str = r#"
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

async fn setup_pool() -> Pool<Sqlite> {
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

fn sample_order(id: Uuid) -> Order {
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

fn sample_dispute(id: Uuid, order_id: Uuid) -> Dispute {
    Dispute {
        id,
        order_id,
        status: "initiated".to_string(),
        order_previous_status: Status::FiatSent.to_string(),
        solver_pubkey: None,
        created_at: 1_700_000_100,
        taken_at: 0,
    }
}

#[tokio::test]
async fn order_create_by_id_roundtrip() {
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
async fn order_by_id_returns_none_for_missing_row() {
    let pool = setup_pool().await;
    let missing = Order::by_id(&pool, Uuid::new_v4())
        .await
        .expect("by_id");
    assert!(missing.is_none());
}

#[tokio::test]
async fn order_update_persists_changes() {
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

#[tokio::test]
async fn dispute_create_by_id_roundtrip() {
    let pool = setup_pool().await;
    let order_id = Uuid::new_v4();
    sample_order(order_id)
        .create(&pool)
        .await
        .expect("seed order");

    let dispute_id = Uuid::new_v4();
    let dispute = sample_dispute(dispute_id, order_id);
    let created = dispute.create(&pool).await.expect("create");
    assert_eq!(created.id, dispute_id);
    assert_eq!(created.order_id, order_id);

    let fetched = Dispute::by_id(&pool, dispute_id)
        .await
        .expect("by_id")
        .expect("row");
    assert_eq!(fetched.order_previous_status, Status::FiatSent.to_string());
}

#[tokio::test]
async fn dispute_by_id_returns_none_for_missing_row() {
    let pool = setup_pool().await;
    let missing = Dispute::by_id(&pool, Uuid::new_v4())
        .await
        .expect("by_id");
    assert!(missing.is_none());
}

#[tokio::test]
async fn dispute_update_persists_changes() {
    let pool = setup_pool().await;
    let order_id = Uuid::new_v4();
    sample_order(order_id)
        .create(&pool)
        .await
        .expect("seed order");

    let dispute_id = Uuid::new_v4();
    let mut created = sample_dispute(dispute_id, order_id)
        .create(&pool)
        .await
        .expect("create");
    assert_eq!(created.status, "initiated");

    created.status = "in-progress".to_string();
    created.solver_pubkey = Some("c".repeat(64));
    created.taken_at = 1_700_000_200;
    let updated = created.update(&pool).await.expect("update");
    assert_eq!(updated.status, "in-progress");
    assert_eq!(updated.solver_pubkey.as_deref(), Some("c".repeat(64).as_str()));
    assert_eq!(updated.taken_at, 1_700_000_200);
}
