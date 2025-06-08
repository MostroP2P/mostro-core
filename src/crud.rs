use crate::prelude::*;
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

/// Basic CRUD operations trait
#[allow(async_fn_in_trait)]
pub trait Crud {
    type Id;
    type Error;

    /// Create a new record
    async fn create(pool: &Pool<Sqlite>, item: &Self) -> Result<Self::Id, Self::Error>
    where
        Self: Sized;

    /// Read a record by ID
    async fn read(pool: &Pool<Sqlite>, id: Self::Id) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Update a record
    async fn update(pool: &Pool<Sqlite>, item: &Self) -> Result<bool, Self::Error>
    where
        Self: Sized;

    /// Delete a record
    async fn delete(pool: &Pool<Sqlite>, id: Self::Id) -> Result<bool, Self::Error>
    where
        Self: Sized;
}

/// CRUD implementation for Order
impl Crud for Order {
    type Id = Uuid;
    type Error = MostroError;

    async fn create(pool: &Pool<Sqlite>, order: &Self) -> Result<Self::Id, Self::Error> {
        let _result = sqlx::query_as_unchecked!(
            Order,
            r#"
            INSERT INTO orders (
                id, kind, event_id, hash, preimage, creator_pubkey, cancel_initiator_pubkey,
                buyer_pubkey, master_buyer_pubkey, seller_pubkey, master_seller_pubkey,
                status, price_from_api, premium, payment_method, amount, min_amount,
                max_amount, buyer_dispute, seller_dispute, buyer_cooperativecancel,
                seller_cooperativecancel, fee, routing_fee, fiat_code, fiat_amount,
                buyer_invoice, range_parent_id, invoice_held_at, taken_at, created_at,
                buyer_sent_rate, seller_sent_rate, failed_payment, payment_attempts,
                expires_at, trade_index_seller, trade_index_buyer, next_trade_pubkey,
                next_trade_index
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28,
                ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40
            )
            "#,
            order.id,
            order.kind,
            order.event_id,
            order.hash,
            order.preimage,
            order.creator_pubkey,
            order.cancel_initiator_pubkey,
            order.buyer_pubkey,
            order.master_buyer_pubkey,
            order.seller_pubkey,
            order.master_seller_pubkey,
            order.status,
            order.price_from_api,
            order.premium,
            order.payment_method,
            order.amount,
            order.min_amount,
            order.max_amount,
            order.buyer_dispute,
            order.seller_dispute,
            order.buyer_cooperativecancel,
            order.seller_cooperativecancel,
            order.fee,
            order.routing_fee,
            order.fiat_code,
            order.fiat_amount,
            order.buyer_invoice,
            order.range_parent_id,
            order.invoice_held_at,
            order.taken_at,
            order.created_at,
            order.buyer_sent_rate,
            order.seller_sent_rate,
            order.failed_payment,
            order.payment_attempts,
            order.expires_at,
            order.trade_index_seller,
            order.trade_index_buyer,
            order.next_trade_pubkey,
            order.next_trade_index
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(Uuid::parse_str(&order.id).map_err(|_| MostroInternalErr(ServiceError::InvalidOrderId))?)
    }

    async fn read(pool: &Pool<Sqlite>, id: Self::Id) -> Result<Self, Self::Error> {
        let order = sqlx::query_as!(
            Order,
            r#"
            SELECT * FROM orders WHERE id = ?1
            "#,
            id
        )
        .fetch_one(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(order)
    }

    async fn update(pool: &Pool<Sqlite>, order: &Self) -> Result<bool, Self::Error> {
        let result = sqlx::query_as_unchecked!(
            Order,
            r#"
            UPDATE orders SET
                kind = ?2,
                event_id = ?3,
                hash = ?4,
                preimage = ?5,
                creator_pubkey = ?6,
                cancel_initiator_pubkey = ?7,
                buyer_pubkey = ?8,
                master_buyer_pubkey = ?9,
                seller_pubkey = ?10,
                master_seller_pubkey = ?11,
                status = ?12,
                price_from_api = ?13,
                premium = ?14,
                payment_method = ?15,
                amount = ?16,
                min_amount = ?17,
                max_amount = ?18,
                buyer_dispute = ?19,
                seller_dispute = ?20,
                buyer_cooperativecancel = ?21,
                seller_cooperativecancel = ?22,
                fee = ?23,
                routing_fee = ?24,
                fiat_code = ?25,
                fiat_amount = ?26,
                buyer_invoice = ?27,
                range_parent_id = ?28,
                invoice_held_at = ?29,
                taken_at = ?30,
                created_at = ?31,
                buyer_sent_rate = ?32,
                seller_sent_rate = ?33,
                failed_payment = ?34,
                payment_attempts = ?35,
                expires_at = ?36,
                trade_index_seller = ?37,
                trade_index_buyer = ?38,
                next_trade_pubkey = ?39,
                next_trade_index = ?40
            WHERE id = ?1
            "#,
            order.id,
            order.kind,
            order.event_id,
            order.hash,
            order.preimage,
            order.creator_pubkey,
            order.cancel_initiator_pubkey,
            order.buyer_pubkey,
            order.master_buyer_pubkey,
            order.seller_pubkey,
            order.master_seller_pubkey,
            order.status,
            order.price_from_api,
            order.premium,
            order.payment_method,
            order.amount,
            order.min_amount,
            order.max_amount,
            order.buyer_dispute,
            order.seller_dispute,
            order.buyer_cooperativecancel,
            order.seller_cooperativecancel,
            order.fee,
            order.routing_fee,
            order.fiat_code,
            order.fiat_amount,
            order.buyer_invoice,
            order.range_parent_id,
            order.invoice_held_at,
            order.taken_at,
            order.created_at,
            order.buyer_sent_rate,
            order.seller_sent_rate,
            order.failed_payment,
            order.payment_attempts,
            order.expires_at,
            order.trade_index_seller,
            order.trade_index_buyer,
            order.next_trade_pubkey,
            order.next_trade_index
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete(pool: &Pool<Sqlite>, id: Self::Id) -> Result<bool, Self::Error> {
        let result = sqlx::query_as_unchecked!(
            Order,
            r#"
            DELETE FROM orders WHERE id = ?1
            "#,
            id
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(result.rows_affected() > 0)
    }
}

/// CRUD implementation for User
impl Crud for User {
    type Id = String; // Using pubkey as ID
    type Error = MostroError;

    async fn create(pool: &Pool<Sqlite>, user: &Self) -> Result<Self::Id, Self::Error> {
        let _result = sqlx::query_as_unchecked!(
            User,
            r#"
            INSERT INTO users (
                pubkey, is_admin, admin_password, is_solver, is_banned,
                category, last_trade_index, total_reviews, total_rating,
                last_rating, max_rating, min_rating, created_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
            )
            "#,
            user.pubkey,
            user.is_admin,
            user.admin_password,
            user.is_solver,
            user.is_banned,
            user.category,
            user.last_trade_index,
            user.total_reviews,
            user.total_rating,
            user.last_rating,
            user.max_rating,
            user.min_rating,
            user.created_at
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(user.pubkey.clone())
    }

    async fn read(pool: &Pool<Sqlite>, id: Self::Id) -> Result<Self, Self::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT * FROM users WHERE pubkey = ?1
            "#,
            id
        )
        .fetch_one(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(user)
    }

    async fn update(pool: &Pool<Sqlite>, user: &Self) -> Result<bool, Self::Error> {
        let result = sqlx::query_as_unchecked!(
            User,
            r#"
            UPDATE users SET
                is_admin = ?2,
                admin_password = ?3,
                is_solver = ?4,
                is_banned = ?5,
                category = ?6,
                last_trade_index = ?7,
                total_reviews = ?8,
                total_rating = ?9,
                last_rating = ?10,
                max_rating = ?11,
                min_rating = ?12,
                created_at = ?13
            WHERE pubkey = ?1
            "#,
            user.pubkey,
            user.is_admin,
            user.admin_password,
            user.is_solver,
            user.is_banned,
            user.category,
            user.last_trade_index,
            user.total_reviews,
            user.total_rating,
            user.last_rating,
            user.max_rating,
            user.min_rating,
            user.created_at
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete(pool: &Pool<Sqlite>, id: Self::Id) -> Result<bool, Self::Error> {
        let result = sqlx::query_as_unchecked!(
            User,
            r#"
            DELETE FROM users WHERE pubkey = ?1
            "#,
            id
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(result.rows_affected() > 0)
    }
}

/// CRUD implementation for Dispute
impl Crud for Dispute {
    type Id = Uuid;
    type Error = MostroError;

    async fn create(pool: &Pool<Sqlite>, dispute: &Self) -> Result<Self::Id, Self::Error> {
        let _result = sqlx::query_as_unchecked!(
            Dispute,
            r#"
            INSERT INTO disputes (
                id, order_id, status, order_previous_status,
                solver_pubkey, created_at, taken_at,
                buyer_token, seller_token
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
            )
            "#,
            dispute.id,
            dispute.order_id,
            dispute.status,
            dispute.order_previous_status,
            dispute.solver_pubkey,
            dispute.created_at,
            dispute.taken_at,
            dispute.buyer_token,
            dispute.seller_token
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(Uuid::parse_str(&dispute.id).map_err(|_| MostroInternalErr(ServiceError::InvalidDisputeId))?)
    }

    async fn read(pool: &Pool<Sqlite>, id: Self::Id) -> Result<Self, Self::Error> {
        let dispute = sqlx::query_as!(
            Dispute,
            r#"
            SELECT * FROM disputes WHERE id = ?1
            "#,
            id
        )
        .fetch_one(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(dispute)
    }

    async fn update(pool: &Pool<Sqlite>, dispute: &Self) -> Result<bool, Self::Error> {
        let result = sqlx::query_as_unchecked!(
            Dispute,
            r#"
            UPDATE disputes SET
                order_id = ?2,
                status = ?3,
                order_previous_status = ?4,
                solver_pubkey = ?5,
                created_at = ?6,
                taken_at = ?7,
                buyer_token = ?8,
                seller_token = ?9
            WHERE id = ?1
            "#,
            dispute.id,
            dispute.order_id,
            dispute.status,
            dispute.order_previous_status,
            dispute.solver_pubkey,
            dispute.created_at,
            dispute.taken_at,
            dispute.buyer_token,
            dispute.seller_token
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete(pool: &Pool<Sqlite>, id: Self::Id) -> Result<bool, Self::Error> {
        let result = sqlx::query_as_unchecked!(
            Dispute,
            r#"
            DELETE FROM disputes WHERE id = ?1
            "#,
            id
        )
        .execute(pool)
        .await
        .map_err(|e| MostroInternalErr(ServiceError::DbAccessError(e.to_string())))?;

        Ok(result.rows_affected() > 0)
    }
} 