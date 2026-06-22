use std::future::Future;

use sqlx::{query_builder::Separated, Pool, QueryBuilder, Sqlite};

use crate::db::Crud;
use crate::dispute::Dispute;

fn push_dispute_insert_binds<'a>(
    b: &mut Separated<'_, 'a, Sqlite, &'static str>,
    dispute: &'a Dispute,
) {
    b.push_bind(dispute.id)
        .push_bind(dispute.order_id)
        .push_bind(&dispute.status)
        .push_bind(&dispute.order_previous_status)
        .push_bind(&dispute.solver_pubkey)
        .push_bind(dispute.created_at)
        .push_bind(dispute.taken_at);
}

fn push_dispute_update_set<'a>(
    set: &mut Separated<'_, 'a, Sqlite, &'static str>,
    dispute: &'a Dispute,
) {
    set.push("order_id = ")
        .push_bind_unseparated(dispute.order_id);
    set.push("status = ").push_bind_unseparated(&dispute.status);
    set.push("order_previous_status = ")
        .push_bind_unseparated(&dispute.order_previous_status);
    set.push("solver_pubkey = ")
        .push_bind_unseparated(&dispute.solver_pubkey);
    set.push("created_at = ")
        .push_bind_unseparated(dispute.created_at);
    set.push("taken_at = ")
        .push_bind_unseparated(dispute.taken_at);
}

impl Crud for Dispute {
    fn create(self, pool: &Pool<Sqlite>) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
        let pool = pool.clone();
        async move {
            let mut qb = QueryBuilder::new("INSERT INTO disputes (");
            {
                let mut cols = qb.separated(", ");
                cols.push("id");
                cols.push("order_id");
                cols.push("status");
                cols.push("order_previous_status");
                cols.push("solver_pubkey");
                cols.push("created_at");
                cols.push("taken_at");
            }
            qb.push(") ");
            qb.push_values(std::iter::once(&self), |mut binds, dispute| {
                push_dispute_insert_binds(&mut binds, dispute);
            });
            qb.push(" RETURNING *");
            qb.build_query_as::<Dispute>().fetch_one(&pool).await
        }
    }

    fn update(self, pool: &Pool<Sqlite>) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
        let pool = pool.clone();
        async move {
            let mut qb = QueryBuilder::new("UPDATE disputes SET ");
            {
                let mut set = qb.separated(", ");
                push_dispute_update_set(&mut set, &self);
            }
            qb.push(" WHERE id = ");
            qb.push_bind(self.id);
            qb.push(" RETURNING *");
            qb.build_query_as::<Dispute>().fetch_one(&pool).await
        }
    }

    fn by_id(
        pool: &Pool<Sqlite>,
        id: uuid::Uuid,
    ) -> impl Future<Output = Result<Option<Self>, sqlx::Error>> + Send {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, Dispute>("SELECT * FROM disputes WHERE id = ? LIMIT 1")
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
    use crate::order::Status;
    use uuid::Uuid;

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
    async fn create_by_id_roundtrip() {
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
    async fn by_id_returns_none_for_missing_row() {
        let pool = setup_pool().await;
        let missing = Dispute::by_id(&pool, Uuid::new_v4()).await.expect("by_id");
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn update_persists_changes() {
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
        assert_eq!(
            updated.solver_pubkey.as_deref(),
            Some("c".repeat(64).as_str())
        );
        assert_eq!(updated.taken_at, 1_700_000_200);
    }
}
