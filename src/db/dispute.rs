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
    set.push("status = ")
        .push_bind_unseparated(&dispute.status);
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
    fn create(
        self,
        pool: &Pool<Sqlite>,
    ) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
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

    fn update(
        self,
        pool: &Pool<Sqlite>,
    ) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
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
