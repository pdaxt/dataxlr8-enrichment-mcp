use anyhow::Result;
use sqlx::PgPool;

/// Create the enrichment schema in PostgreSQL if it doesn't exist.
pub async fn setup_schema(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(
        r#"
        CREATE SCHEMA IF NOT EXISTS enrichment;

        CREATE TABLE IF NOT EXISTS enrichment.lookups (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            lookup_type TEXT NOT NULL,
            query       JSONB NOT NULL,
            result      JSONB,
            source      TEXT,
            cached_at   TIMESTAMPTZ DEFAULT now(),
            expires_at  TIMESTAMPTZ DEFAULT now() + interval '7 days'
        );

        CREATE INDEX IF NOT EXISTS idx_lookups_type ON enrichment.lookups(lookup_type);
        CREATE INDEX IF NOT EXISTS idx_lookups_query ON enrichment.lookups USING gin(query);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
