use sqlx::PgPool;
use tracing::{error, warn};

/// PostgreSQL-backed enrichment cache with TTL support.
pub struct Cache {
    pool: PgPool,
}

impl Cache {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Look up a cached result. Returns None if not found or expired.
    pub async fn get(
        &self,
        lookup_type: &str,
        query: &serde_json::Value,
    ) -> Option<serde_json::Value> {
        match sqlx::query_as::<_, (serde_json::Value,)>(
            "SELECT result FROM enrichment.lookups \
             WHERE lookup_type = $1 AND query @> $2 AND expires_at > now() \
             ORDER BY cached_at DESC LIMIT 1",
        )
        .bind(lookup_type)
        .bind(query)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(Some((result,))) => Some(result),
            Ok(None) => None,
            Err(e) => {
                warn!(lookup_type, error = %e, "Cache lookup failed");
                None
            }
        }
    }

    /// Store a result with the default 7-day TTL.
    pub async fn set(
        &self,
        lookup_type: &str,
        query: &serde_json::Value,
        result: &serde_json::Value,
        source: &str,
    ) {
        if let Err(e) = sqlx::query(
            "INSERT INTO enrichment.lookups (lookup_type, query, result, source) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(lookup_type)
        .bind(query)
        .bind(result)
        .bind(source)
        .execute(&self.pool)
        .await
        {
            error!(lookup_type, error = %e, "Failed to cache enrichment result");
        }
    }

    /// Store a result with a custom TTL in days.
    pub async fn set_with_ttl(
        &self,
        lookup_type: &str,
        query: &serde_json::Value,
        result: &serde_json::Value,
        source: &str,
        ttl_days: i32,
    ) {
        let ttl = format!("{ttl_days} days");
        if let Err(e) = sqlx::query(
            "INSERT INTO enrichment.lookups (lookup_type, query, result, source, expires_at) \
             VALUES ($1, $2, $3, $4, now() + $5::interval)",
        )
        .bind(lookup_type)
        .bind(query)
        .bind(result)
        .bind(source)
        .bind(&ttl)
        .execute(&self.pool)
        .await
        {
            error!(lookup_type, error = %e, "Failed to cache enrichment result");
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
