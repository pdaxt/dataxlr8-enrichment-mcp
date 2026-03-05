//! EmailRep enrichment provider — email reputation scoring.
//!
//! Free API (no key needed, lower rate limits). Optional `EMAILREP_API_KEY` for higher limits.
//! Always classified as Free tier since the API itself is free.

use super::{EmailVerification, EnrichmentProvider, ProviderTier};
use tracing::warn;

pub struct EmailRepProvider {
    client: reqwest::Client,
    api_key: String,
}

impl EmailRepProvider {
    pub fn new(client: reqwest::Client, api_key: String) -> Self {
        Self { client, api_key }
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for EmailRepProvider {
    fn name(&self) -> &str {
        "emailrep"
    }

    /// Always Free — the API is free regardless of whether a key is provided.
    /// A key only increases rate limits, it doesn't change the pricing tier.
    fn tier(&self) -> ProviderTier {
        ProviderTier::Free
    }

    async fn verify_email(&self, email: &str) -> Option<EmailVerification> {
        // Basic email format check before making the API call.
        if !email.contains('@') || email.contains(|c: char| c.is_whitespace()) {
            return None;
        }

        let url = format!("https://emailrep.io/{email}");
        let mut req = self
            .client
            .get(&url)
            .header("User-Agent", "DataXLR8-Enrichment/0.2");

        if !self.api_key.is_empty() {
            req = req.header("Key", &self.api_key);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "EmailRep request failed");
                return None;
            }
        };

        if !resp.status().is_success() {
            warn!(status = %resp.status(), "EmailRep API error");
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;

        let reputation = body["reputation"].as_str().unwrap_or("none");
        let suspicious = body["suspicious"].as_bool().unwrap_or(true);
        let references = body["references"].as_u64().unwrap_or(0);
        let details = &body["details"];

        let deliverable = details["deliverable"].as_bool().unwrap_or(false);
        let disposable = details["disposable"].as_bool().unwrap_or(false);
        let free_provider = details["free_provider"].as_bool().unwrap_or(false);

        let confidence = match reputation {
            "high" => 0.9,
            "medium" => 0.6,
            "low" => 0.3,
            _ => 0.1,
        };

        Some(EmailVerification {
            email: email.to_string(),
            deliverable: deliverable && !suspicious,
            catch_all: false,
            disposable,
            mx_found: true,
            smtp_verified: false,
            smtp_detail: format!(
                "reputation={reputation}, suspicious={suspicious}, references={references}, free={free_provider}"
            ),
            confidence,
            source: "emailrep".to_string(),
        })
    }
}
