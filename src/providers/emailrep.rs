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
    fn tier(&self) -> ProviderTier {
        if self.api_key.is_empty() {
            ProviderTier::Free
        } else {
            ProviderTier::Freemium
        }
    }

    async fn verify_email(&self, email: &str) -> Option<EmailVerification> {
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

        // Confidence based on reputation
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
            mx_found: true, // emailrep doesn't report this directly
            smtp_verified: false,
            smtp_detail: format!(
                "reputation={reputation}, suspicious={suspicious}, references={references}, free={free_provider}"
            ),
            confidence,
            source: "emailrep".to_string(),
        })
    }
}
