use std::sync::Arc;
use tracing::info;

use crate::cache::Cache;
use crate::merge;
use crate::providers::{
    CompanyData, DomainData, EmailCandidate, EmailVerification, EnrichmentProvider, PersonData,
    ProviderTier,
};

const CONFIDENCE_THRESHOLD: f64 = 0.7;

/// Waterfall orchestrator: tries providers cheapest-first, merges results,
/// escalates to next tier only if confidence is below threshold.
pub struct Waterfall {
    providers: Vec<Arc<dyn EnrichmentProvider>>,
    cache: Cache,
}

impl Waterfall {
    pub fn new(providers: Vec<Arc<dyn EnrichmentProvider>>, cache: Cache) -> Self {
        Self { providers, cache }
    }

    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// Get providers grouped and sorted by tier.
    fn providers_by_tier(&self, tier: ProviderTier) -> Vec<&Arc<dyn EnrichmentProvider>> {
        self.providers
            .iter()
            .filter(|p| p.tier() == tier)
            .collect()
    }

    // ---- Person enrichment ----

    pub async fn enrich_person(
        &self,
        first_name: &str,
        last_name: &str,
        domain: &str,
    ) -> PersonData {
        let query = serde_json::json!({
            "first_name": first_name,
            "last_name": last_name,
            "domain": domain,
        });

        // Check cache
        if let Some(cached) = self.cache.get("person", &query).await {
            if let Ok(data) = serde_json::from_value::<PersonData>(cached) {
                return data;
            }
        }

        let mut all_results = Vec::new();

        for tier in [ProviderTier::Free, ProviderTier::Freemium, ProviderTier::Paid] {
            let providers = self.providers_by_tier(tier);
            if providers.is_empty() {
                continue;
            }

            for provider in &providers {
                if let Some(result) = provider.enrich_person(first_name, last_name, domain).await {
                    info!(provider = provider.name(), "Person enrichment result");
                    all_results.push(result);
                }
            }

            let merged = merge::merge_person(all_results.clone());
            if merged.confidence >= CONFIDENCE_THRESHOLD {
                let result_json = serde_json::to_value(&merged).unwrap_or_default();
                self.cache
                    .set("person", &query, &result_json, &merged.source)
                    .await;
                return merged;
            }
        }

        let result = merge::merge_person(all_results);
        let result_json = serde_json::to_value(&result).unwrap_or_default();
        self.cache
            .set("person", &query, &result_json, &result.source)
            .await;
        result
    }

    // ---- Company enrichment ----

    pub async fn enrich_company(&self, domain: &str) -> CompanyData {
        let query = serde_json::json!({ "domain": domain });

        if let Some(cached) = self.cache.get("company", &query).await {
            if let Ok(data) = serde_json::from_value::<CompanyData>(cached) {
                return data;
            }
        }

        let mut all_results = Vec::new();

        for tier in [ProviderTier::Free, ProviderTier::Freemium, ProviderTier::Paid] {
            let providers = self.providers_by_tier(tier);
            if providers.is_empty() {
                continue;
            }

            for provider in &providers {
                if let Some(result) = provider.enrich_company(domain).await {
                    info!(provider = provider.name(), "Company enrichment result");
                    all_results.push(result);
                }
            }

            let merged = merge::merge_company(all_results.clone());
            if merged.confidence >= CONFIDENCE_THRESHOLD {
                let result_json = serde_json::to_value(&merged).unwrap_or_default();
                self.cache
                    .set("company", &query, &result_json, &merged.source)
                    .await;
                return merged;
            }
        }

        let result = merge::merge_company(all_results);
        let result_json = serde_json::to_value(&result).unwrap_or_default();
        self.cache
            .set("company", &query, &result_json, &result.source)
            .await;
        result
    }

    // ---- Email verification ----

    pub async fn verify_email(&self, email: &str) -> EmailVerification {
        let query = serde_json::json!({ "email": email });

        if let Some(cached) = self.cache.get("email", &query).await {
            if let Ok(data) = serde_json::from_value::<EmailVerification>(cached) {
                return data;
            }
        }

        let mut all_results = Vec::new();

        for tier in [ProviderTier::Free, ProviderTier::Freemium, ProviderTier::Paid] {
            let providers = self.providers_by_tier(tier);
            for provider in &providers {
                if let Some(result) = provider.verify_email(email).await {
                    info!(provider = provider.name(), "Email verification result");
                    all_results.push(result);
                }
            }

            if !all_results.is_empty() {
                let merged = merge::merge_email_verification(all_results.clone());
                if merged.confidence >= CONFIDENCE_THRESHOLD {
                    let result_json = serde_json::to_value(&merged).unwrap_or_default();
                    self.cache
                        .set("email", &query, &result_json, &merged.source)
                        .await;
                    return merged;
                }
            }
        }

        if all_results.is_empty() {
            return EmailVerification {
                email: email.to_string(),
                deliverable: false,
                catch_all: false,
                disposable: false,
                mx_found: false,
                smtp_verified: false,
                smtp_detail: "no providers available".to_string(),
                confidence: 0.0,
                source: "none".to_string(),
            };
        }

        let result = merge::merge_email_verification(all_results);
        let result_json = serde_json::to_value(&result).unwrap_or_default();
        self.cache
            .set("email", &query, &result_json, &result.source)
            .await;
        result
    }

    // ---- Email candidate generation ----

    pub async fn find_emails(
        &self,
        first_name: &str,
        last_name: &str,
        domain: &str,
    ) -> Vec<EmailCandidate> {
        let mut all_candidates = Vec::new();
        let mut seen_emails = std::collections::HashSet::new();

        for tier in [ProviderTier::Free, ProviderTier::Freemium, ProviderTier::Paid] {
            for provider in self.providers_by_tier(tier) {
                let candidates = provider.find_emails(first_name, last_name, domain).await;
                for c in candidates {
                    if seen_emails.insert(c.email.clone()) {
                        all_candidates.push(c);
                    }
                }
            }

            // If we have a verified candidate, stop escalating
            if all_candidates.iter().any(|c| c.verified) {
                break;
            }
        }

        // Sort by confidence descending
        all_candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        all_candidates
    }

    // ---- Domain info ----

    pub async fn domain_info(&self, domain: &str) -> Option<DomainData> {
        let query = serde_json::json!({ "domain": domain });

        if let Some(cached) = self.cache.get("domain", &query).await {
            if let Ok(data) = serde_json::from_value::<DomainData>(cached) {
                return Some(data);
            }
        }

        // Domain info is primarily DNS — just call DNS providers
        for provider in &self.providers {
            if let Some(result) = provider.domain_info(domain).await {
                let result_json = serde_json::to_value(&result).unwrap_or_default();
                self.cache
                    .set("domain", &query, &result_json, &result.source)
                    .await;
                return Some(result);
            }
        }

        None
    }
}
