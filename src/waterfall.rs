//! Waterfall orchestrator — tries providers cheapest-first, merges results,
//! escalates to next tier only if confidence is below threshold.
//!
//! Providers within the same tier run concurrently via `tokio::task::JoinSet`
//! to minimize wall-clock time for multi-provider lookups.

use std::sync::Arc;
use tracing::info;

use crate::cache::Cache;
use crate::merge;
use crate::providers::{
    CompanyData, DomainData, EmailCandidate, EmailVerification, EnrichmentProvider, PersonData,
    ProviderTier,
};

/// Minimum confidence to accept a merged result without escalating to the next tier.
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

    /// Get providers that belong to a specific tier.
    fn providers_by_tier(&self, tier: ProviderTier) -> Vec<Arc<dyn EnrichmentProvider>> {
        self.providers
            .iter()
            .filter(|p| p.tier() == tier)
            .cloned()
            .collect()
    }

    /// Cache a result only if it has meaningful content (confidence > 0).
    async fn cache_if_meaningful(
        &self,
        lookup_type: &str,
        query: &serde_json::Value,
        result_json: &serde_json::Value,
        source: &str,
        confidence: f64,
    ) {
        if confidence > 0.0 && !source.is_empty() {
            self.cache.set(lookup_type, query, result_json, source).await;
        }
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

        // Check cache first
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

            // Run all providers in this tier concurrently
            let mut set = tokio::task::JoinSet::new();
            for provider in providers {
                let fn_owned = first_name.to_string();
                let ln_owned = last_name.to_string();
                let d_owned = domain.to_string();
                set.spawn(async move {
                    let name = provider.name().to_string();
                    let result = provider.enrich_person(&fn_owned, &ln_owned, &d_owned).await;
                    (name, result)
                });
            }
            while let Some(Ok((name, Some(result)))) = set.join_next().await {
                info!(provider = %name, "Person enrichment result");
                all_results.push(result);
            }

            // Check if we've reached sufficient confidence
            let max_conf = all_results.iter().map(|r| r.confidence).fold(0.0f64, f64::max);
            if max_conf >= CONFIDENCE_THRESHOLD {
                let merged = merge::merge_person(all_results);
                let result_json = serde_json::to_value(&merged).unwrap_or_default();
                self.cache_if_meaningful("person", &query, &result_json, &merged.source, merged.confidence).await;
                return merged;
            }
        }

        let result = merge::merge_person(all_results);
        let result_json = serde_json::to_value(&result).unwrap_or_default();
        self.cache_if_meaningful("person", &query, &result_json, &result.source, result.confidence).await;
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

            let mut set = tokio::task::JoinSet::new();
            for provider in providers {
                let d_owned = domain.to_string();
                set.spawn(async move {
                    let name = provider.name().to_string();
                    let result = provider.enrich_company(&d_owned).await;
                    (name, result)
                });
            }
            while let Some(Ok((name, Some(result)))) = set.join_next().await {
                info!(provider = %name, "Company enrichment result");
                all_results.push(result);
            }

            let max_conf = all_results.iter().map(|r| r.confidence).fold(0.0f64, f64::max);
            if max_conf >= CONFIDENCE_THRESHOLD {
                let merged = merge::merge_company(all_results);
                let result_json = serde_json::to_value(&merged).unwrap_or_default();
                self.cache_if_meaningful("company", &query, &result_json, &merged.source, merged.confidence).await;
                return merged;
            }
        }

        let result = merge::merge_company(all_results);
        let result_json = serde_json::to_value(&result).unwrap_or_default();
        self.cache_if_meaningful("company", &query, &result_json, &result.source, result.confidence).await;
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
            if providers.is_empty() {
                continue;
            }

            let mut set = tokio::task::JoinSet::new();
            for provider in providers {
                let e_owned = email.to_string();
                set.spawn(async move {
                    let name = provider.name().to_string();
                    let result = provider.verify_email(&e_owned).await;
                    (name, result)
                });
            }
            while let Some(Ok((name, Some(result)))) = set.join_next().await {
                info!(provider = %name, "Email verification result");
                all_results.push(result);
            }

            if !all_results.is_empty() {
                let max_conf = all_results.iter().map(|r| r.confidence).fold(0.0f64, f64::max);
                if max_conf >= CONFIDENCE_THRESHOLD {
                    let merged = merge::merge_email_verification(all_results);
                    let result_json = serde_json::to_value(&merged).unwrap_or_default();
                    self.cache_if_meaningful("email", &query, &result_json, &merged.source, merged.confidence).await;
                    return merged;
                }
            }
        }

        if all_results.is_empty() {
            return EmailVerification {
                email: email.to_string(),
                smtp_detail: "no providers available".to_string(),
                source: "none".to_string(),
                ..Default::default()
            };
        }

        let result = merge::merge_email_verification(all_results);
        let result_json = serde_json::to_value(&result).unwrap_or_default();
        self.cache_if_meaningful("email", &query, &result_json, &result.source, result.confidence).await;
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
