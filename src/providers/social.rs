use super::{CompanyData, EnrichmentProvider, ProviderTier};
use std::collections::HashMap;

pub struct SocialProvider;

impl SocialProvider {
    pub fn new() -> Self {
        Self
    }

    /// Generate social media profile URLs for a company.
    pub fn generate_profiles(
        company_name: &str,
        domain: &str,
    ) -> HashMap<String, serde_json::Value> {
        let slug: String = company_name
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect();
        let domain_slug = domain.split('.').next().unwrap_or(domain);

        let mut profiles = HashMap::new();
        profiles.insert(
            "linkedin".to_string(),
            serde_json::json!({
                "by_name": format!("https://linkedin.com/company/{slug}"),
                "by_domain": format!("https://linkedin.com/company/{domain_slug}"),
            }),
        );
        profiles.insert(
            "twitter".to_string(),
            serde_json::json!({
                "by_name": format!("https://twitter.com/{slug}"),
                "by_domain": format!("https://twitter.com/{domain_slug}"),
            }),
        );
        profiles.insert(
            "github".to_string(),
            serde_json::json!({
                "by_name": format!("https://github.com/{slug}"),
                "by_domain": format!("https://github.com/{domain_slug}"),
            }),
        );
        profiles
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for SocialProvider {
    fn name(&self) -> &str {
        "social"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Free
    }

    async fn enrich_company(&self, domain: &str) -> Option<CompanyData> {
        let domain_slug = domain.split('.').next().unwrap_or(domain);
        let mut social = HashMap::new();
        social.insert(
            "linkedin".to_string(),
            format!("https://linkedin.com/company/{domain_slug}"),
        );
        social.insert(
            "twitter".to_string(),
            format!("https://twitter.com/{domain_slug}"),
        );
        social.insert(
            "github".to_string(),
            format!("https://github.com/{domain_slug}"),
        );

        Some(CompanyData {
            domain: Some(domain.to_string()),
            social_profiles: social,
            confidence: 0.2,
            source: "social".to_string(),
            ..Default::default()
        })
    }
}
