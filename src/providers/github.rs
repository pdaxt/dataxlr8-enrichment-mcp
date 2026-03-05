//! GitHub enrichment provider — person lookup via GitHub user search API.
//!
//! Requires `GITHUB_TOKEN` env var. Free tier: 5,000 requests/hour.

use super::{EnrichmentProvider, PersonData, ProviderTier};
use tracing::warn;

pub struct GithubProvider {
    client: reqwest::Client,
    token: String,
}

impl GithubProvider {
    pub fn new(client: reqwest::Client, token: String) -> Self {
        Self { client, token }
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for GithubProvider {
    fn name(&self) -> &str {
        "github"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Free
    }

    async fn enrich_person(
        &self,
        first_name: &str,
        last_name: &str,
        _domain: &str,
    ) -> Option<PersonData> {
        // Use space separator — reqwest URL-encodes it to `+` which GitHub expects.
        // Using literal `+` would get double-encoded to `%2B`.
        let query = format!("{first_name} {last_name} in:fullname");
        let resp = self
            .client
            .get("https://api.github.com/search/users")
            .query(&[("q", &query)])
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "DataXLR8-Enrichment/0.2")
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            warn!(status = %resp.status(), "GitHub search API error");
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;
        let items = body["items"].as_array()?;
        let first_match = items.first()?;

        let login = first_match["login"].as_str().unwrap_or_default();
        let html_url = first_match["html_url"].as_str().unwrap_or_default();

        // Fetch full user profile for richer data
        let profile_resp = self
            .client
            .get(format!("https://api.github.com/users/{login}"))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "DataXLR8-Enrichment/0.2")
            .send()
            .await
            .ok()?;

        if !profile_resp.status().is_success() {
            return Some(PersonData {
                first_name: Some(first_name.to_string()),
                last_name: Some(last_name.to_string()),
                github_url: Some(html_url.to_string()),
                confidence: 0.3,
                source: "github".to_string(),
                ..Default::default()
            });
        }

        let profile: serde_json::Value = profile_resp.json().await.ok()?;

        Some(PersonData {
            first_name: Some(first_name.to_string()),
            last_name: Some(last_name.to_string()),
            company: profile["company"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
            location: profile["location"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
            github_url: Some(html_url.to_string()),
            twitter_url: profile["twitter_username"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|u| format!("https://twitter.com/{u}")),
            email: profile["email"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
            confidence: 0.4,
            source: "github".to_string(),
            ..Default::default()
        })
    }
}
