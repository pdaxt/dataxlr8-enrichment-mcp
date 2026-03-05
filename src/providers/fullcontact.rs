use super::{EnrichmentProvider, ProviderTier};

/// Stub: FullContact person/company enrichment.
/// Requires FULLCONTACT_API_KEY. 100 free lookups/month.
pub struct FullContactProvider {
    #[allow(dead_code)]
    client: reqwest::Client,
    #[allow(dead_code)]
    api_key: String,
}

impl FullContactProvider {
    pub fn new(client: reqwest::Client, api_key: String) -> Self {
        Self { client, api_key }
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for FullContactProvider {
    fn name(&self) -> &str {
        "fullcontact"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Freemium
    }
}
