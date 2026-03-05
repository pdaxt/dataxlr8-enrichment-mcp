use super::{EnrichmentProvider, ProviderTier};

/// Stub: People Data Labs enrichment.
/// Requires PDL_API_KEY. 1,000 free records.
pub struct PdlProvider {
    #[allow(dead_code)]
    client: reqwest::Client,
    #[allow(dead_code)]
    api_key: String,
}

impl PdlProvider {
    pub fn new(client: reqwest::Client, api_key: String) -> Self {
        Self { client, api_key }
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for PdlProvider {
    fn name(&self) -> &str {
        "pdl"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Freemium
    }
}
