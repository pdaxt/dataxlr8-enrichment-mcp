use super::{EnrichmentProvider, ProviderTier};

/// Stub: WHOIS domain registration data.
/// Future implementation will parse WHOIS responses for registrar, creation date, expiry.
pub struct WhoisProvider;

impl WhoisProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for WhoisProvider {
    fn name(&self) -> &str {
        "whois"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Free
    }
}
