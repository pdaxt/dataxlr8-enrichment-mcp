//! DNS enrichment provider — MX, A/AAAA, NS lookups via hickory-resolver.
//!
//! The resolver is created once (via `OnceCell`) and reused for all lookups,
//! which lets hickory's internal response cache work across calls.

use super::{CompanyData, DomainData, EmailVerification, EnrichmentProvider, ProviderTier};
use tracing::warn;

/// Global resolver — created on first use, then reused for the process lifetime.
/// This is critical: creating a new resolver per call defeats the internal DNS cache
/// and opens a new UDP socket each time.
static RESOLVER: tokio::sync::OnceCell<hickory_resolver::TokioResolver> =
    tokio::sync::OnceCell::const_new();

async fn get_resolver() -> Option<&'static hickory_resolver::TokioResolver> {
    match RESOLVER
        .get_or_try_init(|| async {
            hickory_resolver::Resolver::builder_tokio().map(|b| b.build())
        })
        .await
    {
        Ok(r) => Some(r),
        Err(e) => {
            warn!(error = %e, "DNS resolver init failed");
            None
        }
    }
}

/// Strip the trailing dot from FQDN strings (e.g. "smtp.google.com." → "smtp.google.com").
/// Trailing dots are valid in DNS but break SMTP `TcpStream::connect("host.:25")` on some platforms.
fn strip_trailing_dot(mut s: String) -> String {
    if s.ends_with('.') {
        s.pop();
    }
    s
}

pub struct DnsProvider;

impl DnsProvider {
    pub fn new() -> Self {
        Self
    }

    pub async fn mx_lookup(domain: &str) -> Vec<String> {
        let resolver = match get_resolver().await {
            Some(r) => r,
            None => return Vec::new(),
        };
        match resolver.mx_lookup(domain).await {
            Ok(records) => {
                let mut hosts: Vec<String> = records
                    .iter()
                    .map(|mx| strip_trailing_dot(mx.exchange().to_ascii()))
                    .collect();
                hosts.sort();
                hosts.dedup();
                hosts
            }
            Err(e) => {
                warn!(domain, error = %e, "MX lookup failed");
                Vec::new()
            }
        }
    }

    pub async fn a_lookup(domain: &str) -> Vec<String> {
        let resolver = match get_resolver().await {
            Some(r) => r,
            None => return Vec::new(),
        };
        match resolver.lookup_ip(domain).await {
            Ok(ips) => ips
                .iter()
                .map(|ip: std::net::IpAddr| ip.to_string())
                .collect(),
            Err(e) => {
                warn!(domain, error = %e, "A/AAAA lookup failed");
                Vec::new()
            }
        }
    }

    pub async fn ns_lookup(domain: &str) -> Vec<String> {
        let resolver = match get_resolver().await {
            Some(r) => r,
            None => return Vec::new(),
        };
        match resolver.ns_lookup(domain).await {
            Ok(records) => records
                .iter()
                .map(|ns| strip_trailing_dot(ns.0.to_ascii()))
                .collect(),
            Err(e) => {
                warn!(domain, error = %e, "NS lookup failed");
                Vec::new()
            }
        }
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for DnsProvider {
    fn name(&self) -> &str {
        "dns"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Free
    }

    async fn enrich_company(&self, domain: &str) -> Option<CompanyData> {
        let mx_records = Self::mx_lookup(domain).await;
        let ips = Self::a_lookup(domain).await;
        Some(CompanyData {
            domain: Some(domain.to_string()),
            mx_records,
            ips,
            confidence: 0.3,
            source: "dns".to_string(),
            ..Default::default()
        })
    }

    async fn verify_email(&self, email: &str) -> Option<EmailVerification> {
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return None;
        }
        let domain = parts[1];
        let mx_records = Self::mx_lookup(domain).await;
        let mx_found = !mx_records.is_empty();
        Some(EmailVerification {
            email: email.to_string(),
            deliverable: false,
            catch_all: false,
            disposable: false,
            mx_found,
            smtp_verified: false,
            smtp_detail: if mx_found {
                "MX records found".to_string()
            } else {
                "No MX records".to_string()
            },
            confidence: if mx_found { 0.3 } else { 0.1 },
            source: "dns".to_string(),
        })
    }

    async fn domain_info(&self, domain: &str) -> Option<DomainData> {
        let ips = Self::a_lookup(domain).await;
        let mx_records = Self::mx_lookup(domain).await;
        let nameservers = Self::ns_lookup(domain).await;
        Some(DomainData {
            domain: domain.to_string(),
            ips,
            mx_records,
            nameservers,
            source: "dns".to_string(),
            ..Default::default()
        })
    }
}
