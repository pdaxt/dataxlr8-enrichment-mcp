use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Provider tiers — controls waterfall ordering (cheapest first)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderTier {
    Free = 0,
    Freemium = 1,
    Paid = 2,
}

// ============================================================================
// Shared data types returned by providers
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonData {
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub title: Option<String>,
    pub company: Option<String>,
    pub linkedin_url: Option<String>,
    pub github_url: Option<String>,
    pub twitter_url: Option<String>,
    pub phone: Option<String>,
    pub location: Option<String>,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompanyData {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub description: Option<String>,
    pub industry: Option<String>,
    pub size: Option<String>,
    pub tech_stack: Vec<String>,
    pub social_profiles: HashMap<String, String>,
    pub location: Option<String>,
    pub founded_year: Option<i32>,
    pub logo_url: Option<String>,
    pub mx_records: Vec<String>,
    pub ips: Vec<String>,
    pub nameservers: Vec<String>,
    pub http_status: Option<u16>,
    pub server: Option<String>,
    pub x_powered_by: Option<String>,
    pub x_generator: Option<String>,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailVerification {
    pub email: String,
    pub deliverable: bool,
    pub catch_all: bool,
    pub disposable: bool,
    pub mx_found: bool,
    pub smtp_verified: bool,
    pub smtp_detail: String,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailCandidate {
    pub email: String,
    pub pattern: String,
    pub verified: bool,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainData {
    pub domain: String,
    pub ips: Vec<String>,
    pub mx_records: Vec<String>,
    pub nameservers: Vec<String>,
    pub registrar: Option<String>,
    pub created_date: Option<String>,
    pub expiry_date: Option<String>,
    pub source: String,
}

// ============================================================================
// Provider trait — each provider implements what it can
// ============================================================================

#[async_trait::async_trait]
pub trait EnrichmentProvider: Send + Sync {
    fn name(&self) -> &str;
    fn tier(&self) -> ProviderTier;

    async fn enrich_person(
        &self,
        _first_name: &str,
        _last_name: &str,
        _domain: &str,
    ) -> Option<PersonData> {
        None
    }

    async fn enrich_company(&self, _domain: &str) -> Option<CompanyData> {
        None
    }

    async fn find_emails(
        &self,
        _first_name: &str,
        _last_name: &str,
        _domain: &str,
    ) -> Vec<EmailCandidate> {
        vec![]
    }

    async fn verify_email(&self, _email: &str) -> Option<EmailVerification> {
        None
    }

    async fn domain_info(&self, _domain: &str) -> Option<DomainData> {
        None
    }
}

// ============================================================================
// Submodules — one per provider
// ============================================================================

pub mod dns;
pub mod emailrep;
pub mod fullcontact;
pub mod github;
pub mod http;
pub mod hunter;
pub mod pdl;
pub mod smtp;
pub mod social;
pub mod whois;
