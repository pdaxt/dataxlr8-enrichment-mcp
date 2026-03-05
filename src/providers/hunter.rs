use super::{EmailCandidate, EmailVerification, EnrichmentProvider, PersonData, ProviderTier};
use tracing::warn;

pub struct HunterProvider {
    client: reqwest::Client,
    api_key: String,
}

impl HunterProvider {
    pub fn new(client: reqwest::Client, api_key: String) -> Self {
        Self { client, api_key }
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for HunterProvider {
    fn name(&self) -> &str {
        "hunter"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Freemium
    }

    async fn enrich_person(
        &self,
        first_name: &str,
        last_name: &str,
        domain: &str,
    ) -> Option<PersonData> {
        let resp = self
            .client
            .get("https://api.hunter.io/v2/email-finder")
            .query(&[
                ("domain", domain),
                ("first_name", first_name),
                ("last_name", last_name),
                ("api_key", &self.api_key),
            ])
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            warn!(status = %resp.status(), "Hunter.io email-finder error");
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;
        let data = &body["data"];

        let email = data["email"].as_str().map(String::from);
        if email.is_none() {
            return None;
        }

        let score = data["score"].as_f64().unwrap_or(0.0);

        Some(PersonData {
            email,
            first_name: Some(first_name.to_string()),
            last_name: Some(last_name.to_string()),
            title: data["position"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
            company: data["company"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
            linkedin_url: data["linkedin"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
            twitter_url: data["twitter"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from),
            confidence: score / 100.0,
            source: "hunter".to_string(),
            ..Default::default()
        })
    }

    async fn find_emails(
        &self,
        first_name: &str,
        last_name: &str,
        domain: &str,
    ) -> Vec<EmailCandidate> {
        let resp = match self
            .client
            .get("https://api.hunter.io/v2/email-finder")
            .query(&[
                ("domain", domain),
                ("first_name", first_name),
                ("last_name", last_name),
                ("api_key", &self.api_key),
            ])
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        if !resp.status().is_success() {
            return vec![];
        }

        let body: serde_json::Value = match resp.json().await {
            Ok(b) => b,
            Err(_) => return vec![],
        };

        let data = &body["data"];
        if let Some(email) = data["email"].as_str() {
            let score = data["score"].as_f64().unwrap_or(0.0);
            vec![EmailCandidate {
                email: email.to_string(),
                pattern: "hunter_found".to_string(),
                verified: score > 80.0,
                confidence: score / 100.0,
            }]
        } else {
            vec![]
        }
    }

    async fn verify_email(&self, email: &str) -> Option<EmailVerification> {
        let resp = self
            .client
            .get("https://api.hunter.io/v2/email-verifier")
            .query(&[("email", email), ("api_key", &self.api_key)])
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            warn!(status = %resp.status(), "Hunter.io email-verifier error");
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;
        let data = &body["data"];
        let result = data["result"].as_str().unwrap_or("unknown");
        let score = data["score"].as_f64().unwrap_or(0.0);

        Some(EmailVerification {
            email: email.to_string(),
            deliverable: result == "deliverable",
            catch_all: data["accept_all"].as_bool().unwrap_or(false),
            disposable: data["disposable"].as_bool().unwrap_or(false),
            mx_found: data["mx_records"].as_bool().unwrap_or(false),
            smtp_verified: data["smtp_check"].as_bool().unwrap_or(false),
            smtp_detail: format!("hunter: {result}"),
            confidence: score / 100.0,
            source: "hunter".to_string(),
        })
    }
}
