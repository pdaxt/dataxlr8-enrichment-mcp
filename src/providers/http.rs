use super::{CompanyData, EnrichmentProvider, ProviderTier};
use tracing::warn;

pub struct HttpProvider {
    client: reqwest::Client,
}

impl HttpProvider {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    pub fn extract_title(body: &str) -> String {
        if let Some(start) = body.find("<title") {
            if let Some(gt) = body[start..].find('>') {
                let after = start + gt + 1;
                if let Some(end) = body[after..].find("</title>") {
                    return body[after..after + end].trim().to_string();
                }
            }
        }
        String::new()
    }

    pub fn extract_description(body: &str) -> String {
        let lower = body.to_ascii_lowercase();
        if let Some(pos) = lower.find("name=\"description\"") {
            let region_start = pos.saturating_sub(200);
            let region_end = std::cmp::min(pos + 300, lower.len());
            let region = &lower[region_start..region_end];
            if let Some(c) = region.find("content=\"") {
                let abs_start = region_start + c + 9;
                if abs_start < body.len() {
                    if let Some(end) = body[abs_start..].find('"') {
                        return body[abs_start..abs_start + end].to_string();
                    }
                }
            }
        }
        String::new()
    }

    pub fn detect_technologies(body: &str) -> Vec<String> {
        let lower = body.to_lowercase();
        let mut techs = Vec::new();
        if lower.contains("wp-content") || lower.contains("wp-includes") {
            techs.push("WordPress".to_string());
        }
        if lower.contains("shopify") {
            techs.push("Shopify".to_string());
        }
        if lower.contains("next/static") || lower.contains("_next/") {
            techs.push("Next.js".to_string());
        }
        if lower.contains("react") {
            techs.push("React".to_string());
        }
        if lower.contains("vue") {
            techs.push("Vue.js".to_string());
        }
        if lower.contains("angular") {
            techs.push("Angular".to_string());
        }
        if lower.contains("gatsby") {
            techs.push("Gatsby".to_string());
        }
        if lower.contains("squarespace") {
            techs.push("Squarespace".to_string());
        }
        if lower.contains("wix.com") {
            techs.push("Wix".to_string());
        }
        if lower.contains("drupal") {
            techs.push("Drupal".to_string());
        }
        if lower.contains("hubspot") {
            techs.push("HubSpot".to_string());
        }
        if lower.contains("webflow") {
            techs.push("Webflow".to_string());
        }
        techs
    }

    /// Check common hiring page paths and return structured results.
    pub async fn check_hiring(&self, domain: &str) -> serde_json::Value {
        let paths = ["/careers", "/jobs", "/join-us", "/work-with-us"];
        let mut signals = Vec::new();

        for path in &paths {
            let url = format!("https://{domain}{path}");
            match self.client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let has_content = if status == 200 {
                        resp.text()
                            .await
                            .map(|b| b.len() > 500)
                            .unwrap_or(false)
                    } else {
                        false
                    };
                    signals.push(serde_json::json!({
                        "path": path,
                        "status": status,
                        "has_content": has_content,
                    }));
                }
                Err(_) => {
                    signals.push(serde_json::json!({
                        "path": path,
                        "status": 0,
                        "has_content": false,
                    }));
                }
            }
        }

        let is_hiring = signals
            .iter()
            .any(|s| s["has_content"].as_bool().unwrap_or(false));

        serde_json::json!({
            "domain": domain,
            "is_hiring": is_hiring,
            "pages": signals,
        })
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for HttpProvider {
    fn name(&self) -> &str {
        "http"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Free
    }

    async fn enrich_company(&self, domain: &str) -> Option<CompanyData> {
        let url = format!("https://{domain}");
        match self.client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let server = resp
                    .headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let x_powered_by = resp
                    .headers()
                    .get("x-powered-by")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let x_generator = resp
                    .headers()
                    .get("x-generator")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);

                let body = resp.text().await.unwrap_or_default();
                let title = Self::extract_title(&body);
                let description = Self::extract_description(&body);

                let mut tech_stack = Self::detect_technologies(&body);
                if let Some(ref s) = server {
                    if !s.is_empty() {
                        tech_stack.push(format!("Server: {s}"));
                    }
                }
                if let Some(ref p) = x_powered_by {
                    if !p.is_empty() {
                        tech_stack.push(format!("X-Powered-By: {p}"));
                    }
                }
                if let Some(ref g) = x_generator {
                    if !g.is_empty() {
                        tech_stack.push(format!("X-Generator: {g}"));
                    }
                }
                tech_stack.sort();
                tech_stack.dedup();

                Some(CompanyData {
                    domain: Some(domain.to_string()),
                    name: if title.is_empty() {
                        None
                    } else {
                        Some(title)
                    },
                    description: if description.is_empty() {
                        None
                    } else {
                        Some(description)
                    },
                    http_status: Some(status),
                    server,
                    x_powered_by,
                    x_generator,
                    tech_stack,
                    confidence: 0.4,
                    source: "http".to_string(),
                    ..Default::default()
                })
            }
            Err(e) => {
                warn!(domain, error = %e, "HTTP GET failed for company enrichment");
                None
            }
        }
    }
}
