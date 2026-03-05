//! HTTP enrichment provider — scrapes company websites for title, description,
//! technology stack detection, and hiring signal pages.

use super::{CompanyData, EnrichmentProvider, ProviderTier};
use tracing::warn;

pub struct HttpProvider {
    client: reqwest::Client,
}

impl HttpProvider {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Extract `<title>` content (case-insensitive tag matching).
    pub fn extract_title(body: &str) -> String {
        let lower = body.to_ascii_lowercase();
        if let Some(start) = lower.find("<title") {
            if let Some(gt) = lower[start..].find('>') {
                let after = start + gt + 1;
                if let Some(end) = lower[after..].find("</title>") {
                    // Use original body for the content (preserves casing).
                    return body[after..after + end].trim().to_string();
                }
            }
        }
        String::new()
    }

    /// Extract `<meta name="description" content="...">` value.
    /// Uses ascii_lowercase to ensure byte-position parity with original body.
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

    /// Detect technologies from HTML content using specific, low-false-positive patterns.
    ///
    /// Each check uses patterns that are unique to the technology (class names, script paths,
    /// data attributes) rather than generic words that could appear in normal text.
    pub fn detect_technologies(body: &str) -> Vec<String> {
        let lower = body.to_lowercase();
        let mut techs = Vec::new();

        // WordPress: theme/plugin directory paths
        if lower.contains("wp-content/") || lower.contains("wp-includes/") {
            techs.push("WordPress".to_string());
        }
        // Shopify: CDN or JS paths
        if lower.contains("cdn.shopify.com") || lower.contains("shopify.com/s/") {
            techs.push("Shopify".to_string());
        }
        // Next.js: build output paths
        if lower.contains("/_next/static") || lower.contains("/_next/data") {
            techs.push("Next.js".to_string());
        }
        // React: DOM markers or build artifacts
        if lower.contains("data-reactroot")
            || lower.contains("react-dom")
            || lower.contains("__react")
        {
            techs.push("React".to_string());
        }
        // Vue.js: data attributes or runtime markers
        if lower.contains("data-v-") || lower.contains("vue.min.js") || lower.contains("__vue__")
        {
            techs.push("Vue.js".to_string());
        }
        // Angular: framework attributes
        if lower.contains("ng-version") || lower.contains("ng-app") || lower.contains("angular.min.js") {
            techs.push("Angular".to_string());
        }
        // Gatsby: build markers
        if lower.contains("___gatsby") || lower.contains("/gatsby-") {
            techs.push("Gatsby".to_string());
        }
        // Squarespace: CDN
        if lower.contains("squarespace.com") || lower.contains("sqsp.") {
            techs.push("Squarespace".to_string());
        }
        // Wix: runtime
        if lower.contains("static.wixstatic.com") || lower.contains("wix.com/") {
            techs.push("Wix".to_string());
        }
        // Drupal: settings or paths
        if lower.contains("drupal.settings") || lower.contains("/sites/default/files") {
            techs.push("Drupal".to_string());
        }
        // HubSpot: tracking or CMS
        if lower.contains("js.hs-scripts.com")
            || lower.contains("hubspot.com")
            || lower.contains("hs-banner")
        {
            techs.push("HubSpot".to_string());
        }
        // Webflow: runtime
        if lower.contains("webflow.com") || lower.contains("wf-page") {
            techs.push("Webflow".to_string());
        }
        // Laravel
        if lower.contains("laravel") && lower.contains("csrf-token") {
            techs.push("Laravel".to_string());
        }
        // Svelte
        if lower.contains("__svelte") || lower.contains("svelte-") {
            techs.push("Svelte".to_string());
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
