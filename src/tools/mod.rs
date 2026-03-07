use std::sync::Arc;

use dataxlr8_mcp_core::mcp::{empty_schema, error_result, get_i64, get_str, get_str_array, json_result, make_schema};
use dataxlr8_mcp_core::Database;
use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use rmcp::ServerHandler;

use crate::providers::dns::DnsProvider;
use crate::providers::http::HttpProvider;
use crate::providers::social::SocialProvider;
use crate::providers::smtp::SmtpProvider;
use crate::providers::EnrichmentProvider;
use crate::waterfall::Waterfall;


// ============================================================================
// Validation constants
// ============================================================================

const MAX_NAME_LEN: usize = 500;
const MAX_QUERY_LEN: usize = 1000;

fn build_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "enrich_person".into(),
            title: None,
            description: Some(
                "Enrich a person: generate email candidates, find social profiles, \
                 and verify domain MX. Uses waterfall across free and paid providers."
                    .into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "first_name": { "type": "string", "description": "Person's first name" },
                    "last_name": { "type": "string", "description": "Person's last name" },
                    "company_domain": { "type": "string", "description": "Company domain (e.g. acme.com)" }
                }),
                vec!["first_name", "last_name", "company_domain"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "enrich_company".into(),
            title: None,
            description: Some(
                "Enrich a company by domain: homepage, tech stack, DNS records, \
                 social profiles. Waterfall across multiple providers."
                    .into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "domain": { "type": "string", "description": "Company domain (e.g. acme.com)" }
                }),
                vec!["domain"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "verify_email".into(),
            title: None,
            description: Some(
                "Verify an email address: MX lookup, SMTP handshake, disposable check, \
                 and optional third-party verification via waterfall."
                    .into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "email": { "type": "string", "description": "Email address to verify" }
                }),
                vec!["email"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "domain_emails".into(),
            title: None,
            description: Some(
                "Generate and verify common email patterns for a domain \
                 (info@, hello@, contact@, support@, sales@, admin@)."
                    .into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "domain": { "type": "string", "description": "Domain to generate emails for" }
                }),
                vec!["domain"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "search_people".into(),
            title: None,
            description: Some("Search cached person enrichment results by keyword.".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "query": { "type": "string", "description": "Search keyword" },
                    "limit": { "type": "integer", "description": "Max results (default 20)" }
                }),
                vec!["query"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "reverse_domain".into(),
            title: None,
            description: Some(
                "DNS lookup for a domain: returns A/AAAA IPs, MX records, and nameservers.".into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "domain": { "type": "string", "description": "Domain to look up" }
                }),
                vec!["domain"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "bulk_enrich".into(),
            title: None,
            description: Some(
                "Enrich multiple company domains at once via waterfall.".into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "domains": { "type": "array", "items": { "type": "string" }, "description": "List of domains to enrich" }
                }),
                vec!["domains"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "tech_stack".into(),
            title: None,
            description: Some(
                "Detect technology stack from HTTP headers and HTML content patterns.".into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "domain": { "type": "string", "description": "Domain to analyze" }
                }),
                vec!["domain"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "hiring_signals".into(),
            title: None,
            description: Some(
                "Check if a company has active hiring pages (/careers, /jobs).".into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "domain": { "type": "string", "description": "Domain to check" }
                }),
                vec!["domain"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "social_profiles".into(),
            title: None,
            description: Some(
                "Generate social media profile URLs for a company (LinkedIn, Twitter/X, GitHub)."
                    .into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "company_name": { "type": "string", "description": "Company name" },
                    "domain": { "type": "string", "description": "Company domain" }
                }),
                vec!["company_name", "domain"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "enrichment_stats".into(),
            title: None,
            description: Some("Get statistics on cached enrichment data by lookup type.".into()),
            input_schema: empty_schema(),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "cache_lookup".into(),
            title: None,
            description: Some(
                "Check cache for a previous enrichment result by type and query JSON.".into(),
            ),
            input_schema: make_schema(
                serde_json::json!({
                    "lookup_type": { "type": "string", "description": "Type of lookup (person, company, email, domain)" },
                    "query_json": { "type": "object", "description": "Query parameters as JSON object to match" }
                }),
                vec!["lookup_type", "query_json"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
    ]
}

// ============================================================================
// MCP Server
// ============================================================================

#[derive(Clone)]
pub struct EnrichmentMcpServer {
    waterfall: Arc<Waterfall>,
    http_provider: Arc<HttpProvider>,
    db: Database,
}

impl EnrichmentMcpServer {
    pub fn new(db: Database) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("DataXLR8-Enrichment/0.2")
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to build HTTP client");

        // Free providers (always available)
        let dns = Arc::new(DnsProvider::new());
        let smtp = Arc::new(SmtpProvider::new());
        let http = Arc::new(HttpProvider::new(http_client.clone()));
        let social = Arc::new(SocialProvider::new());

        let mut providers: Vec<Arc<dyn crate::providers::EnrichmentProvider>> = vec![
            dns.clone(),
            smtp.clone(),
            http.clone(),
            social.clone(),
        ];

        // API-based providers — silently skipped if env var is not set
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            providers.push(Arc::new(
                crate::providers::github::GithubProvider::new(http_client.clone(), token),
            ));
        }
        if let Ok(key) = std::env::var("HUNTER_API_KEY") {
            providers.push(Arc::new(
                crate::providers::hunter::HunterProvider::new(http_client.clone(), key),
            ));
        }
        // EmailRep works without a key (lower rate limits)
        let emailrep_key = std::env::var("EMAILREP_API_KEY").unwrap_or_default();
        providers.push(Arc::new(
            crate::providers::emailrep::EmailRepProvider::new(http_client.clone(), emailrep_key),
        ));
        if let Ok(key) = std::env::var("FULLCONTACT_API_KEY") {
            providers.push(Arc::new(
                crate::providers::fullcontact::FullContactProvider::new(http_client.clone(), key),
            ));
        }
        if let Ok(key) = std::env::var("PDL_API_KEY") {
            providers.push(Arc::new(
                crate::providers::pdl::PdlProvider::new(http_client.clone(), key),
            ));
        }

        let cache = crate::cache::Cache::new(db.pool().clone());
        let waterfall = Arc::new(Waterfall::new(providers, cache));

        Self {
            waterfall,
            http_provider: http,
            db,
        }
    }

    /// Basic domain validation: must be non-empty, no whitespace, no path separators.
    fn is_valid_domain(domain: &str) -> bool {
        !domain.is_empty()
            && !domain.contains(|c: char| c.is_whitespace())
            && !domain.contains('/')
            && !domain.contains('\\')
            && domain.contains('.')
    }

    // ---- Tool handlers (thin wrappers) ----

    async fn handle_enrich_person(
        &self,
        first_name: &str,
        last_name: &str,
        domain: &str,
    ) -> CallToolResult {
        if first_name.is_empty() || last_name.is_empty() {
            return error_result("first_name and last_name must not be empty");
        }
        if !Self::is_valid_domain(domain) {
            return error_result("Invalid domain format");
        }

        let person = self
            .waterfall
            .enrich_person(first_name, last_name, domain)
            .await;
        let candidates = self
            .waterfall
            .find_emails(first_name, last_name, domain)
            .await;
        let mx_records = DnsProvider::mx_lookup(domain).await;

        json_result(&serde_json::json!({
            "person": person,
            "email_candidates": candidates,
            "mx_records": mx_records,
            "domain_has_mx": !mx_records.is_empty(),
        }))
    }

    async fn handle_enrich_company(&self, domain: &str) -> CallToolResult {
        if !Self::is_valid_domain(domain) {
            return error_result("Invalid domain format");
        }
        let company = self.waterfall.enrich_company(domain).await;
        json_result(&company)
    }

    async fn handle_verify_email(&self, email: &str) -> CallToolResult {
        // Reject emails with control characters (CRLF injection, null bytes, etc.)
        if email.contains(|c: char| c.is_control()) {
            return error_result("Invalid email: contains control characters");
        }
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return error_result("Invalid email format");
        }
        if parts[0].is_empty() || parts[1].is_empty() || !parts[1].contains('.') {
            return error_result("Invalid email format");
        }
        let result = self.waterfall.verify_email(email).await;
        json_result(&result)
    }

    async fn handle_domain_emails(&self, domain: &str) -> CallToolResult {
        if !Self::is_valid_domain(domain) {
            return error_result("Invalid domain format");
        }
        let prefixes = ["info", "hello", "contact", "support", "sales", "admin"];
        let mx_records = DnsProvider::mx_lookup(domain).await;
        let mx_host = mx_records.first().cloned();

        let mut results = Vec::new();
        for prefix in &prefixes {
            let email = format!("{prefix}@{domain}");
            let verification = if let Some(ref host) = mx_host {
                SmtpProvider::verify_with_mx(&email, &[host.clone()]).await
            } else {
                crate::providers::EmailVerification {
                    email: email.clone(),
                    deliverable: false,
                    catch_all: false,
                    disposable: false,
                    mx_found: false,
                    smtp_verified: false,
                    smtp_detail: "no MX records".to_string(),
                    confidence: 0.0,
                    source: "smtp".to_string(),
                }
            };
            results.push(serde_json::json!({
                "email": email,
                "smtp_valid": verification.smtp_verified,
                "smtp_detail": verification.smtp_detail,
            }));
        }

        json_result(&serde_json::json!({
            "domain": domain,
            "mx_records": mx_records,
            "emails": results,
        }))
    }

    async fn handle_search_people(&self, query_str: &str, limit: i64) -> CallToolResult {
        let query_str = query_str.trim();
        if query_str.is_empty() {
            return error_result("Parameter 'query' must not be empty");
        }
        if query_str.len() > MAX_QUERY_LEN {
            return error_result(&format!("'query' exceeds {} chars", MAX_QUERY_LEN));
        }
        // Escape LIKE/ILIKE metacharacters to prevent wildcard injection.
        let escaped = query_str
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        let rows: Vec<(serde_json::Value, serde_json::Value)> = match sqlx::query_as(
            "SELECT query, result FROM enrichment.lookups \
             WHERE lookup_type = 'person' AND result::text ILIKE $1 \
             ORDER BY cached_at DESC LIMIT $2",
        )
        .bind(&pattern)
        .bind(limit)
        .fetch_all(self.db.pool())
        .await
        {
            Ok(r) => r,
            Err(e) => return error_result(&format!("Database error: {e}")),
        };

        let results: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|(q, r)| serde_json::json!({ "query": q, "result": r }))
            .collect();

        json_result(&serde_json::json!({
            "count": results.len(),
            "results": results,
        }))
    }

    async fn handle_reverse_domain(&self, domain: &str) -> CallToolResult {
        if !Self::is_valid_domain(domain) {
            return error_result("Invalid domain format");
        }
        match self.waterfall.domain_info(domain).await {
            Some(info) => json_result(&info),
            None => error_result("Domain info lookup failed"),
        }
    }

    async fn handle_bulk_enrich(&self, domains: &[String]) -> CallToolResult {
        let mut results = Vec::new();
        for domain in domains {
            if !Self::is_valid_domain(domain) {
                results.push(serde_json::json!({
                    "domain": domain,
                    "error": "Invalid domain format",
                }));
                continue;
            }
            let company = self.waterfall.enrich_company(domain).await;
            results.push(serde_json::json!({
                "domain": domain,
                "data": company,
            }));
        }
        json_result(&serde_json::json!({
            "count": results.len(),
            "results": results,
        }))
    }

    async fn handle_tech_stack(&self, domain: &str) -> CallToolResult {
        if !Self::is_valid_domain(domain) {
            return error_result("Invalid domain format");
        }
        match self.http_provider.enrich_company(domain).await {
            Some(company) => json_result(&serde_json::json!({
                "domain": domain,
                "server": company.server,
                "x_powered_by": company.x_powered_by,
                "x_generator": company.x_generator,
                "technologies": company.tech_stack,
            })),
            None => json_result(&serde_json::json!({
                "domain": domain,
                "technologies": [],
            })),
        }
    }

    async fn handle_hiring_signals(&self, domain: &str) -> CallToolResult {
        if !Self::is_valid_domain(domain) {
            return error_result("Invalid domain format");
        }
        let result = self.http_provider.check_hiring(domain).await;
        json_result(&result)
    }

    async fn handle_social_profiles(
        &self,
        company_name: &str,
        domain: &str,
    ) -> CallToolResult {
        let company_name = company_name.trim();
        if company_name.is_empty() {
            return error_result("Parameter 'company_name' must not be empty");
        }
        if company_name.len() > MAX_NAME_LEN {
            return error_result(&format!("'company_name' exceeds {} chars", MAX_NAME_LEN));
        }
        let domain = domain.trim();
        if domain.is_empty() {
            return error_result("Parameter 'domain' must not be empty");
        }
        if domain.len() > MAX_NAME_LEN {
            return error_result(&format!("'domain' exceeds {} chars", MAX_NAME_LEN));
        }
        let profiles = SocialProvider::generate_profiles(company_name, domain);
        json_result(&serde_json::json!({
            "company_name": company_name,
            "domain": domain,
            "linkedin": profiles.get("linkedin"),
            "twitter": profiles.get("twitter"),
            "github": profiles.get("github"),
        }))
    }

    async fn handle_enrichment_stats(&self) -> CallToolResult {
        let rows: Vec<(String, i64)> = match sqlx::query_as(
            "SELECT lookup_type, count(*)::bigint FROM enrichment.lookups \
             GROUP BY lookup_type ORDER BY count(*) DESC",
        )
        .fetch_all(self.db.pool())
        .await
        {
            Ok(r) => r,
            Err(e) => return error_result(&format!("Database error: {e}")),
        };

        let total_expired: (i64,) = sqlx::query_as(
            "SELECT count(*)::bigint FROM enrichment.lookups WHERE expires_at <= now()",
        )
        .fetch_one(self.db.pool())
        .await
        .unwrap_or((0,));

        let stats: Vec<serde_json::Value> = rows
            .iter()
            .map(|(t, c)| serde_json::json!({ "type": t, "count": c }))
            .collect();
        let total: i64 = rows.iter().map(|(_, c)| c).sum();

        json_result(&serde_json::json!({
            "total": total,
            "expired": total_expired.0,
            "by_type": stats,
        }))
    }

    async fn handle_cache_lookup(
        &self,
        lookup_type: &str,
        query_json: &serde_json::Value,
    ) -> CallToolResult {
        let lookup_type = lookup_type.trim();
        if lookup_type.is_empty() {
            return error_result("Parameter 'lookup_type' must not be empty");
        }
        match self.waterfall.cache().get(lookup_type, query_json).await {
            Some(result) => json_result(&serde_json::json!({
                "found": true,
                "lookup_type": lookup_type,
                "query": query_json,
                "result": result,
            })),
            None => json_result(&serde_json::json!({
                "found": false,
                "lookup_type": lookup_type,
                "query": query_json,
            })),
        }
    }
}

// ============================================================================
// ServerHandler trait implementation
// ============================================================================

impl ServerHandler for EnrichmentMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "DataXLR8 Enrichment MCP — 12 tools for email, company, and person enrichment \
                 with provider-based waterfall architecture and caching"
                    .into(),
            ),
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        async {
            Ok(ListToolsResult {
                tools: build_tools(),
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        async move {
            let args =
                serde_json::to_value(&request.arguments).unwrap_or(serde_json::Value::Null);
            let name_str: &str = request.name.as_ref();

            let result = match name_str {
                "enrich_person" => {
                    match (
                        get_str(&args, "first_name"),
                        get_str(&args, "last_name"),
                        get_str(&args, "company_domain"),
                    ) {
                        (Some(f), Some(l), Some(d)) => {
                            self.handle_enrich_person(&f, &l, &d).await
                        }
                        _ => error_result(
                            "Missing required parameters: first_name, last_name, company_domain",
                        ),
                    }
                }
                "enrich_company" => match get_str(&args, "domain") {
                    Some(d) => self.handle_enrich_company(&d).await,
                    None => error_result("Missing required parameter: domain"),
                },
                "verify_email" => match get_str(&args, "email") {
                    Some(e) => self.handle_verify_email(&e).await,
                    None => error_result("Missing required parameter: email"),
                },
                "domain_emails" => match get_str(&args, "domain") {
                    Some(d) => self.handle_domain_emails(&d).await,
                    None => error_result("Missing required parameter: domain"),
                },
                "search_people" => match get_str(&args, "query") {
                    Some(q) => {
                        let limit = get_i64(&args, "limit")
                            .unwrap_or(20)
                            .clamp(0, 1000);
                        self.handle_search_people(&q, limit).await
                    }
                    None => error_result("Missing required parameter: query"),
                },
                "reverse_domain" => match get_str(&args, "domain") {
                    Some(d) => self.handle_reverse_domain(&d).await,
                    None => error_result("Missing required parameter: domain"),
                },
                "bulk_enrich" => {
                    let domains = get_str_array(&args, "domains");
                    if domains.is_empty() {
                        error_result(
                            "Missing required parameter: domains (must be a non-empty array)",
                        )
                    } else {
                        self.handle_bulk_enrich(&domains).await
                    }
                }
                "tech_stack" => match get_str(&args, "domain") {
                    Some(d) => self.handle_tech_stack(&d).await,
                    None => error_result("Missing required parameter: domain"),
                },
                "hiring_signals" => match get_str(&args, "domain") {
                    Some(d) => self.handle_hiring_signals(&d).await,
                    None => error_result("Missing required parameter: domain"),
                },
                "social_profiles" => {
                    match (
                        get_str(&args, "company_name"),
                        get_str(&args, "domain"),
                    ) {
                        (Some(n), Some(d)) => self.handle_social_profiles(&n, &d).await,
                        _ => error_result(
                            "Missing required parameters: company_name, domain",
                        ),
                    }
                }
                "enrichment_stats" => self.handle_enrichment_stats().await,
                "cache_lookup" => {
                    match (
                        get_str(&args, "lookup_type"),
                        args.get("query_json"),
                    ) {
                        (Some(t), Some(q)) => self.handle_cache_lookup(&t, q).await,
                        _ => error_result(
                            "Missing required parameters: lookup_type, query_json",
                        ),
                    }
                }
                _ => error_result(&format!("Unknown tool: {}", request.name)),
            };

            Ok(result)
        }
    }
}
