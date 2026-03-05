use dataxlr8_mcp_core::Database;
use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use rmcp::ServerHandler;
use serde::Serialize;
use std::sync::Arc;
use tracing::{error, warn};

// ============================================================================
// Disposable email domains
// ============================================================================

const DISPOSABLE_DOMAINS: &[&str] = &[
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwaway.email",
    "yopmail.com",
    "10minutemail.com",
    "trashmail.com",
    "sharklasers.com",
    "guerrillamailblock.com",
    "grr.la",
    "dispostable.com",
    "mailnesia.com",
    "maildrop.cc",
    "discard.email",
    "fakeinbox.com",
    "getairmail.com",
    "mohmal.com",
    "tempail.com",
    "temp-mail.org",
    "getnada.com",
];

// ============================================================================
// Tool schema helpers
// ============================================================================

fn make_schema(
    properties: serde_json::Value,
    required: Vec<&str>,
) -> Arc<serde_json::Map<String, serde_json::Value>> {
    let mut m = serde_json::Map::new();
    m.insert(
        "type".to_string(),
        serde_json::Value::String("object".to_string()),
    );
    m.insert("properties".to_string(), properties);
    if !required.is_empty() {
        m.insert(
            "required".to_string(),
            serde_json::Value::Array(
                required
                    .into_iter()
                    .map(|s| serde_json::Value::String(s.to_string()))
                    .collect(),
            ),
        );
    }
    Arc::new(m)
}

fn empty_schema() -> Arc<serde_json::Map<String, serde_json::Value>> {
    let mut m = serde_json::Map::new();
    m.insert(
        "type".to_string(),
        serde_json::Value::String("object".to_string()),
    );
    Arc::new(m)
}

fn build_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "enrich_person".into(),
            title: None,
            description: Some(
                "Generate email pattern candidates for a person at a company domain. \
                 Performs MX lookup to validate domain."
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
                "Enrich a company by domain: fetch homepage title/description, DNS records, \
                 and detect tech from HTTP headers."
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
                "Verify an email address: MX lookup, SMTP handshake (EHLO/MAIL FROM/RCPT TO), \
                 and disposable domain check."
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
            description: Some(
                "Search cached person enrichment results by keyword."
                    .into(),
            ),
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
                "DNS lookup for a domain: returns A/AAAA IPs, MX records, and nameservers."
                    .into(),
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
                "Enrich multiple company domains at once. Runs enrich_company logic for each."
                    .into(),
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
                "Detect technology stack from HTTP headers (Server, X-Powered-By, X-Generator) \
                 and HTML content patterns."
                    .into(),
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
                "Check if a company has active hiring pages (/careers, /jobs)."
                    .into(),
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
            description: Some(
                "Get statistics on cached enrichment data by lookup type."
                    .into(),
            ),
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
                "Check cache for a previous enrichment result by type and query JSON."
                    .into(),
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
    db: Database,
    http: reqwest::Client,
}

impl EnrichmentMcpServer {
    pub fn new(db: Database) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("DataXLR8-Enrichment/0.1")
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to build HTTP client");
        Self { db, http }
    }

    fn json_result<T: Serialize>(data: &T) -> CallToolResult {
        match serde_json::to_string_pretty(data) {
            Ok(json) => CallToolResult::success(vec![Content::text(json)]),
            Err(e) => CallToolResult::error(vec![Content::text(format!(
                "Serialization error: {e}"
            ))]),
        }
    }

    fn error_result(msg: &str) -> CallToolResult {
        CallToolResult::error(vec![Content::text(msg.to_string())])
    }

    fn get_str(args: &serde_json::Value, key: &str) -> Option<String> {
        args.get(key).and_then(|v| v.as_str()).map(String::from)
    }

    fn get_i64(args: &serde_json::Value, key: &str) -> Option<i64> {
        args.get(key).and_then(|v| v.as_i64())
    }

    fn get_str_array(args: &serde_json::Value, key: &str) -> Vec<String> {
        args.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    // ---- Cache helpers ----

    async fn cache_store(
        &self,
        lookup_type: &str,
        query: &serde_json::Value,
        result: &serde_json::Value,
        source: &str,
    ) {
        if let Err(e) = sqlx::query(
            "INSERT INTO enrichment.lookups (lookup_type, query, result, source) VALUES ($1, $2, $3, $4)",
        )
        .bind(lookup_type)
        .bind(query)
        .bind(result)
        .bind(source)
        .execute(self.db.pool())
        .await
        {
            error!(lookup_type, error = %e, "Failed to cache enrichment result");
        }
    }

    async fn cache_get(
        &self,
        lookup_type: &str,
        query: &serde_json::Value,
    ) -> Option<serde_json::Value> {
        match sqlx::query_as::<_, (serde_json::Value,)>(
            "SELECT result FROM enrichment.lookups WHERE lookup_type = $1 AND query @> $2 AND expires_at > now() ORDER BY cached_at DESC LIMIT 1",
        )
        .bind(lookup_type)
        .bind(query)
        .fetch_optional(self.db.pool())
        .await
        {
            Ok(Some((result,))) => Some(result),
            Ok(None) => None,
            Err(e) => {
                warn!(lookup_type, error = %e, "Cache lookup failed");
                None
            }
        }
    }

    // ---- DNS helpers ----

    fn make_resolver() -> Option<hickory_resolver::TokioResolver> {
        match hickory_resolver::Resolver::builder_tokio() {
            Ok(builder) => Some(builder.build()),
            Err(e) => {
                warn!(error = %e, "Failed to create DNS resolver");
                None
            }
        }
    }

    async fn mx_lookup(&self, domain: &str) -> Vec<String> {
        let resolver = match Self::make_resolver() {
            Some(r) => r,
            None => return Vec::new(),
        };

        match resolver.mx_lookup(domain).await {
            Ok(records) => {
                let mx_lookup: hickory_resolver::lookup::MxLookup = records;
                let mut hosts: Vec<String> = mx_lookup
                    .iter()
                    .map(|mx| mx.exchange().to_ascii())
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

    async fn a_lookup(&self, domain: &str) -> Vec<String> {
        let resolver = match Self::make_resolver() {
            Some(r) => r,
            None => return Vec::new(),
        };

        match resolver.lookup_ip(domain).await {
            Ok(ips) => {
                let lookup: hickory_resolver::lookup_ip::LookupIp = ips;
                lookup.iter().map(|ip: std::net::IpAddr| ip.to_string()).collect()
            }
            Err(e) => {
                warn!(domain, error = %e, "A/AAAA lookup failed");
                Vec::new()
            }
        }
    }

    async fn ns_lookup(&self, domain: &str) -> Vec<String> {
        let resolver = match Self::make_resolver() {
            Some(r) => r,
            None => return Vec::new(),
        };

        match resolver.ns_lookup(domain).await {
            Ok(records) => {
                let ns_lookup: hickory_resolver::lookup::NsLookup = records;
                ns_lookup.iter().map(|ns| ns.0.to_ascii()).collect()
            }
            Err(e) => {
                warn!(domain, error = %e, "NS lookup failed");
                Vec::new()
            }
        }
    }

    // ---- SMTP verification ----

    async fn smtp_verify(&self, email: &str, mx_host: &str) -> (bool, String) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let addr = format!("{mx_host}:25");
        let stream = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return (false, format!("connect failed: {e}")),
            Err(_) => return (false, "connect timeout".to_string()),
        };

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let read_timeout = std::time::Duration::from_secs(5);

        // Read banner
        match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return (false, format!("read banner failed: {e}")),
            Err(_) => return (false, "read banner timeout".to_string()),
        }
        if !line.starts_with("220") {
            return (false, format!("bad banner: {}", line.trim()));
        }

        // EHLO
        line.clear();
        if writer
            .write_all(b"EHLO enrichment.dataxlr8.com\r\n")
            .await
            .is_err()
        {
            return (false, "EHLO write failed".to_string());
        }
        // Read multi-line EHLO response
        loop {
            line.clear();
            match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return (false, "EHLO read failed".to_string()),
                Err(_) => return (false, "EHLO read timeout".to_string()),
            }
            if line.len() < 4 {
                break;
            }
            // "250 " (space) means last line, "250-" means continuation
            if line.as_bytes().get(3) == Some(&b' ') {
                break;
            }
        }

        // MAIL FROM
        line.clear();
        if writer
            .write_all(b"MAIL FROM:<>\r\n")
            .await
            .is_err()
        {
            return (false, "MAIL FROM write failed".to_string());
        }
        match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return (false, "MAIL FROM read failed".to_string()),
            Err(_) => return (false, "MAIL FROM read timeout".to_string()),
        }
        if !line.starts_with("250") {
            return (false, format!("MAIL FROM rejected: {}", line.trim()));
        }

        // RCPT TO
        line.clear();
        let rcpt = format!("RCPT TO:<{email}>\r\n");
        if writer.write_all(rcpt.as_bytes()).await.is_err() {
            return (false, "RCPT TO write failed".to_string());
        }
        match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return (false, "RCPT TO read failed".to_string()),
            Err(_) => return (false, "RCPT TO read timeout".to_string()),
        }

        let accepted = line.starts_with("250");
        let detail = line.trim().to_string();

        // QUIT (best effort)
        let _ = writer.write_all(b"QUIT\r\n").await;

        (accepted, detail)
    }

    // ---- Tool handlers ----

    async fn handle_enrich_person(
        &self,
        first_name: &str,
        last_name: &str,
        domain: &str,
    ) -> CallToolResult {
        let query = serde_json::json!({
            "first_name": first_name,
            "last_name": last_name,
            "domain": domain,
        });

        // Check cache
        if let Some(cached) = self.cache_get("person", &query).await {
            return Self::json_result(&serde_json::json!({
                "cached": true,
                "data": cached,
            }));
        }

        let f = first_name.to_lowercase();
        let l = last_name.to_lowercase();

        if f.is_empty() || l.is_empty() {
            return Self::error_result("first_name and last_name must not be empty");
        }

        let fi: String = f.chars().next().unwrap().to_string();

        let candidates = vec![
            format!("{f}.{l}@{domain}"),
            format!("{fi}.{l}@{domain}"),
            format!("{f}@{domain}"),
            format!("{f}{l}@{domain}"),
            format!("{l}.{f}@{domain}"),
            format!("{l}@{domain}"),
            format!("{fi}{l}@{domain}"),
        ];

        let mx_records = self.mx_lookup(domain).await;
        let has_mx = !mx_records.is_empty();

        let result = serde_json::json!({
            "first_name": first_name,
            "last_name": last_name,
            "domain": domain,
            "email_candidates": candidates,
            "mx_records": mx_records,
            "domain_has_mx": has_mx,
        });

        self.cache_store("person", &query, &result, "pattern_generation")
            .await;

        Self::json_result(&result)
    }

    async fn handle_enrich_company(&self, domain: &str) -> CallToolResult {
        let query = serde_json::json!({ "domain": domain });

        // Check cache
        if let Some(cached) = self.cache_get("company", &query).await {
            return Self::json_result(&serde_json::json!({
                "cached": true,
                "data": cached,
            }));
        }

        let url = format!("https://{domain}");
        let mut title = String::new();
        let mut description = String::new();
        let mut server_header = String::new();
        let mut powered_by = String::new();
        let mut generator = String::new();
        let mut status_code: u16 = 0;

        match self.http.get(&url).send().await {
            Ok(resp) => {
                status_code = resp.status().as_u16();
                if let Some(v) = resp.headers().get("server") {
                    server_header = v.to_str().unwrap_or("").to_string();
                }
                if let Some(v) = resp.headers().get("x-powered-by") {
                    powered_by = v.to_str().unwrap_or("").to_string();
                }
                if let Some(v) = resp.headers().get("x-generator") {
                    generator = v.to_str().unwrap_or("").to_string();
                }

                if let Ok(body) = resp.text().await {
                    // Extract <title>
                    if let Some(start) = body.find("<title") {
                        if let Some(gt) = body[start..].find('>') {
                            let after = start + gt + 1;
                            if let Some(end) = body[after..].find("</title>") {
                                title = body[after..after + end].trim().to_string();
                            }
                        }
                    }
                    // Extract meta description (case-insensitive; ascii_lowercase preserves byte positions)
                    let lower = body.to_ascii_lowercase();
                    if let Some(pos) = lower.find("name=\"description\"") {
                        let region_start = pos.saturating_sub(200);
                        let region_end = std::cmp::min(pos + 300, lower.len());
                        let region = &lower[region_start..region_end];
                        if let Some(c) = region.find("content=\"") {
                            let abs_start = region_start + c + 9;
                            if abs_start < body.len() {
                                if let Some(end) = body[abs_start..].find('"') {
                                    description =
                                        body[abs_start..abs_start + end].to_string();
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(domain, error = %e, "HTTP GET failed for company enrichment");
            }
        }

        let mx_records = self.mx_lookup(domain).await;
        let ips = self.a_lookup(domain).await;

        let result = serde_json::json!({
            "domain": domain,
            "title": title,
            "description": description,
            "http_status": status_code,
            "server": server_header,
            "x_powered_by": powered_by,
            "x_generator": generator,
            "mx_records": mx_records,
            "ips": ips,
        });

        self.cache_store("company", &query, &result, "http_dns")
            .await;

        Self::json_result(&result)
    }

    async fn handle_verify_email(&self, email: &str) -> CallToolResult {
        let query = serde_json::json!({ "email": email });

        // Check cache
        if let Some(cached) = self.cache_get("email", &query).await {
            return Self::json_result(&serde_json::json!({
                "cached": true,
                "data": cached,
            }));
        }

        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return Self::error_result("Invalid email format");
        }
        let domain = parts[1];

        let is_disposable = DISPOSABLE_DOMAINS.contains(&domain.to_lowercase().as_str());

        let mx_records = self.mx_lookup(domain).await;
        let has_mx = !mx_records.is_empty();

        let mut smtp_valid = false;
        let mut smtp_detail = String::from("no MX records");

        if let Some(mx_host) = mx_records.first() {
            let (valid, detail) = self.smtp_verify(email, mx_host).await;
            smtp_valid = valid;
            smtp_detail = detail;
        }

        let result = serde_json::json!({
            "email": email,
            "domain": domain,
            "has_mx": has_mx,
            "mx_records": mx_records,
            "is_disposable": is_disposable,
            "smtp_valid": smtp_valid,
            "smtp_detail": smtp_detail,
        });

        self.cache_store("email", &query, &result, "mx_smtp")
            .await;

        Self::json_result(&result)
    }

    async fn handle_domain_emails(&self, domain: &str) -> CallToolResult {
        let prefixes = ["info", "hello", "contact", "support", "sales", "admin"];
        let mut results = Vec::new();

        let mx_records = self.mx_lookup(domain).await;
        let mx_host = mx_records.first().cloned();

        for prefix in &prefixes {
            let email = format!("{prefix}@{domain}");
            let mut smtp_valid = false;
            let mut smtp_detail = String::from("no MX records");

            if let Some(ref host) = mx_host {
                let (valid, detail) = self.smtp_verify(&email, host).await;
                smtp_valid = valid;
                smtp_detail = detail;
            }

            results.push(serde_json::json!({
                "email": email,
                "smtp_valid": smtp_valid,
                "smtp_detail": smtp_detail,
            }));
        }

        let output = serde_json::json!({
            "domain": domain,
            "mx_records": mx_records,
            "emails": results,
        });

        let query = serde_json::json!({ "domain": domain });
        self.cache_store("domain_emails", &query, &output, "smtp_verify")
            .await;

        Self::json_result(&output)
    }

    async fn handle_search_people(&self, query_str: &str, limit: i64) -> CallToolResult {
        let pattern = format!("%{query_str}%");
        let rows: Vec<(serde_json::Value, serde_json::Value)> = match sqlx::query_as(
            "SELECT query, result FROM enrichment.lookups WHERE lookup_type = 'person' AND result::text ILIKE $1 ORDER BY cached_at DESC LIMIT $2",
        )
        .bind(&pattern)
        .bind(limit)
        .fetch_all(self.db.pool())
        .await
        {
            Ok(r) => r,
            Err(e) => return Self::error_result(&format!("Database error: {e}")),
        };

        let results: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|(q, r)| serde_json::json!({ "query": q, "result": r }))
            .collect();

        Self::json_result(&serde_json::json!({
            "count": results.len(),
            "results": results,
        }))
    }

    async fn handle_reverse_domain(&self, domain: &str) -> CallToolResult {
        let query = serde_json::json!({ "domain": domain });

        if let Some(cached) = self.cache_get("domain", &query).await {
            return Self::json_result(&serde_json::json!({
                "cached": true,
                "data": cached,
            }));
        }

        let ips = self.a_lookup(domain).await;
        let mx_records = self.mx_lookup(domain).await;
        let nameservers = self.ns_lookup(domain).await;

        let result = serde_json::json!({
            "domain": domain,
            "ips": ips,
            "mx_records": mx_records,
            "nameservers": nameservers,
        });

        self.cache_store("domain", &query, &result, "dns").await;

        Self::json_result(&result)
    }

    async fn handle_bulk_enrich(&self, domains: &[String]) -> CallToolResult {
        let mut results = Vec::new();

        for domain in domains {
            let query = serde_json::json!({ "domain": domain });

            if let Some(cached) = self.cache_get("company", &query).await {
                results.push(serde_json::json!({
                    "domain": domain,
                    "cached": true,
                    "data": cached,
                }));
                continue;
            }

            let url = format!("https://{domain}");
            let mut title = String::new();
            let mut status_code: u16 = 0;

            match self.http.get(&url).send().await {
                Ok(resp) => {
                    status_code = resp.status().as_u16();
                    if let Ok(body) = resp.text().await {
                        if let Some(start) = body.find("<title") {
                            if let Some(gt) = body[start..].find('>') {
                                let after = start + gt + 1;
                                if let Some(end) = body[after..].find("</title>") {
                                    title = body[after..after + end].trim().to_string();
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(domain = domain.as_str(), error = %e, "HTTP GET failed");
                }
            }

            let mx_records = self.mx_lookup(domain).await;

            let data = serde_json::json!({
                "domain": domain,
                "title": title,
                "http_status": status_code,
                "mx_records": mx_records,
                "has_mx": !mx_records.is_empty(),
            });

            self.cache_store("company", &query, &data, "bulk_http_dns")
                .await;

            results.push(serde_json::json!({
                "domain": domain,
                "cached": false,
                "data": data,
            }));
        }

        Self::json_result(&serde_json::json!({
            "count": results.len(),
            "results": results,
        }))
    }

    async fn handle_tech_stack(&self, domain: &str) -> CallToolResult {
        let query = serde_json::json!({ "domain": domain });

        if let Some(cached) = self.cache_get("tech_stack", &query).await {
            return Self::json_result(&serde_json::json!({
                "cached": true,
                "data": cached,
            }));
        }

        let url = format!("https://{domain}");
        let mut technologies = Vec::<String>::new();
        let mut server_header = String::new();
        let mut powered_by = String::new();
        let mut generator = String::new();

        match self.http.get(&url).send().await {
            Ok(resp) => {
                if let Some(v) = resp.headers().get("server") {
                    let s = v.to_str().unwrap_or("").to_string();
                    if !s.is_empty() {
                        technologies.push(format!("Server: {s}"));
                        server_header = s;
                    }
                }
                if let Some(v) = resp.headers().get("x-powered-by") {
                    let s = v.to_str().unwrap_or("").to_string();
                    if !s.is_empty() {
                        technologies.push(format!("X-Powered-By: {s}"));
                        powered_by = s;
                    }
                }
                if let Some(v) = resp.headers().get("x-generator") {
                    let s = v.to_str().unwrap_or("").to_string();
                    if !s.is_empty() {
                        technologies.push(format!("X-Generator: {s}"));
                        generator = s;
                    }
                }

                if let Ok(body) = resp.text().await {
                    let lower = body.to_lowercase();
                    if lower.contains("wp-content") || lower.contains("wp-includes") {
                        technologies.push("WordPress".to_string());
                    }
                    if lower.contains("shopify") {
                        technologies.push("Shopify".to_string());
                    }
                    if lower.contains("next/static") || lower.contains("_next/") {
                        technologies.push("Next.js".to_string());
                    }
                    if lower.contains("react") {
                        technologies.push("React".to_string());
                    }
                    if lower.contains("vue") {
                        technologies.push("Vue.js".to_string());
                    }
                    if lower.contains("angular") {
                        technologies.push("Angular".to_string());
                    }
                    if lower.contains("gatsby") {
                        technologies.push("Gatsby".to_string());
                    }
                    if lower.contains("squarespace") {
                        technologies.push("Squarespace".to_string());
                    }
                    if lower.contains("wix.com") {
                        technologies.push("Wix".to_string());
                    }
                    if lower.contains("drupal") {
                        technologies.push("Drupal".to_string());
                    }
                    if lower.contains("hubspot") {
                        technologies.push("HubSpot".to_string());
                    }
                    if lower.contains("webflow") {
                        technologies.push("Webflow".to_string());
                    }
                }
            }
            Err(e) => {
                warn!(domain, error = %e, "HTTP GET failed for tech stack");
            }
        }

        technologies.sort();
        technologies.dedup();

        let result = serde_json::json!({
            "domain": domain,
            "server": server_header,
            "x_powered_by": powered_by,
            "x_generator": generator,
            "technologies": technologies,
        });

        self.cache_store("tech_stack", &query, &result, "http_headers_html")
            .await;

        Self::json_result(&result)
    }

    async fn handle_hiring_signals(&self, domain: &str) -> CallToolResult {
        let query = serde_json::json!({ "domain": domain });

        if let Some(cached) = self.cache_get("hiring", &query).await {
            return Self::json_result(&serde_json::json!({
                "cached": true,
                "data": cached,
            }));
        }

        let paths = ["/careers", "/jobs", "/join-us", "/work-with-us"];
        let mut signals = Vec::new();

        for path in &paths {
            let url = format!("https://{domain}{path}");
            match self.http.get(&url).send().await {
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

        let result = serde_json::json!({
            "domain": domain,
            "is_hiring": is_hiring,
            "pages": signals,
        });

        self.cache_store("hiring", &query, &result, "http_crawl")
            .await;

        Self::json_result(&result)
    }

    async fn handle_social_profiles(
        &self,
        company_name: &str,
        domain: &str,
    ) -> CallToolResult {
        // Slugify company name for URL patterns
        let slug = company_name
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();

        // Also try domain without TLD
        let domain_slug = domain.split('.').next().unwrap_or(domain);

        let profiles = serde_json::json!({
            "company_name": company_name,
            "domain": domain,
            "linkedin": {
                "by_name": format!("https://linkedin.com/company/{slug}"),
                "by_domain": format!("https://linkedin.com/company/{domain_slug}"),
            },
            "twitter": {
                "by_name": format!("https://twitter.com/{slug}"),
                "by_domain": format!("https://twitter.com/{domain_slug}"),
            },
            "github": {
                "by_name": format!("https://github.com/{slug}"),
                "by_domain": format!("https://github.com/{domain_slug}"),
            },
        });

        let query = serde_json::json!({
            "company_name": company_name,
            "domain": domain,
        });
        self.cache_store("social", &query, &profiles, "url_generation")
            .await;

        Self::json_result(&profiles)
    }

    async fn handle_enrichment_stats(&self) -> CallToolResult {
        let rows: Vec<(String, i64)> = match sqlx::query_as(
            "SELECT lookup_type, count(*)::bigint FROM enrichment.lookups GROUP BY lookup_type ORDER BY count(*) DESC",
        )
        .fetch_all(self.db.pool())
        .await
        {
            Ok(r) => r,
            Err(e) => return Self::error_result(&format!("Database error: {e}")),
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

        Self::json_result(&serde_json::json!({
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
        match self.cache_get(lookup_type, query_json).await {
            Some(result) => Self::json_result(&serde_json::json!({
                "found": true,
                "lookup_type": lookup_type,
                "query": query_json,
                "result": result,
            })),
            None => Self::json_result(&serde_json::json!({
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
                 with DNS/SMTP verification and caching"
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
                        Self::get_str(&args, "first_name"),
                        Self::get_str(&args, "last_name"),
                        Self::get_str(&args, "company_domain"),
                    ) {
                        (Some(f), Some(l), Some(d)) => {
                            self.handle_enrich_person(&f, &l, &d).await
                        }
                        _ => Self::error_result(
                            "Missing required parameters: first_name, last_name, company_domain",
                        ),
                    }
                }
                "enrich_company" => match Self::get_str(&args, "domain") {
                    Some(d) => self.handle_enrich_company(&d).await,
                    None => Self::error_result("Missing required parameter: domain"),
                },
                "verify_email" => match Self::get_str(&args, "email") {
                    Some(e) => self.handle_verify_email(&e).await,
                    None => Self::error_result("Missing required parameter: email"),
                },
                "domain_emails" => match Self::get_str(&args, "domain") {
                    Some(d) => self.handle_domain_emails(&d).await,
                    None => Self::error_result("Missing required parameter: domain"),
                },
                "search_people" => match Self::get_str(&args, "query") {
                    Some(q) => {
                        let limit = Self::get_i64(&args, "limit").unwrap_or(20);
                        self.handle_search_people(&q, limit).await
                    }
                    None => Self::error_result("Missing required parameter: query"),
                },
                "reverse_domain" => match Self::get_str(&args, "domain") {
                    Some(d) => self.handle_reverse_domain(&d).await,
                    None => Self::error_result("Missing required parameter: domain"),
                },
                "bulk_enrich" => {
                    let domains = Self::get_str_array(&args, "domains");
                    if domains.is_empty() {
                        Self::error_result(
                            "Missing required parameter: domains (must be a non-empty array)",
                        )
                    } else {
                        self.handle_bulk_enrich(&domains).await
                    }
                }
                "tech_stack" => match Self::get_str(&args, "domain") {
                    Some(d) => self.handle_tech_stack(&d).await,
                    None => Self::error_result("Missing required parameter: domain"),
                },
                "hiring_signals" => match Self::get_str(&args, "domain") {
                    Some(d) => self.handle_hiring_signals(&d).await,
                    None => Self::error_result("Missing required parameter: domain"),
                },
                "social_profiles" => {
                    match (
                        Self::get_str(&args, "company_name"),
                        Self::get_str(&args, "domain"),
                    ) {
                        (Some(n), Some(d)) => self.handle_social_profiles(&n, &d).await,
                        _ => Self::error_result(
                            "Missing required parameters: company_name, domain",
                        ),
                    }
                }
                "enrichment_stats" => self.handle_enrichment_stats().await,
                "cache_lookup" => {
                    match (
                        Self::get_str(&args, "lookup_type"),
                        args.get("query_json"),
                    ) {
                        (Some(t), Some(q)) => self.handle_cache_lookup(&t, q).await,
                        _ => Self::error_result(
                            "Missing required parameters: lookup_type, query_json",
                        ),
                    }
                }
                _ => Self::error_result(&format!("Unknown tool: {}", request.name)),
            };

            Ok(result)
        }
    }
}
