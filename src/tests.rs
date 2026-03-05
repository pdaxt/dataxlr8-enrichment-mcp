use dataxlr8_mcp_core::mcp::{get_bool, get_f64, get_i64, get_str, get_str_array};
use serde_json::json;

// ============================================================================
// Validation logic (mirrors production validators for unit testing)
// ============================================================================

/// Mirrors EnrichmentMcpServer::is_valid_domain
fn is_valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && !domain.contains(|c: char| c.is_whitespace())
        && !domain.contains('/')
        && !domain.contains('\\')
        && domain.contains('.')
}

/// Mirrors email validation in handle_verify_email
fn is_valid_email(email: &str) -> bool {
    if email.contains(|c: char| c.is_control()) {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    if parts[0].is_empty() || parts[1].is_empty() || !parts[1].contains('.') {
        return false;
    }
    true
}

/// Mirrors ILIKE escape logic in handle_search_people
fn escape_ilike(query: &str) -> String {
    let escaped = query
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

// ============================================================================
// Domain validation — empty / missing
// ============================================================================

#[test]
fn domain_empty_string() {
    assert!(!is_valid_domain(""));
}

#[test]
fn domain_no_dot() {
    assert!(!is_valid_domain("localhost"));
    assert!(!is_valid_domain("acme"));
}

#[test]
fn domain_only_dot() {
    assert!(is_valid_domain("."));
}

#[test]
fn domain_leading_dot() {
    assert!(is_valid_domain(".com"));
}

#[test]
fn domain_trailing_dot() {
    // DNS FQDNs end with dot — validator allows this
    assert!(is_valid_domain("acme.com."));
}

// ============================================================================
// Domain validation — whitespace
// ============================================================================

#[test]
fn domain_contains_space() {
    assert!(!is_valid_domain("acme .com"));
}

#[test]
fn domain_contains_tab() {
    assert!(!is_valid_domain("acme\t.com"));
}

#[test]
fn domain_contains_newline() {
    assert!(!is_valid_domain("acme\n.com"));
}

#[test]
fn domain_contains_carriage_return() {
    assert!(!is_valid_domain("acme\r.com"));
}

#[test]
fn domain_only_whitespace() {
    assert!(!is_valid_domain("   "));
    assert!(!is_valid_domain("\t\t"));
}

// ============================================================================
// Domain validation — path separators
// ============================================================================

#[test]
fn domain_contains_forward_slash() {
    assert!(!is_valid_domain("acme.com/path"));
}

#[test]
fn domain_contains_backslash() {
    assert!(!is_valid_domain("acme.com\\path"));
}

#[test]
fn domain_url_format() {
    assert!(!is_valid_domain("https://acme.com"));
}

// ============================================================================
// Domain validation — special characters
// ============================================================================

#[test]
fn domain_with_null_byte() {
    // Null byte is a control char but not whitespace — validator allows it
    // (it doesn't check for control chars, only whitespace and slashes)
    let domain = "acme\0.com";
    // is_whitespace returns false for \0, so this passes the validator
    // This is a known gap
    assert!(is_valid_domain(domain));
}

#[test]
fn domain_with_quotes() {
    assert!(is_valid_domain("ac'me.com"));
    assert!(is_valid_domain("ac\"me.com"));
}

#[test]
fn domain_with_unicode() {
    assert!(is_valid_domain("acmé.com"));
    assert!(is_valid_domain("日本語.jp"));
    assert!(is_valid_domain("münchen.de"));
}

#[test]
fn domain_sql_injection_attempts() {
    // No dot → rejected
    assert!(!is_valid_domain("'; DROP TABLE enrichment.lookups;--"));
    assert!(!is_valid_domain("' OR '1'='1"));
    assert!(!is_valid_domain("1; SELECT * FROM users"));
    // Has dot but also has space → rejected
    assert!(!is_valid_domain("acme.com'; DROP TABLE users;--"));
    // Has dot, no whitespace/slashes → passes validation (SQL injection
    // is prevented by parameterized queries, not by domain validation)
    assert!(is_valid_domain("acme.com';DROPTABLE;--"));
}

// ============================================================================
// Domain validation — very long strings
// ============================================================================

#[test]
fn domain_very_long_string() {
    let long_domain = format!("{}.com", "a".repeat(1000));
    assert!(is_valid_domain(&long_domain));
}

#[test]
fn domain_max_length_label() {
    // DNS labels max 63 chars, full domain max 253 chars
    let long_label = "a".repeat(63);
    let domain = format!("{long_label}.com");
    assert!(is_valid_domain(&domain));

    let very_long_domain = format!("{}.{}.{}.{}.com", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(63));
    assert!(is_valid_domain(&very_long_domain));
}

// ============================================================================
// Domain validation — valid cases
// ============================================================================

#[test]
fn domain_valid_basic() {
    assert!(is_valid_domain("acme.com"));
    assert!(is_valid_domain("sub.acme.com"));
    assert!(is_valid_domain("a.b.c.d.e.com"));
}

#[test]
fn domain_with_hyphen() {
    assert!(is_valid_domain("my-company.com"));
}

#[test]
fn domain_with_numbers() {
    assert!(is_valid_domain("123.456.com"));
    assert!(is_valid_domain("company123.io"));
}

// ============================================================================
// Email validation — empty / missing
// ============================================================================

#[test]
fn email_empty_string() {
    assert!(!is_valid_email(""));
}

#[test]
fn email_no_at_sign() {
    assert!(!is_valid_email("userexample.com"));
}

#[test]
fn email_multiple_at_signs() {
    assert!(!is_valid_email("user@name@example.com"));
}

#[test]
fn email_empty_local_part() {
    assert!(!is_valid_email("@example.com"));
}

#[test]
fn email_empty_domain() {
    assert!(!is_valid_email("user@"));
}

#[test]
fn email_domain_no_dot() {
    assert!(!is_valid_email("user@localhost"));
}

// ============================================================================
// Email validation — control characters
// ============================================================================

#[test]
fn email_with_null_byte() {
    assert!(!is_valid_email("user\0@example.com"));
}

#[test]
fn email_with_crlf_injection() {
    assert!(!is_valid_email("user\r\n@example.com"));
    assert!(!is_valid_email("user@example.com\r\nBCC:evil@attacker.com"));
}

#[test]
fn email_with_tab() {
    assert!(!is_valid_email("user\t@example.com"));
}

#[test]
fn email_with_bell() {
    assert!(!is_valid_email("user\x07@example.com"));
}

#[test]
fn email_with_escape() {
    assert!(!is_valid_email("user\x1b@example.com"));
}

// ============================================================================
// Email validation — special characters
// ============================================================================

#[test]
fn email_with_quotes() {
    assert!(is_valid_email("us'er@example.com"));
    assert!(is_valid_email("us\"er@example.com"));
}

#[test]
fn email_sql_injection() {
    assert!(is_valid_email("'; DROP TABLE users;--@example.com"));
    assert!(is_valid_email("admin'--@example.com"));
    assert!(!is_valid_email("' OR 1=1--"));
}

#[test]
fn email_unicode() {
    assert!(is_valid_email("user@münchen.de"));
    assert!(is_valid_email("用户@example.com"));
}

// ============================================================================
// Email validation — very long strings
// ============================================================================

#[test]
fn email_very_long_local_part() {
    let long_email = format!("{}@example.com", "a".repeat(1000));
    assert!(is_valid_email(&long_email));
}

#[test]
fn email_very_long_domain() {
    let long_email = format!("user@{}.com", "a".repeat(1000));
    assert!(is_valid_email(&long_email));
}

// ============================================================================
// Email validation — valid cases
// ============================================================================

#[test]
fn email_valid_basic() {
    assert!(is_valid_email("user@example.com"));
    assert!(is_valid_email("first.last@company.co.uk"));
    assert!(is_valid_email("user+tag@example.com"));
}

// ============================================================================
// ILIKE escape logic
// ============================================================================

#[test]
fn escape_ilike_plain_text() {
    assert_eq!(escape_ilike("hello"), "%hello%");
}

#[test]
fn escape_ilike_percent() {
    assert_eq!(escape_ilike("100%"), "%100\\%%");
}

#[test]
fn escape_ilike_underscore() {
    assert_eq!(escape_ilike("first_name"), "%first\\_name%");
}

#[test]
fn escape_ilike_backslash() {
    assert_eq!(escape_ilike("path\\file"), "%path\\\\file%");
}

#[test]
fn escape_ilike_all_metacharacters() {
    assert_eq!(escape_ilike("a%b_c\\d"), "%a\\%b\\_c\\\\d%");
}

#[test]
fn escape_ilike_empty_string() {
    assert_eq!(escape_ilike(""), "%%");
}

#[test]
fn escape_ilike_sql_injection_attempt() {
    let result = escape_ilike("'; DROP TABLE users;--");
    // Should NOT contain unescaped SQL — just wrapped in %...%
    assert!(result.starts_with('%'));
    assert!(result.ends_with('%'));
    assert!(result.contains("'; DROP TABLE users;--"));
}

#[test]
fn escape_ilike_wildcard_injection() {
    // Someone trying to match everything with % _ wildcards
    let result = escape_ilike("%%%___");
    assert_eq!(result, "%\\%\\%\\%\\_\\_\\_%");
}

#[test]
fn escape_ilike_very_long_string() {
    let long_query = "a".repeat(1000);
    let result = escape_ilike(&long_query);
    assert_eq!(result.len(), 1002); // 1000 + 2 wrapping %
}

#[test]
fn escape_ilike_unicode() {
    let result = escape_ilike("münchen");
    assert_eq!(result, "%münchen%");
}

#[test]
fn escape_ilike_null_bytes() {
    let result = escape_ilike("abc\0def");
    assert_eq!(result, "%abc\0def%");
}

// ============================================================================
// Core helper — get_str
// ============================================================================

#[test]
fn get_str_valid() {
    let args = json!({"name": "test"});
    assert_eq!(get_str(&args, "name"), Some("test".to_string()));
}

#[test]
fn get_str_missing_key() {
    let args = json!({"name": "test"});
    assert_eq!(get_str(&args, "missing"), None);
}

#[test]
fn get_str_null_value() {
    let args = json!({"name": null});
    assert_eq!(get_str(&args, "name"), None);
}

#[test]
fn get_str_number_value() {
    let args = json!({"name": 42});
    assert_eq!(get_str(&args, "name"), None);
}

#[test]
fn get_str_boolean_value() {
    let args = json!({"name": true});
    assert_eq!(get_str(&args, "name"), None);
}

#[test]
fn get_str_empty_string() {
    let args = json!({"name": ""});
    assert_eq!(get_str(&args, "name"), Some("".to_string()));
}

#[test]
fn get_str_very_long_string() {
    let long = "x".repeat(10_000);
    let args = json!({"name": long});
    assert_eq!(get_str(&args, "name").unwrap().len(), 10_000);
}

#[test]
fn get_str_with_special_chars() {
    let args = json!({"name": "he\"llo\\world\nnew"});
    let result = get_str(&args, "name").unwrap();
    assert!(result.contains('"'));
    assert!(result.contains('\\'));
    assert!(result.contains('\n'));
}

#[test]
fn get_str_unicode() {
    let args = json!({"name": "日本語テスト"});
    assert_eq!(get_str(&args, "name"), Some("日本語テスト".to_string()));
}

#[test]
fn get_str_from_null_args() {
    let args = serde_json::Value::Null;
    assert_eq!(get_str(&args, "name"), None);
}

#[test]
fn get_str_from_array_args() {
    let args = json!([1, 2, 3]);
    assert_eq!(get_str(&args, "0"), None);
}

// ============================================================================
// Core helper — get_i64
// ============================================================================

#[test]
fn get_i64_valid() {
    let args = json!({"count": 42});
    assert_eq!(get_i64(&args, "count"), Some(42));
}

#[test]
fn get_i64_zero() {
    let args = json!({"count": 0});
    assert_eq!(get_i64(&args, "count"), Some(0));
}

#[test]
fn get_i64_negative() {
    let args = json!({"count": -100});
    assert_eq!(get_i64(&args, "count"), Some(-100));
}

#[test]
fn get_i64_max() {
    let args = json!({"count": i64::MAX});
    assert_eq!(get_i64(&args, "count"), Some(i64::MAX));
}

#[test]
fn get_i64_min() {
    let args = json!({"count": i64::MIN});
    assert_eq!(get_i64(&args, "count"), Some(i64::MIN));
}

#[test]
fn get_i64_float_value() {
    let args = json!({"count": 3.14});
    // serde_json as_i64 returns None for floats
    assert_eq!(get_i64(&args, "count"), None);
}

#[test]
fn get_i64_string_value() {
    let args = json!({"count": "42"});
    assert_eq!(get_i64(&args, "count"), None);
}

#[test]
fn get_i64_missing_key() {
    let args = json!({"other": 42});
    assert_eq!(get_i64(&args, "count"), None);
}

#[test]
fn get_i64_null_value() {
    let args = json!({"count": null});
    assert_eq!(get_i64(&args, "count"), None);
}

// ============================================================================
// Core helper — get_f64
// ============================================================================

#[test]
fn get_f64_valid() {
    let args = json!({"value": 3.14});
    assert!((get_f64(&args, "value").unwrap() - 3.14).abs() < f64::EPSILON);
}

#[test]
fn get_f64_integer_value() {
    let args = json!({"value": 42});
    assert_eq!(get_f64(&args, "value"), Some(42.0));
}

#[test]
fn get_f64_zero() {
    let args = json!({"value": 0.0});
    assert_eq!(get_f64(&args, "value"), Some(0.0));
}

#[test]
fn get_f64_negative() {
    let args = json!({"value": -99.99});
    assert!((get_f64(&args, "value").unwrap() - (-99.99)).abs() < f64::EPSILON);
}

#[test]
fn get_f64_missing() {
    let args = json!({});
    assert_eq!(get_f64(&args, "value"), None);
}

// ============================================================================
// Core helper — get_bool
// ============================================================================

#[test]
fn get_bool_true() {
    let args = json!({"flag": true});
    assert_eq!(get_bool(&args, "flag"), Some(true));
}

#[test]
fn get_bool_false() {
    let args = json!({"flag": false});
    assert_eq!(get_bool(&args, "flag"), Some(false));
}

#[test]
fn get_bool_string_true() {
    let args = json!({"flag": "true"});
    assert_eq!(get_bool(&args, "flag"), None);
}

#[test]
fn get_bool_number_one() {
    let args = json!({"flag": 1});
    assert_eq!(get_bool(&args, "flag"), None);
}

#[test]
fn get_bool_missing() {
    let args = json!({});
    assert_eq!(get_bool(&args, "flag"), None);
}

// ============================================================================
// Core helper — get_str_array
// ============================================================================

#[test]
fn get_str_array_valid() {
    let args = json!({"tags": ["a", "b", "c"]});
    assert_eq!(get_str_array(&args, "tags"), vec!["a", "b", "c"]);
}

#[test]
fn get_str_array_empty() {
    let args = json!({"tags": []});
    assert!(get_str_array(&args, "tags").is_empty());
}

#[test]
fn get_str_array_missing() {
    let args = json!({});
    assert!(get_str_array(&args, "tags").is_empty());
}

#[test]
fn get_str_array_null_value() {
    let args = json!({"tags": null});
    assert!(get_str_array(&args, "tags").is_empty());
}

#[test]
fn get_str_array_string_value() {
    let args = json!({"tags": "not-an-array"});
    assert!(get_str_array(&args, "tags").is_empty());
}

#[test]
fn get_str_array_mixed_types() {
    let args = json!({"tags": ["a", 1, true, null, "b"]});
    // Only string items are kept
    assert_eq!(get_str_array(&args, "tags"), vec!["a", "b"]);
}

#[test]
fn get_str_array_with_special_chars() {
    let args = json!({"tags": ["tag\"quote", "tag\\slash", "tag\nnewline"]});
    let result = get_str_array(&args, "tags");
    assert_eq!(result.len(), 3);
    assert!(result[0].contains('"'));
    assert!(result[1].contains('\\'));
    assert!(result[2].contains('\n'));
}

#[test]
fn get_str_array_sql_injection() {
    let args = json!({"tags": ["'; DROP TABLE users;--", "OR 1=1", "admin'--"]});
    let result = get_str_array(&args, "tags");
    assert_eq!(result.len(), 3);
    assert_eq!(result[0], "'; DROP TABLE users;--");
}

#[test]
fn get_str_array_very_long() {
    let long_tag = "x".repeat(5000);
    let args = json!({"tags": [long_tag]});
    assert_eq!(get_str_array(&args, "tags")[0].len(), 5000);
}

#[test]
fn get_str_array_many_items() {
    let tags: Vec<String> = (0..1000).map(|i| format!("tag_{i}")).collect();
    let args = json!({"tags": tags});
    assert_eq!(get_str_array(&args, "tags").len(), 1000);
}

// ============================================================================
// Search limit clamping (mirrors call_tool logic)
// ============================================================================

#[test]
fn search_limit_default() {
    let args = json!({"query": "test"});
    let limit = get_i64(&args, "limit").unwrap_or(20).clamp(0, 1000);
    assert_eq!(limit, 20);
}

#[test]
fn search_limit_zero() {
    let args = json!({"query": "test", "limit": 0});
    let limit = get_i64(&args, "limit").unwrap_or(20).clamp(0, 1000);
    assert_eq!(limit, 0);
}

#[test]
fn search_limit_negative() {
    let args = json!({"query": "test", "limit": -10});
    let limit = get_i64(&args, "limit").unwrap_or(20).clamp(0, 1000);
    assert_eq!(limit, 0); // clamped to 0
}

#[test]
fn search_limit_above_max() {
    let args = json!({"query": "test", "limit": 9999});
    let limit = get_i64(&args, "limit").unwrap_or(20).clamp(0, 1000);
    assert_eq!(limit, 1000); // clamped to 1000
}

#[test]
fn search_limit_i64_max() {
    let args = json!({"query": "test", "limit": i64::MAX});
    let limit = get_i64(&args, "limit").unwrap_or(20).clamp(0, 1000);
    assert_eq!(limit, 1000); // clamped to 1000
}

#[test]
fn search_limit_i64_min() {
    let args = json!({"query": "test", "limit": i64::MIN});
    let limit = get_i64(&args, "limit").unwrap_or(20).clamp(0, 1000);
    assert_eq!(limit, 0); // clamped to 0
}

// ============================================================================
// Bulk enrich — domain list edge cases
// ============================================================================

#[test]
fn bulk_enrich_empty_domains_array() {
    let args = json!({"domains": []});
    let domains = get_str_array(&args, "domains");
    assert!(domains.is_empty());
}

#[test]
fn bulk_enrich_mixed_valid_invalid_domains() {
    let args = json!({"domains": ["acme.com", "", "no-dot", "valid.io"]});
    let domains = get_str_array(&args, "domains");
    assert_eq!(domains.len(), 4);
    assert!(is_valid_domain(&domains[0]));
    assert!(!is_valid_domain(&domains[1]));
    assert!(!is_valid_domain(&domains[2]));
    assert!(is_valid_domain(&domains[3]));
}

#[test]
fn bulk_enrich_duplicate_domains() {
    let args = json!({"domains": ["acme.com", "acme.com", "acme.com"]});
    let domains = get_str_array(&args, "domains");
    assert_eq!(domains.len(), 3); // Duplicates are allowed at this level
}

#[test]
fn bulk_enrich_sql_injection_in_domains() {
    let args = json!({"domains": [
        "acme.com'; DROP TABLE enrichment.lookups;--",
        "acme.com' OR '1'='1",
        "acme.com; SELECT * FROM pg_tables"
    ]});
    let domains = get_str_array(&args, "domains");
    // All contain dots so they pass is_valid_domain, but SQL injection
    // is prevented by parameterized queries (not by domain validation)
    for d in &domains {
        assert!(d.contains('.'));
    }
}

// ============================================================================
// Social profiles — company name edge cases
// ============================================================================

#[test]
fn social_profiles_empty_company_name() {
    let args = json!({"company_name": "", "domain": "acme.com"});
    assert_eq!(get_str(&args, "company_name"), Some("".to_string()));
}

#[test]
fn social_profiles_special_chars_in_name() {
    let args = json!({"company_name": "O'Reilly & Associates, Inc.", "domain": "oreilly.com"});
    let name = get_str(&args, "company_name").unwrap();
    assert!(name.contains('\''));
    assert!(name.contains('&'));
    assert!(name.contains(','));
}

#[test]
fn social_profiles_unicode_company_name() {
    let args = json!({"company_name": "München Technologie GmbH", "domain": "muenchen.de"});
    let name = get_str(&args, "company_name").unwrap();
    assert!(name.contains('ü'));
}

// ============================================================================
// Cache lookup — lookup_type edge cases
// ============================================================================

#[test]
fn cache_lookup_type_sql_injection() {
    let args = json!({
        "lookup_type": "person' OR '1'='1",
        "query_json": {"test": true}
    });
    let lookup_type = get_str(&args, "lookup_type").unwrap();
    // The value is passed to parameterized query, so SQL injection is harmless
    assert!(lookup_type.contains("OR"));
}

#[test]
fn cache_lookup_type_empty_string() {
    let args = json!({"lookup_type": "", "query_json": {}});
    let lookup_type = get_str(&args, "lookup_type").unwrap();
    assert!(lookup_type.is_empty());
}

#[test]
fn cache_lookup_type_very_long() {
    let long_type = "x".repeat(1000);
    let args = json!({"lookup_type": long_type, "query_json": {}});
    let lookup_type = get_str(&args, "lookup_type").unwrap();
    assert_eq!(lookup_type.len(), 1000);
}
