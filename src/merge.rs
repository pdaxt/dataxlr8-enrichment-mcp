use crate::providers::{CompanyData, EmailVerification, PersonData};

/// Merge multiple PersonData results, preferring higher-confidence sources.
pub fn merge_person(mut results: Vec<PersonData>) -> PersonData {
    if results.is_empty() {
        return PersonData::default();
    }
    if results.len() == 1 {
        return results.remove(0);
    }

    // Sort by confidence descending — highest confidence fields win
    results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

    let mut merged = PersonData::default();
    let mut sources = Vec::new();
    let mut max_confidence = 0.0f64;

    for r in &results {
        sources.push(r.source.clone());
        if r.confidence > max_confidence {
            max_confidence = r.confidence;
        }

        if merged.email.is_none() {
            merged.email.clone_from(&r.email);
        }
        if merged.first_name.is_none() {
            merged.first_name.clone_from(&r.first_name);
        }
        if merged.last_name.is_none() {
            merged.last_name.clone_from(&r.last_name);
        }
        if merged.title.is_none() {
            merged.title.clone_from(&r.title);
        }
        if merged.company.is_none() {
            merged.company.clone_from(&r.company);
        }
        if merged.linkedin_url.is_none() {
            merged.linkedin_url.clone_from(&r.linkedin_url);
        }
        if merged.github_url.is_none() {
            merged.github_url.clone_from(&r.github_url);
        }
        if merged.twitter_url.is_none() {
            merged.twitter_url.clone_from(&r.twitter_url);
        }
        if merged.phone.is_none() {
            merged.phone.clone_from(&r.phone);
        }
        if merged.location.is_none() {
            merged.location.clone_from(&r.location);
        }
    }

    merged.confidence = max_confidence;
    merged.source = sources.join("+");
    merged
}

/// Merge multiple CompanyData results, preferring higher-confidence sources.
pub fn merge_company(mut results: Vec<CompanyData>) -> CompanyData {
    if results.is_empty() {
        return CompanyData::default();
    }
    if results.len() == 1 {
        return results.remove(0);
    }

    results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

    let mut merged = CompanyData::default();
    let mut sources = Vec::new();
    let mut max_confidence = 0.0f64;

    for r in &results {
        sources.push(r.source.clone());
        if r.confidence > max_confidence {
            max_confidence = r.confidence;
        }

        if merged.name.is_none() {
            merged.name.clone_from(&r.name);
        }
        if merged.domain.is_none() {
            merged.domain.clone_from(&r.domain);
        }
        if merged.description.is_none() {
            merged.description.clone_from(&r.description);
        }
        if merged.industry.is_none() {
            merged.industry.clone_from(&r.industry);
        }
        if merged.size.is_none() {
            merged.size.clone_from(&r.size);
        }
        if merged.location.is_none() {
            merged.location.clone_from(&r.location);
        }
        if merged.founded_year.is_none() {
            merged.founded_year = r.founded_year;
        }
        if merged.logo_url.is_none() {
            merged.logo_url.clone_from(&r.logo_url);
        }
        if merged.http_status.is_none() {
            merged.http_status = r.http_status;
        }
        if merged.server.is_none() {
            merged.server.clone_from(&r.server);
        }
        if merged.x_powered_by.is_none() {
            merged.x_powered_by.clone_from(&r.x_powered_by);
        }
        if merged.x_generator.is_none() {
            merged.x_generator.clone_from(&r.x_generator);
        }

        // Accumulate list fields
        for t in &r.tech_stack {
            if !merged.tech_stack.contains(t) {
                merged.tech_stack.push(t.clone());
            }
        }
        for mx in &r.mx_records {
            if !merged.mx_records.contains(mx) {
                merged.mx_records.push(mx.clone());
            }
        }
        for ip in &r.ips {
            if !merged.ips.contains(ip) {
                merged.ips.push(ip.clone());
            }
        }
        for ns in &r.nameservers {
            if !merged.nameservers.contains(ns) {
                merged.nameservers.push(ns.clone());
            }
        }
        for (k, v) in &r.social_profiles {
            merged.social_profiles.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    merged.tech_stack.sort();
    merged.tech_stack.dedup();
    merged.confidence = max_confidence;
    merged.source = sources.join("+");
    merged
}

/// Merge email verifications — SMTP/Hunter results beat DNS-only.
///
/// Returns the highest-confidence result, with boolean fields (disposable, mx_found)
/// OR'd across all providers so that a detection from any source is preserved.
pub fn merge_email_verification(mut results: Vec<EmailVerification>) -> EmailVerification {
    if results.is_empty() {
        return EmailVerification::default();
    }
    if results.len() == 1 {
        return results.remove(0);
    }

    results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

    let best = &results[0];
    let mut merged = best.clone();
    let mut sources: Vec<String> = results.iter().map(|r| r.source.clone()).collect();
    sources.dedup();
    merged.source = sources.join("+");

    // If any provider says deliverable with high confidence, trust it
    if results.iter().any(|r| r.deliverable && r.confidence > 0.7) {
        merged.deliverable = true;
    }
    // If any provider detected disposable, mark it
    if results.iter().any(|r| r.disposable) {
        merged.disposable = true;
    }
    // MX found from any provider
    if results.iter().any(|r| r.mx_found) {
        merged.mx_found = true;
    }

    merged
}
