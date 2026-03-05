# dataxlr8-enrichment-mcp

Email, company, and person enrichment MCP server for the DataXLR8 platform.

## What It Does

Enriches leads and contacts with data from multiple providers using a waterfall strategy — if one provider misses, the next is tried. Supports person lookups, company intel, email verification, tech stack detection, and hiring signals. Results are cached in PostgreSQL to avoid redundant API calls.

## Tools

| Tool | Description |
|------|-------------|
| `enrich_person` | Enrich a person by name + company domain |
| `enrich_company` | Get company details by domain |
| `verify_email` | Verify if an email address is deliverable |
| `domain_emails` | Find email addresses for a domain |
| `search_people` | Search for people by role/company |
| `reverse_domain` | Look up company info from a domain |
| `bulk_enrich` | Enrich multiple records at once |
| `tech_stack` | Detect a company's technology stack |
| `hiring_signals` | Check if a company is actively hiring |
| `social_profiles` | Find social media profiles for a person/company |
| `enrichment_stats` | Get enrichment usage statistics |
| `cache_lookup` | Check the enrichment cache for existing data |

## Quick Start

```bash
export DATABASE_URL=postgres://user:pass@localhost:5432/dataxlr8

cargo build
cargo run
```

## Schema

Creates an `enrichment` schema with:

| Table | Purpose |
|-------|---------|
| `enrichment.lookups` | Cached enrichment results (type, query, response, provider) |

## Part of the [DataXLR8](https://github.com/pdaxt) Platform
