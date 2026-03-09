# :mag: dataxlr8-enrichment-mcp

Lead and contact enrichment for AI agents — person, company, email verification, tech stack, and hiring signals with waterfall provider strategy.

[![Rust](https://img.shields.io/badge/Rust-2024_edition-orange?logo=rust)](https://www.rust-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-rmcp_0.17-blue)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What It Does

Enriches contacts and companies with data from multiple providers using a waterfall strategy — if one provider returns nothing, the next is tried automatically. Supports person lookups, company intel, email verification via DNS (hickory-resolver), tech stack detection, and hiring signals. All results are cached in PostgreSQL to eliminate redundant API calls and reduce costs.

## Architecture

```
                    ┌──────────────────────────┐
AI Agent ──stdio──▶ │  dataxlr8-enrichment-mcp │
                    │  (rmcp 0.17 server)       │
                    └─────┬──────────┬─────────┘
                          │ sqlx 0.8 │ reqwest 0.12
                          ▼          │ hickory-resolver
                    ┌──────────┐     ▼
                    │ PostgreSQL│ ┌───────────────┐
                    │ schema:  │ │ Enrichment    │
                    │ enrichment│ │ Providers     │
                    │ (cache)  │ │ (waterfall)   │
                    └──────────┘ └───────────────┘
```

## Tools

| Tool | Description |
|------|-------------|
| `enrich_person` | Enrich a person by name and company domain |
| `enrich_company` | Get company details by domain |
| `verify_email` | Verify if an email address is deliverable |
| `domain_emails` | Find email addresses for a domain |
| `search_people` | Search for people by role and company |
| `reverse_domain` | Look up company info from a domain |
| `bulk_enrich` | Enrich multiple records in one call |
| `tech_stack` | Detect a company's technology stack |
| `hiring_signals` | Check if a company is actively hiring |
| `social_profiles` | Find social media profiles for a person or company |
| `enrichment_stats` | Get enrichment usage and cache hit statistics |
| `cache_lookup` | Check the cache for existing enrichment data |

## Quick Start

```bash
git clone https://github.com/pdaxt/dataxlr8-enrichment-mcp
cd dataxlr8-enrichment-mcp
cargo build --release

export DATABASE_URL=postgres://user:pass@localhost:5432/dataxlr8
./target/release/dataxlr8-enrichment-mcp
```

The server auto-creates the `enrichment` schema and all tables on first run.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `LOG_LEVEL` | No | Tracing level (default: `info`) |

## Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dataxlr8-enrichment": {
      "command": "./target/release/dataxlr8-enrichment-mcp",
      "env": {
        "DATABASE_URL": "postgres://user:pass@localhost:5432/dataxlr8"
      }
    }
  }
}
```

## Part of DataXLR8

One of 14 Rust MCP servers that form the [DataXLR8](https://github.com/pdaxt) platform — a modular, AI-native business operations suite. Each server owns a single domain, shares a PostgreSQL instance, and communicates over the Model Context Protocol.

## License

MIT
