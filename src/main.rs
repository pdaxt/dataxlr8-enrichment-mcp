use anyhow::Result;
use rmcp::transport::io::stdio;
use rmcp::ServiceExt;
use tracing::info;

mod cache;
mod db;
mod merge;
mod providers;
mod tools;
mod waterfall;

#[cfg(test)]
mod tests;

use tools::EnrichmentMcpServer;

#[tokio::main]
async fn main() -> Result<()> {
    let config = dataxlr8_mcp_core::Config::from_env("dataxlr8-enrichment-mcp")
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    dataxlr8_mcp_core::logging::init(&config.log_level);

    info!(
        server = config.server_name,
        "Starting DataXLR8 Enrichment MCP server"
    );

    let database = dataxlr8_mcp_core::Database::connect(&config.database_url)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Run schema setup
    db::setup_schema(database.pool()).await?;

    let server = EnrichmentMcpServer::new(database.clone());

    let transport = stdio();
    let service = server.serve(transport).await?;

    info!("Enrichment MCP server connected via stdio");

    // Wait for either service completion or shutdown signal
    tokio::select! {
        result = service.waiting() => {
            result?;
            info!("MCP service ended");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    // Graceful shutdown
    database.close().await;
    info!("Enrichment MCP server shut down");

    Ok(())
}
