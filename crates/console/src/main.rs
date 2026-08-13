//! Phase 1 fleet console. Scaffolding: accepts agent enrollment and
//! heartbeats over unauthenticated HTTP and records them in the shared
//! Postgres intel graph (the same schema `src-tauri` uses). See
//! docs/phase1-design.md for what's deliberately not here yet (auth, event
//! ingestion, sample retrieval, a fleet UI).

mod host;

use axum::routing::post;
use axum::Router;
use sqlx::PgPool;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
    let pool = nsic_core::db::connect_and_migrate(&database_url).await?;
    tracing::info!("connected to postgres and ran migrations");

    let app = build_router(pool);

    // Unauthenticated HTTP with no TLS (see docs/phase1-design.md), so the
    // default bind is loopback-only. Network-wide exposure has to be an
    // explicit opt-in via NSIC_CONSOLE_ADDR, not the out-of-the-box default.
    let addr: SocketAddr = std::env::var("NSIC_CONSOLE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("console listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(pool: PgPool) -> Router {
    Router::new()
        .route("/agents/enroll", post(host::enroll))
        .route("/agents/{host_id}/heartbeat", post(host::heartbeat))
        .with_state(pool)
}
