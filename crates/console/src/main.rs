//! Phase 1 fleet console. Accepts agent enrollment, heartbeats, and YARA
//! sighting reports, and records them in the shared Postgres intel graph
//! (the same schema `src-tauri` uses). See docs/phase1-design.md for
//! what's deliberately not here yet (TLS, sample retrieval, a fleet UI).
//!
//! Two credentials gate this API (see `nsic_core::proto` for the full
//! rationale): a bootstrap enrollment secret the operator configures via
//! `NSIC_ENROLLMENT_SECRET`, required on every `POST /api/v1/agents/enroll`
//! call, and a per-agent credential minted at enroll time, required on
//! every subsequent authenticated request (heartbeat, sightings).

mod auth;
mod host;
mod sighting;

use anyhow::Context;
use axum::routing::post;
use axum::Router;
use sqlx::PgPool;
use std::net::SocketAddr;

#[derive(Clone)]
pub(crate) struct AppState {
    pool: PgPool,
    bootstrap_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Checked before touching the network: a misconfigured secret should
    // fail fast on local config, not after paying for a Postgres round trip.
    let bootstrap_secret = std::env::var("NSIC_ENROLLMENT_SECRET").context(
        "NSIC_ENROLLMENT_SECRET must be set: the console refuses to start without a \
         bootstrap enrollment secret to authorize new agents",
    )?;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
    let pool = nsic_core::db::connect_and_migrate(&database_url).await?;
    tracing::info!("connected to postgres and ran migrations");

    let app = build_router(AppState {
        pool,
        bootstrap_secret,
    });

    // Unauthenticated transport is still plain HTTP with no TLS (see
    // docs/phase1-design.md), so the default bind is loopback-only.
    // Network-wide exposure has to be an explicit opt-in via
    // NSIC_CONSOLE_ADDR, not the out-of-the-box default.
    let addr: SocketAddr = std::env::var("NSIC_CONSOLE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("console listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/agents/enroll", post(host::enroll))
        .route("/api/v1/agents/{host_id}/heartbeat", post(host::heartbeat))
        .route(
            "/api/v1/agents/{host_id}/sightings",
            post(sighting::report_sighting),
        )
        .with_state(state)
}
