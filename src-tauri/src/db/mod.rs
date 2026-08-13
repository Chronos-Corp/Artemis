pub mod indicators;

/// Connects to Postgres and runs any pending migrations. DATABASE_URL must
/// point at a reachable Postgres instance; see docker-compose.yml for a
/// local dev instance and .env.example for the expected connection string.
/// Lives in `nsic-core` (behind its `db` feature) so the Phase 1 console
/// connects to and migrates the exact same schema.
pub use nsic_core::db::connect_and_migrate;
