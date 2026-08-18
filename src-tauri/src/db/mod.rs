pub mod indicators;

// The concept-aware high-cardinality fallback has one accumulator whose
// value deliberately carries three orthogonal pieces of state together:
// evidence paths, supporting detection identities, and evidence partiality.
// Keep Clippy's type-complexity exception local to this module rather than
// weakening the workspace threshold; the shape is documented at the
// construction site and never crosses the module boundary.
#[allow(clippy::type_complexity)]
pub mod relationship_bounds;

#[cfg(test)]
mod relationship_bounds_tests;

/// Connects to Postgres and runs any pending migrations. DATABASE_URL must
/// point at a reachable Postgres instance; see docker-compose.yml for a
/// local dev instance and .env.example for the expected connection string.
/// Lives in `nsic-core` (behind its `db` feature) so the Phase 1 console
/// connects to and migrates the exact same schema.
pub use nsic_core::db::connect_and_migrate;
