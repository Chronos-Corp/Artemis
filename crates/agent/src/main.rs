//! Phase 1 fleet agent. Talks to a console over HTTP; never touches
//! Postgres directly (see `nsic-core`'s `db` feature, which this crate does
//! not enable), and never sends file contents, only hashes and metadata
//! (see the repo README's "Locked architecture decisions").
//!
//! Local YARA scanning (via `nsic-core`'s `yara-scan` feature) is real,
//! and `scan` can optionally report what it finds to a console as
//! sightings -- see docs/phase1-design.md for what's still not here
//! (batching many files/hosts in one request, credential persistence).

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use nsic_core::hashing::{compute_hashes, hash_bytes};
use nsic_core::proto::{
    EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse, SightingRequest,
    SightingResponse,
};
use nsic_core::yara_scan::YaraEngine;
use reqwest::Response;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "nsic-agent", version, about = "4NSIC Phase 1 fleet agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash a file locally and print the result as JSON. Exercises the same
    /// digest path the console-connected commands will eventually feed into
    /// a verdict lookup; useful standalone while the console has nothing
    /// but enroll/heartbeat to talk to yet.
    Hash { path: PathBuf },
    /// Load local YARA rules and scan a single file, printing any matches
    /// as JSON. If --console-url, --host-id, and --credential are all
    /// given, also reports each match to the console as a sighting;
    /// otherwise this stays entirely local, same as before.
    Scan {
        path: PathBuf,
        /// Directory of .yar/.yara rule files to load. A missing directory
        /// is not an error: it just means zero rules load, zero matches.
        #[arg(long, env = "NSIC_YARA_RULES_DIR", default_value = "yara-rules")]
        rules_dir: PathBuf,
        /// Base URL of a console to report any matches to, e.g.
        /// http://localhost:8787. Requires --host-id and --credential too.
        #[arg(long, env = "NSIC_CONSOLE_URL")]
        console_url: Option<String>,
        #[arg(long, env = "NSIC_HOST_ID")]
        host_id: Option<Uuid>,
        /// This host's per-agent credential, issued at enroll time.
        #[arg(long, env = "NSIC_AGENT_CREDENTIAL")]
        credential: Option<String>,
    },
    /// Register this host with a console, printing the assigned host_id
    /// and the per-agent credential to use for subsequent requests.
    Enroll {
        /// Base URL of the console, e.g. http://localhost:8787
        #[arg(long)]
        console_url: String,
        #[arg(long)]
        hostname: String,
        #[arg(long, default_value = std::env::consts::OS)]
        os: String,
        /// The console's bootstrap enrollment secret, authorizing this
        /// machine to join. Falls back to NSIC_ENROLLMENT_SECRET if not
        /// given, so it doesn't have to appear in shell history or
        /// process listings.
        #[arg(long)]
        enrollment_secret: Option<String>,
    },
    /// Send a single heartbeat for an already-enrolled host.
    Heartbeat {
        #[arg(long)]
        console_url: String,
        #[arg(long)]
        host_id: Uuid,
        /// This host's per-agent credential, issued at enroll time. Falls
        /// back to NSIC_AGENT_CREDENTIAL if not given.
        #[arg(long)]
        credential: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Hash { path } => {
            let result =
                compute_hashes(&path).with_context(|| format!("hashing {}", path.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": path,
                    "sha256": result.sha256,
                    "md5": result.md5,
                }))?
            );
        }
        Command::Scan {
            path,
            rules_dir,
            console_url,
            host_id,
            credential,
        } => {
            let engine = YaraEngine::load(&rules_dir)
                .with_context(|| format!("loading YARA rules from {}", rules_dir.display()))?;
            // Read the file exactly once and hash and scan the identical
            // bytes, rather than hashing and scanning via two separate
            // opens of the same path: a file can change between two reads,
            // and for a match this hashes and may persist durably as a
            // sighting, binding the detection to whichever bytes were
            // actually inspected is an evidence-integrity requirement, not
            // just a nice-to-have.
            let data =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let matches = engine
                .scan_bytes(&data)
                .with_context(|| format!("scanning {}", path.display()))?;
            let hash = hash_bytes(&data);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": path,
                    "rules_dir": rules_dir,
                    "rule_count": engine.rule_count,
                    "sha256": hash.sha256,
                    "matches": matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>(),
                }))?
            );

            match (console_url, host_id, credential) {
                (Some(console_url), Some(host_id), Some(credential)) => {
                    report_sightings(
                        &console_url,
                        host_id,
                        &credential,
                        &path,
                        &hash.sha256,
                        &engine.ruleset_fingerprint,
                        &matches,
                    )
                    .await?;
                }
                (None, None, None) => {}
                _ => eprintln!(
                    "warning: --console-url, --host-id, and --credential must all be given \
                     together to report sightings; skipping report"
                ),
            }
        }
        Command::Enroll {
            console_url,
            hostname,
            os,
            enrollment_secret,
        } => {
            let secret = enrollment_secret
                .or_else(|| std::env::var("NSIC_ENROLLMENT_SECRET").ok())
                .context(
                    "bootstrap enrollment secret required: pass --enrollment-secret or set \
                     NSIC_ENROLLMENT_SECRET",
                )?;
            let req = EnrollRequest {
                hostname,
                os,
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let response = reqwest::Client::new()
                .post(format!("{console_url}/api/v1/agents/enroll"))
                .bearer_auth(secret)
                .json(&req)
                .send()
                .await
                .context("sending enroll request")?;
            let resp: EnrollResponse = parse_or_report(response, "enroll").await?;
            println!("enrolled: host_id={}", resp.host_id);
            println!(
                "credential (store this securely, the console will not show it again): {}",
                resp.credential
            );
        }
        Command::Heartbeat {
            console_url,
            host_id,
            credential,
        } => {
            let credential = credential
                .or_else(|| std::env::var("NSIC_AGENT_CREDENTIAL").ok())
                .context(
                    "agent credential required: pass --credential or set NSIC_AGENT_CREDENTIAL",
                )?;
            let req = HeartbeatRequest {
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let response = reqwest::Client::new()
                .post(format!("{console_url}/api/v1/agents/{host_id}/heartbeat"))
                .bearer_auth(credential)
                .json(&req)
                .send()
                .await
                .context("sending heartbeat")?;
            let resp: HeartbeatResponse = parse_or_report(response, "heartbeat").await?;
            println!("heartbeat ok: received_at={}", resp.received_at);
        }
    }

    Ok(())
}

/// Reports one sighting per YARA match found, in sequence (this PR does
/// not batch multiple sightings into one request -- see
/// docs/phase1-design.md for why that's deferred until scanning stops
/// being one file per CLI invocation). A no-op if `matches` is empty, so
/// callers don't need to check that themselves. Takes the sha256 and
/// ruleset fingerprint the caller already computed from the exact bytes
/// that were scanned, rather than recomputing either here: recomputing
/// the hash via a second read of `path` is exactly the TOCTOU this
/// function must not reintroduce.
#[allow(clippy::too_many_arguments)]
async fn report_sightings(
    console_url: &str,
    host_id: Uuid,
    credential: &str,
    path: &std::path::Path,
    sha256: &str,
    ruleset_fingerprint: &str,
    matches: &[nsic_core::yara_scan::YaraMatch],
) -> Result<()> {
    if matches.is_empty() {
        return Ok(());
    }

    let observed_at = Utc::now();
    let client = reqwest::Client::new();

    for m in matches {
        let req = SightingRequest {
            sha256: sha256.to_string(),
            detection_name: m.rule_name.clone(),
            ruleset_fingerprint: ruleset_fingerprint.to_string(),
            path: Some(path.to_string_lossy().to_string()),
            observed_at,
        };
        let response = client
            .post(format!("{console_url}/api/v1/agents/{host_id}/sightings"))
            .bearer_auth(credential)
            .json(&req)
            .send()
            .await
            .with_context(|| format!("reporting sighting for rule {}", m.rule_name))?;
        let resp: SightingResponse = parse_or_report(response, "sighting").await?;
        println!(
            "reported sighting: indicator_id={} rule={}",
            resp.indicator_id, m.rule_name
        );
    }
    Ok(())
}

/// Parses a successful JSON response, or turns a non-2xx one into an error
/// that includes the console's response body (typically a plain-text
/// reason, e.g. "invalid bootstrap enrollment credential") instead of just
/// a status code, since auth failures are an expected, actionable outcome
/// here, not just an edge case.
async fn parse_or_report<T: serde::de::DeserializeOwned>(
    response: Response,
    what: &str,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("console rejected {what} request: {status} {body}");
    }
    response
        .json()
        .await
        .with_context(|| format!("parsing {what} response"))
}
