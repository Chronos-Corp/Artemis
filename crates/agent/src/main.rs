//! Phase 1 fleet agent. Talks to a console over HTTP; never touches
//! Postgres directly (see `nsic-core`'s `db` feature, which this crate does
//! not enable), and never sends file contents, only hashes and metadata
//! (see the repo README's "Locked architecture decisions").
//!
//! Local YARA scanning (via `nsic-core`'s `yara-scan` feature) is now
//! real; sending what it finds to the console (sighting submission) is
//! not yet -- see docs/phase1-design.md for what's next.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nsic_core::hashing::compute_hashes;
use nsic_core::proto::{EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse};
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
    /// as JSON. Local-only, no console involved -- reporting a match like
    /// this back to the console is sighting submission, not designed yet.
    Scan {
        path: PathBuf,
        /// Directory of .yar/.yara rule files to load. A missing directory
        /// is not an error: it just means zero rules load, zero matches.
        #[arg(long, env = "NSIC_YARA_RULES_DIR", default_value = "yara-rules")]
        rules_dir: PathBuf,
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
        Command::Scan { path, rules_dir } => {
            let engine = YaraEngine::load(&rules_dir)
                .with_context(|| format!("loading YARA rules from {}", rules_dir.display()))?;
            let matches = engine
                .scan(&path)
                .with_context(|| format!("scanning {}", path.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": path,
                    "rules_dir": rules_dir,
                    "rule_count": engine.rule_count,
                    "matches": matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>(),
                }))?
            );
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
