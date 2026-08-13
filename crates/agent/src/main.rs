//! Phase 1 fleet agent. Talks to a console over HTTP; never touches
//! Postgres directly (see `nsic-core`'s `db` feature, which this crate does
//! not enable), and never sends file contents, only hashes and metadata
//! (see the repo README's "Locked architecture decisions").
//!
//! This is scaffolding: enroll and heartbeat only, no local YARA scanning
//! or verdict submission yet. See docs/phase1-design.md for what's next.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nsic_core::hashing::compute_hashes;
use nsic_core::proto::{EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse};
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
    /// Register this host with a console, printing the assigned host_id.
    Enroll {
        /// Base URL of the console, e.g. http://localhost:8787
        #[arg(long)]
        console_url: String,
        #[arg(long)]
        hostname: String,
        #[arg(long, default_value = std::env::consts::OS)]
        os: String,
    },
    /// Send a single heartbeat for an already-enrolled host.
    Heartbeat {
        #[arg(long)]
        console_url: String,
        #[arg(long)]
        host_id: Uuid,
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
        Command::Enroll {
            console_url,
            hostname,
            os,
        } => {
            let req = EnrollRequest {
                hostname,
                os,
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let resp: EnrollResponse = reqwest::Client::new()
                .post(format!("{console_url}/agents/enroll"))
                .json(&req)
                .send()
                .await
                .context("sending enroll request")?
                .error_for_status()
                .context("console rejected enroll request")?
                .json()
                .await
                .context("parsing enroll response")?;
            println!("enrolled: host_id={}", resp.host_id);
        }
        Command::Heartbeat {
            console_url,
            host_id,
        } => {
            let req = HeartbeatRequest {
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let resp: HeartbeatResponse = reqwest::Client::new()
                .post(format!("{console_url}/agents/{host_id}/heartbeat"))
                .json(&req)
                .send()
                .await
                .context("sending heartbeat")?
                .error_for_status()
                .context("console rejected heartbeat")?
                .json()
                .await
                .context("parsing heartbeat response")?;
            println!("heartbeat ok: received_at={}", resp.received_at);
        }
    }

    Ok(())
}
