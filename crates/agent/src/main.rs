//! Phase 1 fleet agent. Talks to a console over HTTP; never touches
//! Postgres directly (see `nsic-core`'s `db` feature, which this crate does
//! not enable). `hash`, `scan`, `enroll`, and `heartbeat` never send file
//! contents, only hashes and metadata (see the repo README's "Locked
//! architecture decisions"). `fulfill-samples` is the one exception, and
//! only because that decision's own carve-out requires it: "file contents
//! leave the host only on explicit analyst request, logged and
//! attributed" -- a sample request is exactly that explicit request,
//! already logged by the console the moment an operator created it.
//!
//! Local YARA scanning (via `nsic-core`'s `yara-scan` feature) is real,
//! and `scan` can optionally report to a console: one sighting per match
//! (a no-op if nothing matched), and, unconditionally, one scan-coverage
//! report -- rule count, ruleset fingerprint, match count, whether or not
//! anything matched. The coverage report is what lets the console tell
//! "this host scanned and found nothing" apart from "this host never
//! scanned, or its rules never loaded," which a sighting alone (match-
//! only) can't distinguish -- see docs/phase1-design.md's "sensor health"
//! section. See docs/phase1-design.md for what's still not here
//! (batching many files/hosts in one request, credential persistence).
//!
//! `--tls-ca-cert` (every subcommand that talks to a console) trusts an
//! additional PEM-encoded root CA when the console is reached over
//! `https://`, on top of the standard public CA trust store `reqwest`
//! already ships with. Needed for a self-signed or internal-CA console
//! certificate; has no effect against a plain-`http://` console or one
//! whose certificate already chains to a public CA.

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use nsic_core::hashing::{hash_bytes, read_regular_file_bounded, MAX_ANALYSIS_BYTES};
use nsic_core::proto::{
    EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse, SampleRequestFailure,
    SampleRequestFulfilled, SampleRequestListResponse, ScanReport, ScanReportResponse,
    SightingRequest, SightingResponse, MAX_SAMPLE_SIZE_BYTES,
};
use nsic_core::yara_scan::YaraEngine;
use reqwest::Response;
use std::path::{Path, PathBuf};
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
        /// Trust this additional PEM-encoded root CA when the console is
        /// reached over https://. See the crate-level doc comment.
        #[arg(long, env = "NSIC_TLS_CA_CERT")]
        tls_ca_cert: Option<PathBuf>,
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
        /// Trust this additional PEM-encoded root CA when the console is
        /// reached over https://. See the crate-level doc comment.
        #[arg(long, env = "NSIC_TLS_CA_CERT")]
        tls_ca_cert: Option<PathBuf>,
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
        /// Trust this additional PEM-encoded root CA when the console is
        /// reached over https://. See the crate-level doc comment.
        #[arg(long, env = "NSIC_TLS_CA_CERT")]
        tls_ca_cert: Option<PathBuf>,
    },
    /// Poll the console for this host's pending sample-retrieval requests
    /// and resolve each one: read the requested path locally and upload
    /// its bytes, or -- if that read fails -- report back why instead of
    /// leaving the request stuck at pending forever. A no-op if there's
    /// nothing pending.
    FulfillSamples {
        #[arg(long)]
        console_url: String,
        #[arg(long)]
        host_id: Uuid,
        /// This host's per-agent credential, issued at enroll time. Falls
        /// back to NSIC_AGENT_CREDENTIAL if not given.
        #[arg(long)]
        credential: Option<String>,
        /// Trust this additional PEM-encoded root CA when the console is
        /// reached over https://. See the crate-level doc comment.
        #[arg(long, env = "NSIC_TLS_CA_CERT")]
        tls_ca_cert: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Hash { path } => {
            let snapshot = read_regular_file_bounded(&path, MAX_ANALYSIS_BYTES)
                .with_context(|| format!("reading {}", path.display()))?;
            let result = hash_bytes(&snapshot.bytes);
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
            tls_ca_cert,
        } => {
            let engine = YaraEngine::load(&rules_dir)
                .with_context(|| format!("loading YARA rules from {}", rules_dir.display()))?;
            // One shared, same-handle-validated, bounded snapshot feeds
            // both hashing and YARA. A hostile path cannot turn this into
            // an unbounded allocation or a blocking FIFO/device open, and
            // the reported hash always identifies the bytes actually
            // inspected.
            let snapshot = read_regular_file_bounded(&path, MAX_ANALYSIS_BYTES)
                .with_context(|| format!("reading {}", path.display()))?;
            let matches = engine
                .scan_bytes(&snapshot.bytes)
                .with_context(|| format!("scanning {}", path.display()))?;
            let hash = hash_bytes(&snapshot.bytes);
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
                    report_scan_results(
                        &console_url,
                        host_id,
                        &credential,
                        &path,
                        &hash.sha256,
                        engine.rule_count,
                        &engine.ruleset_fingerprint,
                        &matches,
                        tls_ca_cert.as_deref(),
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
            tls_ca_cert,
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
            let response = build_http_client(tls_ca_cert.as_deref())?
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
            tls_ca_cert,
        } => {
            let credential = credential
                .or_else(|| std::env::var("NSIC_AGENT_CREDENTIAL").ok())
                .context(
                    "agent credential required: pass --credential or set NSIC_AGENT_CREDENTIAL",
                )?;
            let req = HeartbeatRequest {
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let response = build_http_client(tls_ca_cert.as_deref())?
                .post(format!("{console_url}/api/v1/agents/{host_id}/heartbeat"))
                .bearer_auth(credential)
                .json(&req)
                .send()
                .await
                .context("sending heartbeat")?;
            let resp: HeartbeatResponse = parse_or_report(response, "heartbeat").await?;
            println!("heartbeat ok: received_at={}", resp.received_at);
        }
        Command::FulfillSamples {
            console_url,
            host_id,
            credential,
            tls_ca_cert,
        } => {
            let credential = credential
                .or_else(|| std::env::var("NSIC_AGENT_CREDENTIAL").ok())
                .context(
                    "agent credential required: pass --credential or set NSIC_AGENT_CREDENTIAL",
                )?;
            fulfill_sample_requests(&console_url, host_id, &credential, tls_ca_cert.as_deref())
                .await?;
        }
    }

    Ok(())
}

/// Builds the `reqwest::Client` every console-talking command uses.
/// Without `ca_cert_path`, this is just `reqwest::Client::new()` --
/// standard public CA trust store, same as before this flag existed. With
/// it, the given PEM file is trusted as an *additional* root CA, not a
/// replacement for the public trust store, so a self-signed or internal-
/// CA console certificate can be trusted without disabling certificate
/// validation entirely (there is deliberately no "skip verification"
/// escape hatch here).
///
/// `reqwest::Certificate::from_pem` does not actually validate the
/// certificate's contents at this point -- confirmed directly: garbage
/// text, an empty file, and structurally invalid DER all parse as `Ok`
/// with this reqwest/rustls combination. Real content validation happens
/// later, during an actual TLS handshake against the console, where a
/// bad CA cert will surface as a connection failure rather than a
/// startup error here. The `.with_context` below is kept anyway (in case
/// a future reqwest version does validate eagerly, and because
/// `std::fs::read` failing -- the file not existing or not being
/// readable -- is a real, common error this does catch), but "this
/// function returned `Ok`" should not be read as "the certificate is
/// valid."
fn build_http_client(ca_cert_path: Option<&Path>) -> Result<reqwest::Client> {
    let Some(path) = ca_cert_path else {
        return Ok(reqwest::Client::new());
    };
    let pem = std::fs::read(path)
        .with_context(|| format!("reading TLS CA certificate from {}", path.display()))?;
    let cert = reqwest::Certificate::from_pem(&pem)
        .with_context(|| format!("parsing TLS CA certificate at {}", path.display()))?;
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()
        .context("building HTTP client with custom TLS CA certificate")
}

/// Attempts both post-scan reports -- scan coverage and, if anything
/// matched, sightings -- as two independent operations, neither gated on
/// the other's success. An earlier draft ran them sequentially with `?`
/// after each, which meant a coverage-reporting failure (a transient
/// network blip, the console being briefly unreachable, anything) would
/// exit before `report_sightings` ever ran -- silently dropping a real
/// detection because a lower-value telemetry ping happened to fail first.
/// Caught in review: coverage telemetry must never become a prerequisite
/// for delivering the sightings it exists alongside, not in front of.
/// Both are always attempted; a coverage failure is logged as a warning
/// immediately (so it's not silently swallowed) rather than returned
/// directly, and the sightings outcome -- the more consequential of the
/// two -- is what determines whether this function itself returns an
/// error, falling back to the coverage error if sightings succeeded but
/// coverage didn't, so the process still exits non-zero either way for a
/// script or cron job to notice.
#[allow(clippy::too_many_arguments)]
async fn report_scan_results(
    console_url: &str,
    host_id: Uuid,
    credential: &str,
    path: &Path,
    sha256: &str,
    rule_count: usize,
    ruleset_fingerprint: &str,
    matches: &[nsic_core::yara_scan::YaraMatch],
    tls_ca_cert: Option<&Path>,
) -> Result<()> {
    let coverage_result = report_scan_coverage(
        console_url,
        host_id,
        credential,
        rule_count,
        ruleset_fingerprint,
        matches.len(),
        tls_ca_cert,
    )
    .await;
    if let Err(e) = &coverage_result {
        eprintln!("warning: failed to report scan coverage: {e:#}");
    }

    let sightings_result = report_sightings(
        console_url,
        host_id,
        credential,
        path,
        sha256,
        ruleset_fingerprint,
        matches,
        tls_ca_cert,
    )
    .await;

    sightings_result?;
    coverage_result?;
    Ok(())
}

/// Reports that this scan happened, independent of whether anything
/// matched -- the sensor-health signal `report_sightings` alone can't
/// provide, since a sighting only ever fires on a match. Sent once per
/// `scan` invocation, unconditionally: a zero-rule ruleset or a
/// zero-match scan is exactly the case `report_sightings` (a no-op when
/// `matches` is empty) would otherwise leave completely invisible to the
/// console -- indistinguishable from this host never having scanned at
/// all. See docs/phase1-design.md's "sensor health / scan coverage"
/// section.
async fn report_scan_coverage(
    console_url: &str,
    host_id: Uuid,
    credential: &str,
    rule_count: usize,
    ruleset_fingerprint: &str,
    matched_count: usize,
    tls_ca_cert: Option<&Path>,
) -> Result<()> {
    let req = ScanReport {
        rule_count: rule_count as i32,
        ruleset_fingerprint: ruleset_fingerprint.to_string(),
        matched_count: matched_count as i32,
        scanned_at: Utc::now(),
    };
    let response = build_http_client(tls_ca_cert)?
        .post(format!("{console_url}/api/v1/agents/{host_id}/scans"))
        .bearer_auth(credential)
        .json(&req)
        .send()
        .await
        .context("reporting scan coverage")?;
    let resp: ScanReportResponse = parse_or_report(response, "scan report").await?;
    println!("reported scan coverage: received_at={}", resp.received_at);
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
    tls_ca_cert: Option<&Path>,
) -> Result<()> {
    if matches.is_empty() {
        return Ok(());
    }

    let observed_at = Utc::now();
    let client = build_http_client(tls_ca_cert)?;

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

/// Reads an explicitly requested sample through the same hostile-filesystem
/// boundary used for hashing and YARA, with the protocol's smaller sample
/// limit. The shared primitive follows symlinks to ordinary files, validates
/// the final opened handle, rejects special files, and never buffers more
/// than one byte beyond the configured limit.
fn read_bounded_sample(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let max_bytes = u64::try_from(max_bytes).context("sample byte limit does not fit u64")?;
    Ok(read_regular_file_bounded(path, max_bytes)?.bytes)
}

/// Fetches this host's pending sample requests and resolves each one:
/// reads the requested path locally exactly once, then either uploads
/// those exact bytes as the fulfillment or, if the read itself fails,
/// reports the failure with its reason rather than silently skipping the
/// request and leaving it stuck at `pending`. A no-op if nothing is
/// pending.
async fn fulfill_sample_requests(
    console_url: &str,
    host_id: Uuid,
    credential: &str,
    tls_ca_cert: Option<&Path>,
) -> Result<()> {
    let client = build_http_client(tls_ca_cert)?;
    let response = client
        .get(format!(
            "{console_url}/api/v1/agents/{host_id}/sample-requests"
        ))
        .bearer_auth(credential)
        .send()
        .await
        .context("listing pending sample requests")?;
    let pending: SampleRequestListResponse =
        parse_or_report(response, "sample-request list").await?;

    if pending.requests.is_empty() {
        println!("no pending sample requests");
        return Ok(());
    }
    if pending.truncated {
        eprintln!(
            "warning: more pending sample requests exist than this call returned; re-run \
             after these are resolved to pick up the rest"
        );
    }

    for req in &pending.requests {
        match read_bounded_sample(Path::new(&req.path), MAX_SAMPLE_SIZE_BYTES) {
            Ok(data) => {
                let response = client
                    .post(format!(
                        "{console_url}/api/v1/agents/{host_id}/sample-requests/{}/content",
                        req.id
                    ))
                    .bearer_auth(credential)
                    .header("content-type", "application/octet-stream")
                    .body(data)
                    .send()
                    .await
                    .with_context(|| format!("uploading sample for request {}", req.id))?;
                let resp: SampleRequestFulfilled =
                    parse_or_report(response, "sample-request fulfillment").await?;
                println!(
                    "fulfilled sample request {}: path={} status={:?} sha256={} size_bytes={}",
                    req.id, req.path, resp.status, resp.sha256, resp.size_bytes
                );
            }
            Err(e) => {
                let failure = SampleRequestFailure {
                    reason: format!("reading {}: {e}", req.path),
                };
                let response = client
                    .post(format!(
                        "{console_url}/api/v1/agents/{host_id}/sample-requests/{}/failure",
                        req.id
                    ))
                    .bearer_auth(credential)
                    .json(&failure)
                    .send()
                    .await
                    .with_context(|| format!("reporting failure for request {}", req.id))?;
                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    anyhow::bail!(
                        "console rejected sample-request failure report: {status} {body}"
                    );
                }
                println!(
                    "reported failure for sample request {}: path={} reason={}",
                    req.id, req.path, failure.reason
                );
            }
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

#[cfg(test)]
mod tests {
    use super::{build_http_client, read_bounded_sample};
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn reads_a_file_within_the_limit() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello").unwrap();
        let data = read_bounded_sample(tmp.path(), 100).expect("should read within limit");
        assert_eq!(data, b"hello");
    }

    #[test]
    fn accepts_a_file_exactly_at_the_limit() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 10]).unwrap();
        let data =
            read_bounded_sample(tmp.path(), 10).expect("a file exactly at the limit should pass");
        assert_eq!(data.len(), 10);
    }

    #[test]
    fn rejects_a_file_over_the_limit() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 11]).unwrap();
        let error =
            read_bounded_sample(tmp.path(), 10).expect_err("an over-limit file must be rejected");
        assert!(error.to_string().contains("larger than the 10 byte limit"));
    }

    /// The actual motivating case: an unbounded read of a huge or
    /// endless file must never get far enough to matter. A 10-byte limit
    /// against an 11-byte file already proves the cutoff is exact; this
    /// just confirms the same holds well past that boundary too, so the
    /// `take(max_bytes + 1)` isn't accidentally doing something that only
    /// happens to work for tiny limits.
    #[test]
    fn does_not_buffer_more_than_one_byte_past_the_limit() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 4096]).unwrap();
        let error = read_bounded_sample(tmp.path(), 1024)
            .expect_err("a file well over the limit must still be rejected");
        assert!(error
            .to_string()
            .contains("larger than the 1024 byte limit"));
    }

    #[test]
    fn rejects_a_directory() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let error = read_bounded_sample(tmp_dir.path(), 100)
            .expect_err("a directory is not a regular file");
        assert!(error.to_string().contains("not a regular file"));
    }

    /// The shared reader follows symlinks, then validates the final object
    /// through metadata on the opened handle. A symlink to an ordinary file
    /// remains valid without reintroducing a path-stat/open race.
    #[cfg(unix)]
    #[test]
    fn follows_a_symlink_to_an_ordinary_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"symlinked content").unwrap();
        let link_dir = tempfile::tempdir().unwrap();
        let link_path = link_dir.path().join("link");
        std::os::unix::fs::symlink(tmp.path(), &link_path).unwrap();
        let data = read_bounded_sample(&link_path, 100)
            .expect("a symlink to a regular file should be accepted");
        assert_eq!(data, b"symlinked content");
    }

    // A real self-signed certificate, generated once with `openssl req
    // -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=nsic-test-ca"`,
    // embedded as a fixture rather than shelled out to `openssl` at test
    // time. `reqwest::Certificate::from_pem` only parses the certificate
    // structure -- it doesn't validate expiry or chain to anything -- so
    // a long-dated but otherwise ordinary self-signed cert is a
    // sufficient, stable fixture for exercising the parsing path.
    const TEST_CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDDzCCAfegAwIBAgIUe63a66MzsJUI8dfsPullfQDTTQgwDQYJKoZIhvcNAQEL\n\
BQAwFzEVMBMGA1UEAwwMbnNpYy10ZXN0LWNhMB4XDTI2MDgxNDIzMDAwMVoXDTM2\n\
MDgxMTIzMDAwMVowFzEVMBMGA1UEAwwMbnNpYy10ZXN0LWNhMIIBIjANBgkqhkiG\n\
9w0BAQEFAAOCAQ8AMIIBCgKCAQEApMeLUlfxga2A0WOMHMtUjGiOTzJ/W1K315AI\n\
1C/yNF1ivBr5KlkJgzxGuDFKO37H/oIA9RvopqOcqoaQIu0zGhRF+bwHsctNN+VD\n\
vHuVBqesKQSNxq+9EI1sSnV4zU7iXPuE/HdvUk8GArCLCoSy3IrWaZ0QcGuo81jH\n\
5qnfcgp5+yVJAoSIQeKKUs/PDXwi9UPCJ85ksyboP0TjUPhRQ9BWDPzKRpfJSXnA\n\
kLl630w9gufq44RFhPODImiTQhDPTSD+gB628Td4X7yBxNsOe6jAE8JU7YNvG5r/\n\
ngH21BirrYGKvw8mOhgouBXpBrEmpT5moYE0E0St2wadITbR1wIDAQABo1MwUTAd\n\
BgNVHQ4EFgQUo5eWWiCJEGb4RWa9HtcAOWxkSfUwHwYDVR0jBBgwFoAUo5eWWiCJ\n\
EGb4RWa9HtcAOWxkSfUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n\
AQEAgR4+2yBfNQ391i1nR8W5UcGz6djLDCjHLuVrJzvs7yG33b7MeQy4giIAWP6R\n\
3N2cFFeQHrmVw/offA6t9gcCu9FFZkmAPYXS1RrxVnTtgVC+YsSKxQYC8WcMVwvG\n\
yGB80HC4yFstu7TXh4FiCMHZ5H8UsgHc4ChxyP6qHSF9QMQnGX/vzZNmoyHybhFz\n\
dpA34jpi9PV3c7eC21nfTS93+RX+ZyGEc823ZXnuzpzJbZGwobjPDHxC9W4M3lkV\n\
wpwPXandNWDezRLLas1qzW+wbZzJQldwo29Rdo2z21MkFW4ZW/AU4v84CrCs0CPJ\n\
0Rq5Bpn3J2Y9WylT1VrWzHojzQ==\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn build_http_client_without_ca_cert_succeeds() {
        assert!(build_http_client(None).is_ok());
    }

    #[test]
    fn build_http_client_with_valid_ca_cert_succeeds() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(TEST_CA_CERT_PEM.as_bytes()).unwrap();
        assert!(build_http_client(Some(tmp.path())).is_ok());
    }

    #[test]
    fn build_http_client_with_missing_ca_cert_file_fails() {
        let err = build_http_client(Some(Path::new("/nonexistent/does-not-exist-nsic-test.pem")))
            .expect_err("a missing CA cert file should be a clear error, not a panic");
        assert!(err.to_string().contains("reading TLS CA certificate"));
    }

    /// Documents real, verified behavior rather than assuming it: garbage
    /// content in the CA cert file does *not* make `build_http_client`
    /// fail -- see its doc comment. A test asserting the opposite would
    /// itself be wrong, not just unhelpful; this exists so that fact
    /// stays pinned and visible instead of being silently assumed.
    #[test]
    fn build_http_client_with_malformed_ca_cert_still_succeeds_at_this_stage() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"this is not a PEM certificate").unwrap();
        assert!(build_http_client(Some(tmp.path())).is_ok());
    }

    /// The regression this PR's review round exists to fix: a broken
    /// `/scans` endpoint (the console down, a transient network error,
    /// anything) must never prevent an already-found detection from being
    /// reported. Mocks the console with `/scans` returning `500` and
    /// `/sightings` returning `200`, then confirms via wiremock's request
    /// verification that `/sightings` was actually called -- not just that
    /// the function happened to return successfully, which an earlier,
    /// broken version of this test (checking only the return value) would
    /// not have caught, since both a real bug and a passing case can
    /// return `Err` here for unrelated reasons.
    #[tokio::test]
    async fn a_failed_coverage_report_does_not_prevent_sighting_submission() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let host_id = uuid::Uuid::new_v4();

        Mock::given(method("POST"))
            .and(path_regex(r"^/api/v1/agents/.+/scans$"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/api/v1/agents/.+/sightings$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "indicator_id": uuid::Uuid::new_v4(),
                "recorded_at": chrono::Utc::now().to_rfc3339(),
            })))
            .mount(&server)
            .await;

        let matches = vec![nsic_core::yara_scan::YaraMatch {
            rule_name: "Example_EICAR_Test_File".to_string(),
        }];

        let result = super::report_scan_results(
            &server.uri(),
            host_id,
            "test-credential",
            Path::new("/tmp/eicar.txt"),
            &"a".repeat(64),
            1,
            &"f".repeat(64),
            &matches,
            None,
        )
        .await;

        // The coverage failure must still surface as an overall error
        // (so a wrapping script notices), but that's secondary to the
        // actual point of this test: the request-count assertions below.
        assert!(result.is_err());

        let requests = server.received_requests().await.unwrap();
        let sighting_requests = requests
            .iter()
            .filter(|r| r.url.path().ends_with("/sightings"))
            .count();
        assert_eq!(
            sighting_requests, 1,
            "the sighting must have been reported despite the coverage report failing"
        );
    }
}
