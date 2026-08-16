//! Server-rendered fleet UI: a minimal, no-JS HTML console for the
//! operator persona, served directly by this binary -- no Node/npm, no
//! build step, no second toolchain, consistent with `crates/console`'s
//! existing "plain Rust binary" pitch. See docs/phase1-design.md for why
//! that was chosen over reusing the Phase 0 desktop app's React/Vite
//! stack. `maud`'s `html!` macro auto-escapes interpolated text, which
//! matters here since hostnames, paths, detection names, and failure
//! reasons are all agent- or analyst-supplied strings landing directly in
//! markup -- unescaped, any of them could inject markup or script into
//! this page.
//!
//! Gated by HTTP Basic auth (`authenticate_operator_ui`), not the JSON
//! API's Bearer scheme -- see that function's doc comment for why. There
//! is no session or cookie: the browser caches the Basic credential
//! itself and resends it automatically on every request, including plain
//! `<a href>` navigation and form submissions, which is what lets every
//! page here avoid client-side JS entirely -- downloads are plain links,
//! actions are plain forms.

use axum::extract::{Form, Path, Query, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use nsic_core::proto::{SampleRequestCreate, SampleRequestStatus, SampleRequestView, SightingView};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{authenticate_operator_ui, generate_credential, hash_credential};
use crate::host::{fetch_all_hosts, fetch_host, set_host_credential, REVOKED_CREDENTIAL_SENTINEL};
use crate::sample::{
    fetch_content_by_request, fetch_sample_requests, insert_sample_request, sample_content_response,
};
use crate::sighting::fetch_host_sightings;
use crate::AppState;

/// The fleet directory: every enrolled host, linked through to its detail
/// page. Serves both `/` and `/hosts` (see `crate::build_router`) so
/// pointing a browser at the console's bare address lands somewhere
/// useful rather than a 404.
pub async fn host_directory(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(challenge) = authenticate_operator_ui(&state.operator_secret, &headers) {
        return challenge;
    }

    let (hosts, truncated) = match fetch_all_hosts(&state.pool).await {
        Ok(v) => v,
        Err(e) => return db_error_page(e),
    };

    layout(
        "Fleet",
        html! {
            h1 { "Fleet" }
            @if truncated {
                p class="warning" { "Showing the first page only -- more hosts exist than this view can list yet." }
            }
            @if hosts.is_empty() {
                p { "No hosts enrolled yet." }
            } @else {
                table {
                    thead {
                        tr {
                            th { "Hostname" }
                            th { "OS" }
                            th { "Agent version" }
                            th { "Enrolled" }
                            th { "Last heartbeat" }
                        }
                    }
                    tbody {
                        @for host in &hosts {
                            tr {
                                td { a href=(format!("/hosts/{}", host.id)) { (host.hostname) } }
                                td { (host.os) }
                                td { (host.agent_version) }
                                td { (format_time(host.enrolled_at)) }
                                td { (format_optional_time(host.last_heartbeat_at)) }
                            }
                        }
                    }
                }
            }
        },
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct FlashQuery {
    flash: Option<String>,
}

/// A single host: metadata, its sightings, its sample requests (with
/// download links for anything content-bearing), and the three write
/// actions an operator can take against it -- request a sample, rotate
/// its credential, revoke its credential.
pub async fn host_detail(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    Query(flash): Query<FlashQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(challenge) = authenticate_operator_ui(&state.operator_secret, &headers) {
        return challenge;
    }
    render_host_detail(&state, host_id, flash.flash.as_deref(), None).await
}

/// Shared by `host_detail` and `rotate_credential_action` (which renders
/// the same page directly, with a freshly rotated credential banner,
/// rather than redirecting -- see that handler's doc comment for why).
async fn render_host_detail(
    state: &AppState,
    host_id: Uuid,
    flash: Option<&str>,
    new_credential: Option<&str>,
) -> Response {
    let host = match fetch_host(&state.pool, host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return not_found_page("No such host."),
        Err(e) => return db_error_page(e),
    };
    let (sightings, sightings_truncated) = match fetch_host_sightings(&state.pool, host_id).await {
        Ok(v) => v,
        Err(e) => return db_error_page(e),
    };
    let (sample_requests, samples_truncated) =
        match fetch_sample_requests(&state.pool, host_id).await {
            Ok(v) => v,
            Err(e) => return db_error_page(e),
        };

    let body = html! {
        h1 { "Host: " (host.hostname) }
        p class="meta" {
            "id " code { (host.id) } " -- " (host.os) " -- agent " (host.agent_version)
        }
        p class="meta" {
            "enrolled " (format_time(host.enrolled_at))
            " -- last heartbeat " (format_optional_time(host.last_heartbeat_at))
        }

        @if let Some(credential) = new_credential {
            div class="banner banner-warning" {
                p { strong { "New credential (shown once, copy it now):" } }
                p { code { (credential) } }
                p { "The console will not show this value again. The host's previous credential no longer works." }
            }
        }
        @if flash == Some("revoked") {
            div class="banner" { "Credential revoked. This host cannot authenticate until an operator rotates it a new one." }
        }
        @if flash == Some("sample_requested") {
            div class="banner" { "Sample request created." }
        }

        section {
            h2 { "Credential" }
            form method="post" action=(format!("/hosts/{host_id}/credential/rotate")) {
                button type="submit" { "Rotate credential" }
            }
            form method="post" action=(format!("/hosts/{host_id}/credential/revoke")) onsubmit="return confirm('Revoke this host\\'s credential? It will not be able to authenticate until rotated again.');" {
                button type="submit" class="danger" { "Revoke credential" }
            }
        }

        section {
            h2 { "Request a sample" }
            form method="post" action=(format!("/hosts/{host_id}/sample-requests")) {
                label { "Path on host" br; input type="text" name="path" required autocomplete="off"; }
                label { "Expected sha256 (optional)" br; input type="text" name="expected_sha256" autocomplete="off"; }
                button type="submit" { "Request sample" }
            }
        }

        section {
            h2 { "Sample requests" }
            @if samples_truncated {
                p class="warning" { "Showing the first page only." }
            }
            @if sample_requests.is_empty() {
                p { "No sample requests for this host." }
            } @else {
                table {
                    thead {
                        tr {
                            th { "Path" }
                            th { "Status" }
                            th { "Sha256 / size" }
                            th { "Requested" }
                            th { "Resolved" }
                            th { "" }
                        }
                    }
                    tbody {
                        @for req in &sample_requests {
                            (sample_request_row(host_id, req))
                        }
                    }
                }
            }
        }

        section {
            h2 { "Sightings" }
            @if sightings_truncated {
                p class="warning" { "Showing the first page only." }
            }
            @if sightings.is_empty() {
                p { "No sightings reported for this host." }
            } @else {
                table {
                    thead {
                        tr {
                            th { "Detection" }
                            th { "Sha256" }
                            th { "Path" }
                            th { "First seen" }
                            th { "Last seen" }
                        }
                    }
                    tbody {
                        @for s in &sightings {
                            (sighting_row(s))
                        }
                    }
                }
            }
        }

        p { a href="/hosts" { "\u{2190} back to fleet" } }
    };

    let mut response = layout(&format!("Host: {}", host.hostname), body).into_response();
    if new_credential.is_some() {
        // Same reasoning as the JSON API's rotate response: a shown-once
        // secret must not be retained by an intermediate cache or the
        // browser's own response cache.
        response
            .headers_mut()
            .insert(CACHE_CONTROL, "no-store".parse().unwrap());
    }
    response
}

fn sample_request_row(host_id: Uuid, req: &SampleRequestView) -> Markup {
    html! {
        tr {
            td { (req.path) }
            td { (status_badge(req.status)) }
            td {
                @if let Some(sha256) = &req.sha256 {
                    code { (short_hash(sha256)) }
                    @if let Some(size) = req.size_bytes {
                        " (" (format_size(size)) ")"
                    }
                } @else if let Some(reason) = &req.failure_reason {
                    span class="meta" { (reason) }
                } @else {
                    "--"
                }
            }
            td { (format_time(req.requested_at)) }
            td { (format_optional_time(req.resolved_at)) }
            td {
                @if req.sha256.is_some() {
                    a href=(format!("/hosts/{host_id}/sample-requests/{}/content", req.id)) { "download" }
                }
            }
        }
    }
}

fn sighting_row(s: &SightingView) -> Markup {
    html! {
        tr {
            td { (s.detection_name) }
            td { code { (short_hash(&s.sha256)) } }
            td { (s.path.as_deref().unwrap_or("--")) }
            td { (format_time(s.first_seen)) }
            td { (format_time(s.last_seen)) }
        }
    }
}

fn status_badge(status: SampleRequestStatus) -> Markup {
    let (label, class) = match status {
        SampleRequestStatus::Pending => ("pending", "badge-pending"),
        SampleRequestStatus::Fulfilled => ("fulfilled", "badge-ok"),
        SampleRequestStatus::Mismatched => ("mismatched", "badge-warn"),
        SampleRequestStatus::Failed => ("failed", "badge-err"),
    };
    html! { span class=(format!("badge {class}")) { (label) } }
}

#[derive(Deserialize)]
pub struct SampleRequestForm {
    path: String,
    expected_sha256: String,
}

/// Creates a sample request from the host detail page's form, then
/// redirects back to it (`303 See Other`, so a page refresh doesn't
/// resubmit the form) -- unlike `rotate_credential_action`, nothing here
/// is a secret, so a redirect with a plain flash flag in the query string
/// is fine.
pub async fn create_sample_request_action(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<SampleRequestForm>,
) -> Response {
    if let Some(challenge) = authenticate_operator_ui(&state.operator_secret, &headers) {
        return challenge;
    }

    let expected_sha256 = {
        let trimmed = form.expected_sha256.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    };
    let req = SampleRequestCreate {
        path: form.path,
        expected_sha256,
    };

    match insert_sample_request(&state.pool, host_id, &req).await {
        Ok(_) => Redirect::to(&format!("/hosts/{host_id}?flash=sample_requested")).into_response(),
        Err((StatusCode::NOT_FOUND, _)) => not_found_page("No such host."),
        Err((status, message)) => (status, message).into_response(),
    }
}

/// Rotates the host's credential and renders the host detail page
/// directly (`200`, not a redirect) with the new credential in a banner.
/// Deliberately not a redirect: a redirect would have to carry the new
/// credential somewhere for the next request to display it, and the only
/// place available (the URL's query string) is a bad place to put a
/// secret -- it lands in browser history and can be logged by any proxy
/// in front of the console. Rendering it directly in this response body
/// means it only ever exists in an HTML page marked `Cache-Control:
/// no-store`, the same page/cache discipline the JSON API's rotate
/// response already has. The tradeoff: refreshing this specific page
/// (F5) prompts the browser to ask about resubmitting the form, since
/// it's the direct response to a POST -- accepted as the smaller problem.
pub async fn rotate_credential_action(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Some(challenge) = authenticate_operator_ui(&state.operator_secret, &headers) {
        return challenge;
    }

    let credential = generate_credential();
    let credential_hash = hash_credential(&credential);
    if let Err((status, message)) =
        set_host_credential(&state, host_id, &credential_hash, "rotated").await
    {
        return if status == StatusCode::NOT_FOUND {
            not_found_page("No such host.")
        } else {
            (status, message).into_response()
        };
    }

    render_host_detail(&state, host_id, None, Some(&credential)).await
}

/// Revokes the host's credential, then redirects back to the host detail
/// page -- unlike rotate, there's no secret to display, so a plain
/// redirect-with-flash is fine here.
pub async fn revoke_credential_action(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Some(challenge) = authenticate_operator_ui(&state.operator_secret, &headers) {
        return challenge;
    }

    if let Err((status, message)) =
        set_host_credential(&state, host_id, REVOKED_CREDENTIAL_SENTINEL, "revoked").await
    {
        return if status == StatusCode::NOT_FOUND {
            not_found_page("No such host.")
        } else {
            (status, message).into_response()
        };
    }

    Redirect::to(&format!("/hosts/{host_id}?flash=revoked")).into_response()
}

/// Downloads a sample request's content. Plain `<a href>` from the host
/// detail page works without any JS: the browser attaches the same
/// cached Basic Auth credential to this `GET` that it attaches to every
/// other request on this origin.
pub async fn download_sample(
    State(state): State<AppState>,
    Path((host_id, request_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response {
    if let Some(challenge) = authenticate_operator_ui(&state.operator_secret, &headers) {
        return challenge;
    }

    match fetch_content_by_request(&state.pool, host_id, request_id).await {
        Ok(Some((sha256, content))) => sample_content_response(&sha256, content).into_response(),
        Ok(None) => not_found_page("No content available for this sample request."),
        Err(e) => db_error_page(e),
    }
}

fn db_error_page(e: sqlx::Error) -> Response {
    tracing::error!("db error: {e:#}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

fn not_found_page(message: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        layout("Not found", html! { h1 { "Not found" } p { (message) } }),
    )
        .into_response()
}

fn format_time(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn format_optional_time(t: Option<chrono::DateTime<chrono::Utc>>) -> String {
    t.map(format_time).unwrap_or_else(|| "never".to_string())
}

fn format_size(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Sha256 values are 64 hex characters -- too wide for a table cell to
/// stay legible. Shown truncated with an ellipsis; the full value is
/// still in the page's HTML source (in the download link's `href` and, on
/// the sightings table, nowhere else), never actually hidden from the
/// operator, just not spelled out in every row.
fn short_hash(sha256: &str) -> String {
    format!("{}\u{2026}", &sha256[..12.min(sha256.len())])
}

/// Shared page chrome. No external stylesheet or script -- everything is
/// inlined so the console remains a single deployable binary with no
/// static-asset directory to serve or ship. Returns `Html<String>`
/// directly (not bare `Markup`) so call sites can hand it straight to
/// axum's response machinery without a separate render-to-string step --
/// `maud`'s own `axum` integration feature is deliberately not used here,
/// since it pulls in a second, incompatible `axum-core` version via a
/// newer axum than this workspace's.
fn layout(title: &str, body: Markup) -> Html<String> {
    Html(
        html! {
            (DOCTYPE)
            html {
                head {
                    meta charset="utf-8";
                    title { (title) " -- NSIC Fleet Console" }
                    style { (PreEscaped(STYLE)) }
                }
                body {
                    (body)
                }
            }
        }
        .into_string(),
    )
}

const STYLE: &str = r#"
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; color: #1a1a1a; }
h1 { margin-bottom: 0.25rem; }
h2 { margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: 0.25rem; }
table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }
th { color: #555; font-weight: 600; }
code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85em; }
p.meta, span.meta { color: #666; font-size: 0.9rem; }
p.warning { color: #a15c00; }
.banner { background: #eef6ff; border: 1px solid #b6d9ff; padding: 0.75rem 1rem; border-radius: 4px; margin: 1rem 0; }
.banner-warning { background: #fff8e5; border-color: #f0d78c; }
section { margin-bottom: 1.5rem; }
form { display: inline-block; margin: 0.5rem 1rem 0.5rem 0; vertical-align: top; }
label { display: block; font-size: 0.85rem; color: #444; margin-bottom: 0.5rem; }
input[type=text] { padding: 0.3rem; width: 20rem; max-width: 100%; margin-top: 0.15rem; }
button { padding: 0.4rem 0.9rem; cursor: pointer; }
button.danger { background: #fdeaea; border-color: #e5a3a3; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }
.badge-pending { background: #eee; color: #555; }
.badge-ok { background: #e3f6e3; color: #1b6e1b; }
.badge-warn { background: #fff2d9; color: #8a5a00; }
.badge-err { background: #fbe3e3; color: #9c1f1f; }
"#;

#[cfg(test)]
mod tests {
    use crate::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::Engine as _;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    const BOOTSTRAP_SECRET: &str = "test-bootstrap-secret";
    const OPERATOR_SECRET: &str = "test-operator-secret";

    async fn test_state() -> AppState {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = nsic_core::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");
        AppState {
            pool,
            bootstrap_secret: BOOTSTRAP_SECRET.to_string(),
            operator_secret: OPERATOR_SECRET.to_string(),
        }
    }

    fn basic_auth_header(secret: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!(":{secret}"))
        )
    }

    async fn enroll_named(app: &axum::Router, hostname: &str) -> nsic_core::proto::EnrollResponse {
        let body = serde_json::json!({
            "hostname": hostname,
            "os": "linux",
            "agent_version": "0.1.0-test",
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/enroll")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {BOOTSTRAP_SECRET}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn enroll(app: &axum::Router) -> nsic_core::proto::EnrollResponse {
        enroll_named(app, "test-host").await
    }

    fn get(uri: String, basic: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(secret) = basic {
            builder = builder.header("authorization", basic_auth_header(secret));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn post_form(uri: String, basic: Option<&str>, form_body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(secret) = basic {
            builder = builder.header("authorization", basic_auth_header(secret));
        }
        builder.body(Body::from(form_body.to_string())).unwrap()
    }

    async fn heartbeat_status(app: &axum::Router, host_id: Uuid, credential: &str) -> StatusCode {
        let body = serde_json::json!({ "agent_version": "0.1.0-test" });
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/agents/{host_id}/heartbeat"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {credential}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    async fn body_string(response: axum::response::Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Extracts the text between the first occurrence of `open` and the
    /// following occurrence of `close` after it -- used to pull the
    /// freshly rotated credential out of the rendered HTML without
    /// depending on maud's exact whitespace output.
    fn extract_between<'a>(haystack: &'a str, open: &str, close: &str) -> &'a str {
        let start = haystack.find(open).expect("open marker present") + open.len();
        let rest = &haystack[start..];
        let end = rest.find(close).expect("close marker present");
        &rest[..end]
    }

    #[tokio::test]
    #[ignore]
    async fn host_directory_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);
        let response = app.oneshot(get("/hosts".to_string(), None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("www-authenticate").is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn host_directory_rejects_wrong_credential() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(get("/hosts".to_string(), Some("not-the-secret")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn host_directory_lists_enrolled_hosts() {
        let app = crate::build_router(test_state().await);
        enroll_named(&app, "fleet-directory-host").await;

        let response = app
            .clone()
            .oneshot(get("/hosts".to_string(), Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("fleet-directory-host"));

        // "/" is the same page as "/hosts".
        let response = app
            .oneshot(get("/".to_string(), Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("fleet-directory-host"));
    }

    /// A hostname is agent-supplied and never validated against a
    /// character allowlist (see `host::enroll`) -- if it ever lands in
    /// this page unescaped, a malicious or compromised agent could inject
    /// markup or script into an operator's browser session. Confirms the
    /// raw tag never appears in the response and the escaped form does.
    #[tokio::test]
    #[ignore]
    async fn host_directory_escapes_a_hostile_hostname() {
        let app = crate::build_router(test_state().await);
        enroll_named(&app, "<script>alert(1)</script>").await;

        let response = app
            .oneshot(get("/hosts".to_string(), Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(!body.contains("<script>alert"));
        assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[tokio::test]
    #[ignore]
    async fn host_detail_returns_404_for_unknown_host() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(get(
                format!("/hosts/{}", Uuid::new_v4()),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore]
    async fn host_detail_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(get(format!("/hosts/{}", enrolled.host_id), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn host_detail_shows_host_metadata() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(get(
                format!("/hosts/{}", enrolled.host_id),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("test-host"));
        assert!(body.contains(&enrolled.host_id.to_string()));
    }

    /// `detection_name` and `path` are agent-supplied and, unlike sha256,
    /// never validated against a character allowlist (see
    /// `sighting::validate_sighting_request`) -- if either lands in this
    /// page unescaped, a malicious or compromised agent's own sighting
    /// report could inject markup or script into an operator's browser
    /// session merely by having it displayed. Confirms the raw tag never
    /// appears and the escaped form does.
    #[tokio::test]
    #[ignore]
    async fn host_detail_escapes_hostile_sighting_fields() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let sighting = serde_json::json!({
            "sha256": format!("{:0<64}", "a"),
            "detection_name": "<img src=x onerror=alert(1)>",
            "ruleset_fingerprint": format!("{:0<64}", "f"),
            "path": "<script>document.cookie</script>",
            "observed_at": chrono::Utc::now().to_rfc3339(),
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/agents/{}/sightings", enrolled.host_id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", enrolled.credential))
                    .body(Body::from(sighting.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(get(
                format!("/hosts/{}", enrolled.host_id),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(!body.contains("<img src=x onerror"));
        assert!(!body.contains("<script>document.cookie"));
        assert!(body.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(body.contains("&lt;script&gt;document.cookie&lt;/script&gt;"));
    }

    #[tokio::test]
    #[ignore]
    async fn create_sample_request_action_creates_pending_request_and_redirects() {
        let state = test_state().await;
        let pool = state.pool.clone();
        let app = crate::build_router(state);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(post_form(
                format!("/hosts/{}/sample-requests", enrolled.host_id),
                Some(OPERATOR_SECRET),
                "path=%2Ftmp%2Fmalware.exe&expected_sha256=",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            &format!("/hosts/{}?flash=sample_requested", enrolled.host_id)
        );

        let row: (String, Option<String>, String) = sqlx::query_as(
            "SELECT path, expected_sha256, status FROM sample_request WHERE host_id = $1",
        )
        .bind(enrolled.host_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "/tmp/malware.exe");
        assert_eq!(row.1, None);
        assert_eq!(row.2, "pending");
    }

    #[tokio::test]
    #[ignore]
    async fn create_sample_request_action_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(post_form(
                format!("/hosts/{}/sample-requests", enrolled.host_id),
                None,
                "path=%2Ftmp%2Fx&expected_sha256=",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Full happy path: rotating from the UI hands back a working
    /// credential in the response body, marks the response uncacheable,
    /// and the old credential -- which worked a moment earlier -- no
    /// longer authenticates a heartbeat.
    #[tokio::test]
    #[ignore]
    async fn rotate_credential_action_shows_new_credential_and_locks_out_the_old_one() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(post_form(
                format!("/hosts/{}/credential/rotate", enrolled.host_id),
                Some(OPERATOR_SECRET),
                "",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let body = body_string(response).await;
        // The page's first <code> tag is the host id, not the credential
        // -- slice off everything up to the "shown once" banner text
        // first, so this extracts the credential's <code> tag specifically.
        let after_banner = &body[body.find("copy it now").unwrap()..];
        let new_credential = extract_between(after_banner, "<code>", "</code>").to_string();
        assert_ne!(new_credential, enrolled.credential);
        assert_eq!(
            new_credential.len(),
            64,
            "credential is 32 hex-encoded bytes"
        );

        assert_eq!(
            heartbeat_status(&app, enrolled.host_id, &enrolled.credential).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            heartbeat_status(&app, enrolled.host_id, &new_credential).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    #[ignore]
    async fn rotate_credential_action_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(post_form(
                format!("/hosts/{}/credential/rotate", enrolled.host_id),
                None,
                "",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn revoke_credential_action_redirects_and_locks_out_the_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(post_form(
                format!("/hosts/{}/credential/revoke", enrolled.host_id),
                Some(OPERATOR_SECRET),
                "",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            &format!("/hosts/{}?flash=revoked", enrolled.host_id)
        );

        assert_eq!(
            heartbeat_status(&app, enrolled.host_id, &enrolled.credential).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    #[ignore]
    async fn download_sample_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(get(
                format!(
                    "/hosts/{}/sample-requests/{}/content",
                    enrolled.host_id,
                    Uuid::new_v4()
                ),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn download_sample_returns_404_for_pending_request() {
        let state = test_state().await;
        let pool = state.pool.clone();
        let app = crate::build_router(state);
        let enrolled = enroll(&app).await;

        let request_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sample_request (host_id, path) VALUES ($1, '/tmp/x') RETURNING id",
        )
        .bind(enrolled.host_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let response = app
            .oneshot(get(
                format!(
                    "/hosts/{}/sample-requests/{request_id}/content",
                    enrolled.host_id
                ),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Full happy path: create a sample request through the UI form,
    /// fulfill it via the real agent-facing JSON endpoint (as
    /// `nsic-agent fulfill-samples` would), then download it back through
    /// the UI's own download link and confirm the bytes match exactly.
    #[tokio::test]
    #[ignore]
    async fn download_sample_returns_content_for_a_fulfilled_request() {
        let state = test_state().await;
        let pool = state.pool.clone();
        let app = crate::build_router(state);
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(post_form(
                format!("/hosts/{}/sample-requests", enrolled.host_id),
                Some(OPERATOR_SECRET),
                "path=%2Ftmp%2Fmalware.exe&expected_sha256=",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let request_id: Uuid =
            sqlx::query_scalar("SELECT id FROM sample_request WHERE host_id = $1")
                .bind(enrolled.host_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        let content = b"the actual malware bytes".to_vec();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/api/v1/agents/{}/sample-requests/{request_id}/content",
                        enrolled.host_id
                    ))
                    .header("content-type", "application/octet-stream")
                    .header("authorization", format!("Bearer {}", enrolled.credential))
                    .body(Body::from(content.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(get(
                format!(
                    "/hosts/{}/sample-requests/{request_id}/content",
                    enrolled.host_id
                ),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.to_vec(), content);
    }
}
