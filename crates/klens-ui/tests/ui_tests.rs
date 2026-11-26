//! Phase 5B mandatory security, API–UI parity, read-only zero-write, UTF-8 Turkish picker,
//! fail-closed input validation, and graceful shutdown integration tests for `klens-ui`.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use klens_core::telemetry::{MetricEvent, append_metric_event};
use klens_core::{GlobalConfig, ProjectRoot};
use klens_exec::{NewRunRecord, RunStore};
use klens_ui::assets::{
    ALL_I18N_BUNDLES, APP_JS, INDEX_HTML, STYLE_CSS, VIEWS_BOARD_JS, VIEWS_VAULT_JS,
};
use klens_ui::{UiConfig, UiServer};
use serde_json::{Value, json};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "klens-ui-test-{label}-{}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, rel: &str, content: &str) -> PathBuf {
        let full = self.path.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full, content).unwrap();
        full
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TestServer {
    port: u16,
    token: String,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(config: UiConfig) -> Self {
        let server = UiServer::bind(config).expect("bind test UI server");
        let port = server.bound_port();
        let token = server.session_token().to_string();
        let shutdown = server.shutdown_flag();
        let handle = thread::spawn(move || {
            let _ = server.serve_until_shutdown();
        });
        Self {
            port,
            token,
            shutdown,
            handle: Some(handle),
        }
    }

    fn join(mut self) {
        if let Some(h) = self.handle.take() {
            h.join().expect("server thread exited cleanly");
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct RawHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl RawHttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("invalid JSON body ({e}): {}", self.body))
    }
}

fn send_http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> RawHttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect loopback");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let payload = body.unwrap_or("");
    let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    let has_host = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Host"));
    if !has_host {
        req.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !payload.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
        {
            req.push_str("Content-Type: application/json\r\n");
        }
    }
    req.push_str("\r\n");
    req.push_str(payload);

    stream.write_all(req.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body_part) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut parsed_headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            parsed_headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    RawHttpResponse {
        status,
        headers: parsed_headers,
        body: body_part.to_string(),
    }
}

fn percent_encode_utf8(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn snapshot_tree(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                out.push(p.clone());
                if p.is_dir() {
                    walk(&p, out);
                }
            }
        }
    }
    walk(root, &mut out);
    out.sort();
    out
}

/// Mandatory Gate 1: Triple Security Gate (DNS rebinding Host guard + Session Cookie + Triple CSRF).
#[test]
fn triple_security_gate_blocks_dns_rebinding_missing_cookie_header_and_foreign_origin() {
    let tmp = TempDir::new("security");
    let proj = tmp.path.join("project");
    fs::create_dir_all(&proj).unwrap();
    tmp.write("project/src/lib.rs", "pub fn alpha() -> i32 { 1 }\n");

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: Some(proj),
        read_only: false,
        no_open: true,
        home_dir: Some(tmp.path.join("home")),
        ..UiConfig::default()
    });

    // 1. Foreign Host -> 403 (DNS rebinding guard)
    let r = send_http(srv.port, "GET", "/", &[("Host", "evil.com")], None);
    assert_eq!(r.status, 403, "foreign Host must return 403");

    let r_bad_port = send_http(
        srv.port,
        "GET",
        "/api/status",
        &[("Host", "127.0.0.1:9999")],
        None,
    );
    assert_eq!(r_bad_port.status, 403, "wrong Host port must return 403");

    // 2. Wrong bootstrap token -> 401; Valid token -> 302 with HttpOnly; SameSite=Strict; Path=/
    let r_bad_tok = send_http(srv.port, "GET", "/?token=deadbeef", &[], None);
    assert_eq!(r_bad_tok.status, 401);

    let r_boot = send_http(
        srv.port,
        "GET",
        &format!("/?token={}", srv.token),
        &[],
        None,
    );
    assert_eq!(r_boot.status, 302);
    assert_eq!(r_boot.header("Location"), Some("/"));
    let set_cookie = r_boot
        .header("Set-Cookie")
        .expect("Set-Cookie must be present");
    assert!(set_cookie.contains(&format!("klens_session={}", srv.token)));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Path=/"));

    // 3. Unauthenticated GET /api/status -> 401
    let r_unauth = send_http(srv.port, "GET", "/api/status", &[], None);
    assert_eq!(r_unauth.status, 401);

    let origin = format!("http://127.0.0.1:{}", srv.port);
    let cookie = format!("klens_session={}", srv.token);
    let note_body = r#"{"title":"Guard Test","kind":"decision","body":"hello"}"#;

    // 4a. POST /api/memory without Origin -> 403
    let r_no_origin = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &[("Cookie", &cookie), ("X-Klens-Request", "1")],
        Some(note_body),
    );
    assert_eq!(r_no_origin.status, 403);

    // 4b. POST /api/memory with foreign Origin -> 403
    let r_bad_origin = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &[
            ("Origin", "https://evil.example"),
            ("Cookie", &cookie),
            ("X-Klens-Request", "1"),
        ],
        Some(note_body),
    );
    assert_eq!(r_bad_origin.status, 403);

    // 4c. POST /api/memory without X-Klens-Request -> 403
    let r_no_hdr = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &[("Origin", &origin), ("Cookie", &cookie)],
        Some(note_body),
    );
    assert_eq!(r_no_hdr.status, 403);

    // 4d. POST /api/memory without session cookie -> 401
    let r_no_cookie = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &[("Origin", &origin), ("X-Klens-Request", "1")],
        Some(note_body),
    );
    assert_eq!(r_no_cookie.status, 401);

    // 4e. POST /api/shutdown without cookie or header or with foreign Origin -> 401/403
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/shutdown",
            &[
                ("Origin", "https://evil.example"),
                ("Cookie", &cookie),
                ("X-Klens-Request", "1")
            ],
            Some("{}")
        )
        .status,
        403
    );
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/shutdown",
            &[("Origin", &origin), ("Cookie", &cookie)],
            Some("{}")
        )
        .status,
        403
    );
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/shutdown",
            &[("Origin", &origin), ("X-Klens-Request", "1")],
            Some("{}")
        )
        .status,
        401
    );

    // 5. Full valid triple CSRF gate succeeds!
    let r_ok = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &[
            ("Origin", &origin),
            ("Cookie", &cookie),
            ("X-Klens-Request", "1"),
        ],
        Some(note_body),
    );
    assert_eq!(
        r_ok.status, 201,
        "valid triple-gated POST must succeed: {}",
        r_ok.body
    );
}

/// Mandatory Gate 2: API–UI Field Parity & zero hardcoded fake percentages / zero CDN.
#[test]
fn api_ui_field_parity_and_offline_asset_integrity() {
    let tmp = TempDir::new("parity");
    let home = tmp.path.join("home");
    let metrics_file = home.join(".klens").join("metrics.jsonl");
    let claude_dir = home.join(".claude").join("projects");

    append_metric_event(
        &metrics_file,
        &MetricEvent::new(
            "2026-11-23T12:00:00Z",
            "proj-abc",
            Some("ParityApp".into()),
            "antigravity",
            "1.0",
            "klens_read",
            2400,
            400,
            false,
        ),
    )
    .unwrap();

    let session_line = json!({
        "type": "assistant",
        "timestamp": "2026-11-23T12:05:00Z",
        "sessionId": "sess-parity-1",
        "message": {
            "model": "claude-sonnet-4",
            "usage": { "input_tokens": 5000, "output_tokens": 600 },
            "content": [
                { "type": "tool_use", "id": "k1", "name": "mcp__klens__klens_map", "input": {} }
            ]
        }
    });
    tmp.write(
        "home/.claude/projects/ParityApp/sess-parity-1.jsonl",
        &format!("{session_line}\n"),
    );

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: None,
        read_only: false,
        no_open: true,
        home_dir: Some(home),
        metrics_path: Some(metrics_file),
        claude_projects_dir: Some(claude_dir),
        ..UiConfig::default()
    });

    let cookie = format!("klens_session={}", srv.token);
    let resp = send_http(
        srv.port,
        "GET",
        "/api/stats?range=all",
        &[("Cookie", &cookie)],
        None,
    );
    assert_eq!(resp.status, 200);
    let stats = resp.json();
    assert_eq!(stats["host_logs_connected"], json!(true));

    // Verify EVERY JSON field emitted by `/api/stats` is handled in `assets/app.js`.
    let mut keys_to_verify = Vec::new();
    for k in stats.as_object().unwrap().keys() {
        keys_to_verify.push(k.clone());
    }
    for k in stats["klens_metrics"].as_object().unwrap().keys() {
        keys_to_verify.push(k.clone());
    }
    for k in stats["host_totals"].as_object().unwrap().keys() {
        keys_to_verify.push(k.clone());
    }
    for k in stats["by_model"][0].as_object().unwrap().keys() {
        keys_to_verify.push(k.clone());
    }
    for k in stats["recent_sessions"][0].as_object().unwrap().keys() {
        keys_to_verify.push(k.clone());
    }

    let combined_js = format!("{APP_JS}\n{VIEWS_BOARD_JS}\n{VIEWS_VAULT_JS}");
    for field in keys_to_verify {
        assert!(
            combined_js.contains(&field),
            "API-UI parity violation: `/api/stats` field `{field}` is not handled in embedded JS assets"
        );
    }

    // Regression locks for ImpactHit, ConfiguredAccessEntry, ObservedClientAccess,
    // Blueprint active-input polling guard, and host Connect/Disconnect actions.
    assert!(VIEWS_BOARD_JS.contains("h.path"));
    assert!(
        !VIEWS_BOARD_JS.contains("source_path"),
        "views_board.js must use ImpactHit.path, never nonexistent source_path"
    );
    assert!(VIEWS_BOARD_JS.contains("document.activeElement"));
    assert!(APP_JS.contains("o.tool_calls"));
    assert!(
        !APP_JS.contains("call_count"),
        "app.js must use ObservedClientAccess.tool_calls, never nonexistent call_count"
    );
    assert!(APP_JS.contains("binary_matches_current"));
    assert!(APP_JS.contains("scope_label"));
    assert!(
        !APP_JS.contains("c.installed"),
        "app.js must use ConfiguredAccessEntry.binary_matches_current, never nonexistent c.installed"
    );
    assert!(APP_JS.contains("/api/agents/init"));
    assert!(APP_JS.contains("/api/agents/disconnect"));

    // Zero hardcoded fake savings percentages in UI assets.
    for (name, content) in [
        ("index.html", INDEX_HTML),
        ("app.js", APP_JS),
        ("views_board.js", VIEWS_BOARD_JS),
        ("views_vault.js", VIEWS_VAULT_JS),
        ("style.css", STYLE_CSS),
    ] {
        assert!(
            !content.contains("81%") && !content.contains("%81"),
            "hardcoded fake savings percentage found in {name}"
        );
        assert!(
            !content.contains("https://") && !content.contains("http://"),
            "external CDN URL found in offline embedded asset {name}"
        );
    }

    // Responsive KPI grid rule (never fixed 4-column).
    assert!(STYLE_CSS.contains("repeat(auto-fit, minmax(190px, 1fr))"));
    assert!(!STYLE_CSS.contains("repeat(4, 1fr)"));

    // All 6 embedded i18n bundles must be valid JSON objects.
    assert_eq!(ALL_I18N_BUNDLES.len(), 6);
    for (code, raw) in ALL_I18N_BUNDLES {
        let parsed: Value = serde_json::from_str(raw)
            .unwrap_or_else(|e| panic!("invalid JSON in i18n/{code}.json: {e}"));
        assert!(parsed.is_object(), "i18n/{code}.json must be a JSON object");
        assert!(!raw.contains("81%") && !raw.contains("%81"));
    }
}

/// Mandatory Gate 3: Project Switching + `--read-only` Zero Writes + Path Confinement.
#[test]
fn project_switching_readonly_zero_writes_and_path_confinement() {
    let tmp = TempDir::new("readonly");
    let proj_a = tmp.path.join("proj_a");
    let proj_b = tmp.path.join("proj_b");
    let home = tmp.path.join("home");
    let ro_cache = tmp.path.join("ro_cache");

    tmp.write("proj_a/src/lib.rs", "pub fn a() -> i32 { 1 }\n");
    tmp.write("proj_b/src/lib.rs", "pub fn b() -> i32 { 2 }\n");
    tmp.write("proj_b/.env", "API_KEY=super-secret-value\n");
    tmp.write("outside.txt", "do not read me\n");

    let before_b = snapshot_tree(&proj_b);

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: Some(proj_a),
        read_only: true,
        no_open: true,
        home_dir: Some(home),
        readonly_cache_dir: Some(ro_cache),
        ..UiConfig::default()
    });

    let origin = format!("http://127.0.0.1:{}", srv.port);
    let cookie = format!("klens_session={}", srv.token);
    let write_hdrs = [
        ("Origin", origin.as_str()),
        ("Cookie", cookie.as_str()),
        ("X-Klens-Request", "1"),
    ];

    // Attempting to bypass `--read-only` via API MUST fail closed with 403.
    let bypass_attempt = send_http(
        srv.port,
        "POST",
        "/api/projects/select",
        &write_hdrs,
        Some(&json!({ "path": proj_b.to_string_lossy(), "read_only": false }).to_string()),
    );
    assert_eq!(bypass_attempt.status, 403);

    // Switching to proj_b while preserving read-only succeeds.
    let switch = send_http(
        srv.port,
        "POST",
        "/api/projects/select",
        &write_hdrs,
        Some(&json!({ "path": proj_b.to_string_lossy() }).to_string()),
    );
    assert_eq!(switch.status, 200);
    assert_eq!(switch.json()["read_only"], json!(true));

    // A2 (v0.3.2+): a drive/filesystem root can never be opened as a project (4xx, not 500),
    // and the previously active project stays selected.
    let mut fs_root = tmp.path.clone();
    while let Some(parent) = fs_root.parent() {
        fs_root = parent.to_path_buf();
    }
    let unsafe_select = send_http(
        srv.port,
        "POST",
        "/api/projects/select",
        &write_hdrs,
        Some(&json!({ "path": fs_root.to_string_lossy() }).to_string()),
    );
    assert_eq!(unsafe_select.status, 400);
    assert_eq!(unsafe_select.json()["error"], json!("unsafe_project_root"));
    let status_after = send_http(srv.port, "GET", "/api/status", &[("Cookie", &cookie)], None);
    assert!(
        status_after.json()["active_project"]["path"]
            .as_str()
            .unwrap_or_default()
            .ends_with("proj_b"),
        "active project must remain proj_b after a refused selection"
    );

    // Exercise read-only analysis endpoints on proj_b.
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/code/graph",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        200
    );
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/code/health",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        200
    );
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/code/outline?path=src/lib.rs",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        200
    );
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/handoff?budget=500",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        200
    );
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/agents/doctor",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        200
    );

    // Write endpoints MUST be rejected with 403 in `--read-only` mode.
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/memory",
            &write_hdrs,
            Some(r#"{"title":"No Write","kind":"decision","body":"blocked"}"#)
        )
        .status,
        403
    );
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/projects/attach",
            &write_hdrs,
            Some(r#"{"dry_run":false}"#)
        )
        .status,
        403
    );

    // Path confinement: escaping project root and reading `.env` MUST be blocked.
    let escape_resp = send_http(
        srv.port,
        "GET",
        "/api/code/outline?path=../outside.txt",
        &[("Cookie", &cookie)],
        None,
    );
    assert!(
        escape_resp.status == 400 || escape_resp.status == 403,
        "path escape must be rejected, got {}",
        escape_resp.status
    );

    let env_resp = send_http(
        srv.port,
        "GET",
        "/api/code/outline?path=.env",
        &[("Cookie", &cookie)],
        None,
    );
    assert_eq!(env_resp.status, 403, "sensitive .env file must return 403");

    // Zero writes invariant: `proj_b` directory tree is 100% identical (zero `.klens/` created).
    let after_b = snapshot_tree(&proj_b);
    assert_eq!(
        before_b, after_b,
        "`--read-only` mode must not write a single file into the target project"
    );
    assert!(!proj_b.join(".klens").exists());
}

/// UTF-8 Turkish folder picker + fail-closed query/JSON validation + `ui_lang` persistence + `POST /api/shutdown`.
#[test]
fn utf8_turkish_folder_picker_fail_closed_validation_and_graceful_shutdown() {
    let tmp = TempDir::new("utf8-shutdown");
    let home = tmp.path.join("home");
    let turkish_parent = tmp.path.join("Projeler");
    let turkish_child = turkish_parent.join("Çalışma_ğüşiöç_İÖÜ");
    fs::create_dir_all(&turkish_child).unwrap();
    fs::write(
        turkish_child.join("Cargo.toml"),
        "[package]\nname = \"tr\"\n",
    )
    .unwrap();
    fs::write(turkish_parent.join("secret.txt"), "SHOULD_NEVER_BE_LISTED").unwrap();

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: Some(turkish_child.clone()),
        read_only: false,
        no_open: true,
        home_dir: Some(home.clone()),
        ..UiConfig::default()
    });

    let origin = format!("http://127.0.0.1:{}", srv.port);
    let cookie = format!("klens_session={}", srv.token);
    let write_hdrs = [
        ("Origin", origin.as_str()),
        ("Cookie", cookie.as_str()),
        ("X-Klens-Request", "1"),
    ];

    // 1. UTF-8 Turkish folder picker (returns directories only, never file names or contents).
    let encoded_parent = percent_encode_utf8(&turkish_parent.to_string_lossy());
    let dirs_resp = send_http(
        srv.port,
        "GET",
        &format!("/api/fs/dirs?path={encoded_parent}"),
        &[("Cookie", &cookie)],
        None,
    );
    assert_eq!(
        dirs_resp.status, 200,
        "UTF-8 Turkish path failed: {}",
        dirs_resp.body
    );
    let dirs_json = dirs_resp.json();
    let dirs_arr = dirs_json["dirs"].as_array().unwrap();
    assert_eq!(dirs_arr.len(), 1);
    assert_eq!(dirs_arr[0]["name"], json!("Çalışma_ğüşiöç_İÖÜ"));
    assert_eq!(dirs_arr[0]["has_project_markers"], json!(true));
    assert!(!dirs_resp.body.contains("secret.txt"));
    assert!(!dirs_resp.body.contains("SHOULD_NEVER_BE_LISTED"));

    // Roots/drives query (no path param) succeeds cleanly.
    let roots_resp = send_http(
        srv.port,
        "GET",
        "/api/fs/dirs",
        &[("Cookie", &cookie)],
        None,
    );
    assert_eq!(roots_resp.status, 200);
    assert!(!roots_resp.json()["dirs"].as_array().unwrap().is_empty());

    // 2. Fail-closed query & JSON validation -> 400 Bad Request (never silent fallback).
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/stats?range=bogus",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        400
    );
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/stats?scope=invalid",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        400
    );
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/handoff?budget=abc",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        400
    );
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/handoff?budget=0",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        400
    );
    assert_eq!(
        send_http(
            srv.port,
            "GET",
            "/api/memory?stale_only=maybe",
            &[("Cookie", &cookie)],
            None
        )
        .status,
        400
    );
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/projects/select",
            &write_hdrs,
            Some(r#"{"path":123,"read_only":"yes"}"#)
        )
        .status,
        400
    );
    assert_eq!(
        send_http(
            srv.port,
            "PUT",
            "/api/settings/lang",
            &write_hdrs,
            Some(r#"{"ui_lang":"xx"}"#)
        )
        .status,
        400
    );

    // 3. Valid `PUT /api/settings/lang` persists `ui_lang` into `~/.klens/config.toml`.
    let lang_resp = send_http(
        srv.port,
        "PUT",
        "/api/settings/lang",
        &write_hdrs,
        Some(r#"{"ui_lang":"tr"}"#),
    );
    assert_eq!(lang_resp.status, 200);
    let saved_global = GlobalConfig::load(&home.join(".klens").join("config.toml")).unwrap();
    assert_eq!(saved_global.ui_lang, "tr");

    // 4. Graceful shutdown via triple-gated `POST /api/shutdown`.
    let shut = send_http(srv.port, "POST", "/api/shutdown", &write_hdrs, Some("{}"));
    assert_eq!(shut.status, 200);
    assert_eq!(shut.json()["status"], json!("shutting_down"));
    srv.join();
}

/// End-to-end HTTP CRUD for Blueprint (propose -> select -> lock -> complete) and Memory (add -> STALE -> refresh -> delete).
#[test]
fn end_to_end_blueprint_and_memory_crud_via_http() {
    let tmp = TempDir::new("e2e-crud");
    let proj = tmp.path.join("app");
    let home = tmp.path.join("home");
    let src_file = tmp.write("app/src/main.rs", "fn main() {\n    let x = 1;\n}\n");

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: Some(proj.clone()),
        read_only: false,
        no_open: true,
        home_dir: Some(home),
        ..UiConfig::default()
    });

    let origin = format!("http://127.0.0.1:{}", srv.port);
    let cookie = format!("klens_session={}", srv.token);
    let read_hdrs = [("Cookie", cookie.as_str())];
    let write_hdrs = [
        ("Origin", origin.as_str()),
        ("Cookie", cookie.as_str()),
        ("X-Klens-Request", "1"),
    ];

    // 1. Memory CRUD + live STALE detection + refresh + delete
    let add_r = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &write_hdrs,
        Some(
            r#"{"title":"Split Main","kind":"feedback","body":"Keep main small","anchors":["src/main.rs"],"tags":["ui"]}"#,
        ),
    );
    assert_eq!(add_r.status, 201, "{}", add_r.body);
    let note_id = add_r.json()["data"]["note"]["frontmatter"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Mutate anchored source file -> note becomes STALE!
    fs::write(&src_file, "fn main() {\n    let x = 42;\n}\n").unwrap();

    let verify_r = send_http(srv.port, "GET", "/api/memory/verify", &read_hdrs, None);
    assert_eq!(verify_r.status, 200);
    assert_eq!(verify_r.json()["data"]["stale_count"], json!(1));

    // Refresh anchors -> note returns to fresh!
    let refresh_r = send_http(
        srv.port,
        "POST",
        &format!("/api/memory/{note_id}/refresh"),
        &write_hdrs,
        Some("{}"),
    );
    assert_eq!(refresh_r.status, 200);
    let verify_after = send_http(srv.port, "GET", "/api/memory/verify", &read_hdrs, None);
    assert_eq!(verify_after.json()["data"]["stale_count"], json!(0));

    // Update & delete
    let upd_r = send_http(
        srv.port,
        "PUT",
        &format!("/api/memory/{note_id}"),
        &write_hdrs,
        Some(r#"{"title":"Split Main Updated","body":"Refined note"}"#),
    );
    assert_eq!(upd_r.status, 200);
    let del_r = send_http(
        srv.port,
        "DELETE",
        &format!("/api/memory/{note_id}"),
        &write_hdrs,
        None,
    );
    assert_eq!(del_r.status, 200);

    // 2. Blueprint propose -> select -> lock -> complete task
    let bp_body = json!({
        "project_name": "DemoApp",
        "goal": "Fast local tool",
        "bubbles": [
            {
                "id": "runtime",
                "category": "Runtime",
                "title": "Runtime choice",
                "plain_explanation": "Choose binary runtime",
                "options": [
                    {
                        "id": "rust",
                        "label": "Rust Native",
                        "pros": "Fast",
                        "cons": "Compile time",
                        "recommended": true,
                        "provides": ["native"],
                        "requires": [],
                        "conflicts_with": []
                    }
                ],
                "selected_option": null,
                "user_vision_note": "",
                "status": "pending",
                "depends_on": []
            }
        ]
    });
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/blueprint/propose",
            &write_hdrs,
            Some(&bp_body.to_string())
        )
        .status,
        200
    );
    // Locking while bubble is pending fails with 409 ConflictsPresent.
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/blueprint/lock",
            &write_hdrs,
            Some("{}")
        )
        .status,
        409
    );
    assert_eq!(
        send_http(
            srv.port,
            "POST",
            "/api/blueprint/select",
            &write_hdrs,
            Some(r#"{"bubble_id":"runtime","option_id":"rust","vision_note":"Single exe","confirm":true}"#)
        )
        .status,
        200
    );
    let lock_r = send_http(
        srv.port,
        "POST",
        "/api/blueprint/lock",
        &write_hdrs,
        Some(r#"{"create_scaffold":false}"#),
    );
    assert_eq!(lock_r.status, 200, "{}", lock_r.body);
    assert!(proj.join(".klens/blueprint/PROJECT_CONTRACT.md").is_file());
    assert!(proj.join(".klens/blueprint/tasks.jsonl").is_file());
}

/// Regression lock: symbol-anchored (`path#symbol`) memory notes match file nodes & `stale_files`
/// in `GET /api/code/graph`, and resolved historical failed runs do NOT leak into `failed_run_files`.
#[test]
fn graph_symbol_anchor_badges_and_resolved_run_not_flagged() {
    let tmp = TempDir::new("graph-reg");
    let proj = tmp.path.join("app");
    let home = tmp.path.join("home");
    let src_file = tmp.write("app/src/lib.rs", "pub fn compute() -> i32 {\n    1\n}\n");

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: Some(proj.clone()),
        read_only: false,
        no_open: true,
        home_dir: Some(home),
        ..UiConfig::default()
    });

    let origin = format!("http://127.0.0.1:{}", srv.port);
    let cookie = format!("klens_session={}", srv.token);
    let read_hdrs = [("Cookie", cookie.as_str())];
    let write_hdrs = [
        ("Origin", origin.as_str()),
        ("Cookie", cookie.as_str()),
        ("X-Klens-Request", "1"),
    ];

    // 1. Add a symbol-anchored memory note (`src/lib.rs#fn compute`).
    let add_r = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &write_hdrs,
        Some(
            r#"{"title":"Compute contract","kind":"decision","body":"Keep deterministic","anchors":["src/lib.rs#fn compute"]}"#,
        ),
    );
    assert_eq!(add_r.status, 201, "{}", add_r.body);

    // Fresh symbol anchor must map to file key `"src/lib.rs"` in `memory_badges`.
    let g1 = send_http(srv.port, "GET", "/api/code/graph", &read_hdrs, None);
    assert_eq!(g1.status, 200, "{}", g1.body);
    let g1_json = g1.json();
    assert_eq!(
        g1_json["memory_badges"]["src/lib.rs"]["total_notes"],
        json!(1)
    );
    assert_eq!(
        g1_json["memory_badges"]["src/lib.rs"]["stale_notes"],
        json!(0)
    );
    assert!(g1_json["stale_files"].as_array().unwrap().is_empty());

    // Mutate symbol body -> `src/lib.rs` must appear in `stale_files` and `stale_notes == 1`.
    fs::write(&src_file, "pub fn compute() -> i32 {\n    99\n}\n").unwrap();
    let g2 = send_http(srv.port, "GET", "/api/code/graph", &read_hdrs, None);
    assert_eq!(g2.status, 200);
    let g2_json = g2.json();
    assert_eq!(
        g2_json["memory_badges"]["src/lib.rs"]["stale_notes"],
        json!(1)
    );
    assert!(
        g2_json["stale_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("src/lib.rs")),
        "symbol-anchored stale note must flag file node `src/lib.rs` in stale_files: {}",
        g2.body
    );

    // 2. Active failed run flags `src/lib.rs`; once the same command passes (`exit 0`), it clears.
    let store = RunStore::new(ProjectRoot::new(&proj).unwrap());
    let fail_log = "error[E0308]: mismatched types\n --> src/lib.rs:2:5\n";
    store
        .save_run_with_id(
            "20261124-010000-aaa1",
            "2026-11-24T01:00:00Z",
            &NewRunRecord {
                command: "cargo test",
                cwd: ".",
                filter_used: "cargo",
                exit_code: 101,
                duration_ms: 120,
                raw_bytes: fail_log.len(),
                filtered_bytes: fail_log.len(),
                est_raw_tokens: 20,
                est_filtered_tokens: 20,
                truncated_errors: false,
                raw_log_content: fail_log,
            },
        )
        .unwrap();

    let g3 = send_http(srv.port, "GET", "/api/code/graph", &read_hdrs, None);
    assert_eq!(g3.status, 200);
    assert_eq!(g3.json()["failed_run_files"], json!(["src/lib.rs"]));

    // Record a newer passing run for the exact same command -> historical failure is resolved!
    let pass_log = "test result: ok. 1 passed; 0 failed;\n";
    store
        .save_run_with_id(
            "20261124-010500-bbb2",
            "2026-11-24T01:05:00Z",
            &NewRunRecord {
                command: "cargo test",
                cwd: ".",
                filter_used: "cargo",
                exit_code: 0,
                duration_ms: 100,
                raw_bytes: pass_log.len(),
                filtered_bytes: pass_log.len(),
                est_raw_tokens: 10,
                est_filtered_tokens: 10,
                truncated_errors: false,
                raw_log_content: pass_log,
            },
        )
        .unwrap();

    let g4 = send_http(srv.port, "GET", "/api/code/graph", &read_hdrs, None);
    assert_eq!(g4.status, 200);
    assert!(
        g4.json()["failed_run_files"].as_array().unwrap().is_empty(),
        "resolved historical failure must NOT leak into failed_run_files: {}",
        g4.body
    );
}

/// Path traversal and sensitive file anchors on `POST /api/memory` must return 400 or 403 (never 500).
#[test]
fn memory_post_path_traversal_and_sensitive_anchor_return_4xx_never_500() {
    let tmp = TempDir::new("mem-traversal");
    let proj = tmp.path.join("app");
    let home = tmp.path.join("home");
    tmp.write("app/src/lib.rs", "pub fn ok() -> bool { true }\n");
    tmp.write("app/.env", "SECRET=do-not-expose\n");
    tmp.write("escape.rs", "pub fn outside() {}\n");

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: Some(proj),
        read_only: false,
        no_open: true,
        home_dir: Some(home),
        ..UiConfig::default()
    });

    let origin = format!("http://127.0.0.1:{}", srv.port);
    let cookie = format!("klens_session={}", srv.token);
    let write_hdrs = [
        ("Origin", origin.as_str()),
        ("Cookie", cookie.as_str()),
        ("X-Klens-Request", "1"),
    ];

    let traversal_resp = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &write_hdrs,
        Some(
            r#"{"title":"Escape Attempt","kind":"decision","body":"bad anchor","anchors":["../escape.rs"]}"#,
        ),
    );
    assert!(
        traversal_resp.status == 400 || traversal_resp.status == 403,
        "POST /api/memory with `../escape.rs` anchor must return 400 or 403 (never 500), got {}: {}",
        traversal_resp.status,
        traversal_resp.body
    );

    let sensitive_resp = send_http(
        srv.port,
        "POST",
        "/api/memory",
        &write_hdrs,
        Some(r#"{"title":"Env Anchor","kind":"decision","body":"sensitive","anchors":[".env"]}"#),
    );
    assert_eq!(
        sensitive_resp.status, 403,
        "POST /api/memory with `.env` anchor must return 403: {}",
        sensitive_resp.body
    );
}

/// Verifies Runs search/filter/side-by-side assets and exact key-set parity across all 6 i18n bundles.
#[test]
fn runs_search_filter_side_by_side_and_i18n_key_parity() {
    use std::collections::BTreeSet;

    // 1. HTML toolbar & status filter controls for Runs subtab.
    for needle in [
        r#"id="runs-status-group""#,
        r#"data-run-status="all""#,
        r#"data-run-status="ok""#,
        r#"data-run-status="failed""#,
        r#"id="runs-search""#,
        r#"type="search""#,
        r#"id="runs-count""#,
    ] {
        assert!(
            INDEX_HTML.contains(needle),
            "INDEX_HTML missing expected Runs control: {needle}"
        );
    }

    // 2. JS Runs logic lives in `views_vault.js` (not `app.js`): limit=200, Promise.all, monotonic seq, side-by-side.
    for needle in [
        "/api/runs?limit=200",
        "Promise.all",
        "runDetailSeq",
        "btn-run-compare",
        "run-compare-grid",
        "runs-compare-active",
        "filtered_bytes",
        "raw_bytes",
        "est_filtered_tokens",
        "est_raw_tokens",
        "btn-run-copy-filtered",
        "btn-run-copy-raw",
    ] {
        assert!(
            VIEWS_VAULT_JS.contains(needle),
            "VIEWS_VAULT_JS missing expected Runs feature: {needle}"
        );
    }

    // 3. CSS side-by-side grid, split expansion, and active row styling.
    for needle in [
        ".runs-compare-active",
        ".run-compare-grid",
        "repeat(auto-fit, minmax(260px, 1fr))",
        ".data-table tbody tr.active",
    ] {
        assert!(
            STYLE_CSS.contains(needle),
            "STYLE_CSS missing expected Runs style rule: {needle}"
        );
    }

    // 4. All 6 i18n bundles must share the exact same key set (zero missing or extra keys).
    assert_eq!(ALL_I18N_BUNDLES.len(), 6);
    let mut parsed_sets: Vec<(&str, BTreeSet<String>)> = Vec::new();
    for (code, raw) in ALL_I18N_BUNDLES {
        let val: Value = serde_json::from_str(raw)
            .unwrap_or_else(|e| panic!("invalid JSON in i18n/{code}.json: {e}"));
        let obj = val
            .as_object()
            .unwrap_or_else(|| panic!("i18n/{code}.json must be a JSON object"));
        let mut keys = BTreeSet::new();
        for (k, v) in obj {
            let s = v
                .as_str()
                .unwrap_or_else(|| panic!("i18n/{code}.json key `{k}` must map to a string"));
            assert!(
                !s.trim().is_empty(),
                "i18n/{code}.json key `{k}` must not be empty"
            );
            assert!(
                !s.contains("81%") && !s.contains("%81"),
                "i18n/{code}.json key `{k}` contains forbidden fake percentage"
            );
            keys.insert(k.clone());
        }
        parsed_sets.push((*code, keys));
    }

    let (base_code, base_keys) = &parsed_sets[0];
    for req_key in [
        "mem.runsFilterAll",
        "mem.runsFilterOk",
        "mem.runsFilterFailed",
        "mem.runsSearchPlaceholder",
        "mem.runsNoMatch",
        "mem.runCompareTab",
        "mem.copyFiltered",
        "mem.copyRaw",
        "mem.runBytesLabel",
        "mem.runTokensUnit",
        "mem.runEmptyOutput",
        "mem.export",
        "mem.exportTitle",
        "mem.exportMarkdown",
        "mem.exportJson",
        "mem.exportStaleOnly",
        "mem.exportCopy",
        "mem.exportDownload",
        "mem.refreshAll",
        "mem.refreshAllTitle",
        "mem.refreshAllStaleOnly",
        "mem.refreshAllPreview",
        "mem.refreshAllApply",
        "mem.refreshAllEmpty",
        "code.fitView",
        "modal.registeredProjects",
        "modal.browseFolders",
        "stats.freshVsCache",
        "shutdown.title",
        "shutdown.body",
        "shutdown.restartHint",
    ] {
        assert!(
            base_keys.contains(req_key),
            "base i18n bundle `{base_code}` missing required key `{req_key}`"
        );
    }

    // 5. Phase 3 Vault Export & Batch Refresh + v0.2.1 UI Polish + v0.3.0 Shutdown Overlay controls.
    for needle in [
        r#"id="btn-mem-export""#,
        r#"id="btn-mem-refresh-all""#,
        r#"id="btn-graph-zoom-out""#,
        r#"id="btn-graph-zoom-reset""#,
        r#"id="btn-graph-zoom-in""#,
        r#"id="btn-graph-fit""#,
        r#"id="shutdown-overlay""#,
        r#"id="shutdown-title""#,
        r#"role="alertdialog""#,
        r#"data-i18n="shutdown.title""#,
        r#"data-i18n="shutdown.body""#,
        r#"data-i18n="shutdown.restartHint""#,
    ] {
        assert!(
            INDEX_HTML.contains(needle),
            "INDEX_HTML missing expected UI control: {needle}"
        );
    }
    for needle in [
        "graph-viewport",
        "data-from",
        "data-to",
        "updateSelectedGraphNode",
        "clipPath",
    ] {
        assert!(
            VIEWS_BOARD_JS.contains(needle),
            "VIEWS_BOARD_JS missing expected interactive map feature: {needle}"
        );
    }
    for needle in [
        "color-scheme: dark;",
        "color-scheme: light;",
        "scrollbar-color:",
        "::-webkit-scrollbar",
        ".graph-edge.edge-dim",
        ".graph-edge.edge-highlight",
        ".shutdown-overlay",
        ".shutdown-card",
    ] {
        assert!(
            STYLE_CSS.contains(needle),
            "STYLE_CSS missing expected theme/graph style: {needle}"
        );
    }
    for needle in ["data-reg-path", "enterShutdownState", "isShutDown"] {
        assert!(
            APP_JS.contains(needle),
            "APP_JS missing expected runtime symbol: {needle}"
        );
    }
    assert!(
        APP_JS.lines().count() <= 800,
        "APP_JS exceeded 800-line cap: {} lines",
        APP_JS.lines().count()
    );
    for needle in [
        "/api/memory/export",
        "/api/memory/refresh-all",
        "openExportMemoryModal",
        "openRefreshAllModal",
    ] {
        assert!(
            VIEWS_VAULT_JS.contains(needle),
            "VIEWS_VAULT_JS missing expected Vault batch feature: {needle}"
        );
    }

    for (code, keys) in &parsed_sets[1..] {
        let missing: Vec<&String> = base_keys.difference(keys).collect();
        let extra: Vec<&String> = keys.difference(base_keys).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "i18n key mismatch between `{base_code}` and `{code}`: missing={missing:?}, extra={extra:?}"
        );
    }
}

/// Phase 3 HTTP API tests: `GET /api/memory/export` (read-only OK) and `POST /api/memory/refresh-all`
/// (403 in read-only, 200 OK in writable transitioning STALE -> VERIFIED_RAW).
#[test]
fn memory_export_readonly_and_batch_refresh_all_http_routes() {
    let tmp = TempDir::new("mem-batch-http");
    let proj = tmp.path.join("app");
    let home = tmp.path.join("home");
    let ro_cache = tmp.path.join("ro-cache");
    let src_a = tmp.write("app/src/a.rs", "pub fn a() -> i32 { 1 }\n");
    let src_b = tmp.write("app/src/b.rs", "pub fn b() -> i32 { 2 }\n");
    let fake_token = format!("ghp_{}", "fedcba9876543210fedcba9876543210fedc");

    // 1. Seed notes in writable mode, then mutate `src/a.rs` and delete `src/b.rs`.
    {
        let srv = TestServer::start(UiConfig {
            port: Some(0),
            initial_root: Some(proj.clone()),
            read_only: false,
            no_open: true,
            home_dir: Some(home.clone()),
            ..UiConfig::default()
        });
        let origin = format!("http://127.0.0.1:{}", srv.port);
        let cookie = format!("klens_session={}", srv.token);
        let write_hdrs = [
            ("Origin", origin.as_str()),
            ("Cookie", cookie.as_str()),
            ("X-Klens-Request", "1"),
        ];

        assert_eq!(
            send_http(
                srv.port,
                "POST",
                "/api/memory",
                &write_hdrs,
                Some(
                    &json!({
                        "id": "adr-a",
                        "title": "Note A",
                        "kind": "decision",
                        "body": format!("Body A with {fake_token}"),
                        "anchors": ["src/a.rs"],
                        "tags": ["core"]
                    })
                    .to_string()
                )
            )
            .status,
            201
        );
        assert_eq!(
            send_http(
                srv.port,
                "POST",
                "/api/memory",
                &write_hdrs,
                Some(
                    &json!({
                        "id": "bug-b",
                        "title": "Note B",
                        "kind": "bugfix",
                        "body": "Body B",
                        "anchors": ["src/b.rs"],
                        "tags": ["ops"]
                    })
                    .to_string()
                )
            )
            .status,
            201
        );
    }

    fs::write(&src_a, "pub fn a() -> i32 { 42 }\n").unwrap();
    fs::remove_file(&src_b).unwrap();

    // 2. Read-only server: `GET /api/memory/export` MUST return 200 OK (0 writes),
    //    while `POST /api/memory/refresh-all` MUST return 403 Forbidden.
    {
        let before_tree = snapshot_tree(&proj);
        let srv_ro = TestServer::start(UiConfig {
            port: Some(0),
            initial_root: Some(proj.clone()),
            read_only: true,
            no_open: true,
            home_dir: Some(home.clone()),
            readonly_cache_dir: Some(ro_cache),
            ..UiConfig::default()
        });
        let origin = format!("http://127.0.0.1:{}", srv_ro.port);
        let cookie = format!("klens_session={}", srv_ro.token);
        let read_hdrs = [("Cookie", cookie.as_str())];
        let write_hdrs = [
            ("Origin", origin.as_str()),
            ("Cookie", cookie.as_str()),
            ("X-Klens-Request", "1"),
        ];

        let exp_md = send_http(
            srv_ro.port,
            "GET",
            "/api/memory/export?format=md",
            &read_hdrs,
            None,
        );
        assert_eq!(exp_md.status, 200, "{}", exp_md.body);
        let exp_md_json = exp_md.json();
        assert_eq!(exp_md_json["format"], json!("markdown"));
        assert_eq!(exp_md_json["filename"], json!("klens-memory-export.md"));
        assert_eq!(exp_md_json["total_notes"], json!(2));
        assert_eq!(exp_md_json["stale_count"], json!(2));
        assert_eq!(exp_md_json["redactions_count"], json!(1));
        assert!(
            !exp_md_json["content"]
                .as_str()
                .unwrap()
                .contains(&fake_token)
        );

        let exp_json = send_http(
            srv_ro.port,
            "GET",
            "/api/memory/export?format=json&kind=decision",
            &read_hdrs,
            None,
        );
        assert_eq!(exp_json.status, 200, "{}", exp_json.body);
        assert_eq!(
            exp_json.json()["filename"],
            json!("klens-memory-export.json")
        );
        assert_eq!(exp_json.json()["total_notes"], json!(1));

        let bad_fmt = send_http(
            srv_ro.port,
            "GET",
            "/api/memory/export?format=xml",
            &read_hdrs,
            None,
        );
        assert_eq!(bad_fmt.status, 400);

        let ro_refresh = send_http(
            srv_ro.port,
            "POST",
            "/api/memory/refresh-all",
            &write_hdrs,
            Some(r#"{"stale_only":true,"dry_run":false}"#),
        );
        assert_eq!(
            ro_refresh.status, 403,
            "read-only server must reject POST /api/memory/refresh-all with 403"
        );

        let after_tree = snapshot_tree(&proj);
        assert_eq!(
            before_tree, after_tree,
            "read-only export must write 0 files"
        );
    }

    // 3. Writable server: `POST /api/memory/refresh-all` dry-run then apply transitions `adr-a` STALE -> fresh
    //    and reports `bug-b` in `failed`.
    {
        let srv = TestServer::start(UiConfig {
            port: Some(0),
            initial_root: Some(proj.clone()),
            read_only: false,
            no_open: true,
            home_dir: Some(home),
            ..UiConfig::default()
        });
        let origin = format!("http://127.0.0.1:{}", srv.port);
        let cookie = format!("klens_session={}", srv.token);
        let read_hdrs = [("Cookie", cookie.as_str())];
        let write_hdrs = [
            ("Origin", origin.as_str()),
            ("Cookie", cookie.as_str()),
            ("X-Klens-Request", "1"),
        ];

        let dry_r = send_http(
            srv.port,
            "POST",
            "/api/memory/refresh-all",
            &write_hdrs,
            Some(r#"{"stale_only":true,"dry_run":true}"#),
        );
        assert_eq!(dry_r.status, 200, "{}", dry_r.body);
        let dry_json = dry_r.json();
        assert_eq!(dry_json["data"]["dry_run"], json!(true));
        assert_eq!(dry_json["data"]["refreshed"].as_array().unwrap().len(), 1);
        assert_eq!(dry_json["data"]["refreshed"][0]["id"], json!("adr-a"));
        assert_eq!(dry_json["data"]["failed"].as_array().unwrap().len(), 1);
        assert_eq!(dry_json["data"]["failed"][0]["id"], json!("bug-b"));

        // Verify `adr-a` is still STALE after dry-run.
        let still_stale = send_http(srv.port, "GET", "/api/memory/adr-a", &read_hdrs, None);
        assert_eq!(still_stale.json()["envelope"]["trust"], json!("STALE"));

        // Apply refresh-all.
        let apply_r = send_http(
            srv.port,
            "POST",
            "/api/memory/refresh-all",
            &write_hdrs,
            Some(r#"{"stale_only":true,"dry_run":false}"#),
        );
        assert_eq!(apply_r.status, 200, "{}", apply_r.body);
        let apply_json = apply_r.json();
        assert_eq!(apply_json["data"]["dry_run"], json!(false));
        assert_eq!(apply_json["data"]["refreshed"][0]["id"], json!("adr-a"));
        assert_eq!(apply_json["data"]["failed"][0]["id"], json!("bug-b"));

        // Verify `adr-a` is now VERIFIED_RAW!
        let now_fresh = send_http(srv.port, "GET", "/api/memory/adr-a", &read_hdrs, None);
        assert_eq!(now_fresh.json()["envelope"]["trust"], json!("VERIFIED_RAW"));
    }
}
