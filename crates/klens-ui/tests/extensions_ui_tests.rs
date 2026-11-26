//! Phase 6 Web UI extension management & security integration tests (`GET /api/extensions`,
//! `POST /api/extensions/toggle`, triple CSRF gate, `read_only` lock, fail-closed validation).

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use klens_core::{GlobalConfig, ProjectConfig};
use klens_ui::assets::{APP_JS, INDEX_HTML};
use klens_ui::{UiConfig, UiServer};
use serde_json::{Value, json};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("klens-ui-ext-{label}-{}-{seq}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
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
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct HttpResp {
    status: u16,
    body: String,
}

impl HttpResp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("invalid JSON ({e}): {}", self.body))
    }
}

fn send_http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> HttpResp {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to UI server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let payload = body.unwrap_or("");
    let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if body.is_some() {
        req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    req.push_str("\r\n");
    req.push_str(payload);

    stream.write_all(req.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let (head, body_part) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    HttpResp {
        status,
        body: body_part.to_string(),
    }
}

#[test]
fn extensions_api_supports_project_and_global_toggle_with_csrf_and_fail_closed_validation() {
    let home = TempDir::new("home");
    let proj = TempDir::new("proj");

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: Some(proj.path.clone()),
        read_only: false,
        no_open: true,
        home_dir: Some(home.path.clone()),
        ..UiConfig::default()
    });

    let host = format!("127.0.0.1:{}", srv.port);
    let origin = format!("http://127.0.0.1:{}", srv.port);
    let cookie = format!("klens_session={}", srv.token);

    // 1. Unauthenticated GET /api/extensions fails closed (401).
    let unauth = send_http(srv.port, "GET", "/api/extensions", &[("Host", &host)], None);
    assert_eq!(unauth.status, 401);

    // 2. Authenticated GET /api/extensions returns all 7 known extensions disabled by default.
    let list = send_http(
        srv.port,
        "GET",
        "/api/extensions",
        &[("Host", &host), ("Cookie", &cookie)],
        None,
    );
    assert_eq!(list.status, 200);
    let list_json = list.json();
    assert_eq!(list_json["schema_version"], 1);
    let exts = list_json["extensions"].as_array().unwrap();
    assert_eq!(exts.len(), 7);
    assert!(exts.iter().all(|e| e["default_enabled"] == false));
    assert!(exts.iter().all(|e| e["effective_enabled"] == false));
    let ctags = exts
        .iter()
        .find(|e| e["id"] == "ext-lang-ctags")
        .expect("ext-lang-ctags must be present in GET /api/extensions");
    assert_eq!(ctags["kind"], "language_parser");
    assert_eq!(ctags["health"], "disabled");

    // 3. Triple CSRF gate blocks missing Origin / missing X-Klens-Request on POST /api/extensions/toggle.
    let no_origin = send_http(
        srv.port,
        "POST",
        "/api/extensions/toggle",
        &[
            ("Host", &host),
            ("Cookie", &cookie),
            ("X-Klens-Request", "1"),
        ],
        Some(r#"{"id":"ext-lsp-bridge","enabled":true,"scope":"project"}"#),
    );
    assert_eq!(no_origin.status, 403);

    let no_custom_hdr = send_http(
        srv.port,
        "POST",
        "/api/extensions/toggle",
        &[("Host", &host), ("Origin", &origin), ("Cookie", &cookie)],
        Some(r#"{"id":"ext-lsp-bridge","enabled":true,"scope":"project"}"#),
    );
    assert_eq!(no_custom_hdr.status, 403);

    let write_headers = [
        ("Host", host.as_str()),
        ("Origin", origin.as_str()),
        ("Cookie", cookie.as_str()),
        ("X-Klens-Request", "1"),
        ("Content-Type", "application/json"),
    ];

    // 4. Fail-closed validation: unknown ID, non-boolean `enabled`, invalid `scope` -> 400.
    for bad_body in [
        json!({"id": "ext-nonexistent", "enabled": true, "scope": "project"}),
        json!({"id": "ext-lsp-bridge", "enabled": "true", "scope": "project"}),
        json!({"id": "ext-lsp-bridge", "scope": "project"}),
        json!({"id": "ext-lsp-bridge", "enabled": true, "scope": "workspace"}),
        json!({"id": "../evil", "enabled": true, "scope": "global"}),
    ] {
        let resp = send_http(
            srv.port,
            "POST",
            "/api/extensions/toggle",
            &write_headers,
            Some(&bad_body.to_string()),
        );
        assert_eq!(
            resp.status, 400,
            "expected 400 for payload {bad_body}, got {} ({})",
            resp.status, resp.body
        );
    }

    // 5. Enable `ext-lsp-bridge` in project scope.
    let enable_proj = send_http(
        srv.port,
        "POST",
        "/api/extensions/toggle",
        &write_headers,
        Some(r#"{"id":"ext-lsp-bridge","enabled":true,"scope":"project"}"#),
    );
    assert_eq!(enable_proj.status, 200);
    let ep_json = enable_proj.json();
    assert_eq!(ep_json["id"], "ext-lsp-bridge");
    assert_eq!(ep_json["scope"], "project");
    assert_eq!(ep_json["enabled"], true);
    assert_eq!(ep_json["changed"], true);

    let proj_cfg = ProjectConfig::load(&proj.path.join(".klens").join("config.toml")).unwrap();
    assert_eq!(proj_cfg.enabled_extensions, vec!["ext-lsp-bridge"]);

    // 6. Enable `ext-live-docs` in global scope.
    let enable_global = send_http(
        srv.port,
        "POST",
        "/api/extensions/toggle",
        &write_headers,
        Some(r#"{"id":"ext-live-docs","enabled":true,"scope":"global"}"#),
    );
    assert_eq!(enable_global.status, 200);
    let global_cfg = GlobalConfig::load(&home.path.join(".klens").join("config.toml")).unwrap();
    assert_eq!(global_cfg.enabled_extensions, vec!["ext-live-docs"]);

    // 7. Re-read GET /api/extensions reflects both toggles deterministically.
    let list2 = send_http(
        srv.port,
        "GET",
        "/api/extensions",
        &[("Host", &host), ("Cookie", &cookie)],
        None,
    )
    .json();
    assert_eq!(list2["project_enabled"], json!(["ext-lsp-bridge"]));
    assert_eq!(list2["global_enabled"], json!(["ext-live-docs"]));

    // 8. Disable `ext-lsp-bridge` in project scope.
    let disable_proj = send_http(
        srv.port,
        "POST",
        "/api/extensions/toggle",
        &write_headers,
        Some(r#"{"id":"ext-lsp-bridge","enabled":false,"scope":"project"}"#),
    );
    assert_eq!(disable_proj.status, 200);
    assert_eq!(disable_proj.json()["enabled_extensions"], json!([]));
}

#[test]
fn extensions_toggle_is_blocked_in_read_only_mode_and_tabs_stay_at_four() {
    let home = TempDir::new("ro-home");
    let proj = TempDir::new("ro-proj");

    let srv = TestServer::start(UiConfig {
        port: Some(0),
        initial_root: Some(proj.path.clone()),
        read_only: true,
        no_open: true,
        home_dir: Some(home.path.clone()),
        ..UiConfig::default()
    });

    let host = format!("127.0.0.1:{}", srv.port);
    let origin = format!("http://127.0.0.1:{}", srv.port);
    let cookie = format!("klens_session={}", srv.token);

    // Read works in read-only mode without creating any `.klens/` files.
    let list = send_http(
        srv.port,
        "GET",
        "/api/extensions",
        &[("Host", &host), ("Cookie", &cookie)],
        None,
    );
    assert_eq!(list.status, 200);
    assert!(!proj.path.join(".klens").exists());

    // Toggle fails closed with 403 in read-only mode (both project and global).
    for scope in ["project", "global"] {
        let resp = send_http(
            srv.port,
            "POST",
            "/api/extensions/toggle",
            &[
                ("Host", &host),
                ("Origin", &origin),
                ("Cookie", &cookie),
                ("X-Klens-Request", "1"),
                ("Content-Type", "application/json"),
            ],
            Some(&format!(
                r#"{{"id":"ext-lsp-bridge","enabled":true,"scope":"{scope}"}}"#
            )),
        );
        assert_eq!(resp.status, 403);
    }
    assert!(!proj.path.join(".klens").exists());
    assert!(!home.path.join(".klens").exists());

    // Main tab bar remains strictly 4 core tabs; Extensions lives inside Settings drawer.
    assert_eq!(INDEX_HTML.matches("class=\"tab-btn").count(), 4);
    assert!(APP_JS.contains("/api/extensions/toggle"));
    assert!(APP_JS.contains("modal.extensionsTitle"));
}
