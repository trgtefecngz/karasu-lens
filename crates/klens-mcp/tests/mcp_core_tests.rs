//! Phase 3A integration & adversarial tests for `klens-mcp`.
//!
//! Covers:
//! 1. MCP tool definition token budget (`<= 850` Phase 3A target, `< 1,200` hard ceiling).
//! 2. Windows CRLF input handling, strict pure-LF (`\n`) output, and per-frame `flush()`.
//! 3. JSON-RPC 2.0 notification silence (no reply to `notifications/initialized` / `notifications/cancelled`)
//!    and exact echoing of integer, string, and `null` IDs.
//! 4. Per-project access policy (`paused`, `read_only`, `allowed_clients`) -> `PROJECT_ACCESS_RESTRICTED`.
//! 5. Functional execution of all 6 Phase 3A tools (`klens_map`, `klens_find`, `klens_outline`,
//!    `klens_read` single + batch + `AMBIGUOUS_SYMBOL`, `klens_impact`, `klens_run`) and Layer 1 metrics logging.

use std::fs;
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::telemetry::{StatsQuery, StatsRange, compute_stats};
use klens_core::{ProjectConfig, ProjectMode, ProjectRoot, estimate_tokens};
use klens_mcp::{MAX_TOOLS_LIST_TOKENS, McpServer, McpServerConfig, PROJECT_ACCESS_RESTRICTED};
use serde_json::{Value, json};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-mcp-test-{label}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, content).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Writer wrapper that counts every `flush()` call so we prove per-message flushing.
struct FlushCountingWriter {
    bytes: Vec<u8>,
    flushes: usize,
}

impl FlushCountingWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            flushes: 0,
        }
    }
}

impl Write for FlushCountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

fn make_sample_project(label: &str) -> (Sandbox, Sandbox) {
    let proj = Sandbox::new(label);
    let aux = Sandbox::new(&format!("{label}-aux"));

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\n",
    );
    proj.write(
        "src/lib.rs",
        concat!(
            "pub struct Alpha;\n",
            "impl Alpha {\n",
            "    pub fn new() -> Self { Self }\n",
            "}\n",
            "pub struct Beta;\n",
            "impl Beta {\n",
            "    pub fn new() -> Self { Self }\n",
            "}\n",
            "/// Türkçe yorum: ğüşiöç\n",
            "pub fn greet_turkish(name: &str) -> String {\n",
            "    format!(\"Merhaba {name} — ğüşiöç\")\n",
            "}\n",
        ),
    );
    proj.write(
        "src/main.rs",
        "use demo::greet_turkish;\nfn main() { let _ = greet_turkish(\"Karasu\"); }\n",
    );

    (proj, aux)
}

fn new_server(proj: &Sandbox, aux: &Sandbox) -> McpServer {
    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut cfg = McpServerConfig::new(root);
    cfg.metrics_path = Some(aux.path().join("metrics.jsonl"));
    cfg.readonly_cache_dir = Some(aux.path().join("readonly-cache"));
    McpServer::new(cfg)
}

// ---------------------------------------------------------------------------
// Test 1: Token Budget, Notification Silence, ID Echo, and Windows CRLF/LF
// ---------------------------------------------------------------------------

#[test]
fn mcp_token_budget_notifications_ids_and_windows_crlf_lf_flush() {
    let (proj, aux) = make_sample_project("crlf");
    let mut server = new_server(&proj, &aux);

    // Feed CRLF-terminated JSON-RPC frames including notifications (no `id`)
    // and integer, string, and null IDs.
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"clientInfo\":{\"name\":\"claude-code\",\"version\":\"1.2.3\"}}}\r\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\r\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":99}}\r\n",
        "{\"jsonrpc\":\"2.0\",\"id\":\"str-list-42\",\"method\":\"tools/list\",\"params\":{}}\r\n",
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}\r\n",
    );

    let mut writer = FlushCountingWriter::new();
    server
        .serve_io(Cursor::new(input.as_bytes()), &mut writer)
        .unwrap();

    // Windows stdio guarantee: ZERO `\r` bytes in stdout; every frame ends with pure `\n`.
    assert!(
        !writer.bytes.contains(&b'\r'),
        "MCP stdout MUST NOT contain CR (`\\r`) bytes"
    );
    assert!(
        writer.bytes.ends_with(b"\n"),
        "MCP stdout must end with LF (`\\n`)"
    );

    let text = String::from_utf8(writer.bytes).unwrap();
    let lines: Vec<&str> = text.lines().collect();

    // 5 incoming lines, 2 of which are notifications -> EXACTLY 3 outgoing responses & 3 flushes!
    assert_eq!(
        lines.len(),
        3,
        "notifications must produce ZERO output; got {lines:?}"
    );
    assert_eq!(
        writer.flushes, 3,
        "stdout.flush() must be called after every single JSON-RPC frame"
    );

    // 1. Integer ID echoed verbatim + initialize.instructions workflow guidance
    let init_resp: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "klens");
    assert_eq!(server.client_name(), Some("claude-code"));
    let instructions = init_resp["result"]["instructions"]
        .as_str()
        .expect("initialize result must include non-empty `instructions` string");
    assert!(!instructions.trim().is_empty());
    for expected_tool in [
        "klens_map",
        "klens_outline",
        "klens_read",
        "klens_impact",
        "klens_run",
    ] {
        assert!(
            instructions.contains(expected_tool),
            "initialize instructions must guide `{expected_tool}`, got: {instructions}"
        );
    }

    // 2. String ID echoed verbatim + tools/list annotations & token budget lock (8 tools)
    let list_resp: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(list_resp["id"], "str-list-42");
    let tools = list_resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 8);

    let read_only_tools = [
        "klens_map",
        "klens_find",
        "klens_outline",
        "klens_read",
        "klens_impact",
    ];
    let mutating_tools = ["klens_run", "klens_memory", "klens_blueprint"];
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        let ann = &tool["annotations"];
        assert_eq!(
            ann["openWorldHint"], false,
            "{name} must declare openWorldHint == false"
        );
        if read_only_tools.contains(&name) {
            assert_eq!(
                ann["readOnlyHint"], true,
                "{name} must be readOnlyHint=true"
            );
            assert_eq!(
                ann["destructiveHint"], false,
                "{name} must be destructiveHint=false"
            );
            assert_eq!(
                ann["idempotentHint"], true,
                "{name} must be idempotentHint=true"
            );
        } else if mutating_tools.contains(&name) {
            assert_eq!(
                ann["readOnlyHint"], false,
                "{name} must be readOnlyHint=false"
            );
            assert!(
                ann.get("destructiveHint").is_none(),
                "{name} must omit destructiveHint"
            );
            assert!(
                ann.get("idempotentHint").is_none(),
                "{name} must omit idempotentHint"
            );
        } else {
            panic!("unexpected tool in tools/list: {name}");
        }
    }

    let full_list_tokens = estimate_tokens(lines[1]);
    assert!(
        full_list_tokens < MAX_TOOLS_LIST_TOKENS,
        "tools/list response is {full_list_tokens} tokens, exceeding hard ceiling < {MAX_TOOLS_LIST_TOKENS}"
    );
    assert!(
        full_list_tokens <= 1_080,
        "tools/list response is {full_list_tokens} tokens, exceeding target <= 1,080"
    );

    // 3. Explicit null ID echoed verbatim
    let ping_resp: Value = serde_json::from_str(lines[2]).unwrap();
    assert!(ping_resp["id"].is_null());
    assert_eq!(ping_resp["result"], json!({}));
}

// ---------------------------------------------------------------------------
// Test 2: Project Access Policy (`paused`, `read_only`, `allowed_clients`)
// ---------------------------------------------------------------------------

#[test]
fn project_access_policy_enforces_paused_readonly_and_allowed_clients() {
    let (proj, aux) = make_sample_project("policy");
    let cfg_path = proj.path().join(".klens").join("config.toml");

    // --- Case A: mode = paused -> ALL tools denied ---
    ProjectConfig {
        mode: ProjectMode::Paused,
        ..ProjectConfig::default()
    }
    .save_atomic(&cfg_path)
    .unwrap();

    let mut server = new_server(&proj, &aux);
    let _ = server.handle_raw_line(
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "clientInfo": { "name": "claude-code", "version": "1.0" } }
        })
        .to_string(),
    );

    for (i, call) in [
        json!({ "name": "klens_read", "arguments": { "path": "src/lib.rs", "symbol": "greet_turkish" } }),
        json!({ "name": "klens_map", "arguments": {} }),
        json!({ "name": "klens_run", "arguments": { "command": ["echo", "hi"] } }),
    ]
    .into_iter()
    .enumerate()
    {
        let raw = server
            .handle_raw_line(
                &json!({ "jsonrpc": "2.0", "id": i + 2, "method": "tools/call", "params": call })
                    .to_string(),
            )
            .unwrap();
        let resp: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(PROJECT_ACCESS_RESTRICTED),
            "paused mode must return {PROJECT_ACCESS_RESTRICTED}, got: {text}"
        );
    }

    // --- Case B: mode = read_only -> klens_run denied, klens_read succeeds ---
    ProjectConfig {
        mode: ProjectMode::ReadOnly,
        ..ProjectConfig::default()
    }
    .save_atomic(&cfg_path)
    .unwrap();

    let run_denied = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                "params": { "name": "klens_run", "arguments": { "command": ["echo", "hi"] } }
            })
            .to_string(),
        )
        .unwrap();
    let run_resp: Value = serde_json::from_str(&run_denied).unwrap();
    assert_eq!(run_resp["result"]["isError"], true);
    assert!(
        run_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(PROJECT_ACCESS_RESTRICTED)
    );

    let read_ok = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                "params": { "name": "klens_read", "arguments": { "path": "src/lib.rs", "symbol": "greet_turkish" } }
            })
            .to_string(),
        )
        .unwrap();
    let read_resp: Value = serde_json::from_str(&read_ok).unwrap();
    assert!(read_resp["result"].get("isError").is_none());
    let read_text = read_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(read_text.contains("greet_turkish"));
    assert!(read_text.contains("ğüşiöç"));
    // Zero `.klens/cache/` created inside project during read_only mode!
    assert!(!proj.path().join(".klens").join("cache").exists());

    // --- Case C: allowed_clients = ["claude-code"] -> other client denied, claude-code allowed ---
    ProjectConfig {
        mode: ProjectMode::Active,
        allowed_clients: vec!["claude-code".to_string()],
        ..ProjectConfig::default()
    }
    .save_atomic(&cfg_path)
    .unwrap();

    // Same server (initialized as "claude-code") succeeds:
    let allowed_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 20, "method": "tools/call",
                "params": { "name": "klens_map", "arguments": {} }
            })
            .to_string(),
        )
        .unwrap();
    let allowed_resp: Value = serde_json::from_str(&allowed_raw).unwrap();
    assert!(allowed_resp["result"].get("isError").is_none());

    // Different client ("rogue-client") is rejected:
    let mut rogue_server = new_server(&proj, &aux);
    let _ = rogue_server.handle_raw_line(
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "clientInfo": { "name": "rogue-client", "version": "0.1" } }
        })
        .to_string(),
    );
    let rogue_raw = rogue_server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "klens_read", "arguments": { "path": "src/lib.rs", "lines": "1:3" } }
            })
            .to_string(),
        )
        .unwrap();
    let rogue_resp: Value = serde_json::from_str(&rogue_raw).unwrap();
    assert_eq!(rogue_resp["result"]["isError"], true);
    assert!(
        rogue_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(PROJECT_ACCESS_RESTRICTED)
    );
}

// ---------------------------------------------------------------------------
// Test 3: All 6 Tools + Ambiguous Symbol + Batch Read + Layer 1 Metrics
// ---------------------------------------------------------------------------

#[test]
fn all_six_mcp_tools_execute_and_record_layer1_telemetry() {
    let (proj, aux) = make_sample_project("all-tools");
    let mut server = new_server(&proj, &aux);

    let _ = server.handle_raw_line(
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "clientInfo": { "name": "antigravity", "version": "2.0" } }
        })
        .to_string(),
    );

    // 1. klens_map
    let map_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "klens_map", "arguments": { "budget": 1200 } }
            })
            .to_string(),
        )
        .unwrap();
    let map_val: Value = serde_json::from_str(&map_raw).unwrap();
    assert!(
        map_val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("src/lib.rs")
    );

    // 2. klens_find
    let find_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "klens_find", "arguments": { "query": "greet_turkish" } }
            })
            .to_string(),
        )
        .unwrap();
    let find_val: Value = serde_json::from_str(&find_raw).unwrap();
    assert!(
        find_val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("src/lib.rs")
    );

    // 3. klens_outline
    let out_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "klens_outline", "arguments": { "path": "src/lib.rs" } }
            })
            .to_string(),
        )
        .unwrap();
    let out_val: Value = serde_json::from_str(&out_raw).unwrap();
    assert!(
        out_val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("impl Alpha::new")
    );

    // 4a. klens_read ambiguous symbol -> AMBIGUOUS_SYMBOL (Article 3)
    let amb_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": { "name": "klens_read", "arguments": { "path": "src/lib.rs", "symbol": "new", "format": "json" } }
            })
            .to_string(),
        )
        .unwrap();
    let amb_val: Value = serde_json::from_str(&amb_raw).unwrap();
    let amb_inner: Value =
        serde_json::from_str(amb_val["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(amb_inner["data"]["status"], "AMBIGUOUS_SYMBOL");
    assert_eq!(amb_inner["data"]["candidates"].as_array().unwrap().len(), 2);

    // 4b. klens_read batch targets
    let batch_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": {
                    "name": "klens_read",
                    "arguments": {
                        "targets": [
                            { "path": "src/lib.rs", "symbol": "impl Beta::new" },
                            { "path": "src/main.rs", "lines": "1:2" }
                        ]
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
    let batch_val: Value = serde_json::from_str(&batch_raw).unwrap();
    let batch_text = batch_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(batch_text.contains("impl Beta::new"));
    assert!(batch_text.contains("L1| use demo::greet_turkish;"));

    // 5. klens_impact
    let imp_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": { "name": "klens_impact", "arguments": { "target": "src/lib.rs#greet_turkish" } }
            })
            .to_string(),
        )
        .unwrap();
    let imp_val: Value = serde_json::from_str(&imp_raw).unwrap();
    assert!(
        imp_val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("src/main.rs")
    );

    // 6. klens_run
    #[cfg(windows)]
    let run_cmd = json!(["cmd", "/C", "echo", "hello_from_klens_mcp"]);
    #[cfg(not(windows))]
    let run_cmd = json!(["sh", "-c", "echo hello_from_klens_mcp"]);

    let run_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 8, "method": "tools/call",
                "params": { "name": "klens_run", "arguments": { "command": run_cmd } }
            })
            .to_string(),
        )
        .unwrap();
    let run_val: Value = serde_json::from_str(&run_raw).unwrap();
    let run_text = run_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(run_text.contains("hello_from_klens_mcp"));

    // Verify Layer 1 telemetry captured all 7 tool calls + 1 filtered run!
    let stats = compute_stats(&StatsQuery {
        range: StatsRange::All,
        metrics_path: Some(aux.path().join("metrics.jsonl")),
        claude_projects_dir: Some(aux.path().join("no-claude")),
        ..StatsQuery::default()
    })
    .unwrap();
    assert_eq!(stats.klens_metrics.klens_calls, 7);
    assert_eq!(stats.klens_metrics.runs_filtered, 1);
    assert!(!stats.host_logs_connected);
    assert!(stats.host_totals.is_none());
}

#[test]
fn klens_run_raw_records_zero_savings_and_validates_param_types() {
    let (proj, aux) = make_sample_project("run-raw-edge");
    let mut server = new_server(&proj, &aux);

    let _ = server.handle_raw_line(
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "clientInfo": { "name": "codex", "version": "1.0" } }
        })
        .to_string(),
    );

    #[cfg(windows)]
    let run_cmd = json!(["cmd", "/C", "echo", "raw_mode_output_line"]);
    #[cfg(not(windows))]
    let run_cmd = json!(["sh", "-c", "echo raw_mode_output_line"]);

    // Invalid parameter types for `timeout_secs` and `raw` MUST return JSON-RPC -32602 (InvalidParams).
    for (id, bad_args) in [
        (2, json!({ "command": run_cmd, "timeout_secs": "10" })),
        (3, json!({ "command": run_cmd, "timeout_secs": -5 })),
        (4, json!({ "command": run_cmd, "raw": "true" })),
    ] {
        let resp_raw = server
            .handle_raw_line(
                &json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": { "name": "klens_run", "arguments": bad_args }
                })
                .to_string(),
            )
            .unwrap();
        let resp: Value = serde_json::from_str(&resp_raw).unwrap();
        assert_eq!(
            resp["error"]["code"], -32602,
            "invalid param type must fail with -32602, got: {resp}"
        );
    }

    // Valid `klens_run(raw: true)` call must record `tokens_saved == 0` and `runs_filtered == 0`.
    let raw_resp = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": { "name": "klens_run", "arguments": { "command": run_cmd, "raw": true } }
            })
            .to_string(),
        )
        .unwrap();
    let val: Value = serde_json::from_str(&raw_resp).unwrap();
    assert!(
        val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("raw_mode_output_line")
    );

    let metrics_path = aux.path().join("metrics.jsonl");
    let raw_metric_line = fs::read_to_string(&metrics_path).unwrap();
    let metric_json: Value = serde_json::from_str(raw_metric_line.trim()).unwrap();
    assert_eq!(metric_json["tokens_saved"], 0);
    assert_eq!(metric_json["is_run_filtered"], false);
    assert_eq!(
        metric_json["raw_est_tokens"],
        metric_json["filtered_est_tokens"]
    );

    let stats = compute_stats(&StatsQuery {
        range: StatsRange::All,
        metrics_path: Some(metrics_path),
        claude_projects_dir: Some(aux.path().join("no-claude")),
        ..StatsQuery::default()
    })
    .unwrap();
    assert_eq!(stats.klens_metrics.klens_calls, 1);
    assert_eq!(stats.klens_metrics.estimated_tokens_saved, 0);
    assert_eq!(stats.klens_metrics.runs_filtered, 0);
}

#[test]
fn klens_map_module_focus_returns_boundary_links_deterministically_and_fails_closed() {
    let proj = Sandbox::new("map-focus");
    let aux = Sandbox::new("map-focus-aux");

    proj.write(
        "shared/util.ts",
        "export function formatId(n: number): string { return String(n); }\n",
    );
    proj.write(
        "subpkg/core.ts",
        "export function runCore(n: number): number { return n + 1; }\n",
    );
    proj.write(
        "subpkg/bridge.ts",
        "import { formatId } from '../shared/util';\nexport function labelCore(n: number): string { return formatId(n); }\n",
    );
    proj.write(
        "app/entry.ts",
        "import { runCore } from '../subpkg/core';\nexport function start(): number { return runCore(7); }\n",
    );

    let mut server = new_server(&proj, &aux);
    let _ = server.handle_raw_line(
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "clientInfo": { "name": "codex", "version": "1.0" } }
        })
        .to_string(),
    );

    // 1. Focused JSON call twice -> byte-for-byte deterministic, scoped to `subpkg`, with boundary_links.
    let call_req = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "klens_map", "arguments": { "path": "subpkg", "format": "json" } }
    })
    .to_string();
    let raw_1 = server.handle_raw_line(&call_req).unwrap();
    let raw_2 = server.handle_raw_line(&call_req).unwrap();
    assert_eq!(
        raw_1, raw_2,
        "focused klens_map must be byte-for-byte deterministic"
    );

    let resp_1: Value = serde_json::from_str(&raw_1).unwrap();
    assert!(resp_1["result"].get("isError").is_none());
    let payload: Value =
        serde_json::from_str(resp_1["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["data"]["focus_path"], "subpkg");
    assert_eq!(payload["data"]["total_files"], 2);
    let files = payload["data"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    for f in files {
        assert!(
            f["path"].as_str().unwrap().starts_with("subpkg/"),
            "focused map leaked external file: {f}"
        );
    }
    let links = payload["data"]["boundary_links"].as_array().unwrap();
    assert!(
        links.iter().any(|l| {
            l["direction"] == "incoming"
                && l["internal_path"] == "subpkg/core.ts"
                && l["external_path"] == "app/entry.ts"
        }),
        "expected incoming boundary link, got: {links:?}"
    );
    assert!(
        links.iter().any(|l| {
            l["direction"] == "outgoing"
                && l["internal_path"] == "subpkg/bridge.ts"
                && l["external_path"] == "shared/util.ts"
        }),
        "expected outgoing boundary link, got: {links:?}"
    );

    // 2. Conflicting `path` and `focus` alias -> JSON-RPC -32602 (InvalidParams).
    let conflict_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "klens_map", "arguments": { "path": "subpkg", "focus": "shared" } }
            })
            .to_string(),
        )
        .unwrap();
    let conflict_resp: Value = serde_json::from_str(&conflict_raw).unwrap();
    assert_eq!(conflict_resp["error"]["code"], -32602);

    // 3. Path traversal `../escape` -> rejected (fail-closed).
    let trav_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "klens_map", "arguments": { "path": "../escape" } }
            })
            .to_string(),
        )
        .unwrap();
    let trav_resp: Value = serde_json::from_str(&trav_raw).unwrap();
    assert_eq!(
        trav_resp["result"]["isError"], true,
        "traversal must be rejected: {trav_resp}"
    );

    // 4. Nonexistent subdirectory -> fail-closed error (never silent empty map).
    let missing_raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": { "name": "klens_map", "arguments": { "path": "does_not_exist" } }
            })
            .to_string(),
        )
        .unwrap();
    let missing_resp: Value = serde_json::from_str(&missing_raw).unwrap();
    assert_eq!(
        missing_resp["result"]["isError"], true,
        "nonexistent focus path must fail closed: {missing_resp}"
    );
}

fn call_tool(server: &mut McpServer, id: u64, name: &str, arguments: Value) -> Value {
    let raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": name, "arguments": arguments }
            })
            .to_string(),
        )
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}

/// The first calls an agent makes must work: absolute paths inside the project (what Claude
/// Code and Codex pass by default) and `klens_read` with only a `path`.
#[test]
fn first_calls_accept_absolute_paths_and_path_only_reads() {
    let (proj, aux) = make_sample_project("first-calls");
    let mut server = new_server(&proj, &aux);
    let abs_lib = ProjectRoot::new(proj.path())
        .unwrap()
        .root()
        .join("src")
        .join("lib.rs")
        .display()
        .to_string();

    let outline = call_tool(&mut server, 2, "klens_outline", json!({ "path": abs_lib }));
    assert!(outline["error"].is_null(), "{outline}");
    let text = outline["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("greet_turkish"), "{text}");

    let read = call_tool(&mut server, 3, "klens_read", json!({ "path": abs_lib }));
    assert!(read["error"].is_null(), "{read}");
    let text = read["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("L1| pub struct Alpha;"), "{text}");
    assert!(!text.contains("clamped"), "{text}");

    let outside = call_tool(
        &mut server,
        4,
        "klens_read",
        json!({ "path": aux.path().join("x.rs").display().to_string(), "lines": "1-2" }),
    );
    let message = outside.to_string();
    assert!(message.contains("outside the project"), "{message}");
}

/// Path-only reads are capped by bytes too: one huge line (minified bundle, data dump) must
/// not flood the agent's context.
#[test]
fn path_only_read_is_capped_by_bytes() {
    let (proj, aux) = make_sample_project("head-bytes");
    proj.write(
        "bundle.min.js",
        &format!("var a='{}';\n", "x".repeat(200_000)),
    );
    let mut server = new_server(&proj, &aux);

    let read = call_tool(
        &mut server,
        2,
        "klens_read",
        json!({ "path": "bundle.min.js" }),
    );
    assert!(read["error"].is_null(), "{read}");
    let text = read["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.len() < 40_000, "response is {} bytes", text.len());
    assert!(
        text.contains("bytes"),
        "no truncation notice: {}",
        &text[..200]
    );
}

/// Agents often pass the absolute project root itself as `path` / `focus`.
#[test]
fn absolute_project_root_means_the_whole_project() {
    let (proj, aux) = make_sample_project("abs-root");
    let mut server = new_server(&proj, &aux);
    let canonical = ProjectRoot::new(proj.path())
        .unwrap()
        .root()
        .display()
        .to_string();
    let root = canonical.trim_start_matches(r"\\?\").to_string();

    for (id, (tool, args)) in [
        ("klens_outline", json!({ "path": canonical.clone() })),
        ("klens_outline", json!({ "path": root.clone() })),
        ("klens_outline", json!({ "path": format!("{root}/") })),
        ("klens_map", json!({ "focus": root.clone() })),
    ]
    .into_iter()
    .enumerate()
    {
        let res = call_tool(&mut server, 10 + id as u64, tool, args.clone());
        assert!(res["error"].is_null(), "{tool} {args}: {res}");
        assert!(
            res["result"]["isError"].as_bool() != Some(true),
            "{tool} {args}: {res}"
        );
    }
}
