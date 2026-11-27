//! End-to-end CLI binary tests for Phase 3A (`klens mcp` and `klens stats`).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static E2E_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempWorkspace {
    dir: PathBuf,
}

impl TempWorkspace {
    fn new(label: &str) -> Self {
        let n = E2E_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-p3a-e2e-{label}-{}-{n}", std::process::id()));
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

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn e2e_klens_mcp_stdio_and_klens_stats_pipeline() {
    let proj = TempWorkspace::new("proj");
    let home = TempWorkspace::new("home");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"e2e_app\"\nversion = \"0.1.0\"\n",
    );
    proj.write(
        "src/lib.rs",
        "pub fn compute_answer(x: i32) -> i32 {\n    x * 2\n}\n",
    );

    #[cfg(windows)]
    let run_cmd = json!(["cmd", "/C", "echo", "e2e_run_ok"]);
    #[cfg(not(windows))]
    let run_cmd = json!(["sh", "-c", "echo e2e_run_ok"]);

    // Send CRLF-terminated MCP session over real process stdin:
    // initialize -> notifications/initialized -> tools/list -> klens_map -> klens_read -> klens_run
    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": { "name": "codex", "version": "1.0" }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "list-1",
            "method": "tools/list",
            "params": {}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "klens_map", "arguments": { "budget": 1000 } }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "klens_read", "arguments": { "path": "src/lib.rs", "symbol": "compute_answer" } }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "klens_run", "arguments": { "command": run_cmd } }
        }),
    ];

    let mut payload = String::new();
    for req in &requests {
        payload.push_str(&req.to_string());
        payload.push_str("\r\n");
    }

    let bin = env!("CARGO_BIN_EXE_klens");
    let mut child = Command::new(bin)
        .args(["mcp", "--project"])
        .arg(proj.path())
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn `klens mcp`");

    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "`klens mcp` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Pure LF output guarantee on Windows!
    assert!(
        !output.stdout.contains(&b'\r'),
        "`klens mcp` emitted CR byte on stdout!"
    );

    let stdout_str = String::from_utf8(output.stdout).unwrap();
    let resp_lines: Vec<&str> = stdout_str.lines().collect();
    // 6 incoming messages, 1 notification -> exactly 5 JSON-RPC responses!
    assert_eq!(resp_lines.len(), 5, "got stdout:\n{stdout_str}");

    let init_r: Value = serde_json::from_str(resp_lines[0]).unwrap();
    assert_eq!(init_r["id"], 1);
    assert_eq!(init_r["result"]["serverInfo"]["name"], "klens");

    let list_r: Value = serde_json::from_str(resp_lines[1]).unwrap();
    assert_eq!(list_r["id"], "list-1");
    assert_eq!(list_r["result"]["tools"].as_array().unwrap().len(), 9);

    let map_r: Value = serde_json::from_str(resp_lines[2]).unwrap();
    assert!(
        map_r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("src/lib.rs")
    );

    let read_r: Value = serde_json::from_str(resp_lines[3]).unwrap();
    assert!(
        read_r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("L1| pub fn compute_answer(x: i32) -> i32 {")
    );

    let run_r: Value = serde_json::from_str(resp_lines[4]).unwrap();
    assert!(
        run_r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("e2e_run_ok")
    );

    // Now invoke `klens stats --range 7d --project <proj> --json` against the same isolated HOME.
    let stats_out = Command::new(bin)
        .args(["stats", "--range", "7d", "--project"])
        .arg(proj.path())
        .arg("--json")
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("failed to execute `klens stats`");

    assert!(
        stats_out.status.success(),
        "`klens stats` failed: {}",
        String::from_utf8_lossy(&stats_out.stderr)
    );

    let stats_json: Value = serde_json::from_slice(&stats_out.stdout).unwrap();
    assert_eq!(stats_json["schema_version"], 1);
    assert_eq!(stats_json["range"], "7d");
    assert_eq!(stats_json["host_logs_connected"], false);
    assert!(stats_json["host_totals"].is_null());
    assert_eq!(stats_json["klens_metrics"]["klens_calls"], 3);
    assert_eq!(stats_json["klens_metrics"]["runs_filtered"], 1);
}

#[test]
fn e2e_klens_stats_reads_claude_host_logs_with_all_four_regression_guards() {
    let home = TempWorkspace::new("stats-host");

    let bash_25k = "b".repeat(25_000);
    let log_content = [
        json!({
            "type": "assistant",
            "timestamp": "2026-11-22T18:00:00Z",
            "sessionId": "sess-1",
            "message": {
                "model": "claude-sonnet-4",
                "usage": { "input_tokens": 5000, "output_tokens": 500 },
                "content": [
                    { "type": "tool_use", "id": "b1", "name": "Bash", "input": { "command": "dump" } },
                    { "type": "tool_use", "id": "r1", "name": "Read", "input": { "file_path": "src/a.rs", "offset": 1, "limit": 100 } },
                    { "type": "tool_use", "id": "r2", "name": "Read", "input": { "file_path": "src/a.rs", "offset": 101, "limit": 100 } },
                    { "type": "tool_use", "id": "r3", "name": "Read", "input": { "file_path": "src/a.rs", "offset": 50, "limit": 71 } },
                    { "type": "tool_use", "id": "k1", "name": "mcp__klens__klens_read", "input": { "path": "src/a.rs", "symbol": "run" } }
                ]
            }
        }),
        json!({
            "type": "user",
            "timestamp": "2026-11-22T18:00:02Z",
            "message": {
                "content": [
                    { "type": "tool_result", "tool_use_id": "b1", "content": bash_25k }
                ]
            }
        }),
    ]
    .iter()
    .map(|v| format!("{v}\n"))
    .collect::<String>();

    home.write(
        ".claude/projects/MyApp/sess-1/subagents/agent-2.jsonl",
        &log_content,
    );

    let bin = env!("CARGO_BIN_EXE_klens");
    let out = Command::new(bin)
        .args(["stats", "--range", "all", "--project", "MyApp", "--json"])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("failed to execute `klens stats`");

    assert!(
        out.status.success(),
        "`klens stats` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["host_logs_connected"], true);
    assert_eq!(json["host_logs_source"], "claude-code");
    assert_eq!(json["klens_metrics"]["klens_calls"], 1);
    assert_eq!(json["host_totals"]["sessions_count"], 1);
    assert_eq!(json["host_totals"]["big_file_reads"], 0);
    assert_eq!(json["host_totals"]["repeated_overlapping_reads"], 1);
    assert_eq!(json["recent_sessions"][0]["project"], "MyApp");
}

#[test]
fn e2e_klens_map_focus_readonly_json() {
    let proj = TempWorkspace::new("map-focus-cli");
    let home = TempWorkspace::new("map-focus-cli-home");

    proj.write(
        "shared/ext.ts",
        "export function helper(): number { return 42; }\n",
    );
    proj.write(
        "subpkg/mod.ts",
        "import { helper } from '../shared/ext';\nexport function runMod(): number { return helper(); }\n",
    );
    proj.write(
        "app/main.ts",
        "import { runMod } from '../subpkg/mod';\nexport function main(): number { return runMod(); }\n",
    );

    let bin = env!("CARGO_BIN_EXE_klens");
    let out = Command::new(bin)
        .arg("map")
        .arg(proj.path())
        .args(["--focus", "subpkg", "--read-only", "--json"])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("failed to execute `klens map --focus`");

    assert!(
        out.status.success(),
        "`klens map --focus` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !proj.path().join(".klens").exists(),
        "`--read-only` must write zero files into target project"
    );

    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["data"]["focus_path"], "subpkg");
    assert_eq!(json["data"]["total_files"], 1);
    assert_eq!(json["data"]["files"][0]["path"], "subpkg/mod.ts");
    let links = json["data"]["boundary_links"].as_array().unwrap();
    assert_eq!(
        links.len(),
        2,
        "expected incoming + outgoing boundary links: {links:?}"
    );

    // Nonexistent focus path must fail closed with non-zero exit code.
    let bad = Command::new(bin)
        .arg("map")
        .arg(proj.path())
        .args(["--focus", "no_such_dir", "--read-only", "--json"])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("failed to execute `klens map --focus` on missing dir");
    assert!(!bad.status.success());
}
