//! Phase 5A MCP integration tests for the 8th tool (`klens_blueprint`).
//!
//! Verifies:
//! 1. `tools/list` exposes all 8 tools including `klens_blueprint` and remains strictly `< 1,200` tokens.
//! 2. Full `klens_blueprint` MCP lifecycle: `status` -> `propose` -> `check` (conflict blocks `lock`
//!    without writing files) -> `select` -> `lock` -> `next_task` -> `complete_task` -> `handoff`.
//! 3. `read_only` policy allows `status`/`check`/`next_task`/`handoff` with zero `.klens/cache/`
//!    footprint, and blocks `propose`/`select`/`lock`/`complete_task` with `PROJECT_ACCESS_RESTRICTED`.
//! 4. Fail-closed parameter type validation returns JSON-RPC `-32602` (`InvalidParams`).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::{ProjectConfig, ProjectMode, ProjectRoot, estimate_tokens};
use klens_exec::{NewRunRecord, RunStore};
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
            std::env::temp_dir().join(format!("klens-mcp-p5a-{label}-{}-{n}", std::process::id()));
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

fn new_server(proj: &Sandbox, aux: &Sandbox) -> McpServer {
    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut cfg = McpServerConfig::new(root);
    cfg.metrics_path = Some(aux.path().join("metrics.jsonl"));
    cfg.readonly_cache_dir = Some(aux.path().join("readonly-cache"));
    let mut server = McpServer::new(cfg);
    let _ = server.handle_raw_line(
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "clientInfo": { "name": "antigravity", "version": "2.0" } }
        })
        .to_string(),
    );
    server
}

fn call_tool(server: &mut McpServer, id: u64, name: &str, arguments: Value) -> Value {
    let raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": name, "arguments": arguments }
            })
            .to_string(),
        )
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn sample_blueprint_json() -> Value {
    json!({
        "schema_version": 1,
        "project_name": "KarasuDemo",
        "goal": "Yerel deterministik demo uygulaması (ğüşiöç)",
        "bubbles": [
            {
                "id": "platform",
                "category": "Platform",
                "title": "Çalışma ortamı?",
                "plain_explanation": "Hedef çalışma ortamını seçer.",
                "options": [
                    {
                        "id": "desktop_native",
                        "label": "Masaüstü",
                        "provides": ["desktop_native", "local_fs"],
                        "requires": [],
                        "conflicts_with": ["browser_only"]
                    },
                    {
                        "id": "web_browser",
                        "label": "Tarayıcı",
                        "provides": ["browser_only"],
                        "requires": [],
                        "conflicts_with": ["local_fs"]
                    }
                ],
                "selected_option": "web_browser",
                "user_vision_note": "Önce masaüstü 60 FPS",
                "status": "user_confirmed",
                "depends_on": []
            },
            {
                "id": "storage",
                "category": "Depolama",
                "title": "Kayıt katmanı?",
                "options": [
                    {
                        "id": "sqlite",
                        "label": "SQLite WAL",
                        "provides": ["sqlite"],
                        "requires": ["local_fs"],
                        "conflicts_with": ["browser_only"]
                    }
                ],
                "selected_option": "sqlite",
                "status": "user_confirmed",
                "depends_on": ["platform"]
            }
        ],
        "scaffold": [
            { "path": "src/keep.rs", "is_dir": false, "content": "// overwrite attempt" },
            { "path": "src/generated", "is_dir": true }
        ]
    })
}

#[test]
fn mcp_eight_tools_budget_and_blueprint_full_lifecycle_with_handoff() {
    let proj = Sandbox::new("lifecycle");
    let aux = Sandbox::new("lifecycle-aux");
    proj.write("src/keep.rs", "// KEEP_ME\n");

    let mut server = new_server(&proj, &aux);

    // 1. Verify 8 tools and strict < 1,200 token ceiling.
    let list_raw = server
        .handle_raw_line(
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }).to_string(),
        )
        .unwrap();
    let list_val: Value = serde_json::from_str(&list_raw).unwrap();
    let tools = list_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 8);
    assert!(tools.iter().any(|t| t["name"] == "klens_blueprint"));
    let list_tokens = estimate_tokens(&list_raw);
    assert!(
        list_tokens < MAX_TOOLS_LIST_TOKENS,
        "8-tool tools/list is {list_tokens} tokens (>= {MAX_TOOLS_LIST_TOKENS})"
    );

    // 2. Initial status reports uninitialized cleanly.
    let st0 = call_tool(
        &mut server,
        3,
        "klens_blueprint",
        json!({ "action": "status", "format": "json" }),
    );
    let st0_inner: Value =
        serde_json::from_str(st0["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(st0_inner["data"]["initialized"], false);

    // 3. Propose conflicting blueprint -> `check` reports errors, `lock` is rejected and creates no contract!
    let prop = call_tool(
        &mut server,
        4,
        "klens_blueprint",
        json!({ "action": "propose", "blueprint": sample_blueprint_json(), "format": "json" }),
    );
    let prop_inner: Value =
        serde_json::from_str(prop["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(prop_inner["data"]["conflicts"]["can_lock"], false);

    let chk_bad = call_tool(
        &mut server,
        5,
        "klens_blueprint",
        json!({ "action": "check", "format": "json" }),
    );
    let chk_bad_inner: Value =
        serde_json::from_str(chk_bad["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(chk_bad_inner["data"]["error_count"].as_u64().unwrap() >= 2);

    let lock_bad = call_tool(
        &mut server,
        6,
        "klens_blueprint",
        json!({ "action": "lock" }),
    );
    assert_eq!(lock_bad["result"]["isError"], true);
    assert!(
        !proj
            .path()
            .join(".klens/blueprint/PROJECT_CONTRACT.md")
            .exists()
    );

    // 4. Resolve conflict via `select` -> `check` passes -> `lock` succeeds with non-destructive scaffold!
    let sel = call_tool(
        &mut server,
        7,
        "klens_blueprint",
        json!({
            "action": "select",
            "bubble_id": "platform",
            "option_id": "desktop_native",
            "vision_note": "Windows 60 FPS hedefi (ğüşiöç)",
            "confirm": true,
            "format": "json"
        }),
    );
    let sel_inner: Value =
        serde_json::from_str(sel["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(sel_inner["data"]["conflicts"]["can_lock"], true);

    let lock_ok = call_tool(
        &mut server,
        8,
        "klens_blueprint",
        json!({ "action": "lock", "create_scaffold": true, "format": "json" }),
    );
    let lock_inner: Value =
        serde_json::from_str(lock_ok["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(lock_inner["trust"], "USER_LOCKED");
    assert_eq!(lock_inner["data"]["task_count"], 2);
    assert_eq!(
        fs::read_to_string(proj.path().join("src/keep.rs")).unwrap(),
        "// KEEP_ME\n"
    );
    assert!(proj.path().join("src/generated").is_dir());

    // 5. `next_task` returns `T01-platform`; `complete_task` unlocks `T02-storage`.
    let nt1 = call_tool(
        &mut server,
        9,
        "klens_blueprint",
        json!({ "action": "next_task", "format": "json" }),
    );
    let nt1_inner: Value =
        serde_json::from_str(nt1["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(nt1_inner["data"]["task"]["id"], "T01-platform");

    let ct1 = call_tool(
        &mut server,
        10,
        "klens_blueprint",
        json!({ "action": "complete_task", "task_id": "T01-platform", "format": "json" }),
    );
    let ct1_inner: Value =
        serde_json::from_str(ct1["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(ct1_inner["data"]["next_ready_task"]["id"], "T02-storage");

    // 6. `handoff` is deterministic and respects `budget`.
    let h1 = call_tool(
        &mut server,
        11,
        "klens_blueprint",
        json!({ "action": "handoff", "budget": 450 }),
    );
    let h2 = call_tool(
        &mut server,
        12,
        "klens_blueprint",
        json!({ "action": "handoff", "budget": 450 }),
    );
    let h1_text = h1["result"]["content"][0]["text"].as_str().unwrap();
    let h2_text = h2["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(h1_text, h2_text);
    assert!(estimate_tokens(h1_text) <= 450);
    assert!(h1_text.contains("T02-storage"));
    assert!(h1_text.contains("USER_LOCKED"));
}

#[test]
fn mcp_blueprint_enforces_readonly_policy_and_fail_closed_param_validation() {
    let proj = Sandbox::new("policy");
    let aux = Sandbox::new("policy-aux");
    proj.write("src/lib.rs", "pub fn ok() -> bool { true }\n");

    let mut server = new_server(&proj, &aux);

    // Seed a valid draft before switching to `read_only`.
    assert!(
        call_tool(
            &mut server,
            2,
            "klens_blueprint",
            json!({ "action": "propose", "blueprint": sample_blueprint_json() })
        )["result"]
            .get("isError")
            .is_none()
    );

    ProjectConfig {
        mode: ProjectMode::ReadOnly,
        ..ProjectConfig::default()
    }
    .save_atomic(&proj.path().join(".klens/config.toml"))
    .unwrap();

    // Read-only actions MUST succeed and MUST NOT create `.klens/cache/`.
    for (idx, action) in ["status", "check", "next_task", "handoff"]
        .into_iter()
        .enumerate()
    {
        let resp = call_tool(
            &mut server,
            10 + idx as u64,
            "klens_blueprint",
            json!({ "action": action }),
        );
        assert!(
            resp["result"].get("isError").is_none(),
            "read-only action `{action}` should be allowed, got: {resp}"
        );
    }
    assert!(
        !proj.path().join(".klens/cache").exists(),
        "read_only blueprint/handoff calls must not create `.klens/cache/`"
    );

    // Write actions MUST be blocked with `PROJECT_ACCESS_RESTRICTED`.
    let write_calls = [
        json!({ "action": "propose", "blueprint": sample_blueprint_json() }),
        json!({ "action": "select", "bubble_id": "platform", "option_id": "desktop_native" }),
        json!({ "action": "lock" }),
        json!({ "action": "complete_task", "task_id": "T01-platform" }),
    ];
    for (idx, args) in write_calls.into_iter().enumerate() {
        let resp = call_tool(
            &mut server,
            20 + idx as u64,
            "klens_blueprint",
            args.clone(),
        );
        assert_eq!(resp["result"]["isError"], true, "expected deny for {args}");
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains(PROJECT_ACCESS_RESTRICTED)
        );
    }

    // Switch back to Active and verify fail-closed parameter validation (-32602 InvalidParams).
    ProjectConfig {
        mode: ProjectMode::Active,
        ..ProjectConfig::default()
    }
    .save_atomic(&proj.path().join(".klens/config.toml"))
    .unwrap();

    let invalid_cases = [
        json!({}),
        json!({ "action": 123 }),
        json!({ "action": "unknown_op" }),
        json!({ "action": "status", "format": 42 }),
        json!({ "action": "propose", "blueprint": ["not", "an", "object"] }),
        json!({ "action": "select", "bubble_id": 123, "option_id": "desktop_native" }),
        json!({ "action": "select", "bubble_id": "platform", "option_id": "desktop_native", "confirm": "true" }),
        json!({ "action": "select", "bubble_id": "platform", "option_id": "desktop_native", "vision_note": 99 }),
        json!({ "action": "lock", "create_scaffold": "yes" }),
        json!({ "action": "complete_task", "task_id": false }),
        json!({ "action": "handoff", "budget": "800" }),
        json!({ "action": "handoff", "budget": -10 }),
    ];
    for (idx, bad) in invalid_cases.into_iter().enumerate() {
        let resp = call_tool(&mut server, 40 + idx as u64, "klens_blueprint", bad.clone());
        assert_eq!(
            resp["error"]["code"], -32602,
            "expected JSON-RPC -32602 for invalid params {bad}, got: {resp}"
        );
    }
}

#[test]
fn regression_handoff_skips_resolved_runs_dedups_stale_warning_and_read_rejects_bad_types() {
    let proj = Sandbox::new("reg-mcp");
    let aux = Sandbox::new("reg-mcp-aux");
    proj.write("src/lib.rs", "pub fn foo() -> u32 { 1 }\n");
    let mut server = new_server(&proj, &aux);

    // 1. Failing run followed by a newer passing (`exit 0`) run of the SAME command ->
    //    `handoff` MUST report `has_failed_run == false`.
    let store = RunStore::new(ProjectRoot::new(proj.path()).unwrap());
    store
        .save_run_with_id(
            "20261124-000100-aaaa",
            "2026-11-24T00:01:00Z",
            &NewRunRecord {
                command: "cargo test --workspace",
                cwd: ".",
                filter_used: "cargo",
                exit_code: 101,
                duration_ms: 420,
                raw_bytes: 64,
                filtered_bytes: 32,
                est_raw_tokens: 16,
                est_filtered_tokens: 8,
                truncated_errors: false,
                raw_log_content: "error[E0382]: borrow of moved value\n",
            },
        )
        .unwrap();

    let h_failing = call_tool(
        &mut server,
        3,
        "klens_blueprint",
        json!({ "action": "handoff", "format": "json" }),
    );
    let h_failing_val: Value =
        serde_json::from_str(h_failing["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(h_failing_val["data"]["has_failed_run"], true);

    // Newer run of the exact same command succeeds (`exit 0`) -> resolves the prior failure!
    store
        .save_run_with_id(
            "20261124-000200-bbbb",
            "2026-11-24T00:02:00Z",
            &NewRunRecord {
                command: "cargo test --workspace",
                cwd: ".",
                filter_used: "cargo",
                exit_code: 0,
                duration_ms: 310,
                raw_bytes: 40,
                filtered_bytes: 20,
                est_raw_tokens: 10,
                est_filtered_tokens: 5,
                truncated_errors: false,
                raw_log_content: "test result: ok. 10 passed; 0 failed\n",
            },
        )
        .unwrap();

    let h_resolved = call_tool(
        &mut server,
        5,
        "klens_blueprint",
        json!({ "action": "handoff", "format": "json" }),
    );
    let h_resolved_val: Value =
        serde_json::from_str(h_resolved["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        h_resolved_val["data"]["has_failed_run"], false,
        "resolved historical failure must not be reported as an active failure: {h_resolved_val}"
    );

    // 2. STALE memory note must NOT duplicate into `parse_warnings` (`- [WARN] ... STALE BLAKE3 anchors`),
    //    whereas a corrupt `.md` file MUST surface in `parse_warnings` (`- [WARN]`).
    assert!(
        call_tool(
            &mut server,
            6,
            "klens_memory",
            json!({
                "action": "add",
                "id": "adr-stale-dedup",
                "title": "Stale dedup check",
                "kind": "decision",
                "anchors": ["src/lib.rs"],
                "body": "Initial body\n"
            })
        )["result"]
            .get("isError")
            .is_none()
    );
    proj.write("src/lib.rs", "pub fn foo() -> u32 { 2 }\n");
    proj.write(".klens/memory/broken-note.md", "not valid frontmatter\n");

    let h_mem = call_tool(
        &mut server,
        7,
        "klens_blueprint",
        json!({ "action": "handoff", "format": "json" }),
    );
    let h_mem_val: Value =
        serde_json::from_str(h_mem["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let md = h_mem_val["data"]["summary_markdown"].as_str().unwrap();
    assert!(
        !md.contains("STALE BLAKE3 anchors"),
        "aggregate STALE warning must not be duplicated as [WARN] in handoff:\n{md}"
    );
    assert!(
        md.contains("- [STALE] `adr-stale-dedup`"),
        "stale note must appear once under [STALE]:\n{md}"
    );
    assert!(
        md.contains("- [WARN]") && md.contains("broken-note.md"),
        "corrupt memory markdown must surface as [WARN] in handoff:\n{md}"
    );
    let warnings = h_mem_val["warnings"].as_array().unwrap();
    assert!(
        !warnings
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("STALE BLAKE3 anchors")),
        "envelope warnings must not duplicate aggregate STALE warning: {warnings:?}"
    );

    // 3. `klens_read` MUST fail closed (`-32602`) on non-string `symbol` or `lines` in single & batch mode.
    let bad_reads = [
        json!({ "path": "src/lib.rs", "symbol": "foo", "lines": 123 }),
        json!({ "path": "src/lib.rs", "symbol": 123 }),
        json!({ "path": "src/lib.rs", "lines": true }),
        json!({ "targets": [{ "path": "src/lib.rs", "symbol": "foo", "lines": 123 }] }),
        json!({ "targets": [{ "path": "src/lib.rs", "symbol": ["foo"] }] }),
    ];
    for (idx, bad_args) in bad_reads.into_iter().enumerate() {
        let resp = call_tool(&mut server, 20 + idx as u64, "klens_read", bad_args.clone());
        assert_eq!(
            resp["error"]["code"], -32602,
            "expected JSON-RPC -32602 for bad klens_read params {bad_args}, got: {resp}"
        );
    }
}
