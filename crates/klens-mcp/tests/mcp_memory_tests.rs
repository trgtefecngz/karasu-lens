//! Phase 4 integration tests for `klens_memory` (7th MCP tool) and `klens_run` bugfix hints.
//!
//! Covers:
//! 1. `tools/list` has 7 tools within `<= 1,000` tokens (`< 1,200` hard ceiling, headroom for Phase 5A).
//! 2. Full `klens_memory` MCP CRUD lifecycle (`add`, `index`, `get`, `search`, `verify`, `refresh`, `update`, `delete`)
//!    with Tree-sitter AST symbol anchoring (`impl World::save_chunk`) and deleted-symbol `missing_symbol`.
//! 3. `read_only` policy allows `index`/`get`/`search`/`verify` (zero `.klens/cache/` footprint) and
//!    blocks `add`/`update`/`delete`/`refresh` with `PROJECT_ACCESS_RESTRICTED`.
//! 4. `klens_run` non-zero failure attaches verified `kind: bugfix` note (`[Taze]` / `[STALE]`) and
//!    records `stale_memories_caught` honestly in Layer 1 telemetry (`metrics.jsonl`).

use std::fs;
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
            std::env::temp_dir().join(format!("klens-mcp-p4-{label}-{}-{n}", std::process::id()));
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

#[test]
fn mcp_seven_tools_budget_and_klens_memory_ast_symbol_staleness_lifecycle() {
    let proj = Sandbox::new("lifecycle");
    let aux = Sandbox::new("lifecycle-aux");

    proj.write(
        "src/world.rs",
        concat!(
            "pub struct World;\n",
            "impl World {\n",
            "    pub fn save_chunk(&self, id: u32) -> bool {\n",
            "        id > 0\n",
            "    }\n",
            "}\n",
        ),
    );

    let mut server = new_server(&proj, &aux);

    // 1. Verify 8 tools (including `klens_memory` & `klens_blueprint`) within < 1,200 token ceiling.
    let list_raw = server
        .handle_raw_line(
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }).to_string(),
        )
        .unwrap();
    let list_val: Value = serde_json::from_str(&list_raw).unwrap();
    let tools = list_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 8);
    assert!(tools.iter().any(|t| t["name"] == "klens_memory"));
    assert!(tools.iter().any(|t| t["name"] == "klens_blueprint"));
    let tokens = estimate_tokens(&list_raw);
    assert!(
        tokens < MAX_TOOLS_LIST_TOKENS,
        "8-tool tools/list is {tokens} tokens (>= {MAX_TOOLS_LIST_TOKENS})"
    );

    // 2. Add a decision note anchored via Tree-sitter AST to `src/world.rs#impl World::save_chunk`.
    let add_resp = call_tool(
        &mut server,
        3,
        "klens_memory",
        json!({
            "action": "add",
            "id": "adr-world-save",
            "title": "Dünya kayıt kararı (ğüşiöç)",
            "kind": "decision",
            "anchors": ["src/world.rs#impl World::save_chunk"],
            "tags": ["world", "storage"],
            "body": "## Karar\nUNIQUE_BODY_SECRET_999\nİlgili: [[PROJECT_CONTRACT]]\n",
            "format": "json"
        }),
    );
    let add_inner: Value =
        serde_json::from_str(add_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(add_inner["trust"], "VERIFIED_RAW");
    assert_eq!(
        add_inner["data"]["note"]["frontmatter"]["id"],
        "adr-world-save"
    );

    // 3. `index` returns metadata without leaking `UNIQUE_BODY_SECRET_999`.
    let idx_resp = call_tool(
        &mut server,
        4,
        "klens_memory",
        json!({ "action": "index", "format": "json" }),
    );
    let idx_str = idx_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!idx_str.contains("UNIQUE_BODY_SECRET_999"));
    let idx_inner: Value = serde_json::from_str(idx_str).unwrap();
    assert_eq!(idx_inner["data"]["total_notes"], 1);
    assert_eq!(idx_inner["data"]["stale_count"], 0);

    // 4. Delete `save_chunk` -> `get` & `verify` report STALE + `missing_symbol` AND log telemetry!
    proj.write("src/world.rs", "pub struct World;\nimpl World {}\n");

    let stale_get = call_tool(
        &mut server,
        5,
        "klens_memory",
        json!({ "action": "get", "id": "adr-world-save", "format": "json" }),
    );
    let stale_inner: Value =
        serde_json::from_str(stale_get["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(stale_inner["trust"], "STALE");
    assert_eq!(
        stale_inner["data"]["verification"]["anchor_checks"][0]["stale_reason"],
        "missing_symbol"
    );

    // Restore `save_chunk` with new body, then `refresh` -> fresh again!
    proj.write(
        "src/world.rs",
        "pub struct World;\nimpl World {\n    pub fn save_chunk(&self, id: u32) -> bool { id >= 1 }\n}\n",
    );
    let ref_resp = call_tool(
        &mut server,
        6,
        "klens_memory",
        json!({ "action": "refresh", "id": "adr-world-save", "format": "json" }),
    );
    let ref_inner: Value =
        serde_json::from_str(ref_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(ref_inner["trust"], "VERIFIED_RAW");

    // Verify Layer 1 telemetry recorded `stale_memories_caught >= 1`.
    let stats = compute_stats(&StatsQuery {
        range: StatsRange::All,
        metrics_path: Some(aux.path().join("metrics.jsonl")),
        claude_projects_dir: Some(aux.path().join("no-claude")),
        ..StatsQuery::default()
    })
    .unwrap();
    assert!(stats.klens_metrics.stale_memories_caught >= 1);
}

#[test]
fn mcp_memory_enforces_readonly_policy_and_klens_run_attaches_bugfix_hints() {
    let proj = Sandbox::new("run-bugfix");
    let aux = Sandbox::new("run-bugfix-aux");

    proj.write("src/store.rs", "pub fn open() -> bool { true }\n");
    let mut server = new_server(&proj, &aux);

    // Add a `kind: bugfix` note for error code `E0382` / `SQLITE_BUSY`.
    let add_bug = call_tool(
        &mut server,
        2,
        "klens_memory",
        json!({
            "action": "add",
            "id": "bug-e0382-wal",
            "title": "E0382 borrow after move in store",
            "kind": "bugfix",
            "anchors": ["src/store.rs"],
            "tags": ["rust", "borrow"],
            "body": "Use clone or borrow before move when hitting E0382.\n"
        }),
    );
    assert!(add_bug["result"].get("isError").is_none());

    // Trigger a failing `klens_run` command that prints `E0382`.
    #[cfg(windows)]
    let fail_cmd = json!([
        "cmd",
        "/C",
        "echo error[E0382]: borrow of moved value & exit /B 1"
    ]);
    #[cfg(not(windows))]
    let fail_cmd = json!([
        "sh",
        "-c",
        "echo 'error[E0382]: borrow of moved value' && exit 1"
    ]);

    let run_fail = call_tool(&mut server, 3, "klens_run", json!({ "command": fail_cmd }));
    let run_text = run_fail["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        run_text.contains(
            "[bugfix] \"E0382 borrow after move in store\" (.klens/memory/bug-e0382-wal.md) [Taze]"
        ),
        "failing klens_run must attach fresh bugfix hint, got:\n{run_text}"
    );

    // Mutate `src/store.rs` -> failing `klens_run` now reports `[STALE]`!
    proj.write("src/store.rs", "pub fn open() -> bool { false }\n");
    let run_stale = call_tool(
        &mut server,
        4,
        "klens_run",
        json!({ "command": fail_cmd, "format": "json" }),
    );
    let run_json: Value =
        serde_json::from_str(run_stale["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let hints = run_json["data"]["related_bugfix_notes"].as_array().unwrap();
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0]["id"], "bug-e0382-wal");
    assert_eq!(hints[0]["freshness"], "STALE");
    assert_eq!(hints[0]["is_stale"], true);

    // Switch project to `read_only` mode: `index` succeeds, `add` is denied with `PROJECT_ACCESS_RESTRICTED`.
    ProjectConfig {
        mode: ProjectMode::ReadOnly,
        ..ProjectConfig::default()
    }
    .save_atomic(&proj.path().join(".klens/config.toml"))
    .unwrap();

    let ro_index = call_tool(&mut server, 5, "klens_memory", json!({ "action": "index" }));
    assert!(ro_index["result"].get("isError").is_none());

    let ro_add = call_tool(
        &mut server,
        6,
        "klens_memory",
        json!({ "action": "add", "title": "Blocked write", "kind": "decision" }),
    );
    assert_eq!(ro_add["result"]["isError"], true);
    assert!(
        ro_add["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(PROJECT_ACCESS_RESTRICTED)
    );
}

#[test]
fn mcp_memory_rejects_invalid_param_types_and_filters_multiple_tags() {
    let proj = Sandbox::new("mcp-validation");
    let aux = Sandbox::new("mcp-validation-aux");
    let mut server = new_server(&proj, &aux);

    // Seed 2 notes with overlapping tags to test multi-tag AND filtering.
    assert!(
        call_tool(
            &mut server,
            2,
            "klens_memory",
            json!({
                "action": "add",
                "id": "note-rust-only",
                "title": "Rust only note",
                "kind": "decision",
                "tags": ["rust"],
                "body": "Body 1\n"
            })
        )["result"]
            .get("isError")
            .is_none()
    );
    assert!(
        call_tool(
            &mut server,
            3,
            "klens_memory",
            json!({
                "action": "add",
                "id": "note-rust-sqlite",
                "title": "Rust + SQLite note",
                "kind": "decision",
                "tags": ["rust", "sqlite"],
                "body": "Body 2\n"
            })
        )["result"]
            .get("isError")
            .is_none()
    );

    // Multi-tag filter `["rust", "sqlite"]` MUST require BOTH tags (never drop the 2nd tag!).
    let multi = call_tool(
        &mut server,
        4,
        "klens_memory",
        json!({ "action": "index", "tags": ["rust", "sqlite"], "format": "json" }),
    );
    let multi_inner: Value =
        serde_json::from_str(multi["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let entries = multi_inner["data"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "note-rust-sqlite");

    // Invalid parameter types MUST fail closed with JSON-RPC -32602 (InvalidParams).
    let invalid_cases = [
        json!({ "action": "index", "stale_only": "true" }),
        json!({ "action": "index", "stale_only": 1 }),
        json!({ "action": "index", "tags": "rust" }),
        json!({ "action": "index", "tags": ["rust", 42] }),
        json!({ "action": "index", "tag": 99 }),
        json!({ "action": "add", "title": "Bad body", "body": 12345 }),
        json!({ "action": "add", "title": "Bad body arr", "body": ["a"] }),
        json!({ "action": "update", "id": "note-rust-only", "body": true }),
    ];

    for (idx, bad_args) in invalid_cases.into_iter().enumerate() {
        let resp = call_tool(
            &mut server,
            10 + idx as u64,
            "klens_memory",
            bad_args.clone(),
        );
        assert_eq!(
            resp["error"]["code"], -32602,
            "expected JSON-RPC -32602 for invalid params {bad_args}, got: {resp}"
        );
    }
}
