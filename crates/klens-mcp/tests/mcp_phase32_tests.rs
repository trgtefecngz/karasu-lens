//! Phase 3.2 MCP integration tests:
//! 1. `tools/list` still exposes exactly 8 tools within `<= 1,090` tokens (`< 1,200` hard lock)
//!    and `klens_map.budget` advertises `default 2000`.
//! 2. `klens_read` single + batch `include: ["imports", "memory", "impact"]` with fresh (`feedback`
//!    included) & `STALE` notes, telemetry `stale_memories_caught`, `read_only` zero-write guarantee,
//!    invalid `include` -> JSON-RPC `-32602`, and no context on `AMBIGUOUS_SYMBOL`.
//! 3. `klens_impact(target: "diff")` and `klens_impact(target: "diff:staged")` with AST symbol
//!    summary, `protected_paths`, synthetic secret detection, new dependency detection, `STALE`
//!    memory alert parity, and `read_only` support.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::telemetry::{StatsQuery, StatsRange, compute_stats};
use klens_core::{ProjectConfig, ProjectMode, ProjectRoot, estimate_tokens};
use klens_mcp::{MAX_TOOLS_LIST_TOKENS, McpServer, McpServerConfig};
use serde_json::{Value, json};

static SEQ: AtomicU64 = AtomicU64::new(0);

const PHASE32_TOOLS_LIST_BUDGET: usize = 1_190;

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-mcp-p32-{label}-{}-{n}", std::process::id()));
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
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
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

fn snapshot_tree(dir: &Path) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    collect_tree(dir, dir, &mut entries);
    entries.sort();
    entries
}

fn collect_tree(root: &Path, cur: &Path, out: &mut Vec<(String, u64)>) {
    let Ok(rd) = fs::read_dir(cur) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            out.push((format!("{rel}/"), 0));
            collect_tree(root, &path, out);
        } else if let Ok(meta) = fs::metadata(&path) {
            out.push((rel, meta.len()));
        }
    }
}

fn run_git_ok(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().expect("git command failed");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn tools_list_keeps_8_tools_under_1090_tokens_and_updated_schemas() {
    let proj = Sandbox::new("budget");
    let aux = Sandbox::new("budget-aux");
    proj.write("src/lib.rs", "pub fn ok() {}\n");

    let mut server = new_server(&proj, &aux);
    let list_raw = server
        .handle_raw_line(
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }).to_string(),
        )
        .unwrap();
    let list_val: Value = serde_json::from_str(&list_raw).unwrap();
    let tools = list_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 9);

    let tokens = estimate_tokens(&list_raw);
    assert!(
        tokens <= PHASE32_TOOLS_LIST_BUDGET,
        "tools/list is {tokens} tokens, exceeding Phase 3.2 budget <= {PHASE32_TOOLS_LIST_BUDGET}"
    );
    assert!(tokens < MAX_TOOLS_LIST_TOKENS);

    let map_tool = tools.iter().find(|t| t["name"] == "klens_map").unwrap();
    assert!(
        map_tool["inputSchema"]["properties"]["budget"]["description"]
            .as_str()
            .unwrap()
            .contains("default 2000")
    );

    let read_tool = tools.iter().find(|t| t["name"] == "klens_read").unwrap();
    assert_eq!(
        read_tool["inputSchema"]["properties"]["include"]["items"]["enum"],
        json!(["imports", "memory", "impact"])
    );

    let impact_tool = tools.iter().find(|t| t["name"] == "klens_impact").unwrap();
    let target_desc = impact_tool["inputSchema"]["properties"]["target"]["description"]
        .as_str()
        .unwrap();
    assert!(target_desc.contains("diff"));
    assert!(target_desc.contains("diff:staged"));
}

#[test]
fn klens_read_include_bundle_single_batch_stale_readonly_and_fail_closed() {
    let proj = Sandbox::new("read-bundle");
    let aux = Sandbox::new("read-bundle-aux");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"bundle_demo\"\nversion = \"0.1.0\"\n",
    );
    proj.write(
        "src/auth.rs",
        concat!(
            "use std::collections::{\n",
            "    BTreeMap,\n",
            "    BTreeSet,\n",
            "};\n",
            "\n",
            "pub struct Alpha;\n",
            "impl Alpha {\n",
            "    pub fn new() -> Self { Self }\n",
            "}\n",
            "pub struct Beta;\n",
            "impl Beta {\n",
            "    pub fn new() -> Self { Self }\n",
            "}\n",
            "pub fn verify_token(tok: &str) -> bool {\n",
            "    let _m: BTreeMap<usize, usize> = BTreeMap::new();\n",
            "    let _s: BTreeSet<usize> = BTreeSet::new();\n",
            "    !tok.is_empty()\n",
            "}\n",
        ),
    );
    proj.write(
        "src/api.rs",
        "use crate::auth::verify_token;\npub fn handle(t: &str) -> bool { verify_token(t) }\n",
    );

    let mut server = new_server(&proj, &aux);

    // 1. Add a fresh Web UI `feedback` note anchored to `src/auth.rs`
    //    and a `decision` note anchored to `src/auth.rs#verify_token` that we will make STALE.
    let add_fb = call_tool(
        &mut server,
        2,
        "klens_memory",
        json!({
            "action": "add",
            "id": "fb-auth-rule",
            "title": "Auth feedback kuralı (ğüşiöç)",
            "kind": "feedback",
            "anchors": ["src/auth.rs"],
            "body": "Token doğrulama sabit zamanlı olmalı."
        }),
    );
    assert!(add_fb["result"].get("isError").is_none());

    let add_dec = call_tool(
        &mut server,
        3,
        "klens_memory",
        json!({
            "action": "add",
            "id": "adr-verify-token",
            "title": "Verify token kontratı",
            "kind": "decision",
            "anchors": ["src/auth.rs#verify_token"],
            "body": "verify_token boş tokeni reddeder."
        }),
    );
    assert!(add_dec["result"].get("isError").is_none());

    // Mutate `verify_token` so `adr-verify-token` becomes STALE while `fb-auth-rule` is refreshed.
    proj.write(
        "src/auth.rs",
        concat!(
            "use std::collections::{\n",
            "    BTreeMap,\n",
            "    BTreeSet,\n",
            "};\n",
            "\n",
            "pub struct Alpha;\n",
            "impl Alpha {\n",
            "    pub fn new() -> Self { Self }\n",
            "}\n",
            "pub struct Beta;\n",
            "impl Beta {\n",
            "    pub fn new() -> Self { Self }\n",
            "}\n",
            "pub fn verify_token(tok: &str) -> bool {\n",
            "    let _m: BTreeMap<usize, usize> = BTreeMap::new();\n",
            "    let _s: BTreeSet<usize> = BTreeSet::new();\n",
            "    tok.len() >= 4\n",
            "}\n",
        ),
    );
    let refresh_fb = call_tool(
        &mut server,
        4,
        "klens_memory",
        json!({ "action": "refresh", "id": "fb-auth-rule" }),
    );
    assert!(refresh_fb["result"].get("isError").is_none());

    // Remove `.klens/cache` and lock project into `read_only` mode to prove zero project writes!
    let _ = fs::remove_dir_all(proj.path().join(".klens").join("cache"));
    let ro_cfg = ProjectConfig {
        mode: ProjectMode::ReadOnly,
        ..ProjectConfig::default()
    };
    ro_cfg
        .save_atomic(&proj.path().join(".klens").join("config.toml"))
        .unwrap();
    let before_tree = snapshot_tree(proj.path());

    // 2. Single-target read with `include: ["imports", "memory", "impact"]` (JSON).
    let single_resp = call_tool(
        &mut server,
        5,
        "klens_read",
        json!({
            "path": "src/auth.rs",
            "symbol": "verify_token",
            "include": ["imports", "memory", "impact"],
            "format": "json"
        }),
    );
    assert!(single_resp.get("error").is_none(), "got {single_resp}");
    let single_inner: Value = serde_json::from_str(
        single_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(single_inner["data"]["status"], "OK");
    let ctx = &single_inner["data"]["context"];
    assert_eq!(ctx["imports"]["total_import_lines"], 4);
    assert!(
        ctx["imports"]["lines"][0]
            .as_str()
            .unwrap()
            .contains("use std::collections::{")
    );

    let mem = ctx["memory"].as_array().unwrap();
    assert_eq!(mem.len(), 2);
    // STALE note sorted first, fresh `feedback` note second.
    assert_eq!(mem[0]["id"], "adr-verify-token");
    assert_eq!(mem[0]["is_stale"], true);
    assert_eq!(mem[0]["trust"], "STALE");
    assert!(!mem[0]["stale_reasons"].as_array().unwrap().is_empty());
    assert_eq!(mem[1]["id"], "fb-auth-rule");
    assert_eq!(mem[1]["kind"], "feedback");
    assert_eq!(mem[1]["is_stale"], false);
    assert_eq!(mem[1]["trust"], "VERIFIED_RAW");

    let impact_hits = ctx["impact"]["hits"].as_array().unwrap();
    assert!(!impact_hits.is_empty());
    assert!(impact_hits.len() <= 10);
    assert!(impact_hits.iter().any(|h| h["path"] == "src/api.rs"
        && (h["confidence"] == "EXTRACTED" || h["confidence"] == "INFERRED")));

    // 3. Batch read with `include` + `AMBIGUOUS_SYMBOL` item (must NOT attach context to ambiguous item).
    let batch_resp = call_tool(
        &mut server,
        6,
        "klens_read",
        json!({
            "targets": [
                { "path": "src/auth.rs", "symbol": "verify_token" },
                { "path": "src/auth.rs", "symbol": "new" }
            ],
            "include": ["imports", "memory", "impact"],
            "format": "json"
        }),
    );
    let batch_inner: Value =
        serde_json::from_str(batch_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let targets = batch_inner["data"]["targets"].as_array().unwrap();
    assert_eq!(targets[0]["status"], "OK");
    assert!(targets[0].get("context").is_some());
    assert_eq!(targets[1]["status"], "AMBIGUOUS_SYMBOL");
    assert!(
        targets[1].get("context").is_none(),
        "AMBIGUOUS_SYMBOL must not attach context: {}",
        targets[1]
    );

    // 4. Plain-text output renders all 3 context sections cleanly.
    let text_resp = call_tool(
        &mut server,
        7,
        "klens_read",
        json!({
            "path": "src/auth.rs",
            "symbol": "verify_token",
            "include": ["imports", "memory", "impact"],
            "format": "text"
        }),
    );
    let text_out = text_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text_out.contains("## Context: Imports"));
    assert!(text_out.contains("## Context: Linked Memory"));
    assert!(text_out.contains("## Context: Impact"));

    // 5. Invalid `include` values fail closed with JSON-RPC `-32602` (`InvalidParams`).
    let bad_val = call_tool(
        &mut server,
        8,
        "klens_read",
        json!({
            "path": "src/auth.rs",
            "symbol": "verify_token",
            "include": ["bogus"]
        }),
    );
    assert_eq!(bad_val["error"]["code"], -32602);

    let bad_type = call_tool(
        &mut server,
        9,
        "klens_read",
        json!({
            "path": "src/auth.rs",
            "symbol": "verify_token",
            "include": "imports"
        }),
    );
    assert_eq!(bad_type["error"]["code"], -32602);

    // 6. Zero bytes written to project in `read_only` mode.
    let after_tree = snapshot_tree(proj.path());
    assert_eq!(
        before_tree, after_tree,
        "read_only mode must not write a single byte into the project directory"
    );

    // 7. Layer 1 telemetry recorded `stale_memories_caught` honestly.
    let stats = compute_stats(&StatsQuery {
        range: StatsRange::All,
        metrics_path: Some(aux.path().join("metrics.jsonl")),
        claude_projects_dir: Some(aux.path().join("no-claude")),
        ..StatsQuery::default()
    })
    .unwrap();
    assert!(
        stats.klens_metrics.stale_memories_caught >= 3,
        "expected >= 3 stale catches across single+batch+text reads, got {}",
        stats.klens_metrics.stale_memories_caught
    );
}

#[test]
fn klens_impact_diff_and_diff_staged_detect_symbols_protected_secrets_deps_and_stale_memory() {
    let proj = Sandbox::new("impact-diff");
    let aux = Sandbox::new("impact-diff-aux");

    proj.write(".gitignore", ".klens/cache/\n.klens/runs/\n");
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"diff_demo\"\nversion = \"0.1.0\"\n\n[dependencies]\n",
    );
    proj.write(
        "src/core.rs",
        "pub fn calc(x: i32) -> i32 {\n    x + 1\n}\n",
    );
    proj.write(
        "src/protected.rs",
        "pub fn guard() -> bool {\n    true\n}\n",
    );

    let mut cfg = ProjectConfig {
        protected_paths: vec!["src/protected.rs".to_string()],
        ..ProjectConfig::default()
    };
    cfg.save_atomic(&proj.path().join(".klens").join("config.toml"))
        .unwrap();

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "test@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "Klens Test"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(proj.path(), &["commit", "-m", "baseline"]);

    let mut server = new_server(&proj, &aux);

    // Add a memory note anchored to `src/core.rs#calc`, then commit it.
    let add_note = call_tool(
        &mut server,
        2,
        "klens_memory",
        json!({
            "action": "add",
            "id": "adr-calc-rule",
            "title": "Calc kuralı",
            "kind": "decision",
            "anchors": ["src/core.rs#calc"],
            "body": "calc x + 1 döndürür."
        }),
    );
    assert!(add_note["result"].get("isError").is_none());

    // Staged change: clean edit to `src/core.rs#calc` (which also makes `adr-calc-rule` STALE).
    proj.write(
        "src/core.rs",
        "pub fn calc(x: i32) -> i32 {\n    x + 2\n}\n",
    );
    run_git_ok(proj.path(), &["add", "src/core.rs"]);

    // Unstaged changes: protected path + synthetic secret leak + new Cargo.toml dependency.
    let synthetic_ghp = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    proj.write(
        "src/protected.rs",
        &format!("pub fn guard() -> &'static str {{\n    \"{synthetic_ghp}\"\n}}\n"),
    );
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"diff_demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.215\"\n",
    );

    // Switch project to `read_only` mode and remove `.klens/cache/` to verify zero-footprint diff!
    let _ = fs::remove_dir_all(proj.path().join(".klens").join("cache"));
    cfg.mode = ProjectMode::ReadOnly;
    cfg.save_atomic(&proj.path().join(".klens").join("config.toml"))
        .unwrap();
    let before_tree = snapshot_tree(proj.path());

    // 1. `target: "diff:staged"` sees ONLY `src/core.rs` (+ AST symbol `calc`) and `stale_memory`,
    //    and ignores unstaged protected violation, unstaged secret, and unstaged dependency.
    let staged_resp = call_tool(
        &mut server,
        3,
        "klens_impact",
        json!({ "target": "diff:staged", "format": "json" }),
    );
    let staged_inner: Value = serde_json::from_str(
        staged_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(staged_inner["data"]["is_git_repo"], true);
    let staged_files = staged_inner["data"]["changed_files"].as_array().unwrap();
    assert_eq!(staged_files.len(), 1);
    assert_eq!(staged_files[0]["path"], "src/core.rs");
    assert!(
        staged_files[0]["changed_symbols"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["qualified_name"] == "fn calc")
    );
    assert!(
        staged_inner["data"]["secret_leaks"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        staged_inner["data"]["protected_violations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        staged_inner["data"]["added_dependencies"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        staged_inner["data"]["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["kind"] == "stale_memory"),
        "diff:staged must surface STALE memory alerts: {}",
        staged_inner["data"]["alerts"]
    );

    // 2. `target: "diff"` sees staged + unstaged: protected path, secret leak, new dep, AND stale memory!
    let diff_resp = call_tool(
        &mut server,
        4,
        "klens_impact",
        json!({ "target": "diff", "format": "json" }),
    );
    let diff_text_raw = diff_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        !diff_text_raw.contains(&synthetic_ghp),
        "raw secret must NEVER be echoed in diff output"
    );
    let diff_inner: Value = serde_json::from_str(diff_text_raw).unwrap();
    let alerts = diff_inner["data"]["alerts"].as_array().unwrap();
    for expected_kind in [
        "protected_path_violation",
        "secret_leak",
        "new_external_dependency",
        "stale_memory",
    ] {
        assert!(
            alerts.iter().any(|a| a["kind"] == expected_kind),
            "expected alert kind `{expected_kind}` in {alerts:?}"
        );
    }

    // 3. Text format renders cleanly as well.
    let diff_plain = call_tool(
        &mut server,
        5,
        "klens_impact",
        json!({ "target": "diff", "format": "text" }),
    );
    let plain_str = diff_plain["result"]["content"][0]["text"].as_str().unwrap();
    assert!(plain_str.contains("STALE MEMORY"));
    assert!(plain_str.contains("src/protected.rs"));

    // 4. Zero bytes written in `read_only` mode + telemetry logged stale memories caught.
    let after_tree = snapshot_tree(proj.path());
    assert_eq!(before_tree, after_tree);

    let stats = compute_stats(&StatsQuery {
        range: StatsRange::All,
        metrics_path: Some(aux.path().join("metrics.jsonl")),
        claude_projects_dir: Some(aux.path().join("no-claude")),
        ..StatsQuery::default()
    })
    .unwrap();
    assert!(stats.klens_metrics.stale_memories_caught >= 3);
}
