//! Full Constitutional & Pre-Release Audit Suite (`tests/constitution_audit.rs`).
//!
//! Together with `tests/adversarial_truth.rs` (Articles 2, 3, 5 + Blacklist #1, #2, #6, #7)
//! and `tests/dep_budget.rs` (core dependency & zero-network budget), this suite locks all
//! 8 Articles of the Zero-Misleading Constitution (`docs/00-VISION-AND-CONSTITUTION.md`),
//! all 14 Regression Blacklist items, Windows `stdio`/CRLF/WAL/CREATE_NO_WINDOW guarantees,
//! and the Phase 6 `klens ext` out-of-core extension layer in one `cargo test --workspace` run.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use klens_code::{CodeIndex, outline_file};
use klens_core::telemetry::{StatsQuery, StatsRange, compute_stats};
use klens_core::{
    CommandFilter, ProjectRoot, RelPath, TrustLevel, blake3_text, estimate_tokens, known_extensions,
};
use klens_exec::{CargoFilter, WINDOWS_CREATE_NO_WINDOW, contains_ansi, strip_ansi};
use klens_mcp::{MAX_TOOLS_LIST_TOKENS, tool_definitions};
use klens_memory::{
    AddMemoryRequest, AnchorSpec, HeuristicSymbolResolver, MemoryKind, add_memory, get_memory,
    verify_all_notes,
};
use klens_ui::assets::{
    ALL_I18N_BUNDLES, APP_JS, INDEX_HTML, STYLE_CSS, VIEWS_BOARD_JS, VIEWS_VAULT_JS,
};

static AUDIT_SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let seq = AUDIT_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-audit-{label}-{}-{seq}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn write(&self, rel: &str, content: &str) {
        let target = self.dir.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(target, content).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for ancestor in manifest_dir.ancestors() {
        if ancestor.join("Cargo.lock").is_file() && ancestor.join("LICENSE").is_file() {
            return ancestor.to_path_buf();
        }
    }
    panic!("workspace root not found from {}", manifest_dir.display());
}

// ---------------------------------------------------------------------------
// Article 1 & 6 + Windows CRLF: Filesystem Single Truth, Cache Rebuild, STALE
// ---------------------------------------------------------------------------

#[test]
fn article_1_and_6_cache_deletion_loses_zero_data_and_crlf_never_triggers_false_stale() {
    let proj = Sandbox::new("art1-6-crlf");
    proj.write(
        "src/lib.rs",
        "pub fn stable_fn(x: i32) -> i32 {\n    x + 1\n}\n",
    );

    let root = ProjectRoot::new(proj.path()).unwrap();

    // 1. Build writable SQLite cache at `.klens/cache/index.db` and read outline.
    let outline_before = {
        let mut idx = CodeIndex::open(root.clone(), false).unwrap();
        idx.sync_workspace().unwrap();
        outline_file(&mut idx, &RelPath::normalize("src/lib.rs").unwrap(), None).unwrap()
    };
    let db_path = proj.path().join(".klens").join("cache").join("index.db");
    assert!(db_path.is_file(), "expected index.db cache file");

    // 2. Anchor a memory note to `src/lib.rs`.
    let mut resolver = HeuristicSymbolResolver::new(&root);
    let created = add_memory(
        &root,
        AddMemoryRequest {
            id: Some("adr-crlf-proof".to_string()),
            title: "CRLF stability decision".to_string(),
            kind: MemoryKind::Decision,
            body: "Line endings on Windows must not cause false STALE alarms.".to_string(),
            anchors: vec![AnchorSpec {
                path: "src/lib.rs".to_string(),
                symbol: None,
            }],
            tags: vec!["windows".to_string()],
        },
        &mut resolver,
    )
    .unwrap();
    assert_eq!(created.trust, TrustLevel::VerifiedRaw);

    // 3. Delete the entire `.klens/cache/` directory (Article 6: cache is disposable).
    fs::remove_dir_all(proj.path().join(".klens").join("cache")).unwrap();
    assert!(!db_path.exists());

    // Rebuilding produces identical AST output; memory note remains intact.
    let outline_after = {
        let mut idx = CodeIndex::open(root.clone(), false).unwrap();
        idx.sync_workspace().unwrap();
        outline_file(&mut idx, &RelPath::normalize("src/lib.rs").unwrap(), None).unwrap()
    };
    assert_eq!(
        serde_json::to_string(&outline_before).unwrap(),
        serde_json::to_string(&outline_after).unwrap()
    );

    // 4. Convert `src/lib.rs` from LF to Windows CRLF — hash MUST stay identical (no false STALE).
    assert_eq!(blake3_text("a\nb\n"), blake3_text("a\r\nb\r\n"));
    proj.write(
        "src/lib.rs",
        "pub fn stable_fn(x: i32) -> i32 {\r\n    x + 1\r\n}\r\n",
    );
    let verified_crlf = get_memory(&root, "adr-crlf-proof", &mut resolver).unwrap();
    assert_eq!(
        verified_crlf.trust,
        TrustLevel::VerifiedRaw,
        "CRLF conversion must NEVER trigger a false STALE alarm"
    );

    // 5. Genuine code edit MUST flip trust to `STALE` with explicit warning (Article 1).
    proj.write(
        "src/lib.rs",
        "pub fn stable_fn(x: i32) -> i32 {\r\n    x + 99\r\n}\r\n",
    );
    let verified_stale = get_memory(&root, "adr-crlf-proof", &mut resolver).unwrap();
    assert_eq!(verified_stale.trust, TrustLevel::Stale);
    assert!(!verified_stale.warnings.is_empty());

    let report = verify_all_notes(&root, &mut resolver).unwrap();
    assert_eq!(report.data.stale_count, 1);
}

// ---------------------------------------------------------------------------
// Article 4 + Blacklist #3, #4, #5: Zero Error Loss, ANSI Strip, CREATE_NO_WINDOW
// ---------------------------------------------------------------------------

#[test]
fn article_4_and_blacklist_3_4_5_ansi_strip_error_block_context_and_no_window() {
    // Blacklist #5: Windows CREATE_NO_WINDOW constant locked to 0x0800_0000.
    assert_eq!(WINDOWS_CREATE_NO_WINDOW, 0x0800_0000);

    // Blacklist #4: ANSI SGR & OSC sequences stripped completely before filtering.
    let raw_ansi = concat!(
        "\x1b[1;32m   Compiling\x1b[0m demo v0.1.0\n",
        "\x1b[1;31merror[E0308]\x1b[0m: mismatched types\n",
        " \x1b[1;34m-->\x1b[0m src/main.rs:42:5\n",
        "  \x1b[1;34m|\x1b[0m\n",
        "42 |     let x: u32 = \"oops\";\n",
        "   |            ---   ^^^^^^ expected `u32`, found `&str`\n",
        "   = \x1b[1mnote\x1b[0m: expected type `u32`\n",
        "   = \x1b[1mhelp\x1b[0m: parse the string with `.parse::<u32>()`\n",
    );
    let cleaned = strip_ansi(raw_ansi);
    assert!(!contains_ansi(&cleaned));

    // Blacklist #3 + Article 4: CargoFilter preserves full error block, pointer, code, note, help.
    let filter = CargoFilter;
    let filtered = filter.filter("", &cleaned, 101);
    assert!(
        !filtered.truncated_errors,
        "Article 4 forbids truncating errors"
    );
    assert!(filtered.summary.contains("error[E0308]: mismatched types"));
    assert!(filtered.summary.contains("--> src/main.rs:42:5"));
    assert!(filtered.summary.contains("let x: u32 = \"oops\";"));
    assert!(filtered.summary.contains("note: expected type `u32`"));
    assert!(filtered.summary.contains("help: parse the string"));
}

// ---------------------------------------------------------------------------
// Article 7 + Blacklist #8..#12: Real Stats, No Fake %81, Responsive Grid, Themes
// ---------------------------------------------------------------------------

#[test]
fn article_7_and_blacklist_8_to_12_zero_fake_stats_and_ui_css_parity() {
    // No hardcoded fake savings percentage (`%81` / `81%`) anywhere in UI assets or i18n.
    for asset in [
        INDEX_HTML,
        STYLE_CSS,
        APP_JS,
        VIEWS_BOARD_JS,
        VIEWS_VAULT_JS,
    ] {
        assert!(
            !asset.contains("%81"),
            "fake hardcoded %81 found in UI asset"
        );
        assert!(
            !asset.contains("81%"),
            "fake hardcoded 81% found in UI asset"
        );
    }
    for (lang, bundle) in ALL_I18N_BUNDLES {
        assert!(
            !bundle.contains("%81") && !bundle.contains("81%"),
            "fake hardcoded 81% found in i18n bundle `{lang}`"
        );
    }

    // Blacklist #12 & #14: responsive auto-fit grid + light/dark theme support.
    assert!(STYLE_CSS.contains("auto-fit"), "KPI grid must use auto-fit");
    assert!(
        STYLE_CSS.contains("prefers-color-scheme: light"),
        "CSS must support prefers-color-scheme: light"
    );
    assert!(
        STYLE_CSS.contains("[data-theme=\"light\"]"),
        "CSS must support manual light theme toggle"
    );

    // Blacklist #8, #9, #10, #11: verify host log streaming parser rules end-to-end.
    let tmp = Sandbox::new("art7-stats");
    let big_bash = "z".repeat(25_000);
    let big_read = "r".repeat(25_000);
    let log_lines = [
        serde_json::json!({
            "type": "assistant",
            "timestamp": "2026-11-22T18:00:00Z",
            "sessionId": "s1",
            "message": {
                "model": "claude-sonnet-4",
                "usage": { "input_tokens": 500, "output_tokens": 100 },
                "content": [
                    { "type": "tool_use", "id": "b1", "name": "Bash", "input": { "command": "ls" } },
                    { "type": "tool_use", "id": "r1", "name": "Read", "input": { "file_path": "a.rs", "offset": 1, "limit": 50 } },
                    { "type": "tool_use", "id": "r2", "name": "Read", "input": { "file_path": "a.rs", "offset": 51, "limit": 50 } },
                    { "type": "tool_use", "id": "r3", "name": "Read", "input": { "file_path": "a.rs", "offset": 25, "limit": 40 } },
                    { "type": "tool_use", "id": "k1", "name": "mcp__klens__klens_map", "input": {} }
                ]
            }
        }),
        serde_json::json!({
            "type": "user",
            "timestamp": "2026-11-22T18:00:02Z",
            "message": {
                "content": [
                    { "type": "tool_result", "tool_use_id": "b1", "content": big_bash },
                    { "type": "tool_result", "tool_use_id": "r1", "content": big_read }
                ]
            }
        }),
    ];
    let serialized: String = log_lines
        .iter()
        .map(|v| format!("{}\n", serde_json::to_string(v).unwrap()))
        .collect();
    tmp.write("projects/RealProj/s1/subagents/sub1.jsonl", &serialized);

    let report = compute_stats(&StatsQuery {
        range: StatsRange::All,
        metrics_path: Some(tmp.path().join("missing-metrics.jsonl")),
        claude_projects_dir: Some(tmp.path().join("projects")),
        now_unix_secs: Some(1_795_372_200),
        ..StatsQuery::default()
    })
    .unwrap();
    let totals = report.host_totals.unwrap();
    assert_eq!(
        totals.big_file_reads, 1,
        "Bash output must NOT count as big_file_reads"
    );
    assert_eq!(
        totals.repeated_overlapping_reads, 1,
        "non-overlapping chunk reads must NOT trigger repeated_overlapping_reads"
    );
    assert_eq!(report.recent_sessions[0].project, "RealProj");
    assert_ne!(report.recent_sessions[0].project, "subagents");
    assert_eq!(report.klens_metrics.klens_calls, 1);
}

// ---------------------------------------------------------------------------
// Article 8 + Blacklist #14: Zero-Stdout Lint, LICENSE Parity, Idempotent Init
// ---------------------------------------------------------------------------

#[test]
fn article_8_library_crates_deny_stdout_and_license_matches_cargo_toml() {
    let root = workspace_root();
    let lib_crates = [
        "klens-core",
        "klens-code",
        "klens-exec",
        "klens-memory",
        "klens-blueprint",
        "klens-mcp",
        "klens-ui",
        "klens-adapters",
    ];
    for crate_name in lib_crates {
        let lib_rs = root
            .join("crates")
            .join(crate_name)
            .join("src")
            .join("lib.rs");
        let text = fs::read_to_string(&lib_rs)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", lib_rs.display()));
        assert!(
            text.contains("#![deny(clippy::print_stdout)]"),
            "{} must enforce #![deny(clippy::print_stdout)]",
            lib_rs.display()
        );
        assert!(
            text.contains("#![forbid(unsafe_code)]"),
            "{} must enforce #![forbid(unsafe_code)]",
            lib_rs.display()
        );
    }

    let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let license_txt = fs::read_to_string(root.join("LICENSE")).unwrap();
    // v0.3.2+: source-available under PolyForm Strict 1.0.0 (personal/noncommercial use only).
    assert!(cargo_toml.contains("license = \"LicenseRef-PolyForm-Strict-1.0.0\""));
    assert!(license_txt.starts_with("# PolyForm Strict License 1.0.0"));
    assert!(license_txt.contains("Copyright (c) 2026 trgtefecngz"));
    assert!(root.join("README.md").is_file());
    assert!(root.join("SECURITY.md").is_file());
}

#[test]
fn blacklist_14_idempotent_init_updates_moved_binary_path_without_error() {
    let proj = Sandbox::new("init-moved-bin");
    let home = Sandbox::new("init-moved-home");
    proj.write("src/main.rs", "fn main() {}\n");

    let bin = env!("CARGO_BIN_EXE_klens");
    let old_bin = proj.path().join("bin-v1").join("klens.exe");
    let new_bin = proj.path().join("bin-v2").join("klens.exe");

    let run1 = Command::new(bin)
        .args([
            "init",
            "--host",
            "claude-code",
            "--project",
            proj.path().to_str().unwrap(),
            "--binary",
            old_bin.to_str().unwrap(),
            "--json",
        ])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens init v1 failed");
    assert!(
        run1.status.success(),
        "init v1 stderr: {}",
        String::from_utf8_lossy(&run1.stderr)
    );

    // Re-running `klens init` after the binary moved must succeed and update the path cleanly.
    let run2 = Command::new(bin)
        .args([
            "init",
            "--host",
            "claude-code",
            "--project",
            proj.path().to_str().unwrap(),
            "--binary",
            new_bin.to_str().unwrap(),
            "--json",
        ])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens init v2 failed");
    assert!(
        run2.status.success(),
        "init v2 stderr: {}",
        String::from_utf8_lossy(&run2.stderr)
    );

    let mcp_json = fs::read_to_string(proj.path().join(".mcp.json")).unwrap();
    assert!(mcp_json.contains("bin-v2"));
    assert!(!mcp_json.contains("bin-v1"));
}

// ---------------------------------------------------------------------------
// Windows stdio MCP CRLF Framing + 9-Tool Token Budget (< 1,200 tokens)
// ---------------------------------------------------------------------------

#[test]
fn mcp_stdio_handles_windows_crlf_emits_pure_lf_and_stays_under_token_budget() {
    let tools = tool_definitions();
    assert_eq!(tools.len(), 9, "expected exactly 9 core MCP tools");
    let tools_json = serde_json::to_string(&serde_json::json!({ "tools": tools })).unwrap();
    let token_count = estimate_tokens(&tools_json);
    assert!(
        token_count < MAX_TOOLS_LIST_TOKENS,
        "MCP tools/list token count ({token_count}) must stay < {MAX_TOOLS_LIST_TOKENS}"
    );

    let proj = Sandbox::new("mcp-crlf");
    let home = Sandbox::new("mcp-crlf-home");
    proj.write("src/lib.rs", "pub fn hello() -> i32 { 1 }\n");

    let bin = env!("CARGO_BIN_EXE_klens");
    let mut child = Command::new(bin)
        .args(["mcp", "--project", proj.path().to_str().unwrap()])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn klens mcp");

    {
        let stdin = child.stdin.as_mut().unwrap();
        // Send Windows CRLF (`\r\n`) framed JSON-RPC messages.
        stdin
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"clientInfo\":{\"name\":\"audit\",\"version\":\"1.0\"}}}\r\n",
            )
            .unwrap();
        stdin
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\r\n",
            )
            .unwrap();
        stdin.flush().unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "klens mcp stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.contains(&b'\r'),
        "MCP stdout MUST emit pure LF (\\n), never CR (\\r)"
    );
    let stdout_str = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout_str.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected exactly 2 JSON-RPC responses, zero stdout noise"
    );
    let r1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let r2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r1["id"], 1);
    assert_eq!(r2["id"], 2);
    assert_eq!(r2["result"]["tools"].as_array().unwrap().len(), 9);
    assert!(
        !proj.path().join(".klens").exists(),
        "MCP initialize + tools/list must write 0 files into project"
    );
}

// ---------------------------------------------------------------------------
// SQLite WAL + busy_timeout Concurrent Access Verification
// ---------------------------------------------------------------------------

#[test]
fn sqlite_wal_mode_supports_concurrent_readers_without_sqlite_busy() {
    let proj = Sandbox::new("sqlite-wal");
    proj.write("src/a.rs", "pub fn alpha() -> i32 { 1 }\n");
    proj.write("src/b.rs", "pub fn beta() -> i32 { 2 }\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    {
        let mut idx = CodeIndex::open(root.clone(), false).unwrap();
        idx.sync_workspace().unwrap();
    }

    // Spawn 4 concurrent threads reading from the same WAL-backed `.klens/cache/index.db`.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let r = root.clone();
        handles.push(thread::spawn(move || {
            let mut idx = CodeIndex::open(r, false).unwrap();
            for _ in 0..10 {
                let rel = RelPath::normalize("src/a.rs").unwrap();
                let out = outline_file(&mut idx, &rel, None).unwrap();
                assert_eq!(out.trust, TrustLevel::VerifiedAst);
            }
        }));
    }
    for h in handles {
        h.join().expect("concurrent WAL reader thread failed");
    }
}

// ---------------------------------------------------------------------------
// Phase 6: `klens ext` Out-of-Core Extension CLI End-to-End Verification
// ---------------------------------------------------------------------------

#[test]
fn phase6_cli_ext_list_enable_disable_fail_closed_and_deterministic() {
    assert_eq!(known_extensions().len(), 7);
    let proj = Sandbox::new("ext-cli");
    let home = Sandbox::new("ext-home");
    let bin = env!("CARGO_BIN_EXE_klens");

    // 1. `klens ext list --json` is read-only (writes zero files) and deterministic.
    let list1 = Command::new(bin)
        .args([
            "ext",
            "list",
            "--root",
            proj.path().to_str().unwrap(),
            "--json",
        ])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens ext list 1 failed");
    assert!(
        list1.status.success(),
        "ext list stderr: {}",
        String::from_utf8_lossy(&list1.stderr)
    );
    let list2 = Command::new(bin)
        .args([
            "ext",
            "list",
            "--root",
            proj.path().to_str().unwrap(),
            "--json",
        ])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens ext list 2 failed");
    assert_eq!(
        list1.stdout, list2.stdout,
        "klens ext list must be byte-for-byte deterministic"
    );
    assert!(!proj.path().join(".klens").exists());
    assert!(!home.path().join(".klens").exists());

    let lj: serde_json::Value = serde_json::from_slice(&list1.stdout).unwrap();
    assert_eq!(lj["schema_version"], 1);
    assert_eq!(lj["extensions"].as_array().unwrap().len(), 7);
    assert!(
        lj["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["default_enabled"] == false && e["effective_enabled"] == false)
    );

    // 2. Unknown extension ID fails closed (non-zero exit, zero files written).
    let bad = Command::new(bin)
        .args([
            "ext",
            "enable",
            "ext-does-not-exist",
            "--root",
            proj.path().to_str().unwrap(),
        ])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens ext enable bad failed");
    assert!(
        !bad.status.success(),
        "unknown extension ID must fail closed"
    );
    assert!(!proj.path().join(".klens").exists());

    // 3. Enable in project scope & global scope atomically.
    let en_proj = Command::new(bin)
        .args([
            "ext",
            "enable",
            "ext-lsp-bridge",
            "--root",
            proj.path().to_str().unwrap(),
            "--json",
        ])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens ext enable project failed");
    assert!(en_proj.status.success());
    let ep: serde_json::Value = serde_json::from_slice(&en_proj.stdout).unwrap();
    assert_eq!(ep["scope"], "project");
    assert_eq!(ep["enabled"], true);
    assert_eq!(ep["changed"], true);

    let en_glob = Command::new(bin)
        .args(["ext", "enable", "ext-live-docs", "--global", "--json"])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens ext enable global failed");
    assert!(en_glob.status.success());
    let eg: serde_json::Value = serde_json::from_slice(&en_glob.stdout).unwrap();
    assert_eq!(eg["scope"], "global");
    assert_eq!(eg["enabled"], true);

    // 4. `klens ext list --json` reflects both global and project enabled extensions.
    let list3 = Command::new(bin)
        .args([
            "ext",
            "list",
            "--root",
            proj.path().to_str().unwrap(),
            "--json",
        ])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens ext list 3 failed");
    let lj3: serde_json::Value = serde_json::from_slice(&list3.stdout).unwrap();
    assert_eq!(
        lj3["project_enabled"],
        serde_json::json!(["ext-lsp-bridge"])
    );
    assert_eq!(lj3["global_enabled"], serde_json::json!(["ext-live-docs"]));

    // 5. Disable both atomically.
    let dis_proj = Command::new(bin)
        .args([
            "ext",
            "disable",
            "ext-lsp-bridge",
            "--root",
            proj.path().to_str().unwrap(),
            "--json",
        ])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens ext disable project failed");
    assert!(dis_proj.status.success());
    let dp: serde_json::Value = serde_json::from_slice(&dis_proj.stdout).unwrap();
    assert_eq!(dp["enabled"], false);
    assert_eq!(dp["enabled_extensions"], serde_json::json!([]));

    let dis_glob = Command::new(bin)
        .args(["ext", "disable", "ext-live-docs", "--global", "--json"])
        .env("USERPROFILE", home.path())
        .env("HOME", home.path())
        .output()
        .expect("klens ext disable global failed");
    assert!(dis_glob.status.success());
    let dg: serde_json::Value = serde_json::from_slice(&dis_glob.stdout).unwrap();
    assert_eq!(dg["enabled"], false);
    assert_eq!(dg["enabled_extensions"], serde_json::json!([]));
}
