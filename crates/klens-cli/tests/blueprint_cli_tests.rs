//! Phase 5A end-to-end CLI tests (`klens blueprint status|check|lock|next-task|complete-task`
//! and `klens handoff [--budget] [--json] [--read-only]`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::estimate_tokens;
use serde_json::{Value, json};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-cli-p5a-{label}-{}-{n}", std::process::id()));
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

fn run_klens(proj: &Sandbox, cache: &Sandbox, args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_klens");
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd.output().expect("failed to execute klens binary")
}

#[test]
fn cli_blueprint_lock_task_queue_and_deterministic_handoff_e2e() {
    let proj = Sandbox::new("e2e");
    let cache = Sandbox::new("e2e-cache");

    proj.write(".gitignore", ".env\n.klens/cache/\n.klens/runs/\n");
    proj.write(
        ".klens/config.toml",
        "schema_version = 1\nmode = \"active\"\nprotected_paths = [\"src/core.rs\"]\n",
    );
    proj.write("src/core.rs", "pub fn version() -> u32 { 1 }\n");

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "ci@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "Klens CI"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(
        proj.path(),
        &["commit", "-m", "init: temel iskelet (ğüşiöç)"],
    );

    // 1. Write conflicting blueprint.json -> `check` reports error, `lock` exits non-zero & writes nothing.
    let bad_bp = json!({
        "schema_version": 1,
        "project_name": "KarasuCLI",
        "goal": "Deterministik CLI testi (ğüşiöç)",
        "bubbles": [
            {
                "id": "platform",
                "category": "Platform",
                "title": "Hedef?",
                "options": [
                    { "id": "web", "label": "Web", "provides": ["browser_only"], "conflicts_with": ["local_fs"] },
                    { "id": "desktop", "label": "Masaüstü", "provides": ["local_fs"], "conflicts_with": ["browser_only"] }
                ],
                "selected_option": "web",
                "user_vision_note": "Türkçe vizyon notu: ğüşiöçĞÜŞİÖÇ",
                "status": "user_confirmed",
                "depends_on": []
            },
            {
                "id": "db",
                "category": "Depolama",
                "title": "Veritabanı?",
                "options": [
                    { "id": "sqlite", "label": "SQLite", "provides": ["sqlite"], "requires": ["local_fs"], "conflicts_with": ["browser_only"] }
                ],
                "selected_option": "sqlite",
                "status": "user_confirmed",
                "depends_on": ["platform"]
            }
        ],
        "scaffold": [
            { "path": "src/core.rs", "is_dir": false, "content": "// MUST_NOT_OVERWRITE" },
            { "path": "src/new_mod.rs", "is_dir": false, "content": "pub fn fresh() {}\n" }
        ]
    });
    proj.write(
        ".klens/blueprint/blueprint.json",
        &serde_json::to_string_pretty(&bad_bp).unwrap(),
    );

    let chk_bad = run_klens(&proj, &cache, &["blueprint", "check", "--json"]);
    assert!(chk_bad.status.success());
    let chk_bad_json: Value = serde_json::from_slice(&chk_bad.stdout).unwrap();
    assert_eq!(chk_bad_json["data"]["can_lock"], false);

    let lock_bad = run_klens(&proj, &cache, &["blueprint", "lock"]);
    assert!(!lock_bad.status.success());
    assert!(
        !proj
            .path()
            .join(".klens/blueprint/PROJECT_CONTRACT.md")
            .exists()
    );

    // 2. Fix blueprint selection -> `lock --scaffold` succeeds and preserves `src/core.rs`.
    let mut good_bp = bad_bp;
    good_bp["bubbles"][0]["selected_option"] = json!("desktop");
    proj.write(
        ".klens/blueprint/blueprint.json",
        &serde_json::to_string_pretty(&good_bp).unwrap(),
    );

    let lock_ok = run_klens(
        &proj,
        &cache,
        &["blueprint", "lock", "--scaffold", "--json"],
    );
    assert!(
        lock_ok.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&lock_ok.stderr)
    );
    let lock_json: Value = serde_json::from_slice(&lock_ok.stdout).unwrap();
    assert_eq!(lock_json["trust"], "USER_LOCKED");
    assert_eq!(
        fs::read_to_string(proj.path().join("src/core.rs")).unwrap(),
        "pub fn version() -> u32 { 1 }\n"
    );
    assert!(proj.path().join("src/new_mod.rs").is_file());

    // 3. Verify `status`, `next-task`, and `complete-task`.
    let st_out = run_klens(&proj, &cache, &["blueprint", "status", "--json"]);
    assert!(st_out.status.success());
    let st_json: Value = serde_json::from_slice(&st_out.stdout).unwrap();
    assert_eq!(st_json["data"]["locked"], true);
    assert_eq!(st_json["data"]["next_ready_task"]["id"], "T01-platform");

    let nt_out = run_klens(&proj, &cache, &["blueprint", "next-task", "--json"]);
    assert!(nt_out.status.success());
    let nt_json: Value = serde_json::from_slice(&nt_out.stdout).unwrap();
    assert_eq!(nt_json["data"]["task"]["id"], "T01-platform");

    let ct_out = run_klens(
        &proj,
        &cache,
        &["blueprint", "complete-task", "T01-platform", "--json"],
    );
    assert!(ct_out.status.success());
    let ct_json: Value = serde_json::from_slice(&ct_out.stdout).unwrap();
    assert_eq!(ct_json["data"]["next_ready_task"]["id"], "T02-db");

    // 4. Add a memory note, make it STALE, and record a failing `klens run`.
    assert!(
        run_klens(
            &proj,
            &cache,
            &[
                "memory",
                "add",
                "--id",
                "adr-core-ver",
                "--title",
                "Core sürüm kuralı (ğüşiöç)",
                "--kind",
                "decision",
                "--anchor",
                "src/core.rs",
                "--body",
                "Core sürüm sabit kalmalı.\n"
            ]
        )
        .status
        .success()
    );
    proj.write("src/core.rs", "pub fn version() -> u32 { 2 }\n");

    #[cfg(windows)]
    let fail_args = [
        "run",
        "--",
        "cmd",
        "/C",
        "echo error[E0001]: Türkçe hata ğüşiöç & exit /B 1",
    ];
    #[cfg(not(windows))]
    let fail_args = [
        "run",
        "--",
        "sh",
        "-c",
        "echo 'error[E0001]: Türkçe hata ğüşiöç' && exit 1",
    ];
    assert!(!run_klens(&proj, &cache, &fail_args).status.success());

    // Remove any cache dir first so we verify `--read-only` creates zero `.klens/cache/`.
    let _ = fs::remove_dir_all(proj.path().join(".klens/cache"));

    // 5. Run `klens handoff --budget 600 --read-only` twice -> byte-for-byte identical!
    let h1 = run_klens(
        &proj,
        &cache,
        &["handoff", "--budget", "600", "--read-only"],
    );
    let h2 = run_klens(
        &proj,
        &cache,
        &["handoff", "--budget", "600", "--read-only"],
    );
    assert!(h1.status.success());
    assert!(h2.status.success());
    assert_eq!(
        h1.stdout, h2.stdout,
        "klens handoff MUST be byte-for-byte deterministic"
    );
    assert!(!proj.path().join(".klens/cache").exists());

    let h_text = String::from_utf8(h1.stdout).unwrap();
    assert!(estimate_tokens(&h_text) <= 600);
    assert!(h_text.contains("USER_LOCKED"));
    assert!(h_text.contains("PROTECTED PATHS"));
    assert!(h_text.contains("src/core.rs"));
    assert!(h_text.contains("T02-db"));
    assert!(h_text.contains("STALE"));
    assert!(h_text.contains("adr-core-ver"));
    assert!(h_text.contains("Last Failed Run"));

    // Also verify `--json` emits valid `ProvenanceEnvelope` with `schema_version == 1`.
    let hj = run_klens(
        &proj,
        &cache,
        &["handoff", "--budget", "600", "--read-only", "--json"],
    );
    assert!(hj.status.success());
    let hj_val: Value = serde_json::from_slice(&hj.stdout).unwrap();
    assert_eq!(hj_val["schema_version"], 1);
    assert_eq!(hj_val["trust"], "USER_LOCKED");
    assert_eq!(hj_val["data"]["stale_memory_count"], 1);
    assert_eq!(hj_val["data"]["has_failed_run"], true);
}

#[test]
fn regression_doctor_symbol_anchor_fresh_lockfile_not_god_node_and_turkish_git_status() {
    let proj = Sandbox::new("reg-cross");
    let cache = Sandbox::new("reg-cross-cache");

    proj.write(".gitignore", ".env\n.klens/cache/\n.klens/runs/\n");
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
    // 900-line auto-generated `Cargo.lock` must NEVER trigger God Node RED alarm!
    let mut big_lock =
        String::from("# This file is automatically @generated by Cargo.\nversion = 4\n");
    for i in 0..300 {
        big_lock.push_str(&format!(
            "[[package]]\nname = \"dep-{i}\"\nversion = \"0.1.0\"\n"
        ));
    }
    assert!(big_lock.lines().count() > 800);
    proj.write("Cargo.lock", &big_lock);

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "ci@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "Klens CI"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(proj.path(), &["commit", "-m", "baseline"]);

    // 1. Add a symbol-anchored memory note (`src/world.rs#impl World::save_chunk`).
    let add_out = run_klens(
        &proj,
        &cache,
        &[
            "memory",
            "add",
            "--id",
            "adr-sym-fresh",
            "--title",
            "Symbol anchor freshness",
            "--kind",
            "decision",
            "--anchor",
            "src/world.rs#impl World::save_chunk",
            "--body",
            "Only save_chunk is anchored.\n",
        ],
    );
    assert!(
        add_out.status.success(),
        "memory add failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );

    // `klens doctor --json` MUST report `[OK]` (0 stale) for the fresh symbol-anchored note!
    let doc_out = run_klens(&proj, &cache, &["doctor", "--json"]);
    assert!(doc_out.status.success());
    let doc_json: Value = serde_json::from_slice(&doc_out.stdout).unwrap();
    let mem_chk = doc_json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Memory staleness (.klens/memory/)")
        .expect("Memory staleness check must exist in klens doctor");
    assert_eq!(
        mem_chk["severity"], "ok",
        "fresh symbol-anchored note must NEVER be falsely flagged stale by klens doctor: {mem_chk}"
    );
    assert!(
        mem_chk["message"].as_str().unwrap().contains("0 stale"),
        "expected 0 stale message, got: {mem_chk}"
    );

    // 2. `klens health --read-only --json` MUST NOT flag the 900-line `Cargo.lock` as a God Node.
    let health_out = run_klens(&proj, &cache, &["health", "--read-only", "--json"]);
    assert!(health_out.status.success());
    let health_json: Value = serde_json::from_slice(&health_out.stdout).unwrap();
    let god_chk = health_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "god_nodes")
        .expect("god_nodes check must exist");
    assert_eq!(
        god_chk["light"], "GREEN",
        "auto-generated 900-line Cargo.lock must NOT trigger God Node alarm: {god_chk}"
    );

    // 3. Untracked Turkish filename in `klens handoff --read-only` must NOT be octal-escaped (`core.quotepath=false`).
    proj.write("src/güneş_ğüşiöç.rs", "pub fn gunes() {}\n");
    let handoff_out = run_klens(&proj, &cache, &["handoff", "--read-only"]);
    assert!(handoff_out.status.success());
    let handoff_txt = String::from_utf8(handoff_out.stdout).unwrap();
    assert!(
        handoff_txt.contains("src/güneş_ğüşiöç.rs"),
        "Turkish dirty filename must appear unescaped in handoff (core.quotepath=false), got:\n{handoff_txt}"
    );
}

#[test]
fn cli_handoff_tiny_budget_warns_on_stderr_without_polluting_stdout_or_json() {
    let proj = Sandbox::new("tiny-budget");
    let cache = Sandbox::new("tiny-budget-cache");
    proj.write("src/lib.rs", "pub fn demo() -> u32 { 42 }\n");

    // 1. Text mode with tiny `--budget 5`: single-line warning on stderr, stdout unpolluted.
    let txt_out = run_klens(&proj, &cache, &["handoff", "--budget", "5", "--read-only"]);
    assert!(txt_out.status.success());
    let stdout_str = String::from_utf8(txt_out.stdout).unwrap();
    let stderr_str = String::from_utf8(txt_out.stderr).unwrap();
    assert!(
        !stdout_str.contains("warning:"),
        "stdout must not be polluted by budget warning, got:\n{stdout_str}"
    );
    let stderr_lines: Vec<&str> = stderr_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        stderr_lines.len(),
        1,
        "expected exactly one warning line on stderr, got: {stderr_lines:?}"
    );
    assert!(
        stderr_lines[0].contains("warning:")
            && stderr_lines[0].contains("omitted")
            && stderr_lines[0].contains("--budget"),
        "expected clear budget omission warning on stderr, got: {}",
        stderr_lines[0]
    );

    // 2. JSON mode with tiny `--budget 5`: valid JSON ProvenanceEnvelope on stdout, no stderr warning.
    let json_out = run_klens(
        &proj,
        &cache,
        &["handoff", "--budget", "5", "--read-only", "--json"],
    );
    assert!(json_out.status.success());
    let parsed: Value = serde_json::from_slice(&json_out.stdout)
        .expect("`klens handoff --budget 5 --json` must remain valid JSON");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["data"]["budget_tokens"], 5);
    assert!(
        !parsed["omissions"].as_array().unwrap().is_empty(),
        "JSON envelope must explicitly record omissions"
    );
    assert!(
        String::from_utf8_lossy(&json_out.stderr).trim().is_empty(),
        "JSON mode should not emit text-mode warning to stderr"
    );
}
