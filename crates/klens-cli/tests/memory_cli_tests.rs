//! Phase 4 end-to-end CLI tests (`klens memory`, `diff-check`, `health`, `run` bugfix hook).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-cli-p4-{label}-{}-{n}", std::process::id()));
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
fn cli_memory_crud_staleness_diff_check_health_and_run_bugfix_e2e() {
    let proj = Sandbox::new("e2e");
    let cache = Sandbox::new("e2e-cache");

    proj.write(".gitignore", ".env\n.klens/cache/\n.klens/runs/\n");
    proj.write(
        "src/save.rs",
        concat!(
            "pub struct World;\n",
            "impl World {\n",
            "    pub fn save_chunk(&self, id: u32) -> bool {\n",
            "        id > 0\n",
            "    }\n",
            "}\n",
        ),
    );

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "ci@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "Klens CI"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(proj.path(), &["commit", "-m", "baseline"]);

    // 1. Add a decision note anchored to `src/save.rs#impl World::save_chunk`.
    let add_out = run_klens(
        &proj,
        &cache,
        &[
            "memory",
            "add",
            "--id",
            "adr-001-save",
            "--title",
            "Parçalı kayıt kuralı (ğüşiöç)",
            "--kind",
            "decision",
            "--anchor",
            "src/save.rs#impl World::save_chunk",
            "--tag",
            "storage",
            "--body",
            "## Karar\n[[PROJECT_CONTRACT]] uyumlu chunk kaydı.\n",
            "--json",
        ],
    );
    assert!(
        add_out.status.success(),
        "memory add failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    let add_json: Value = serde_json::from_slice(&add_out.stdout).unwrap();
    assert_eq!(add_json["trust"], "VERIFIED_RAW");

    // 2. Add a `kind: bugfix` note for error code `SQLITE_BUSY`.
    let bug_out = run_klens(
        &proj,
        &cache,
        &[
            "memory",
            "add",
            "--id",
            "bug-wal-lock",
            "--title",
            "SQLITE_BUSY kilidini WAL ile çöz",
            "--kind",
            "bugfix",
            "--anchor",
            "src/save.rs",
            "--tag",
            "sqlite",
            "--body",
            "PRAGMA journal_mode=WAL ve busy_timeout=5000 zorunlu.\n",
        ],
    );
    assert!(bug_out.status.success());

    // 3. `klens health --read-only --json` reports `memory_staleness` GREEN when all notes are fresh.
    let h_fresh = run_klens(&proj, &cache, &["health", "--read-only", "--json"]);
    assert!(h_fresh.status.success());
    let h_fresh_json: Value = serde_json::from_slice(&h_fresh.stdout).unwrap();
    let mem_chk = h_fresh_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "memory_staleness")
        .expect("memory_staleness check must appear in klens health");
    assert_eq!(mem_chk["light"], "GREEN");

    // 4. Failing `klens run` attaches the fresh `[Taze]` bugfix note!
    #[cfg(windows)]
    let fail_args = [
        "run",
        "--",
        "cmd",
        "/C",
        "echo fatal: SQLITE_BUSY database locked & exit /B 1",
    ];
    #[cfg(not(windows))]
    let fail_args = [
        "run",
        "--",
        "sh",
        "-c",
        "echo 'fatal: SQLITE_BUSY database locked' && exit 1",
    ];
    let run_fail = run_klens(&proj, &cache, &fail_args);
    assert!(!run_fail.status.success());
    let run_stdout = String::from_utf8_lossy(&run_fail.stdout);
    assert!(
        run_stdout.contains(
            "[bugfix] \"SQLITE_BUSY kilidini WAL ile çöz\" (.klens/memory/bug-wal-lock.md) [Taze]"
        ),
        "expected fresh bugfix match line in klens run stdout, got:\n{run_stdout}"
    );

    // 5. Modify `src/save.rs` -> both `diff-check` and `health` immediately catch stale memory!
    proj.write(
        "src/save.rs",
        concat!(
            "pub struct World;\n",
            "impl World {\n",
            "    pub fn save_chunk(&self, id: u32) -> bool {\n",
            "        id >= 42\n",
            "    }\n",
            "}\n",
        ),
    );

    let dc_out = run_klens(&proj, &cache, &["diff-check", "--read-only", "--json"]);
    assert!(dc_out.status.success());
    let dc_json: Value = serde_json::from_slice(&dc_out.stdout).unwrap();
    let alerts = dc_json["data"]["alerts"].as_array().unwrap();
    assert!(
        alerts.iter().any(|a| a["kind"] == "stale_memory"),
        "diff-check must emit stale_memory alert, got: {alerts:?}"
    );

    let h_stale = run_klens(&proj, &cache, &["health", "--read-only", "--json"]);
    assert!(h_stale.status.success());
    let h_stale_json: Value = serde_json::from_slice(&h_stale.stdout).unwrap();
    let mem_chk_stale = h_stale_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "memory_staleness")
        .unwrap();
    assert_eq!(mem_chk_stale["light"], "YELLOW");

    // 6. `klens memory refresh` restores freshness and keeps body intact!
    assert!(
        run_klens(&proj, &cache, &["memory", "refresh", "adr-001-save"])
            .status
            .success()
    );
    assert!(
        run_klens(&proj, &cache, &["memory", "refresh", "bug-wal-lock"])
            .status
            .success()
    );

    let ver_out = run_klens(
        &proj,
        &cache,
        &["memory", "verify", "--read-only", "--json"],
    );
    assert!(ver_out.status.success());
    let ver_json: Value = serde_json::from_slice(&ver_out.stdout).unwrap();
    assert_eq!(ver_json["trust"], "VERIFIED_RAW");
    assert_eq!(ver_json["data"]["stale_count"], 0);
    assert_eq!(ver_json["data"]["fresh_count"], 2);
}

#[test]
fn cli_corrupt_memory_markdown_triggers_health_yellow_and_diff_check_warning() {
    let proj = Sandbox::new("corrupt-md");
    let cache = Sandbox::new("corrupt-md-cache");

    proj.write(".gitignore", ".env\n.klens/cache/\n.klens/runs/\n");
    proj.write("src/lib.rs", "pub fn ok() -> bool { true }\n");
    proj.write(
        ".klens/memory/corrupt-note.md",
        "not valid frontmatter at all\njust broken text\n",
    );

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "ci@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "Klens CI"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(proj.path(), &["commit", "-m", "baseline"]);

    // `klens health --read-only --json` MUST flag `memory_staleness` as YELLOW (never GREEN!)
    // and include the malformed file diagnostic in `details`.
    let health_out = run_klens(&proj, &cache, &["health", "--read-only", "--json"]);
    assert!(health_out.status.success());
    let health_json: Value = serde_json::from_slice(&health_out.stdout).unwrap();
    let mem_chk = health_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "memory_staleness")
        .expect("memory_staleness check must be present");
    assert_eq!(
        mem_chk["light"], "YELLOW",
        "corrupt .klens/memory/*.md must NEVER pass as GREEN: {mem_chk}"
    );
    let details = mem_chk["details"].as_array().unwrap();
    assert!(
        details
            .iter()
            .any(|d| d.as_str().unwrap_or("").contains("corrupt-note.md")),
        "health details must identify corrupt-note.md, got: {details:?}"
    );

    // `klens diff-check --read-only --json` MUST surface the parse warning in `warnings`.
    let dc_out = run_klens(&proj, &cache, &["diff-check", "--read-only", "--json"]);
    assert!(dc_out.status.success());
    let dc_json: Value = serde_json::from_slice(&dc_out.stdout).unwrap();
    let warnings = dc_json["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("corrupt-note.md")),
        "diff-check warnings must surface corrupt-note.md, got: {warnings:?}"
    );
}

#[test]
fn cli_memory_export_and_batch_refresh_fail_closed_and_readonly_guards() {
    let proj = Sandbox::new("export-refresh");
    let cache = Sandbox::new("export-refresh-cache");
    let outside = Sandbox::new("export-outside");

    proj.write("src/mod_a.rs", "pub fn alpha() -> i32 { 1 }\n");
    proj.write("src/mod_b.rs", "pub fn beta() -> i32 { 2 }\n");
    proj.write("src/gone.rs", "pub fn vanish() -> i32 { 3 }\n");

    let fake_token = format!("ghp_{}", "0123456789abcdef0123456789abcdef0123");

    assert!(
        run_klens(
            &proj,
            &cache,
            &[
                "memory",
                "add",
                "--id",
                "adr-alpha",
                "--title",
                "Alpha design",
                "--kind",
                "decision",
                "--anchor",
                "src/mod_a.rs",
                "--tag",
                "core",
                "--body",
                &format!("Keep alpha pure. Secret: {fake_token}\n"),
            ],
        )
        .status
        .success()
    );
    assert!(
        run_klens(
            &proj,
            &cache,
            &[
                "memory",
                "add",
                "--id",
                "bug-beta",
                "--title",
                "Beta bugfix",
                "--kind",
                "bugfix",
                "--anchor",
                "src/mod_b.rs",
                "--tag",
                "ops",
                "--body",
                "Hand-edited beta fix body.\n",
            ],
        )
        .status
        .success()
    );
    assert!(
        run_klens(
            &proj,
            &cache,
            &[
                "memory",
                "add",
                "--id",
                "fb-gone",
                "--title",
                "Vanished anchor note",
                "--kind",
                "feedback",
                "--anchor",
                "src/gone.rs",
                "--body",
                "Do not corrupt me.\n",
            ],
        )
        .status
        .success()
    );

    // Mutate mod_b (becomes STALE) and delete gone.rs (missing_file).
    proj.write("src/mod_b.rs", "pub fn beta() -> i32 { 99 }\n");
    fs::remove_file(proj.path().join("src/gone.rs")).unwrap();

    // 1. `klens memory export --format md --read-only` emits unified redacted Markdown cleanly.
    let exp_md = run_klens(
        &proj,
        &cache,
        &["memory", "export", "--format", "md", "--read-only"],
    );
    assert!(
        exp_md.status.success(),
        "memory export md failed: {}",
        String::from_utf8_lossy(&exp_md.stderr)
    );
    let md_stdout = String::from_utf8_lossy(&exp_md.stdout);
    assert!(md_stdout.contains("# Karasu Lens Memory Export"));
    assert!(md_stdout.contains("adr-alpha"));
    assert!(md_stdout.contains("bug-beta"));
    assert!(md_stdout.contains("[REDACTED:GITHUB_TOKEN]"));
    assert!(!md_stdout.contains(&fake_token));

    // 2. `klens memory export --format json --read-only` emits ProvenanceEnvelope JSON.
    let exp_json_out = run_klens(
        &proj,
        &cache,
        &["memory", "export", "--format", "json", "--read-only"],
    );
    assert!(exp_json_out.status.success());
    let exp_json: Value = serde_json::from_slice(&exp_json_out.stdout).unwrap();
    assert_eq!(exp_json["schema_version"], 1);
    assert_eq!(exp_json["data"]["total_notes"], 3);
    assert_eq!(exp_json["data"]["stale_count"], 2);
    assert_eq!(exp_json["redactions_count"], 1);
    assert!(!String::from_utf8_lossy(&exp_json_out.stdout).contains(&fake_token));

    // 3. `--read-only` MUST fail-closed when `--out` points inside the project root!
    let inside_out = proj.path().join("exported.md");
    let blocked_out = run_klens(
        &proj,
        &cache,
        &[
            "memory",
            "export",
            "--format",
            "md",
            "--read-only",
            "--out",
            inside_out.to_str().unwrap(),
        ],
    );
    assert!(
        !blocked_out.status.success(),
        "--read-only must reject writing --out inside project root"
    );
    assert!(
        String::from_utf8_lossy(&blocked_out.stderr)
            .contains("read-only mode forbids writing inside the project root"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&blocked_out.stderr)
    );
    assert!(!inside_out.exists(), "blocked export must write 0 bytes");

    // 4. `--out` outside the project root succeeds atomically even with `--read-only`!
    let outside_out = outside.path().join("vault-export.md");
    let ok_outside = run_klens(
        &proj,
        &cache,
        &[
            "memory",
            "export",
            "--format",
            "md",
            "--read-only",
            "--out",
            outside_out.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(
        ok_outside.status.success(),
        "export --out outside project failed: {}",
        String::from_utf8_lossy(&ok_outside.stderr)
    );
    let outside_summary: Value = serde_json::from_slice(&ok_outside.stdout).unwrap();
    assert_eq!(outside_summary["data"]["total_notes"], 3);
    assert!(outside_out.is_file());
    let disk_export = fs::read_to_string(&outside_out).unwrap();
    assert!(disk_export.contains("[REDACTED:GITHUB_TOKEN]"));
    assert!(!disk_export.contains(&fake_token));

    // 5. `klens memory refresh` with no `<ID>` and no `--all` MUST fail closed.
    let no_args = run_klens(&proj, &cache, &["memory", "refresh"]);
    assert!(!no_args.status.success());
    assert!(
        String::from_utf8_lossy(&no_args.stderr).contains("specify a note <ID> or pass --all"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&no_args.stderr)
    );

    // 6. `klens memory refresh --all --read-only` MUST fail closed.
    let ro_refresh = run_klens(
        &proj,
        &cache,
        &["memory", "refresh", "--all", "--read-only"],
    );
    assert!(!ro_refresh.status.success());

    // 7. `klens memory refresh --all --dry-run --json` plans refresh without modifying disk!
    let beta_before = fs::read(proj.path().join(".klens/memory/bug-beta.md")).unwrap();
    let gone_before = fs::read(proj.path().join(".klens/memory/fb-gone.md")).unwrap();

    let dry_out = run_klens(
        &proj,
        &cache,
        &["memory", "refresh", "--all", "--dry-run", "--json"],
    );
    assert!(
        dry_out.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    let dry_json: Value = serde_json::from_slice(&dry_out.stdout).unwrap();
    assert_eq!(dry_json["data"]["dry_run"], true);
    assert_eq!(dry_json["data"]["refreshed"].as_array().unwrap().len(), 1);
    assert_eq!(dry_json["data"]["refreshed"][0]["id"], "bug-beta");
    assert_eq!(dry_json["data"]["failed"].as_array().unwrap().len(), 1);
    assert_eq!(dry_json["data"]["failed"][0]["id"], "fb-gone");
    assert_eq!(
        fs::read(proj.path().join(".klens/memory/bug-beta.md")).unwrap(),
        beta_before,
        "dry-run must write 0 bytes"
    );

    // 8. Real `klens memory refresh --all --json` refreshes `bug-beta` and leaves `fb-gone` intact!
    let apply_out = run_klens(&proj, &cache, &["memory", "refresh", "--all", "--json"]);
    assert!(
        apply_out.status.success(),
        "refresh --all failed: {}",
        String::from_utf8_lossy(&apply_out.stderr)
    );
    let apply_json: Value = serde_json::from_slice(&apply_out.stdout).unwrap();
    assert_eq!(apply_json["data"]["dry_run"], false);
    assert_eq!(apply_json["data"]["refreshed"].as_array().unwrap().len(), 1);
    assert_eq!(apply_json["data"]["refreshed"][0]["id"], "bug-beta");
    assert_eq!(apply_json["data"]["failed"].as_array().unwrap().len(), 1);
    assert_eq!(apply_json["data"]["failed"][0]["id"], "fb-gone");
    assert_eq!(
        fs::read(proj.path().join(".klens/memory/fb-gone.md")).unwrap(),
        gone_before,
        "broken anchor note must stay byte-for-byte untouched"
    );
}
