//! Comprehensive Phase 2 tests (`docs/phases/phase-2.md`):
//! 1. Rust compiler error context preservation (zero lines lost).
//! 2. ANSI/OSC/`\r` cleaning on colored `cargo` and `tsc` outputs (zero `\x1b`).
//! 3. Zero error truncation across ALL 6 filters + exact raw log on disk.
//! 4. 200 passing tests compression (>= 75% token reduction + `"200 passed (omitted)"`).
//! 5. Windows `CREATE_NO_WINDOW` (`0x0800_0000`) static + unit audit.
//! 6. Secret redaction (`ANTHROPIC_API_KEY=...` -> `[REDACTED:ANTHROPIC_KEY]`).
//! 7. Git checkpoint / list / rollback `--dry-run` / rollback apply without polluting branch.
//! 8. Timeout + process-tree kill & run-log retention pruning.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use klens_core::{CommandFilter, ProjectRoot, estimate_tokens};
use klens_exec::{
    CargoFilter, ExecError, FilterRegistry, GenericSafeFilter, GitFilter, GoTestFilter,
    NodePkgFilter, PytestFilter, RunOptions, TIMEOUT_EXIT_CODE, WINDOWS_CREATE_NO_WINDOW,
    contains_ansi, create_checkpoint, execute_command, list_checkpoints, rollback_checkpoint,
    show_stored_run, strip_ansi,
};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("klens-p2-{label}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn write(&self, rel: &str, content: &str) {
        let p = self.dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn run_git_ok(dir: &Path, args: &[&str]) -> String {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.quotepath=false"])
        .args(args)
        .current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(WINDOWS_CREATE_NO_WINDOW);
    }
    let out = cmd.output().expect("git invocation failed");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn shell_cmd(script_win: &str, script_unix: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let _ = script_unix;
        vec!["cmd".to_string(), "/C".to_string(), script_win.to_string()]
    }
    #[cfg(not(windows))]
    {
        let _ = script_win;
        vec!["sh".to_string(), "-c".to_string(), script_unix.to_string()]
    }
}

// ---------------------------------------------------------------------------
// Mandatory Test 1: Rust Compiler Error Context Preservation (Zero Lines Lost)
// ---------------------------------------------------------------------------

#[test]
fn test_1_rust_compiler_error_context_preserves_every_single_line() {
    let stderr = concat!(
        "   Compiling klens-core v0.1.0 (C:\\repo\\crates\\klens-core)\n",
        "   Compiling klens-demo v0.1.0 (C:\\repo\\crates\\klens-demo)\n",
        "error[E0308]: mismatched types\n",
        "  --> src/main.rs:42:22\n",
        "   |\n",
        "42 |     let count: u32 = \"hello\";\n",
        "   |                ---   ^^^^^^^ expected `u32`, found `&str`\n",
        "   |                |\n",
        "   |                expected due to this\n",
        "   |\n",
        "   = note: expected type `u32`\n",
        "           found reference `&'static str`\n",
        "   = help: try parsing the string with `.parse::<u32>()`\n",
        "\n",
        "For more information about this error, try `rustc --explain E0308`.\n",
        "error: could not compile `klens-demo` (bin \"klens-demo\") due to 1 previous error\n",
    );

    let res = CargoFilter.filter("", stderr, 101);
    assert!(!res.truncated_errors);
    assert_eq!(res.exit_code, 101);

    // Every single error context line MUST be present verbatim without a single dropped line.
    let mandatory_lines = [
        "error[E0308]: mismatched types",
        "  --> src/main.rs:42:22",
        "42 |     let count: u32 = \"hello\";",
        "   |                ---   ^^^^^^^ expected `u32`, found `&str`",
        "   |                expected due to this",
        "   = note: expected type `u32`",
        "           found reference `&'static str`",
        "   = help: try parsing the string with `.parse::<u32>()`",
        "For more information about this error, try `rustc --explain E0308`.",
        "error: could not compile `klens-demo` (bin \"klens-demo\") due to 1 previous error",
    ];
    for expected in mandatory_lines {
        assert!(
            res.summary.contains(expected),
            "missing mandatory error context line `{expected}` in:\n{}",
            res.summary
        );
    }

    // Build progress noise (`Compiling ...`) was cleanly omitted and recorded.
    assert!(!res.summary.contains("Compiling klens-core"));
    assert!(
        res.omissions
            .iter()
            .any(|o| o.reason == "cargo_build_progress_omitted" && o.count == 2)
    );
}

#[test]
fn test_1b_cargo_failed_test_block_and_panic_diff_preserved_verbatim() {
    let stdout = concat!(
        "running 3 tests\n",
        "test alpha ... ok\n",
        "test beta ... FAILED\n",
        "test gamma ... ok\n",
        "\n",
        "failures:\n",
        "\n",
        "---- beta stdout ----\n",
        "thread 'beta' panicked at src/calc.rs:19:9:\n",
        "assertion `left == right` failed\n",
        "  left: 41\n",
        " right: 42\n",
        "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n",
        "\n",
        "failures:\n",
        "    beta\n",
        "\n",
        "test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
    );

    let res = CargoFilter.filter(stdout, "", 101);
    assert!(!res.truncated_errors);
    for line in [
        "test beta ... FAILED",
        "---- beta stdout ----",
        "thread 'beta' panicked at src/calc.rs:19:9:",
        "assertion `left == right` failed",
        "  left: 41",
        " right: 42",
        "    beta",
        "test result: FAILED. 2 passed; 1 failed;",
        "2 passed (omitted)",
    ] {
        assert!(
            res.summary.contains(line),
            "missing failed test context `{line}` in:\n{}",
            res.summary
        );
    }
    assert!(!res.summary.contains("test alpha ... ok"));
    assert!(!res.summary.contains("test gamma ... ok"));
}

// ---------------------------------------------------------------------------
// Mandatory Test 2: ANSI & Control Sequence Cleaning (`cargo` + `tsc`)
// ---------------------------------------------------------------------------

#[test]
fn test_2_ansi_cleaning_leaves_zero_escape_bytes_for_cargo_and_tsc() {
    let colored_cargo = concat!(
        "\x1b]0;cargo check\x07",
        "   \x1b[1;32mCompiling\x1b[0m demo v0.1.0\r",
        "   \x1b[1;32mCompiling\x1b[0m demo v0.1.0 (C:\\demo)\r\n",
        "\x1b[1;31merror[\x1b]8;;https://doc.rust-lang.org/error_codes/E0308.html\x1b\\E0308\x1b]8;;\x1b\\]\x1b[0m: \x1b[1mmismatched types\x1b[0m\r\n",
        "\x1b[1;34m  --> \x1b[0msrc/main.rs:42:5\r\n",
        "\x1b[1;34m   |\x1b[0m\r\n",
        "\x1b[1;34m42 |\x1b[0m     let x: u32 = \"bad\";\r\n",
        "\x1b[1;34m   |\x1b[0m                  \x1b[1;31m^^^^^ expected `u32`, found `&str`\x1b[0m\r\n",
    );

    let clean_cargo = strip_ansi(colored_cargo);
    assert!(!contains_ansi(&clean_cargo));
    assert!(!clean_cargo.contains('\r'));

    let cargo_filtered = CargoFilter.filter("", &clean_cargo, 101);
    assert!(!contains_ansi(&cargo_filtered.summary));
    assert!(!cargo_filtered.summary.contains('\x1b'));
    assert!(
        cargo_filtered
            .summary
            .contains("error[E0308]: mismatched types")
    );
    assert!(cargo_filtered.summary.contains("--> src/main.rs:42:5"));
    assert!(
        cargo_filtered
            .summary
            .contains("expected `u32`, found `&str`")
    );
    // Token counting used ANSI-stripped text, NOT raw ANSI bytes.
    assert_eq!(cargo_filtered.est_raw_tokens, estimate_tokens(&clean_cargo));
    assert!(cargo_filtered.raw_bytes < colored_cargo.len());

    let colored_tsc = concat!(
        "\x1b[96msrc/api.ts\x1b[0m:\x1b[93m18\x1b[0m:\x1b[93m7\x1b[0m - \x1b[91merror\x1b[0m\x1b[90m TS2322: \x1b[0mType 'string' is not assignable to type 'number'.\r\n",
        "  Type 'string' is not assignable to type 'UserId'.\r\n",
        "\r\n",
        "\x1b[7m18\x1b[0m const id: number = \"abc\";\r\n",
        "\x1b[7m  \x1b[0m \x1b[91m      ~~\x1b[0m\r\n",
        "\r\n",
        "Found 1 error in src/api.ts\x1b[90m:18\x1b[0m\r\n",
    );
    let clean_tsc = strip_ansi(colored_tsc);
    assert!(!contains_ansi(&clean_tsc));
    let tsc_filtered = NodePkgFilter.filter(&clean_tsc, "", 2);
    assert!(!contains_ansi(&tsc_filtered.summary));
    assert!(!tsc_filtered.truncated_errors);
    for line in [
        "src/api.ts:18:7 - error TS2322: Type 'string' is not assignable to type 'number'.",
        "  Type 'string' is not assignable to type 'UserId'.",
        "18 const id: number = \"abc\";",
        "Found 1 error in src/api.ts:18",
    ] {
        assert!(
            tsc_filtered.summary.contains(line),
            "missing tsc context `{line}` in:\n{}",
            tsc_filtered.summary
        );
    }
}

// ---------------------------------------------------------------------------
// Mandatory Test 3: Zero Error Truncation Across ALL 6 Filters + Raw Log Match
// ---------------------------------------------------------------------------

#[test]
fn test_3_all_six_filters_preserve_errors_with_truncated_errors_false() {
    // 1. CargoFilter
    let c = CargoFilter.filter(
        "",
        "error[E0425]: cannot find value `x`\n  --> src/lib.rs:3:5\n",
        101,
    );
    assert!(!c.truncated_errors);
    assert!(c.summary.contains("--> src/lib.rs:3:5"));

    // 2. GitFilter (error + code diff without lockfile)
    let g = GitFilter.filter(
        "",
        "fatal: not a git repository (or any of the parent directories): .git\n",
        128,
    );
    assert!(!g.truncated_errors);
    assert!(g.summary.contains("fatal: not a git repository"));

    // 3. NodePkgFilter (vitest/jest failure + stack trace)
    let n_out = concat!(
        "✓ renders header (4ms)\n",
        "✓ renders footer (2ms)\n",
        "FAIL src/auth.test.ts > login > rejects expired token\n",
        "AssertionError: expected 200 to be 401\n",
        "    at src/auth.test.ts:44:12\n",
        "    at runTest (node_modules/vitest/dist/chunk.js:12:3)\n",
        "Test Files  1 failed (1)\n",
    );
    let n = NodePkgFilter.filter(n_out, "", 1);
    assert!(!n.truncated_errors);
    assert!(n.summary.contains("2 passed (omitted)"));
    assert!(n.summary.contains("AssertionError: expected 200 to be 401"));
    assert!(n.summary.contains("at src/auth.test.ts:44:12"));

    // 4. PytestFilter (FAILURES + full traceback)
    let py_out = concat!(
        "tests/test_math.py::test_add PASSED [ 50%]\n",
        "tests/test_math.py::test_div FAILED [100%]\n",
        "=================================== FAILURES ===================================\n",
        "___________________________________ test_div ___________________________________\n",
        "    def test_div():\n",
        ">       assert divide(10, 0) == 0\n",
        "E       ZeroDivisionError: division by zero\n",
        "tests/test_math.py:12: ZeroDivisionError\n",
        "=========================== short test summary info ============================\n",
        "FAILED tests/test_math.py::test_div - ZeroDivisionError: division by zero\n",
        "1 failed, 1 passed in 0.04s\n",
    );
    let p = PytestFilter.filter(py_out, "", 1);
    assert!(!p.truncated_errors);
    assert!(p.summary.contains("1 passed (omitted)"));
    assert!(p.summary.contains("ZeroDivisionError: division by zero"));
    assert!(
        p.summary
            .contains("tests/test_math.py:12: ZeroDivisionError")
    );

    // 5. GoTestFilter (`--- FAIL:` + panic trace; passing tests omitted)
    let go_out = concat!(
        "=== RUN   TestAdd\n",
        "    add_test.go:10: verbose debug noise\n",
        "--- PASS: TestAdd (0.00s)\n",
        "=== RUN   TestSave\n",
        "    save_test.go:25: expected chunk size 16, got 8\n",
        "--- FAIL: TestSave (0.01s)\n",
        "FAIL\tgithub.com/karasu/world\t0.02s\n",
    );
    let go = GoTestFilter.filter(go_out, "", 1);
    assert!(!go.truncated_errors);
    assert!(go.summary.contains("1 passed (omitted)"));
    assert!(!go.summary.contains("verbose debug noise"));
    assert!(go.summary.contains("=== RUN   TestSave"));
    assert!(
        go.summary
            .contains("save_test.go:25: expected chunk size 16, got 8")
    );
    assert!(go.summary.contains("--- FAIL: TestSave (0.01s)"));

    // 6. GenericSafeFilter (`exit_code != 0`: ±4 context lines + last 40 lines)
    let mut generic_lines = Vec::new();
    for i in 1..=120 {
        if i == 30 {
            generic_lines.push("ERROR: disk checksum mismatch on sector 9".to_string());
        } else {
            generic_lines.push(format!("info log line {i}"));
        }
    }
    let gen_input = generic_lines.join("\n");
    let gen_res = GenericSafeFilter.filter(&gen_input, "", 2);
    assert!(!gen_res.truncated_errors);
    // ±4 lines around line 30 (lines 26..=34) MUST ALL be preserved!
    for line_no in 26..=34 {
        let needle = if line_no == 30 {
            "ERROR: disk checksum mismatch on sector 9".to_string()
        } else {
            format!("info log line {line_no}")
        };
        assert!(
            gen_res.summary.contains(&needle),
            "missing ±4 context `{needle}` in:\n{}",
            gen_res.summary
        );
    }
    // Last 40 lines (lines 81..=120) MUST ALL be preserved!
    assert!(gen_res.summary.contains("info log line 81"));
    assert!(gen_res.summary.contains("info log line 120"));
    // Non-error middle gap was explicitly marked as omitted.
    assert!(!gen_res.omissions.is_empty());
}

#[test]
fn test_3b_live_nonzero_run_writes_exact_raw_log_on_disk() {
    let proj = Sandbox::new("raw-log-exact");
    let root = ProjectRoot::new(proj.path()).unwrap();

    let cmd = shell_cmd(
        "echo line_before_err & echo ERROR: critical failure at L99 & exit /B 7",
        "echo line_before_err; echo 'ERROR: critical failure at L99'; exit 7",
    );
    let env = execute_command(&root, &cmd, &RunOptions::default()).unwrap();

    assert_eq!(env.data.meta.exit_code, 7);
    assert!(!env.data.meta.truncated_errors);
    assert!(env.data.output.contains("ERROR: critical failure at L99"));

    // Raw log file MUST exist on disk and match raw output verbatim.
    let raw_path = proj.path().join(&env.data.meta.raw_log_path);
    assert!(
        raw_path.is_file(),
        "raw_log_path missing: {}",
        raw_path.display()
    );
    let disk_raw = fs::read_to_string(&raw_path).unwrap();
    assert!(disk_raw.contains("line_before_err"));
    assert!(disk_raw.contains("ERROR: critical failure at L99"));

    // `show_stored_run(..., raw = true)` returns the exact same content.
    let shown = show_stored_run(&root, &env.data.meta.run_id, true).unwrap();
    assert_eq!(shown.data.content, disk_raw);
}

// ---------------------------------------------------------------------------
// Mandatory Test 4: 200 Passing Tests Compression (>= 75% Token Reduction)
// ---------------------------------------------------------------------------

#[test]
fn test_4_cargo_200_passing_tests_compresses_at_least_75_percent() {
    let mut stderr = String::new();
    for i in 1..=15 {
        stderr.push_str(&format!("   Compiling crate_{i:02} v0.1.0\n"));
    }
    stderr.push_str("    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.25s\n");
    stderr.push_str("     Running unittests src/lib.rs (target/debug/deps/app-1234)\n");

    let mut stdout = String::from("running 200 tests\n");
    for i in 1..=200 {
        stdout.push_str(&format!(
            "test module_alpha::subsystem_beta::case_{i:03}_verifies_invariant ... ok\n"
        ));
    }
    stdout.push_str("\ntest result: ok. 200 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s\n");

    let res = CargoFilter.filter(&stdout, &stderr, 0);
    assert!(!res.truncated_errors);
    assert!(
        res.summary.contains("200 passed (omitted)"),
        "expected `200 passed (omitted)` in:\n{}",
        res.summary
    );
    assert!(res.summary.contains("test result: ok. 200 passed;"));

    let reduction_ratio = 1.0 - (res.est_filtered_tokens as f64 / res.est_raw_tokens.max(1) as f64);
    assert!(
        reduction_ratio >= 0.75,
        "expected >= 75% token reduction, got {:.1}% ({} -> {})",
        reduction_ratio * 100.0,
        res.est_raw_tokens,
        res.est_filtered_tokens
    );
}

// ---------------------------------------------------------------------------
// Mandatory Test 5: Windows CREATE_NO_WINDOW (0x0800_0000) Static + Unit Audit
// ---------------------------------------------------------------------------

#[test]
fn test_5_windows_create_no_window_enforced_on_all_exec_commands_and_taskkill() {
    assert_eq!(WINDOWS_CREATE_NO_WINDOW, 0x0800_0000);

    let exec_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let runner_src = fs::read_to_string(exec_src.join("runner.rs")).unwrap();
    let checkpoint_src = fs::read_to_string(exec_src.join("checkpoint.rs")).unwrap();

    // Runner MUST configure `creation_flags(WINDOWS_CREATE_NO_WINDOW)` under `#[cfg(windows)]`.
    assert!(runner_src.contains("#[cfg(windows)]"));
    assert!(runner_src.contains("creation_flags(WINDOWS_CREATE_NO_WINDOW)"));
    assert!(runner_src.contains("0x0800_0000"));
    // Timeout process-tree killer MUST use `taskkill` with `/T`, `/F`, `/PID` and `configure_no_window`.
    assert!(runner_src.contains("Command::new(\"taskkill\")"));
    assert!(runner_src.contains("\"/T\", \"/F\", \"/PID\""));
    assert!(runner_src.contains("configure_no_window(&mut kill_cmd)"));

    // Every `Command::new` in `runner.rs` and `checkpoint.rs` MUST pair with `configure_no_window`.
    let runner_spawns = runner_src.matches("Command::new(").count();
    let runner_guards = runner_src.matches("configure_no_window(").count();
    assert!(
        runner_guards >= runner_spawns,
        "runner.rs has {runner_spawns} Command::new calls but only {runner_guards} configure_no_window calls"
    );

    let cp_spawns = checkpoint_src.matches("Command::new(").count();
    let cp_guards = checkpoint_src.matches("configure_no_window(").count();
    assert!(
        cp_guards >= cp_spawns,
        "checkpoint.rs has {cp_spawns} Command::new calls but only {cp_guards} configure_no_window calls"
    );
}

// ---------------------------------------------------------------------------
// Mandatory Test 6: Secret Redaction (`ANTHROPIC_API_KEY=...`)
// ---------------------------------------------------------------------------

#[test]
fn test_6_secret_redaction_masks_anthropic_api_key_in_command_output() {
    let proj = Sandbox::new("redact-secret");
    let root = ProjectRoot::new(proj.path()).unwrap();

    let synthetic_key = format!("sk-ant-api03-{}", "zY9xW8vU7tS6rQ5pO4nM3lK2");
    let win_script = format!("echo boot ok & echo ANTHROPIC_API_KEY={synthetic_key}");
    let unix_script = format!("echo 'boot ok'; echo 'ANTHROPIC_API_KEY={synthetic_key}'");
    let cmd = shell_cmd(&win_script, &unix_script);

    let env = execute_command(&root, &cmd, &RunOptions::default()).unwrap();
    assert!(env.redactions_count >= 1);
    assert!(
        env.data.output.contains("[REDACTED:ANTHROPIC_KEY]"),
        "expected [REDACTED:ANTHROPIC_KEY] in:\n{}",
        env.data.output
    );
    assert!(
        !env.data.output.contains(&synthetic_key),
        "raw secret leaked into filtered output!"
    );

    // Even `--raw` display mode MUST redact secrets at the output gate!
    let raw_shown = show_stored_run(&root, &env.data.meta.run_id, true).unwrap();
    assert!(raw_shown.redactions_count >= 1);
    assert!(raw_shown.data.content.contains("[REDACTED:ANTHROPIC_KEY]"));
    assert!(!raw_shown.data.content.contains(&synthetic_key));
}

// ---------------------------------------------------------------------------
// Test 7: GitFilter (`diff` lockfile omission, `status`, `log`)
// ---------------------------------------------------------------------------

#[test]
fn test_7_git_filter_omits_lockfiles_and_compacts_status_and_log() {
    let diff = concat!(
        "diff --git a/Cargo.lock b/Cargo.lock\n",
        "index 111..222 100644\n",
        "--- a/Cargo.lock\n",
        "+++ b/Cargo.lock\n",
        "@@ -1,3 +1,3 @@\n",
        "-version = \"0.1.0\"\n",
        "+version = \"0.2.0\"\n",
        "diff --git a/src/main.rs b/src/main.rs\n",
        "index 333..444 100644\n",
        "--- a/src/main.rs\n",
        "+++ b/src/main.rs\n",
        "@@ -1,2 +1,3 @@\n",
        " fn main() {\n",
        "+    println!(\"hi\");\n",
        " }\n",
    );
    let diff_res = GitFilter.filter(diff, "", 0);
    assert!(!diff_res.truncated_errors);
    assert!(
        diff_res
            .summary
            .contains("omitted lockfile/generated diff: Cargo.lock")
    );
    assert!(!diff_res.summary.contains("-version = \"0.1.0\""));
    assert!(diff_res.summary.contains("+    println!(\"hi\");"));
    assert!(
        diff_res
            .omissions
            .iter()
            .any(|o| o.path.as_deref() == Some("Cargo.lock"))
    );

    let status = concat!(
        "On branch main\n",
        "Changes to be committed:\n",
        "  (use \"git restore --staged <file>...\" to unstage)\n",
        "\tmodified:   src/lib.rs\n",
        "\n",
        "Untracked files:\n",
        "  (use \"git add <file>...\" to include in what will be committed)\n",
        "\tsrc/new.rs\n",
    );
    let st_res = GitFilter.filter(status, "", 0);
    assert!(st_res.summary.contains("On branch main"));
    assert!(
        st_res
            .summary
            .contains("Staged (1): modified:   src/lib.rs")
    );
    assert!(st_res.summary.contains("Untracked (1): src/new.rs"));
    assert!(!st_res.summary.contains("use \"git add"));

    let log = concat!(
        "commit 7028a98f1234567890abcdef1234567890abcdef\n",
        "Author: Dev User <dev@example.com>\n",
        "Date:   Sun Nov 22 18:30:00 2026 +0300\n",
        "\n",
        "    feat: implement smart terminal filter\n",
    );
    let log_res = GitFilter.filter(log, "", 0);
    assert!(log_res.summary.contains("7028a98"));
    assert!(log_res.summary.contains("Dev User"));
    assert!(
        log_res
            .summary
            .contains("feat: implement smart terminal filter")
    );
    assert!(!log_res.summary.contains("Author:"));
}

// ---------------------------------------------------------------------------
// Test 8: Git Checkpoint / List / Dry-Run Rollback / Real Rollback
// ---------------------------------------------------------------------------

#[test]
fn test_8_checkpoint_and_rollback_never_pollute_branch_and_restore_exact_tree() {
    let proj = Sandbox::new("checkpoint-flow");
    proj.write(".gitignore", ".klens/runs/\n.klens/cache/\n");
    proj.write("src/app.rs", "pub fn version() -> u32 { 1 }\n");
    proj.write("src/keep_me.rs", "pub const KEEP: bool = true;\n");

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "test@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "Klens Test"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(proj.path(), &["commit", "-m", "initial commit"]);

    let head_before = run_git_ok(proj.path(), &["rev-parse", "HEAD"]);
    let log_count_before = run_git_ok(proj.path(), &["rev-list", "--count", "HEAD"]);

    // Make an uncommitted modification + untracked file BEFORE taking checkpoint.
    proj.write("src/app.rs", "pub fn version() -> u32 { 2 }\n");
    proj.write("src/draft.rs", "pub fn draft() {}\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let cp = create_checkpoint(&root, Some("before risky refactor")).unwrap();
    assert_eq!(cp.data.note, "before risky refactor");

    // Branch / HEAD / git log / stash MUST NOT be polluted by checkpointing!
    assert_eq!(run_git_ok(proj.path(), &["rev-parse", "HEAD"]), head_before);
    assert_eq!(
        run_git_ok(proj.path(), &["rev-list", "--count", "HEAD"]),
        log_count_before
    );
    assert!(
        run_git_ok(proj.path(), &["stash", "list"])
            .trim()
            .is_empty()
    );

    let listed = list_checkpoints(&root).unwrap();
    assert_eq!(listed.data.len(), 1);
    assert_eq!(listed.data[0].id, cp.data.id);
    assert_eq!(listed.data[0].note, "before risky refactor");

    // Simulate a destructive refactor: modify `app.rs`, delete `keep_me.rs`, add `garbage.rs`,
    // and also write a `.klens/runs/keep.raw.log` runtime log that MUST survive rollback.
    proj.write("src/app.rs", "BROKEN CODE\n");
    fs::remove_file(proj.path().join("src/keep_me.rs")).unwrap();
    proj.write("src/garbage.rs", "should be deleted on rollback\n");
    proj.write(".klens/runs/keep.raw.log", "do not delete run logs\n");

    // 1. `--dry-run` MUST preview exact changes without touching disk!
    let preview = rollback_checkpoint(&root, &cp.data.id, true).unwrap();
    assert!(preview.data.dry_run);
    assert!(!preview.data.applied);
    assert_eq!(preview.data.files_to_modify, vec!["src/app.rs"]);
    assert_eq!(preview.data.files_to_restore, vec!["src/keep_me.rs"]);
    assert_eq!(preview.data.files_to_delete, vec!["src/garbage.rs"]);

    // Verify filesystem was NOT modified by dry-run.
    assert_eq!(
        fs::read_to_string(proj.path().join("src/app.rs")).unwrap(),
        "BROKEN CODE\n"
    );
    assert!(!proj.path().join("src/keep_me.rs").exists());
    assert!(proj.path().join("src/garbage.rs").exists());

    // 2. Real rollback restores exact checkpoint tree while keeping HEAD & `.klens/runs/` intact.
    let applied = rollback_checkpoint(&root, &cp.data.id, false).unwrap();
    assert!(!applied.data.dry_run);
    assert!(applied.data.applied);
    assert_eq!(
        fs::read_to_string(proj.path().join("src/app.rs")).unwrap(),
        "pub fn version() -> u32 { 2 }\n"
    );
    assert_eq!(
        fs::read_to_string(proj.path().join("src/keep_me.rs")).unwrap(),
        "pub const KEEP: bool = true;\n"
    );
    assert_eq!(
        fs::read_to_string(proj.path().join("src/draft.rs")).unwrap(),
        "pub fn draft() {}\n"
    );
    assert!(!proj.path().join("src/garbage.rs").exists());
    assert!(proj.path().join(".klens/runs/keep.raw.log").is_file());
    assert_eq!(run_git_ok(proj.path(), &["rev-parse", "HEAD"]), head_before);
    assert_eq!(
        run_git_ok(proj.path(), &["rev-list", "--count", "HEAD"]),
        log_count_before
    );
}

#[test]
fn test_8b_checkpoint_fails_cleanly_outside_git_repo_and_on_ambiguous_prefix() {
    let non_git = Sandbox::new("non-git");
    let root = ProjectRoot::new(non_git.path()).unwrap();
    assert!(matches!(
        create_checkpoint(&root, None),
        Err(ExecError::NotAGitRepository(_))
    ));

    // Create two checkpoints with the same date prefix and verify ambiguous prefix fails closed.
    let git_proj = Sandbox::new("cp-ambig");
    git_proj.write("a.txt", "v1\n");
    run_git_ok(git_proj.path(), &["init"]);
    run_git_ok(git_proj.path(), &["add", "."]);
    run_git_ok(
        git_proj.path(),
        &[
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@t",
            "commit",
            "-m",
            "init",
        ],
    );
    let git_root = ProjectRoot::new(git_proj.path()).unwrap();
    let cp1 = create_checkpoint(&git_root, Some("first")).unwrap();
    git_proj.write("a.txt", "v2\n");
    let cp2 = create_checkpoint(&git_root, Some("second")).unwrap();
    assert_ne!(cp1.data.id, cp2.data.id);

    // Common prefix (first 8 chars `YYYYMMDD`) matches both -> must fail closed as AmbiguousCheckpoint.
    let shared_prefix = &cp1.data.id[..8];
    assert!(matches!(
        rollback_checkpoint(&git_root, shared_prefix, true),
        Err(ExecError::AmbiguousCheckpoint { .. })
    ));
}

// ---------------------------------------------------------------------------
// Test 9: Timeout & Process Tree Termination + Registry Routing
// ---------------------------------------------------------------------------

#[test]
fn test_9_timeout_kills_slow_process_cleanly() {
    let proj = Sandbox::new("timeout");
    let root = ProjectRoot::new(proj.path()).unwrap();

    // Sleep 10s, with a 1s timeout.
    #[cfg(windows)]
    let cmd = vec![
        "powershell".to_string(),
        "-NoProfile".to_string(),
        "-Command".to_string(),
        "Start-Sleep -Seconds 10".to_string(),
    ];
    #[cfg(not(windows))]
    let cmd = vec!["sleep".to_string(), "10".to_string()];
    let opts = RunOptions {
        timeout: Some(Duration::from_secs(1)),
        ..RunOptions::default()
    };

    let started = Instant::now();
    let env = execute_command(&root, &cmd, &opts).unwrap();
    let elapsed = started.elapsed();

    assert!(env.data.timed_out);
    assert_eq!(env.data.meta.exit_code, TIMEOUT_EXIT_CODE);
    assert!(!env.data.meta.truncated_errors);
    assert!(
        elapsed < Duration::from_secs(6),
        "timed-out process took too long to terminate: {elapsed:?}"
    );
    assert!(proj.path().join(&env.data.meta.raw_log_path).is_file());
}

#[test]
fn test_10_filter_registry_routes_all_supported_tools() {
    let reg = FilterRegistry::with_defaults();
    assert_eq!(reg.select("cargo", &[]).id(), "cargo");
    assert_eq!(
        reg.select("C:\\Users\\x\\.cargo\\bin\\cargo.exe", &[]).id(),
        "cargo"
    );
    assert_eq!(reg.select("git", &["diff".into()]).id(), "git");
    assert_eq!(reg.select("npm.cmd", &["test".into()]).id(), "node");
    assert_eq!(reg.select("tsc", &["--noEmit".into()]).id(), "node");
    assert_eq!(reg.select("vitest", &[]).id(), "node");
    assert_eq!(reg.select("pytest", &[]).id(), "pytest");
    assert_eq!(
        reg.select("python", &["-m".into(), "pytest".into()]).id(),
        "pytest"
    );
    assert_eq!(
        reg.select("go", &["test".into(), "./...".into()]).id(),
        "go_test"
    );
    assert_eq!(reg.select("some_unknown_tool", &[]).id(), "generic");
}

// ---------------------------------------------------------------------------
// Audit Regression Tests (Items 1-7)
// ---------------------------------------------------------------------------

#[test]
fn regression_1_ansi_malformed_charset_utf8_never_panics() {
    let inputs = [
        "\x1b(ğ",
        "\x1b)ş",
        "\x1b*ü",
        "\x1b+🚀",
        "\x1b(ğ\x1b[31merr\x1b[0m",
    ];
    for raw in inputs {
        let clean = strip_ansi(raw);
        assert!(!contains_ansi(&clean));
        assert!(!clean.contains('\x1b'));
    }
    assert_eq!(strip_ansi("\x1b(ğ"), "ğ");
    assert_eq!(strip_ansi("\x1b(Bascii"), "ascii");
}

#[test]
fn regression_2_git_log_utf8_commit_line_and_git_diff_lockfile_fatal_preserved() {
    // 2a: `git log` combined raw log with a Turkish `"commit ağacı"` line + `fatal:` error
    //     must never panic on UTF-8 slicing and must preserve diagnostic lines verbatim.
    let combined_log = concat!(
        "commit 7028a98f1234567890abcdef1234567890abcdef\n",
        "Author: Dev User <dev@example.com>\n",
        "Date:   Sun Nov 22 18:30:00 2026 +0300\n",
        "\n",
        "    feat: initial work\n",
        "commit ağacı bozuldu\n",
        "fatal: bad object HEAD~99\n",
        "hint: check reflog\n",
    );
    let log_res = GitFilter.filter(combined_log, "", 128);
    assert!(!log_res.truncated_errors);
    assert!(log_res.summary.contains("7028a98"));
    assert!(log_res.summary.contains("commit ağacı bozuldu"));
    assert!(log_res.summary.contains("fatal: bad object HEAD~99"));
    assert!(log_res.summary.contains("hint: check reflog"));

    // 2b: `git diff` where a lockfile section is immediately followed by `fatal:` / `error:`
    //     must flush the lockfile omission first and preserve the error lines verbatim.
    let diff_with_fatal = concat!(
        "diff --git a/Cargo.lock b/Cargo.lock\n",
        "index 111..222 100644\n",
        "--- a/Cargo.lock\n",
        "+++ b/Cargo.lock\n",
        "@@ -1,2 +1,2 @@\n",
        "-version = \"0.1.0\"\n",
        "+version = \"0.2.0\"\n",
        "fatal: unable to read tree 0123456789abcdef\n",
        "error: diff aborted\n",
    );
    let diff_res = GitFilter.filter(diff_with_fatal, "", 128);
    assert!(!diff_res.truncated_errors);
    assert!(
        diff_res
            .summary
            .contains("omitted lockfile/generated diff: Cargo.lock")
    );
    assert!(
        diff_res
            .summary
            .contains("fatal: unable to read tree 0123456789abcdef"),
        "fatal line was swallowed inside lockfile diff:\n{}",
        diff_res.summary
    );
    assert!(diff_res.summary.contains("error: diff aborted"));
}

#[test]
fn regression_3_node_failure_block_keeps_indented_ok_assignment_and_parses_tap_ok() {
    let output = concat!(
        "ok 1 - auth middleware allows valid session\n",
        "FAIL src/check.test.ts > verifies status flag\n",
        "  const result = validate();\n",
        "  ok = false;\n",
        "  expect(ok).toBe(true);\n",
        "AssertionError: expected false to be true\n",
        "    at src/check.test.ts:12:5\n",
    );

    let res = NodePkgFilter.filter(output, "", 1);
    assert!(!res.truncated_errors);
    assert!(
        res.summary.contains("  ok = false;"),
        "indented `  ok = false;` inside failure block was dropped:\n{}",
        res.summary
    );
    assert!(res.summary.contains("  expect(ok).toBe(true);"));
    assert!(
        res.summary
            .contains("AssertionError: expected false to be true")
    );
    // Only the real unindented TAP `ok 1 - ...` line counts as passed.
    assert!(res.summary.contains("1 passed (omitted)"));
    assert!(!res.summary.contains("2 passed (omitted)"));
}

#[test]
fn regression_4_pytest_rootdir_and_cwd_dot_never_produce_fake_passed_count() {
    let header_only = concat!(
        "============================= test session starts ==============================\n",
        "platform win32 -- Python 3.12.0, pytest-8.3.0\n",
        "rootdir: .\n",
        "cwd: .\n",
        "collected 0 items\n",
        "============================ no tests ran in 0.01s =============================\n",
    );
    let res_empty = PytestFilter.filter(header_only, "", 0);
    assert!(
        res_empty.summary.contains("rootdir: ."),
        "rootdir line was erroneously omitted:\n{}",
        res_empty.summary
    );
    assert!(res_empty.summary.contains("cwd: ."));
    assert!(
        !res_empty.summary.contains("passed (omitted)"),
        "fake passed count emitted for `rootdir: .`:\n{}",
        res_empty.summary
    );
    assert!(res_empty.omissions.is_empty());

    // Real dot progress line after `rootdir: .` counts ONLY the 5 real dots.
    let with_real_dots = concat!(
        "rootdir: .\n",
        "tests/test_engine.py .....                                               [100%]\n",
        "5 passed in 0.03s\n",
    );
    let res_dots = PytestFilter.filter(with_real_dots, "", 0);
    assert!(res_dots.summary.contains("rootdir: ."));
    assert!(res_dots.summary.contains("5 passed (omitted)"));
    assert!(!res_dots.summary.contains("6 passed (omitted)"));
}

#[test]
fn regression_6_cargo_omits_relative_path_test_suite_banners_on_success() {
    let stderr = concat!(
        "     Running ..\\..\\tests\\adversarial_truth.rs (target\\debug\\deps\\adversarial_truth-57d8f52cace8661b.exe)\n",
        "     Running ../../tests/dep_budget.rs (target/debug/deps/dep_budget-1234)\n",
    );
    let stdout = concat!(
        "running 1 test\n",
        "test ok_case ... ok\n",
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
    );
    let res = CargoFilter.filter(stdout, stderr, 0);
    assert!(!res.summary.contains("adversarial_truth.rs"));
    assert!(!res.summary.contains("dep_budget.rs"));
    assert!(res.summary.contains("1 passed (omitted)"));
}

#[test]
fn regression_7_checkpoint_rollback_preserves_unchanged_file_mtime_and_skips_noop() {
    let proj = Sandbox::new("cp-mtime");
    proj.write("src/unchanged.rs", "pub const STABLE: u32 = 1;\n");
    proj.write("src/changed.rs", "pub const VERSION: u32 = 1;\n");

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "t@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "T"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(proj.path(), &["commit", "-m", "init"]);

    let root = ProjectRoot::new(proj.path()).unwrap();
    let cp = create_checkpoint(&root, Some("baseline")).unwrap();

    let unchanged_path = proj.path().join("src/unchanged.rs");
    let mtime_before = fs::metadata(&unchanged_path).unwrap().modified().unwrap();

    // Sleep briefly so any filesystem rewrite would produce a strictly newer mtime.
    std::thread::sleep(Duration::from_millis(50));
    proj.write("src/changed.rs", "pub const VERSION: u32 = 999;\n");

    let applied = rollback_checkpoint(&root, &cp.data.id, false).unwrap();
    assert_eq!(applied.data.files_to_modify, vec!["src/changed.rs"]);
    assert_eq!(
        fs::read_to_string(proj.path().join("src/changed.rs")).unwrap(),
        "pub const VERSION: u32 = 1;\n"
    );

    // Unchanged file MUST NOT have been rewritten by `checkout-index`.
    let mtime_after = fs::metadata(&unchanged_path).unwrap().modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "rollback unnecessarily rewrote unchanged file and altered its mtime"
    );

    // Second rollback with 0 changes must be a complete no-op.
    let changed_mtime_before = fs::metadata(proj.path().join("src/changed.rs"))
        .unwrap()
        .modified()
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let noop = rollback_checkpoint(&root, &cp.data.id, false).unwrap();
    assert_eq!(noop.data.total_changes(), 0);
    let changed_mtime_after = fs::metadata(proj.path().join("src/changed.rs"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(changed_mtime_before, changed_mtime_after);
}

#[test]
fn raw_output_redacts_tokens_right_after_ansi_colour_codes() {
    let proj = Sandbox::new("raw-ansi-token");
    let root = ProjectRoot::new(proj.path()).unwrap();
    let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let raw = format!("\x1b[32m{token}\x1b[0m\r\nok \x1b[1;31mERROR\x1b[0m\n");
    let store = klens_exec::RunStore::new(root.clone());
    let meta = store
        .save_run(&klens_exec::NewRunRecord {
            command: "tool",
            cwd: ".",
            filter_used: "generic",
            exit_code: 0,
            duration_ms: 1,
            raw_bytes: raw.len(),
            filtered_bytes: 0,
            est_raw_tokens: 1,
            est_filtered_tokens: 1,
            truncated_errors: false,
            raw_log_content: &raw,
        })
        .unwrap();

    let shown = show_stored_run(&root, &meta.run_id, true).unwrap();
    assert!(
        !shown.data.content.contains(token),
        "{}",
        shown.data.content
    );
    assert!(shown.data.content.contains("[REDACTED:GITHUB_TOKEN]"));
    assert!(shown.redactions_count >= 1);
    // Only escape sequences are removed; line endings and text stay verbatim.
    assert_eq!(shown.data.content, "[REDACTED:GITHUB_TOKEN]\r\nok ERROR\n");
    // The log on disk keeps the original bytes.
    let disk = fs::read_to_string(proj.path().join(&meta.raw_log_path)).unwrap();
    assert_eq!(disk, raw);
}

#[test]
fn live_raw_run_redacts_tokens_after_ansi_codes() {
    let proj = Sandbox::new("raw-ansi-live");
    let root = ProjectRoot::new(proj.path()).unwrap();
    let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    proj.write("out.txt", &format!("\x1b[32m{token}\x1b[0m\n"));
    let cmd = shell_cmd("type out.txt", "cat out.txt");
    let env = execute_command(
        &root,
        &cmd,
        &RunOptions {
            raw: true,
            ..RunOptions::default()
        },
    )
    .unwrap();
    assert!(!env.data.output.contains(token), "{}", env.data.output);
    assert!(env.data.output.contains("[REDACTED:GITHUB_TOKEN]"));
}

#[test]
fn checkpoints_and_rollback_honour_project_sensitive_and_protected_patterns() {
    let proj = Sandbox::new("cp-project-guards");
    proj.write(
        ".klens/config.toml",
        "extra_sensitive_patterns = [\"*.secret\", \"private/*\"]\nprotected_paths = [\"src/locked*\"]\n",
    );
    proj.write("app.secret", "PROJECT_SECRET_VALUE\n");
    proj.write("private/notes.txt", "PRIVATE_NOTES\n");
    proj.write(".envrc", "export TOKEN=x\n");
    proj.write("src/main.rs", "fn main() {}\n");
    proj.write("src/locked.rs", "pub const LOCKED: u32 = 1;\n");

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "t@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "T"]);
    run_git_ok(proj.path(), &["add", "src"]);
    run_git_ok(proj.path(), &["commit", "-m", "init"]);

    let root = ProjectRoot::new(proj.path()).unwrap();
    let cp = create_checkpoint(&root, Some("guards")).unwrap();

    let tree = run_git_ok(
        proj.path(),
        &[
            "ls-tree",
            "-r",
            "--name-only",
            &format!("refs/klens/checkpoints/{}", cp.data.id),
        ],
    );
    for never in ["app.secret", "private/notes.txt", ".envrc"] {
        assert!(
            !tree.lines().any(|l| l == never),
            "`{never}` must not be stored in a checkpoint:\n{tree}"
        );
    }
    assert!(tree.lines().any(|l| l == "src/main.rs"), "{tree}");
    assert!(tree.lines().any(|l| l == "src/locked.rs"), "{tree}");

    // After the checkpoint: edit both files and add a new protected file.
    proj.write("src/main.rs", "fn main() { changed(); }\n");
    proj.write("src/locked.rs", "pub const LOCKED: u32 = 2;\n");
    proj.write("src/locked_new.rs", "pub const NEW: u32 = 3;\n");

    let report = rollback_checkpoint(&root, &cp.data.id, false).unwrap();
    assert_eq!(report.data.files_to_modify, vec!["src/main.rs"]);
    assert!(report.data.files_to_delete.is_empty(), "{:?}", report.data);
    assert_eq!(
        fs::read_to_string(proj.path().join("src/main.rs")).unwrap(),
        "fn main() {}\n"
    );
    // Protected paths are never modified or deleted by a rollback.
    assert_eq!(
        fs::read_to_string(proj.path().join("src/locked.rs")).unwrap(),
        "pub const LOCKED: u32 = 2;\n"
    );
    assert!(proj.path().join("src/locked_new.rs").is_file());
    // Sensitive files are untouched.
    assert!(proj.path().join("app.secret").is_file());
    assert!(proj.path().join("private/notes.txt").is_file());
}
