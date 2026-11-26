//! Unit, security, budget, and determinism tests for Phase 3.3 automatic error source context
//! (`crates/klens-exec/src/error_context.rs` + `runner.rs` integration).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::{OmissionKind, ProjectRoot, estimate_tokens};
use klens_exec::{
    ERROR_CONTEXT_RADIUS_LINES, MAX_ERROR_CONTEXT_LOCATIONS, MAX_ERROR_CONTEXT_TOKENS, RunOptions,
    collect_error_contexts, enrich_error_context_symbols, execute_command, extract_error_locations,
    format_error_contexts_text, format_run_text,
};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-errctx-test-{label}-{}-{n}",
            std::process::id()
        ));
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

fn numbered_lines(prefix: &str, count: usize) -> String {
    (1..=count)
        .map(|n| format!("{prefix} line {n}"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
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

#[test]
fn extracts_multilang_and_project_absolute_error_locations_in_order() {
    let proj = Sandbox::new("multilang");
    proj.write("src/lib.rs", &numbered_lines("// rs", 25));
    proj.write("src/app.ts", &numbered_lines("// ts", 25));
    proj.write("src/app.py", &numbered_lines("# py", 25));
    proj.write("cmd/main.go", &numbered_lines("// go", 25));
    proj.write("crates/demo/src/util.rs", &numbered_lines("// util", 25));

    let root = ProjectRoot::new(proj.path()).unwrap();

    // Verify raw extraction across Rust (ANSI-colored), TS, Python, Go, and Windows backslashes.
    let multi_output = concat!(
        "\x1b[1;31merror[E0308]\x1b[0m: mismatched types\n",
        "  \x1b[1;34m-->\x1b[0m src/lib.rs:12:5\n",
        "src/app.ts(12,5): error TS2322: Type 'string' is not assignable to type 'number'.\n",
        "  File \"src/app.py\", line 12, in broken_fn\n",
        "cmd/main.go:12:4: undefined: missingSym\n",
        "  --> crates\\demo\\src\\util.rs:12:9\n",
    );

    let extracted = extract_error_locations(multi_output);
    assert_eq!(
        extracted,
        vec![
            ("src/lib.rs".to_string(), 12),
            ("src/app.ts".to_string(), 12),
            ("src/app.py".to_string(), 12),
            ("cmd/main.go".to_string(), 12),
            ("crates\\demo\\src\\util.rs".to_string(), 12),
        ]
    );

    // Individual language resolutions via `collect_error_contexts`.
    for (snippet_input, expected_path) in [
        ("  --> src/lib.rs:12:5", "src/lib.rs"),
        ("src/app.ts(12,5): error TS2322", "src/app.ts"),
        ("  File \"src/app.py\", line 12, in run", "src/app.py"),
        ("src/app.py:12: AssertionError", "src/app.py"),
        ("cmd/main.go:12:", "cmd/main.go"),
        (
            "  --> crates\\demo\\src\\util.rs:12:9",
            "crates/demo/src/util.rs",
        ),
    ] {
        let res = collect_error_contexts(&root, snippet_input);
        assert_eq!(res.contexts.len(), 1, "input: {snippet_input}");
        let ctx = &res.contexts[0];
        assert_eq!(ctx.path, expected_path);
        assert_eq!(ctx.line, 12);
        assert_eq!(ctx.start_line, 12 - ERROR_CONTEXT_RADIUS_LINES);
        assert_eq!(ctx.end_line, 12 + ERROR_CONTEXT_RADIUS_LINES);
        assert!(ctx.snippet.contains("> L12| "));
        assert!(ctx.snippet.contains("  L7| "));
        assert!(ctx.snippet.contains("  L17| "));
    }

    // Project-internal absolute paths (both non-verbatim `proj.path()` and canonical `root.root()`).
    let abs_plain = proj.path().join("src").join("lib.rs");
    let abs_canon = root.root().join("src").join("app.ts");
    let abs_out = format!(
        "error at {}:12:5\n{}(12,5): error TS1005\n",
        abs_plain.display(),
        abs_canon.display()
    );
    let abs_res = collect_error_contexts(&root, &abs_out);
    assert_eq!(abs_res.contexts.len(), 2);
    assert_eq!(abs_res.contexts[0].path, "src/lib.rs");
    assert_eq!(abs_res.contexts[1].path, "src/app.ts");
}

#[test]
fn deduplicates_identical_and_overlapping_window_references() {
    let proj = Sandbox::new("dedup");
    proj.write("src/lib.rs", &numbered_lines("let x =", 60));
    let root = ProjectRoot::new(proj.path()).unwrap();

    // Line 12 window covers [7..=17]; repeated line 12 and nearby line 15 must NOT consume slot 2.
    // Line 40 is outside [7..=17] and gets slot 2.
    let out = concat!(
        "  --> src/lib.rs:12:5\n",
        "  --> src/lib.rs:12:9\n",
        "  --> src/lib.rs:15:3\n",
        "  --> src/lib.rs:40:1\n",
    );
    let res = collect_error_contexts(&root, out);
    assert_eq!(res.contexts.len(), 2);
    assert_eq!(res.contexts[0].line, 12);
    assert_eq!(res.contexts[1].line, 40);
    assert!(res.omissions.is_empty());
}

#[test]
fn security_matrix_blocks_sensitive_outside_symlink_extra_patterns_binary_and_bad_utf8() {
    let outer = Sandbox::new("sec-outer");
    let proj_dir = outer.path().join("project");
    let outside_dir = outer.path().join("outside");
    fs::create_dir_all(&proj_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let outside_file = outside_dir.join("outside.rs");
    fs::write(
        &outside_file,
        "const OUTSIDE_LEAK: &str = \"NEVER_READ\";\n",
    )
    .unwrap();

    // Project files: blocked sensitive files, custom extra_sensitive_patterns, binary, bad UTF-8, plus 1 safe file.
    fs::create_dir_all(proj_dir.join(".klens")).unwrap();
    fs::write(
        proj_dir.join(".klens/config.toml"),
        "schema_version = 1\nextra_sensitive_patterns = [\"vault/*.toml\"]\n",
    )
    .unwrap();
    fs::write(proj_dir.join(".env"), "DB_PASS=SUPER_SECRET_ENV\n").unwrap();
    fs::write(proj_dir.join(".env.production"), "PROD_SECRET=1\n").unwrap();
    fs::write(proj_dir.join("secrets.pem"), "PEM_BODY_NEVER_READ\n").unwrap();
    fs::write(proj_dir.join("private.key"), "KEY_BODY_NEVER_READ\n").unwrap();
    fs::write(proj_dir.join("id_rsa"), "SSH_KEY_NEVER_READ\n").unwrap();
    fs::write(
        proj_dir.join("credentials.json"),
        "{\"client_secret\":\"CRED_NEVER_READ\"}\n",
    )
    .unwrap();
    fs::create_dir_all(proj_dir.join("vault")).unwrap();
    fs::write(
        proj_dir.join("vault/prod.toml"),
        "token = \"VAULT_NEVER_READ\"\n",
    )
    .unwrap();
    fs::write(
        proj_dir.join("blob.bin"),
        b"\x00\x01\x02BINARY_NEVER_READ\n",
    )
    .unwrap();
    fs::write(proj_dir.join("bad_utf8.rs"), [0xFF, 0xFE, 0x80, b'\n']).unwrap();

    fs::create_dir_all(proj_dir.join("src")).unwrap();
    fs::write(
        proj_dir.join("src/safe.rs"),
        "pub fn safe_ok() -> i32 {\n    42\n}\n",
    )
    .unwrap();

    // Create escaping symlink (or NTFS junction on Windows without symlink privilege).
    let escape_ref: String;
    #[cfg(unix)]
    {
        let link = proj_dir.join("escape.rs");
        std::os::unix::fs::symlink(&outside_file, &link).unwrap();
        escape_ref = "escape.rs:1:1".to_string();
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let link = proj_dir.join("escape.rs");
        match std::os::windows::fs::symlink_file(&outside_file, &link) {
            Ok(()) => escape_ref = "escape.rs:1:1".to_string(),
            Err(e) if e.raw_os_error() == Some(1314) => {
                let junction = proj_dir.join("escape_dir");
                let status = std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(&junction)
                    .arg(&outside_dir)
                    .creation_flags(0x0800_0000)
                    .output()
                    .unwrap();
                assert!(status.status.success());
                escape_ref = "escape_dir/outside.rs:1:1".to_string();
            }
            Err(e) => panic!("unexpected symlink error: {e}"),
        }
    }

    let root = ProjectRoot::new(&proj_dir).unwrap();
    let error_output = format!(
        concat!(
            "error: .env:1:1\n",
            "error: .env.production:1:1\n",
            "error: secrets.pem:1:1\n",
            "error: private.key:1:1\n",
            "error: id_rsa:1:1\n",
            "error: credentials.json:1:1\n",
            "error: vault/prod.toml:1:1\n",
            "error: ../outside/outside.rs:1:1\n",
            "error: {}:1:1\n",
            "error: {}\n",
            "error: blob.bin:1:1\n",
            "error: bad_utf8.rs:1:1\n",
            "  --> src/safe.rs:2:5\n",
        ),
        outside_file.display(),
        escape_ref
    );

    let res = collect_error_contexts(&root, &error_output);
    assert_eq!(res.contexts.len(), 1, "only src/safe.rs may be read");
    assert_eq!(res.contexts[0].path, "src/safe.rs");
    assert!(res.contexts[0].snippet.contains("> L2|     42"));
    assert!(res.omissions.is_empty());

    // Clean up NTFS junction before Sandbox Drop on Windows.
    #[cfg(windows)]
    {
        let junction = proj_dir.join("escape_dir");
        if junction.exists() {
            let _ = fs::remove_dir(&junction);
        }
    }
}

#[test]
fn redacts_secrets_in_neighboring_context_lines_and_propagates_count() {
    let proj = Sandbox::new("redact");
    let synthetic_gh = format!("{}{}", "ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789");
    let src = format!(
        concat!(
            "pub fn init_client() {{\n",
            "    let token = \"{}\";\n",
            "    let a = 1;\n",
            "    let b = a + 2;\n",
            "    panic!(\"boom\");\n",
            "    let _ = (token, b);\n",
            "}}\n"
        ),
        synthetic_gh
    );
    proj.write("src/client.rs", &src);

    let root = ProjectRoot::new(proj.path()).unwrap();

    // Direct call to `collect_error_contexts`.
    let ctx_res = collect_error_contexts(&root, "  --> src/client.rs:5:5\n");
    assert_eq!(ctx_res.contexts.len(), 1);
    assert!(ctx_res.redactions_count >= 1);
    assert!(
        ctx_res.contexts[0]
            .snippet
            .contains("[REDACTED:GITHUB_TOKEN]")
    );
    assert!(!ctx_res.contexts[0].snippet.contains(&synthetic_gh));

    // Full `execute_command` propagation (non-zero exit, auto_context default true).
    let cmd = shell_cmd(
        "echo   --^> src/client.rs:5:5 1>&2 && exit /b 1",
        "echo '  --> src/client.rs:5:5' >&2; exit 1",
    );
    let env = execute_command(&root, &cmd, &RunOptions::default()).unwrap();
    assert_eq!(env.data.meta.exit_code, 1);
    assert_eq!(env.data.error_contexts.len(), 1);
    assert!(env.redactions_count >= 1);
    assert!(
        env.data.error_contexts[0]
            .snippet
            .contains("[REDACTED:GITHUB_TOKEN]")
    );
    assert!(!env.data.error_contexts[0].snippet.contains(&synthetic_gh));
}

#[test]
fn enforces_max_locations_token_budget_explicit_omissions_and_determinism() {
    let proj = Sandbox::new("budget-det");
    for i in 1..=5 {
        proj.write(
            &format!("src/mod_{i}.rs"),
            &numbered_lines(&format!("// file {i}"), 20),
        );
    }
    let root = ProjectRoot::new(proj.path()).unwrap();

    let output = concat!(
        "  --> src/mod_1.rs:10:1\n",
        "  --> src/mod_2.rs:10:1\n",
        "  --> src/mod_3.rs:10:1\n",
        "  --> src/mod_4.rs:10:1\n",
        "  --> src/mod_5.rs:10:1\n",
    );

    let r1 = collect_error_contexts(&root, output);
    let r2 = collect_error_contexts(&root, output);
    assert_eq!(r1, r2, "consecutive runs must be deterministic");
    assert_eq!(
        serde_json::to_string(&r1.contexts).unwrap(),
        serde_json::to_string(&r2.contexts).unwrap()
    );

    assert_eq!(r1.contexts.len(), MAX_ERROR_CONTEXT_LOCATIONS);
    assert_eq!(r1.contexts[0].path, "src/mod_1.rs");
    assert_eq!(r1.contexts[1].path, "src/mod_2.rs");
    assert_eq!(r1.contexts[2].path, "src/mod_3.rs");

    let total_tokens: usize = r1
        .contexts
        .iter()
        .map(|c| estimate_tokens(&c.snippet))
        .sum();
    assert!(
        total_tokens <= MAX_ERROR_CONTEXT_TOKENS,
        "total snippet tokens {total_tokens} exceeded {MAX_ERROR_CONTEXT_TOKENS}"
    );
    assert!(r1.omissions.iter().any(|o| {
        o.kind == OmissionKind::Items && o.reason == "error_context_limit" && o.count == 2
    }));

    // Also test hard 400-token cap when lines are very long.
    let long_line = "x".repeat(220); // ~55 tokens per line -> 11 lines ~ 605 tokens > 400
    for i in 1..=3 {
        let body = (1..=15)
            .map(|n| format!("let v_{i}_{n} = \"{long_line}\";"))
            .collect::<Vec<_>>()
            .join("\n");
        proj.write(&format!("src/wide_{i}.rs"), &body);
    }
    let wide_out = concat!(
        "  --> src/wide_1.rs:8:1\n",
        "  --> src/wide_2.rs:8:1\n",
        "  --> src/wide_3.rs:8:1\n",
    );
    let wr = collect_error_contexts(&root, wide_out);
    let wide_tokens: usize = wr
        .contexts
        .iter()
        .map(|c| estimate_tokens(&c.snippet))
        .sum();
    assert!(
        wide_tokens <= MAX_ERROR_CONTEXT_TOKENS,
        "wide snippet tokens {wide_tokens} exceeded {MAX_ERROR_CONTEXT_TOKENS}"
    );
    assert!(
        !wr.contexts.is_empty(),
        "narrowed radius fallback should still fit at least one location"
    );
    if wr.contexts.len() < 3 {
        assert!(
            wr.omissions
                .iter()
                .any(|o| o.kind == OmissionKind::Items
                    && o.reason == "error_context_budget_exceeded")
        );
    }
}

#[test]
fn runner_skips_auto_context_on_success_raw_or_disabled_and_formats_text() {
    let proj = Sandbox::new("runner-modes");
    proj.write("src/demo.rs", &numbered_lines("let demo =", 15));
    let root = ProjectRoot::new(proj.path()).unwrap();

    // 1. exit_code == 0 -> empty error_contexts even if output mentions path:line.
    let ok_cmd = shell_cmd(
        "echo   --^> src/demo.rs:8:1",
        "echo '  --> src/demo.rs:8:1'",
    );
    let ok_env = execute_command(&root, &ok_cmd, &RunOptions::default()).unwrap();
    assert_eq!(ok_env.data.meta.exit_code, 0);
    assert!(ok_env.data.error_contexts.is_empty());

    // 2. raw == true -> empty error_contexts on non-zero exit.
    let fail_cmd = shell_cmd(
        "echo   --^> src/demo.rs:8:1 1>&2 && exit /b 1",
        "echo '  --> src/demo.rs:8:1' >&2; exit 1",
    );
    let raw_env = execute_command(
        &root,
        &fail_cmd,
        &RunOptions {
            raw: true,
            ..RunOptions::default()
        },
    )
    .unwrap();
    assert_eq!(raw_env.data.meta.exit_code, 1);
    assert!(raw_env.data.error_contexts.is_empty());

    // 3. auto_context == false -> empty error_contexts on non-zero exit.
    let disabled_env = execute_command(
        &root,
        &fail_cmd,
        &RunOptions {
            auto_context: false,
            ..RunOptions::default()
        },
    )
    .unwrap();
    assert_eq!(disabled_env.data.meta.exit_code, 1);
    assert!(disabled_env.data.error_contexts.is_empty());

    // 4. Default (auto_context == true, raw == false, exit != 0) populates context and formats text.
    let mut enabled_env = execute_command(&root, &fail_cmd, &RunOptions::default()).unwrap();
    assert_eq!(enabled_env.data.error_contexts.len(), 1);
    // Filtered token metrics stay strictly based on terminal output (same as disabled run).
    assert_eq!(
        enabled_env.data.meta.est_filtered_tokens,
        disabled_env.data.meta.est_filtered_tokens
    );
    assert_eq!(
        enabled_env.data.saved_tokens,
        disabled_env.data.saved_tokens
    );

    enrich_error_context_symbols(&mut enabled_env.data.error_contexts, |rel, line| {
        assert_eq!(rel.as_str(), "src/demo.rs");
        assert_eq!(line, 8);
        Some("fn demo_fn".to_string())
    });
    let rendered = format_run_text(&enabled_env);
    assert!(rendered.contains("## Error Context"));
    assert!(rendered.contains("### src/demo.rs:8 (fn demo_fn) [L3-L13]"));
    assert!(rendered.contains("> L8| let demo = line 8"));
    assert_eq!(format_error_contexts_text(&[]), "");
}
