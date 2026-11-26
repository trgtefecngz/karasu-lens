//! End-to-end CLI tests for Phase 3.3 `klens run` automatic error source context
//! (`--no-auto-context`, `--raw`, `--json`, plain text, and AST symbol enrichment).

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
        let dir = std::env::temp_dir().join(format!(
            "klens-cli-run-ctx-{label}-{}-{n}",
            std::process::id()
        ));
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

fn fail_shell_args() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        vec!["cmd", "/C", "echo   --^> src/calc.rs:7:5 1>&2 && exit /b 2"]
    }
    #[cfg(not(windows))]
    {
        vec!["sh", "-c", "echo '  --> src/calc.rs:7:5' >&2; exit 2"]
    }
}

#[test]
fn cli_run_auto_context_populates_ast_symbol_and_respects_no_auto_context_and_raw() {
    let proj = Sandbox::new("e2e");
    let cache = Sandbox::new("e2e-cache");

    proj.write(
        "src/calc.rs",
        concat!(
            "pub fn helper() -> i32 { 1 }\n",
            "\n",
            "pub fn broken_calc(n: i32) -> i32 {\n",
            "    let a = n + 1;\n",
            "    let b = a * 2;\n",
            "    let c = b - 3;\n",
            "    panic!(\"broken at {c}\")\n",
            "}\n",
        ),
    );

    // 1. `klens run --json -- <failing_cmd>` attaches error_contexts + AST symbol `fn broken_calc`.
    let mut args_json = vec!["run", "--json", "--"];
    args_json.extend(fail_shell_args());
    let out_json = run_klens(&proj, &cache, &args_json);
    assert_eq!(out_json.status.code(), Some(2));
    let parsed: Value = serde_json::from_slice(&out_json.stdout).unwrap();
    let contexts = parsed["data"]["error_contexts"].as_array().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0]["path"], "src/calc.rs");
    assert_eq!(contexts[0]["line"], 7);
    assert_eq!(contexts[0]["symbol"], "fn broken_calc");
    assert!(
        contexts[0]["snippet"]
            .as_str()
            .unwrap()
            .contains("> L7|     panic!(\"broken at {c}\")")
    );
    // Read-only CodeIndex must not create `.klens/cache/` inside the project directory.
    assert!(!proj.path().join(".klens").join("cache").exists());

    // 2. Plain text `klens run -- <failing_cmd>` displays `## Error Context` + AST symbol.
    let mut args_text = vec!["run", "--"];
    args_text.extend(fail_shell_args());
    let out_text = run_klens(&proj, &cache, &args_text);
    assert_eq!(out_text.status.code(), Some(2));
    let text = String::from_utf8(out_text.stdout).unwrap();
    assert!(text.contains("## Error Context"));
    assert!(text.contains("### src/calc.rs:7 (fn broken_calc)"));
    assert!(text.contains("> L7|     panic!(\"broken at {c}\")"));

    // 3. `klens run --no-auto-context --json -- <failing_cmd>` omits `error_contexts`.
    let mut args_no_ctx = vec!["run", "--no-auto-context", "--json", "--"];
    args_no_ctx.extend(fail_shell_args());
    let out_no_ctx = run_klens(&proj, &cache, &args_no_ctx);
    assert_eq!(out_no_ctx.status.code(), Some(2));
    let parsed_no_ctx: Value = serde_json::from_slice(&out_no_ctx.stdout).unwrap();
    assert!(parsed_no_ctx["data"].get("error_contexts").is_none());

    // 4. `klens run --raw --json -- <failing_cmd>` omits `error_contexts`.
    let mut args_raw = vec!["run", "--raw", "--json", "--"];
    args_raw.extend(fail_shell_args());
    let out_raw = run_klens(&proj, &cache, &args_raw);
    assert_eq!(out_raw.status.code(), Some(2));
    let parsed_raw: Value = serde_json::from_slice(&out_raw.stdout).unwrap();
    assert!(parsed_raw["data"].get("error_contexts").is_none());
}
