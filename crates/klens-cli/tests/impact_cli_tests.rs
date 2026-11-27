//! `klens impact`: `diff` / `diff:staged` targets (same as the MCP tool) and bounded output
//! (`--budget`, `--limit`, honest omission footer).
//!
//! Runs the real `klens` binary with a sandboxed `USERPROFILE`/`HOME`.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use klens_core::estimate_tokens;
use serde_json::Value;

struct Workspace {
    base: PathBuf,
    home: PathBuf,
    repo: PathBuf,
}

impl Workspace {
    fn new(label: &str) -> Self {
        let base =
            std::env::temp_dir().join(format!("klens-impact-cli-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let ws = Self {
            home: base.join("home"),
            repo: base.join("repo"),
            base,
        };
        fs::create_dir_all(&ws.home).unwrap();
        fs::create_dir_all(ws.repo.join("src")).unwrap();
        fs::write(
            ws.repo.join("Cargo.toml"),
            "[package]\nname = \"impact_demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        // One shared module used by many files: a wide blast radius.
        let mut lib = String::from("pub mod core;\n");
        fs::write(
            ws.repo.join("src").join("core.rs"),
            "pub fn shared_helper(x: i32) -> i32 {\n    x + 1\n}\n",
        )
        .unwrap();
        for i in 0..120 {
            lib.push_str(&format!("pub mod user_{i:03};\n"));
            fs::write(
                ws.repo.join("src").join(format!("user_{i:03}.rs")),
                format!(
                    "use crate::core::shared_helper;\n\npub fn caller_{i:03}() -> i32 {{\n    shared_helper({i})\n}}\n"
                ),
            )
            .unwrap();
        }
        fs::write(ws.repo.join("src").join("lib.rs"), lib).unwrap();
        ws.git(&["init", "-q"]);
        ws.git(&["config", "user.email", "test@klens.local"]);
        ws.git(&["config", "user.name", "Klens Test"]);
        ws.git(&["add", "."]);
        ws.git(&["commit", "-q", "-m", "baseline"]);
        ws
    }

    fn git(&self, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(&self.repo)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn klens(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_klens"));
        cmd.args(args)
            .current_dir(&self.repo)
            .env("USERPROFILE", &self.home)
            .env("HOME", &self.home)
            .stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        cmd.output().expect("failed to run klens binary")
    }

    fn klens_ok(&self, args: &[&str]) -> String {
        let out = self.klens(args);
        assert!(
            out.status.success(),
            "klens {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn impact_diff_targets_run_the_diff_blast_radius_instead_of_not_found() {
    let ws = Workspace::new("diff");
    fs::write(
        ws.repo.join("src").join("core.rs"),
        "pub fn shared_helper(x: i32) -> i32 {\n    x + 2\n}\n",
    )
    .unwrap();

    let text = ws.klens_ok(&["impact", "--read-only", "diff"]);
    assert!(!text.contains("NotFound"), "{text}");
    assert!(text.contains("diff-check status="), "{text}");
    assert!(text.contains("src/core.rs"), "{text}");
    assert!(text.contains("## Blast Radius"), "{text}");
    // 120 dependents, listed up to the text cap, the rest counted.
    assert!(text.contains("more impacted files:"), "{text}");
    // Each blast-radius line names its location once.
    for line in text.lines().filter(|l| l.starts_with("  - [d=")) {
        let path = line.split("] ").nth(1).unwrap().split(':').next().unwrap();
        assert_eq!(line.matches(path).count(), 1, "{line}");
    }

    // Nothing staged yet: `diff:staged` sees no changed files.
    let staged = ws.klens_ok(&["impact", "--read-only", "--json", "diff:staged"]);
    let staged: Value = serde_json::from_str(&staged).unwrap();
    assert_eq!(staged["data"]["changed_files"].as_array().unwrap().len(), 0);

    ws.git(&["add", "src/core.rs"]);
    let staged = ws.klens_ok(&["impact", "--read-only", "--json", "diff:staged"]);
    let staged: Value = serde_json::from_str(&staged).unwrap();
    let changed = staged["data"]["changed_files"].as_array().unwrap();
    assert_eq!(changed.len(), 1, "{staged}");
    assert_eq!(changed[0]["path"], "src/core.rs");
}

#[test]
fn impact_budget_and_limit_bound_text_and_json_with_an_honest_tail() {
    let ws = Workspace::new("budget");

    let text = ws.klens_ok(&["impact", "--read-only", "--budget", "300", "src/core.rs"]);
    assert!(estimate_tokens(text.trim_end()) <= 300, "{text}");
    assert!(text.contains("affected_files="), "{text}");
    let tail = text.trim_end().lines().last().unwrap();
    assert!(
        tail.starts_with("  +") && tail.contains("more files"),
        "{tail}"
    );
    assert!(
        tail.contains("at d1-2") && tail.contains("at d3+"),
        "{tail}"
    );

    // Default budget still bounds the output; `--budget 0` lists every file.
    let default = ws.klens_ok(&["impact", "--read-only", "src/core.rs"]);
    let all = ws.klens_ok(&["impact", "--read-only", "--budget", "0", "src/core.rs"]);
    assert!(all.len() > default.len(), "no cap must show more");
    assert!(!all.contains("more files"), "{all}");

    // `--limit` caps listed files; JSON honours it with explicit omission counts.
    let limited = ws.klens_ok(&["impact", "--read-only", "--limit", "3", "src/core.rs"]);
    assert_eq!(
        limited.lines().filter(|l| l.starts_with("  [d")).count(),
        3,
        "{limited}"
    );
    let json = ws.klens_ok(&[
        "impact",
        "--read-only",
        "--json",
        "--limit",
        "3",
        "src/core.rs",
    ]);
    let json: Value = serde_json::from_str(&json).unwrap();
    let total = json["data"]["affected_files_count"].as_u64().unwrap();
    assert!(total > 3);
    assert_eq!(json["data"]["omitted_files"].as_u64().unwrap(), total - 3);

    // Without an explicit cap, JSON stays the full list (no omission fields).
    let full = ws.klens_ok(&["impact", "--read-only", "--json", "src/core.rs"]);
    assert!(!full.contains("omitted_files"), "full JSON is unbounded");
}
