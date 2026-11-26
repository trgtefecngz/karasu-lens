//! End-to-end CLI tests for `klens read --include imports,memory,impact --read-only`.

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
            "klens-cli-read-ctx-{label}-{}-{n}",
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

#[test]
fn cli_read_include_imports_memory_impact_readonly_writes_zero_bytes() {
    let proj = Sandbox::new("e2e");
    let cache = Sandbox::new("e2e-cache");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"cli_ctx_demo\"\nversion = \"0.1.0\"\n",
    );
    proj.write(
        "src/engine.rs",
        concat!(
            "use std::collections::BTreeMap;\n",
            "use std::fmt;\n",
            "\n",
            "pub fn run_step(val: usize) -> usize {\n",
            "    let _m: BTreeMap<usize, usize> = BTreeMap::new();\n",
            "    let _ = fmt::Error;\n",
            "    val + 1\n",
            "}\n",
        ),
    );
    proj.write(
        "src/main.rs",
        "use crate::engine::run_step;\nfn main() { let _ = run_step(1); }\n",
    );

    // Seed a linked memory note first, then delete `.klens/cache/` before testing `--read-only`.
    let add_out = run_klens(
        &proj,
        &cache,
        &[
            "memory",
            "add",
            "--id",
            "fb-engine-note",
            "--title",
            "Engine geri bildirimi (ğüşiöç)",
            "--kind",
            "feedback",
            "--anchor",
            "src/engine.rs#run_step",
            "--body",
            "run_step her zaman deterministik kalmalı.",
            "--json",
        ],
    );
    assert!(
        add_out.status.success(),
        "memory add failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    let _ = fs::remove_dir_all(proj.path().join(".klens").join("cache"));

    let before_tree = snapshot_tree(proj.path());

    // Run `klens read src/engine.rs --symbol run_step --include imports,memory,impact --read-only --json`.
    let read_out = run_klens(
        &proj,
        &cache,
        &[
            "read",
            "src/engine.rs",
            "--symbol",
            "run_step",
            "--include",
            "imports,memory,impact",
            "--read-only",
            "--json",
        ],
    );
    assert!(
        read_out.status.success(),
        "klens read failed: {}",
        String::from_utf8_lossy(&read_out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&read_out.stdout).unwrap();
    assert_eq!(parsed["data"]["status"], "OK");
    let ctx = &parsed["data"]["context"];
    assert_eq!(ctx["imports"]["total_import_lines"], 2);
    assert_eq!(ctx["memory"][0]["id"], "fb-engine-note");
    assert_eq!(ctx["memory"][0]["kind"], "feedback");
    assert_eq!(ctx["memory"][0]["is_stale"], false);
    assert!(
        ctx["impact"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["path"] == "src/main.rs")
    );

    // Invalid `--include` fails closed with non-zero exit code.
    let bad_out = run_klens(
        &proj,
        &cache,
        &[
            "read",
            "src/engine.rs",
            "--symbol",
            "run_step",
            "--include",
            "unknown",
            "--read-only",
        ],
    );
    assert!(!bad_out.status.success());

    // Verify ZERO bytes were written to the project directory during `--read-only`.
    let after_tree = snapshot_tree(proj.path());
    assert_eq!(before_tree, after_tree);
}
