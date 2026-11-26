//! Raw run logs hold unfiltered command output (which can include secrets). They must never
//! show up as committable files, even in a project that was never `klens attach`-ed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use klens_core::ProjectRoot;
use klens_exec::store::{NewRunRecord, RunStore};

struct TempRepo(PathBuf);

impl TempRepo {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("klens-runs-gi-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        Self(dir)
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git must be installed");
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn record(raw: &str) -> NewRunRecord<'_> {
    NewRunRecord {
        command: "deploy --token x",
        cwd: ".",
        filter_used: "generic",
        exit_code: 0,
        duration_ms: 1,
        raw_bytes: raw.len(),
        filtered_bytes: raw.len(),
        est_raw_tokens: 1,
        est_filtered_tokens: 1,
        truncated_errors: false,
        raw_log_content: raw,
    }
}

#[test]
fn run_logs_are_not_committable_in_an_unattached_project() {
    let repo = TempRepo::new("unattached");
    let store = RunStore::new(ProjectRoot::new(&repo.0).unwrap());
    store
        .save_run_with_id(
            "20261126-120000-aa01",
            "2026-11-26T12:00:00Z",
            &record("raw\n"),
        )
        .unwrap();

    let status = git(&repo.0, &["status", "--porcelain", "--untracked-files=all"]);
    assert!(
        !status.contains(".klens/runs"),
        "run logs are visible to git:\n{status}"
    );
}

#[test]
fn ignore_file_does_not_disturb_listing_or_pruning() {
    let repo = TempRepo::new("listing");
    let store = RunStore::new(ProjectRoot::new(&repo.0).unwrap()).with_max_kept_runs(2);
    for i in 1..=3 {
        store
            .save_run_with_id(
                &format!("20261126-12000{i}-aa0{i}"),
                "2026-11-26T12:00:00Z",
                &record("raw\n"),
            )
            .unwrap();
    }
    assert_eq!(store.list_runs(None).unwrap().len(), 2);
    assert!(store.runs_dir().join(".gitignore").is_file());
}
