//! Raw log + structured metadata store (`.klens/runs/<timestamp>-<id>.{raw.log,meta.json}`).
//!
//! Follows `docs/02-DATA-SCHEMAS.md` §4 with atomic writes and automatic retention pruning.

use std::fs;
use std::path::{Path, PathBuf};

use klens_core::{ProjectRoot, SCHEMA_VERSION, write_atomic};
use serde::{Deserialize, Serialize};

use crate::error::ExecError;
use klens_core::time::generate_sortable_id;

/// Default maximum number of historical runs retained under `.klens/runs/`.
pub const DEFAULT_MAX_KEPT_RUNS: usize = 200;

/// Relative directory where terminal run artifacts are stored inside a project.
pub const RUNS_REL_DIR: &str = ".klens/runs";

/// Contents of `.klens/runs/.gitignore`: ignore everything, including this file.
const RUNS_GITIGNORE: &str = "# Created by klens: raw run logs are local-only.\n*\n";

/// Persistent run metadata schema (`docs/02-DATA-SCHEMAS.md` §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMeta {
    pub schema_version: u32,
    pub run_id: String,
    pub timestamp_utc: String,
    pub command: String,
    pub cwd: String,
    pub filter_used: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub raw_bytes: usize,
    pub filtered_bytes: usize,
    pub est_raw_tokens: usize,
    pub est_filtered_tokens: usize,
    pub raw_log_path: String,
    pub truncated_errors: bool,
}

impl RunMeta {
    /// Tokens saved (`est_raw_tokens - est_filtered_tokens`, saturated at 0).
    pub fn saved_tokens(&self) -> usize {
        self.est_raw_tokens.saturating_sub(self.est_filtered_tokens)
    }

    /// Real measured percentage saved (0.0 when raw tokens is 0). Never hardcoded.
    pub fn savings_percent(&self) -> f64 {
        if self.est_raw_tokens == 0 {
            return 0.0;
        }
        (self.saved_tokens() as f64 / self.est_raw_tokens as f64) * 100.0
    }
}

/// Parameters required to persist a run pair (`.raw.log` + `.meta.json`).
#[derive(Debug, Clone)]
pub struct NewRunRecord<'a> {
    pub command: &'a str,
    pub cwd: &'a str,
    pub filter_used: &'a str,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub raw_bytes: usize,
    pub filtered_bytes: usize,
    pub est_raw_tokens: usize,
    pub est_filtered_tokens: usize,
    pub truncated_errors: bool,
    pub raw_log_content: &'a str,
}

/// Manages `.klens/runs/` persistence, loading, listing, and retention pruning.
#[derive(Debug, Clone)]
pub struct RunStore {
    root: ProjectRoot,
    max_kept_runs: usize,
}

impl RunStore {
    /// Open a run store rooted at `project_root` with the default 200-run retention policy.
    pub fn new(root: ProjectRoot) -> Self {
        Self {
            root,
            max_kept_runs: DEFAULT_MAX_KEPT_RUNS,
        }
    }

    /// Override the maximum number of retained runs (minimum 1).
    pub fn with_max_kept_runs(mut self, max_kept_runs: usize) -> Self {
        self.max_kept_runs = max_kept_runs.max(1);
        self
    }

    /// Borrow the underlying confined project root.
    pub fn project_root(&self) -> &ProjectRoot {
        &self.root
    }

    /// Absolute path to `.klens/runs`.
    pub fn runs_dir(&self) -> PathBuf {
        self.root.root().join(".klens").join("runs")
    }

    /// Atomically persist `.raw.log` and `.meta.json` and prune older runs beyond `max_kept_runs`.
    pub fn save_run(&self, record: &NewRunRecord<'_>) -> Result<RunMeta, ExecError> {
        let (run_id, timestamp_utc) = generate_sortable_id(record.command);
        self.save_run_with_id(&run_id, &timestamp_utc, record)
    }

    /// Persist a run with an explicit ID and timestamp (useful for deterministic tests).
    pub fn save_run_with_id(
        &self,
        run_id: &str,
        timestamp_utc: &str,
        record: &NewRunRecord<'_>,
    ) -> Result<RunMeta, ExecError> {
        validate_run_id(run_id)?;

        let raw_rel = format!("{RUNS_REL_DIR}/{run_id}.raw.log");
        let meta_rel = format!("{RUNS_REL_DIR}/{run_id}.meta.json");

        let (raw_abs, _) = self.root.resolve_for_write(&raw_rel)?;
        let (meta_abs, _) = self.root.resolve_for_write(&meta_rel)?;

        let meta = RunMeta {
            schema_version: SCHEMA_VERSION,
            run_id: run_id.to_string(),
            timestamp_utc: timestamp_utc.to_string(),
            // Shown by `klens runs`, the UI and handoffs: never keep a token typed on the
            // command line (`--token ghp_...`, `-H "Authorization: Bearer ..."`).
            command: klens_core::redact_secrets(record.command).text,
            cwd: record.cwd.to_string(),
            filter_used: record.filter_used.to_string(),
            exit_code: record.exit_code,
            duration_ms: record.duration_ms,
            raw_bytes: record.raw_bytes,
            filtered_bytes: record.filtered_bytes,
            est_raw_tokens: record.est_raw_tokens,
            est_filtered_tokens: record.est_filtered_tokens,
            raw_log_path: raw_rel,
            truncated_errors: record.truncated_errors,
        };

        let meta_json = serde_json::to_string_pretty(&meta)?;

        self.ensure_runs_ignored_by_git()?;
        write_atomic(&raw_abs, record.raw_log_content.as_bytes())?;
        write_atomic(&meta_abs, meta_json.as_bytes())?;

        self.prune_old_runs()?;
        Ok(meta)
    }

    /// List stored run metadata, sorted newest-first (`run_id` descending).
    pub fn list_runs(&self, limit: Option<usize>) -> Result<Vec<RunMeta>, ExecError> {
        let dir = self.runs_dir();
        if !dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut meta_files: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|source| ExecError::Io {
            path: dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| ExecError::Io {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".meta.json"))
            {
                meta_files.push(path);
            }
        }

        // Lexicographical descending order = newest first because IDs begin with `YYYYMMDD-HHMMSS-`.
        meta_files.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

        let mut runs = Vec::new();
        for path in meta_files {
            if let Some(max) = limit
                && runs.len() >= max
            {
                break;
            }
            let content = fs::read_to_string(&path).map_err(|source| ExecError::Io {
                path: path.clone(),
                source,
            })?;
            if let Ok(meta) = serde_json::from_str::<RunMeta>(&content) {
                runs.push(meta);
            }
        }

        runs.sort_by(|a, b| b.run_id.cmp(&a.run_id));
        Ok(runs)
    }

    /// Load a single run's metadata and exact raw log content by `run_id`.
    pub fn load_run(&self, run_id: &str) -> Result<(RunMeta, String), ExecError> {
        validate_run_id(run_id)?;

        let meta_rel = format!("{RUNS_REL_DIR}/{run_id}.meta.json");
        let raw_rel = format!("{RUNS_REL_DIR}/{run_id}.raw.log");

        let meta_abs = self
            .root
            .resolve_existing(&meta_rel)
            .map(|(p, _)| p)
            .map_err(|_| ExecError::RunNotFound(run_id.to_string()))?;

        let meta_text = fs::read_to_string(&meta_abs).map_err(|source| ExecError::Io {
            path: meta_abs.clone(),
            source,
        })?;
        let meta: RunMeta = serde_json::from_str(&meta_text)?;

        let raw_abs = self
            .root
            .resolve_existing(&raw_rel)
            .map(|(p, _)| p)
            .map_err(|_| ExecError::RunNotFound(run_id.to_string()))?;

        let raw_text = fs::read_to_string(&raw_abs).map_err(|source| ExecError::Io {
            path: raw_abs,
            source,
        })?;

        Ok((meta, raw_text))
    }

    /// Raw logs are unfiltered command output and may contain secrets. A self-ignoring
    /// `.klens/runs/.gitignore` keeps them out of commits even in projects that never ran
    /// `klens attach`.
    fn ensure_runs_ignored_by_git(&self) -> Result<(), ExecError> {
        let (ignore_abs, _) = self
            .root
            .resolve_for_write(format!("{RUNS_REL_DIR}/.gitignore"))?;
        if !ignore_abs.exists() {
            write_atomic(&ignore_abs, RUNS_GITIGNORE.as_bytes())?;
        }
        Ok(())
    }

    /// Remove oldest `.meta.json` + `.raw.log` pairs beyond `self.max_kept_runs`.
    pub fn prune_old_runs(&self) -> Result<usize, ExecError> {
        let dir = self.runs_dir();
        if !dir.is_dir() {
            return Ok(0);
        }

        let mut ids: Vec<String> = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|source| ExecError::Io {
            path: dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| ExecError::Io {
                path: dir.clone(),
                source,
            })?;
            let name = entry.file_name();
            if let Some(s) = name.to_str()
                && let Some(id) = s.strip_suffix(".meta.json")
            {
                ids.push(id.to_string());
            }
        }

        if ids.len() <= self.max_kept_runs {
            return Ok(0);
        }

        // Ascending order puts oldest IDs first.
        ids.sort();
        let to_remove = ids.len() - self.max_kept_runs;
        let mut removed = 0usize;

        for id in ids.into_iter().take(to_remove) {
            remove_if_exists(&dir.join(format!("{id}.meta.json")));
            remove_if_exists(&dir.join(format!("{id}.raw.log")));
            removed += 1;
        }

        Ok(removed)
    }
}

fn remove_if_exists(path: &Path) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
}

/// Strictly validate a run ID to prevent directory traversal or weird path characters.
pub fn validate_run_id(run_id: &str) -> Result<(), ExecError> {
    if run_id.is_empty()
        || run_id.len() > 128
        || !run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ExecError::InvalidRunId(run_id.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("klens-store-{tag}-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn saves_loads_and_prunes_oldest_runs_cleanly() {
        let tmp = TempDir::new("prune");
        let root = ProjectRoot::new(&tmp.0).unwrap();
        let store = RunStore::new(root).with_max_kept_runs(3);

        for i in 1..=5 {
            let id = format!("20261122-12000{i}-aa0{i}");
            let rec = NewRunRecord {
                command: "cargo test",
                cwd: ".",
                filter_used: "cargo",
                exit_code: 0,
                duration_ms: 100 + i as u64,
                raw_bytes: 500,
                filtered_bytes: 100,
                est_raw_tokens: 125,
                est_filtered_tokens: 25,
                truncated_errors: false,
                raw_log_content: &format!("raw output #{i}\n"),
            };
            store
                .save_run_with_id(&id, "2026-11-22T12:00:00Z", &rec)
                .unwrap();
        }

        let runs = store.list_runs(None).unwrap();
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].run_id, "20261122-120005-aa05");
        assert_eq!(runs[1].run_id, "20261122-120004-aa04");
        assert_eq!(runs[2].run_id, "20261122-120003-aa03");

        // Oldest two runs must have been removed (both meta and raw log).
        assert!(store.load_run("20261122-120001-aa01").is_err());
        assert!(
            !store
                .runs_dir()
                .join("20261122-120001-aa01.raw.log")
                .exists()
        );
        assert!(
            !store
                .runs_dir()
                .join("20261122-120002-aa02.raw.log")
                .exists()
        );

        // Newest run loads verbatim.
        let (meta, raw) = store.load_run("20261122-120005-aa05").unwrap();
        assert_eq!(meta.schema_version, 1);
        assert_eq!(
            meta.raw_log_path,
            ".klens/runs/20261122-120005-aa05.raw.log"
        );
        assert_eq!(raw, "raw output #5\n");
    }

    #[test]
    fn rejects_traversal_run_ids() {
        assert!(validate_run_id("../secret").is_err());
        assert!(validate_run_id("a/b").is_err());
        assert!(validate_run_id("a\\b").is_err());
        assert!(validate_run_id("").is_err());
    }
}
