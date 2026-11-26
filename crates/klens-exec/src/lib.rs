#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

//! Karasu Lens (`klens-exec`) — deterministic terminal runner, ANSI cleaner,
//! block-aware command filters, raw log + metadata persistence, and Git checkpoints.
//!
//! Constitutional guarantees:
//! - Article 4: zero error context loss (`truncated_errors == false` on every non-zero run)
//!   and complete raw output persisted to `.klens/runs/<id>.raw.log`.
//! - Article 7: real measured token savings computed strictly on ANSI-cleaned text.
//! - Article 8: secret redaction at the output gate, `#![deny(clippy::print_stdout)]`,
//!   and Windows `CREATE_NO_WINDOW` (`0x08000000`) on all subprocess spawns and kills.

pub mod ansi;
pub mod checkpoint;
pub mod error;
pub mod error_context;
pub mod filters;
pub mod output;
pub mod runner;
pub mod store;

use klens_core::{ProjectRoot, ProvenanceEnvelope, RawFallback, TrustLevel, redact_secrets};
use serde::{Deserialize, Serialize};

pub use ansi::{contains_ansi, strip_ansi};
pub use checkpoint::{
    CheckpointInfo, RollbackReport, create_checkpoint, format_checkpoint_created_text,
    format_checkpoints_list_text, format_rollback_text, list_checkpoints, rollback_checkpoint,
};
pub use error::ExecError;
pub use error_context::{
    ERROR_CONTEXT_RADIUS_LINES, ErrorContextResult, ErrorSourceContext,
    MAX_ERROR_CONTEXT_LOCATIONS, MAX_ERROR_CONTEXT_TOKENS, collect_error_contexts,
    enrich_error_context_symbols, extract_error_locations, format_error_contexts_text,
};
pub use filters::{
    CargoFilter, DockerFilter, DotnetFilter, EslintFilter, FilterRegistry, GenericSafeFilter,
    GitFilter, GoTestFilter, GradleFilter, MakeFilter, NodePkgFilter, PytestFilter,
};
pub use runner::{
    RawProcessOutput, RelatedBugfixHint, RunOptions, RunResponse, TIMEOUT_EXIT_CODE,
    WINDOWS_CREATE_NO_WINDOW, combine_raw_output, execute_command, format_run_text, run_process,
};
pub use store::{
    DEFAULT_MAX_KEPT_RUNS, NewRunRecord, RUNS_REL_DIR, RunMeta, RunStore, validate_run_id,
};

/// Payload returned by `klens runs show <run_id> [--raw]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDetail {
    pub meta: RunMeta,
    pub content: String,
    pub raw_mode: bool,
}

/// List stored runs wrapped in a `ProvenanceEnvelope`.
pub fn list_stored_runs(
    project_root: &ProjectRoot,
    limit: Option<usize>,
) -> Result<ProvenanceEnvelope<Vec<RunMeta>>, ExecError> {
    let store = RunStore::new(project_root.clone());
    let runs = store.list_runs(limit)?;
    Ok(ProvenanceEnvelope::new(
        TrustLevel::VerifiedRaw,
        project_root.project_id(),
        runs,
    ))
}

/// Load and display a single stored run (either filtered or `--raw`), applying secret
/// redaction at the output gate.
pub fn show_stored_run(
    project_root: &ProjectRoot,
    run_id: &str,
    raw: bool,
) -> Result<ProvenanceEnvelope<RunDetail>, ExecError> {
    let store = RunStore::new(project_root.clone());
    let (meta, raw_text) = store.load_run(run_id)?;

    let (content, omissions, redactions_count) = if raw {
        let redacted = redact_secrets(&raw_text);
        (redacted.text, Vec::new(), redacted.redactions_count)
    } else {
        let clean = strip_ansi(&raw_text);
        let registry = FilterRegistry::with_defaults();
        let filter = registry.by_id(&meta.filter_used);
        let filtered = filter.filter(&clean, "", meta.exit_code);
        let redacted = redact_secrets(&filtered.summary);
        (redacted.text, filtered.omissions, redacted.redactions_count)
    };

    let raw_log_path = meta.raw_log_path.clone();
    let detail = RunDetail {
        meta,
        content,
        raw_mode: raw,
    };

    let mut env =
        ProvenanceEnvelope::new(TrustLevel::VerifiedRaw, project_root.project_id(), detail)
            .with_redactions_count(redactions_count)
            .with_raw_fallback(RawFallback {
                reason: "complete unfiltered terminal output saved on disk".to_string(),
                path: Some(raw_log_path),
                hint: Some("pass `--raw` to inspect unfiltered output".to_string()),
            });

    for om in omissions {
        env = env.with_omission(om);
    }

    Ok(env)
}

/// Plain-text formatter for `klens runs list`.
pub fn format_runs_list_text(env: &ProvenanceEnvelope<Vec<RunMeta>>) -> String {
    if env.data.is_empty() {
        return "[klens runs] no runs recorded yet".to_string();
    }
    let mut lines = vec![format!("[klens runs] {} recorded:", env.data.len())];
    for r in &env.data {
        lines.push(format!(
            "  {}  exit={:<3}  filter={:<7}  tokens={}->{} ({:.1}% saved)  {}ms  {}",
            r.run_id,
            r.exit_code,
            r.filter_used,
            r.est_raw_tokens,
            r.est_filtered_tokens,
            r.savings_percent(),
            r.duration_ms,
            r.command
        ));
    }
    lines.join("\n")
}

/// Plain-text formatter for `klens runs show <run_id> [--raw]`.
pub fn format_run_detail_text(env: &ProvenanceEnvelope<RunDetail>) -> String {
    let d = &env.data;
    let m = &d.meta;
    let mode = if d.raw_mode { "raw" } else { "filtered" };
    let header = format!(
        "[klens runs show ({mode})] id={} exit={} filter={} duration={}ms tokens={}->{} ({:.1}% saved) cmd=\"{}\" raw={}",
        m.run_id,
        m.exit_code,
        m.filter_used,
        m.duration_ms,
        m.est_raw_tokens,
        m.est_filtered_tokens,
        m.savings_percent(),
        m.command,
        m.raw_log_path
    );
    if d.content.is_empty() {
        header
    } else {
        format!("{header}\n{}", d.content.trim_end())
    }
}
