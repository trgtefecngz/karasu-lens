//! Safe subprocess runner with timeout support, process-tree termination,
//! Windows `CREATE_NO_WINDOW` (`0x08000000`) enforcement, ANSI cleaning,
//! secret redaction at the output gate, and raw log persistence.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use klens_core::{
    ProjectRoot, ProvenanceEnvelope, RawFallback, TrustLevel, estimate_tokens, redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::ansi::strip_ansi;
use crate::error::ExecError;
use crate::error_context::{
    ErrorSourceContext, collect_error_contexts, format_error_contexts_text,
};
use crate::filters::FilterRegistry;
pub use crate::output::combine_raw_output;
use crate::store::{DEFAULT_MAX_KEPT_RUNS, NewRunRecord, RunMeta, RunStore};

/// Windows `CREATE_NO_WINDOW` creation flag (`0x0800_0000`) to prevent console window flashes.
pub const WINDOWS_CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Standard exit code used when a command exceeds its configured timeout.
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// Configure a `Command` so it never opens a visible console window on Windows.
pub(crate) fn configure_no_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(WINDOWS_CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

/// Kill a process and its entire descendant tree without flashing a console window on Windows.
pub(crate) fn kill_process_tree(pid: u32) {
    #[cfg(windows)]
    {
        let mut kill_cmd = Command::new("taskkill");
        kill_cmd
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_no_window(&mut kill_cmd);
        let _ = kill_cmd.status();
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
    }
}

/// Options controlling `execute_command`.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Optional working directory (defaults to `project_root.root()`).
    pub cwd: Option<PathBuf>,
    /// Optional execution timeout. On expiry, the child process tree is killed cleanly.
    pub timeout: Option<Duration>,
    /// When `true`, returns the redacted raw output instead of the filtered summary.
    pub raw: bool,
    /// When `true` (default), automatically attaches confined, secret-redacted source snippets
    /// around referenced `path:line` locations on non-zero exit codes (skipped in `--raw` mode).
    pub auto_context: bool,
    /// Maximum historical runs to keep in `.klens/runs/`.
    pub max_kept_runs: usize,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            cwd: None,
            timeout: None,
            raw: false,
            auto_context: true,
            max_kept_runs: DEFAULT_MAX_KEPT_RUNS,
        }
    }
}

/// Captured raw process execution result before filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProcessOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub timed_out: bool,
}

/// Optional verified bugfix note hint attached by higher layers (`klens-cli`/`klens-mcp`)
/// when a command exits non-zero. Plain DTO — keeps `klens-exec` isolated from `klens-memory`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedBugfixHint {
    pub id: String,
    pub title: String,
    pub path: String,
    pub freshness: String,
    pub is_stale: bool,
}

/// Structured payload wrapped inside `ProvenanceEnvelope<RunResponse>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResponse {
    pub meta: RunMeta,
    pub output: String,
    pub raw_mode: bool,
    pub timed_out: bool,
    pub saved_tokens: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_bugfix_notes: Vec<RelatedBugfixHint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_contexts: Vec<ErrorSourceContext>,
}

/// Spawn and run a subprocess directly, capturing stdout/stderr without pipe deadlock
/// and enforcing `CREATE_NO_WINDOW` on Windows plus optional timeout + process-tree kill.
pub fn run_process(
    program: &str,
    args: &[String],
    cwd: &Path,
    timeout: Option<Duration>,
) -> Result<RawProcessOutput, ExecError> {
    if program.trim().is_empty() {
        return Err(ExecError::EmptyCommand);
    }

    let mut child = spawn_with_windows_fallback(program, args, cwd)?;
    let child_pid = child.id();

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_handle = thread::spawn(move || read_all_bytes(stdout_pipe));
    let stderr_handle = thread::spawn(move || read_all_bytes(stderr_pipe));

    let started = Instant::now();
    let mut timed_out = false;

    let exit_code = if let Some(limit) = timeout {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code().unwrap_or(1),
                Ok(None) => {
                    if started.elapsed() >= limit {
                        timed_out = true;
                        kill_process_tree(child_pid);
                        let _ = child.kill();
                        let _ = child.wait();
                        break TIMEOUT_EXIT_CODE;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(source) => {
                    return Err(ExecError::Io {
                        path: cwd.to_path_buf(),
                        source,
                    });
                }
            }
        }
    } else {
        let status = child.wait().map_err(|source| ExecError::Io {
            path: cwd.to_path_buf(),
            source,
        })?;
        status.code().unwrap_or(1)
    };

    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;

    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();

    Ok(RawProcessOutput {
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        exit_code,
        duration_ms,
        timed_out,
    })
}

/// Execute a command inside `project_root`, strip ANSI before filtering & token counting,
/// preserve 100% of error context, redact secrets at the output gate, and persist
/// `.klens/runs/<id>.raw.log` + `.klens/runs/<id>.meta.json`.
pub fn execute_command(
    project_root: &ProjectRoot,
    command: &[String],
    options: &RunOptions,
) -> Result<ProvenanceEnvelope<RunResponse>, ExecError> {
    let Some((program, args)) = command.split_first() else {
        return Err(ExecError::EmptyCommand);
    };

    let exec_cwd = options
        .cwd
        .clone()
        .unwrap_or_else(|| project_root.root().to_path_buf());

    let raw_proc = run_process(program, args, &exec_cwd, options.timeout)?;
    let raw_combined = combine_raw_output(&raw_proc.stdout, &raw_proc.stderr);

    // Constitution Article 4 & Phase 2 §1:
    // Strip ANSI/OSC/`\r` progress bars BEFORE filtering and BEFORE token counting.
    let clean_stdout = strip_ansi(&raw_proc.stdout);
    let clean_stderr = strip_ansi(&raw_proc.stderr);

    let registry = FilterRegistry::with_defaults();
    let filter = registry.select(program, args);
    let mut filtered = filter.filter(&clean_stdout, &clean_stderr, raw_proc.exit_code);

    if raw_proc.timed_out {
        filtered.truncated_errors = false;
        let timeout_note = format!(
            "[klens] command timed out after {}ms (exit_code={TIMEOUT_EXIT_CODE})",
            raw_proc.duration_ms
        );
        if filtered.summary.is_empty() {
            filtered.summary = timeout_note;
        } else {
            filtered.summary = format!("{timeout_note}\n{}", filtered.summary);
        }
    }

    // Apply secret redaction at the output gate (`klens-core::redact`).
    let redacted_summary = redact_secrets(&filtered.summary);
    let final_filtered_text = redacted_summary.text;
    let filtered_bytes = final_filtered_text.len();
    let est_filtered_tokens = estimate_tokens(&final_filtered_text);

    // Output text returned to caller (`--raw` returns redacted raw text; default returns filtered).
    let (returned_output, redactions_count) = if options.raw {
        let redacted_raw = redact_secrets(&raw_combined);
        (redacted_raw.text, redacted_raw.redactions_count)
    } else {
        (final_filtered_text, redacted_summary.redactions_count)
    };

    // Normalize relative cwd for metadata.
    let cwd_display = format_meta_cwd(project_root, &exec_cwd);
    let command_str = format_command_display(command);

    let store = RunStore::new(project_root.clone()).with_max_kept_runs(options.max_kept_runs);
    let meta = store.save_run(&NewRunRecord {
        command: &command_str,
        cwd: &cwd_display,
        filter_used: &filtered.filter_id,
        exit_code: raw_proc.exit_code,
        duration_ms: raw_proc.duration_ms,
        raw_bytes: filtered.raw_bytes,
        filtered_bytes,
        est_raw_tokens: filtered.est_raw_tokens,
        est_filtered_tokens,
        truncated_errors: filtered.truncated_errors,
        raw_log_content: &raw_combined,
    })?;

    let saved_tokens = meta.saved_tokens();
    let raw_log_path = meta.raw_log_path.clone();

    let ctx_res = if raw_proc.exit_code != 0 && !options.raw && options.auto_context {
        collect_error_contexts(project_root, &returned_output)
    } else {
        Default::default()
    };
    let total_redactions = redactions_count.saturating_add(ctx_res.redactions_count);

    let response = RunResponse {
        meta,
        output: returned_output,
        raw_mode: options.raw,
        timed_out: raw_proc.timed_out,
        saved_tokens,
        related_bugfix_notes: Vec::new(),
        error_contexts: ctx_res.contexts,
    };

    let mut envelope =
        ProvenanceEnvelope::new(TrustLevel::VerifiedRaw, project_root.project_id(), response)
            .with_redactions_count(total_redactions)
            .with_raw_fallback(RawFallback {
                reason: "complete unfiltered terminal output saved on disk".to_string(),
                path: Some(raw_log_path),
                hint: Some("re-read verbatim with `klens runs show <run_id> --raw`".to_string()),
            });

    if !options.raw {
        for omission in filtered.omissions {
            envelope = envelope.with_omission(omission);
        }
        for omission in ctx_res.omissions {
            envelope = envelope.with_omission(omission);
        }
    }
    if raw_proc.timed_out {
        envelope = envelope.with_warning(format!(
            "command timed out after {}ms and process tree was terminated",
            raw_proc.duration_ms
        ));
    }

    Ok(envelope)
}

/// Format a `RunResponse` envelope into concise human/AI-readable plain text.
pub fn format_run_text(envelope: &ProvenanceEnvelope<RunResponse>) -> String {
    let data = &envelope.data;
    let meta = &data.meta;
    let header = if data.raw_mode {
        format!(
            "[klens run --raw] id={} filter={} exit={} duration={}ms raw_tokens={} raw={}",
            meta.run_id,
            meta.filter_used,
            meta.exit_code,
            meta.duration_ms,
            meta.est_raw_tokens,
            meta.raw_log_path
        )
    } else {
        format!(
            "[klens run] id={} filter={} exit={} duration={}ms tokens={}->{} (saved {:.1}%, {} tokens) raw={}",
            meta.run_id,
            meta.filter_used,
            meta.exit_code,
            meta.duration_ms,
            meta.est_raw_tokens,
            meta.est_filtered_tokens,
            meta.savings_percent(),
            meta.saved_tokens(),
            meta.raw_log_path
        )
    };

    let mut text = if data.output.is_empty() {
        header
    } else {
        format!("{header}\n{}", data.output.trim_end())
    };

    if !data.related_bugfix_notes.is_empty() {
        for hint in &data.related_bugfix_notes {
            text.push_str(&format!(
                "\n[bugfix] \"{}\" ({}) [{}]",
                hint.title, hint.path, hint.freshness
            ));
        }
    }

    if !data.error_contexts.is_empty() {
        text.push('\n');
        text.push_str(&format_error_contexts_text(&data.error_contexts));
    }

    text
}

fn spawn_with_windows_fallback(
    program: &str,
    args: &[String],
    cwd: &Path,
) -> Result<std::process::Child, ExecError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_no_window(&mut cmd);

    match cmd.spawn() {
        Ok(child) => Ok(child),
        #[cfg(windows)]
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if let Some(resolved) = resolve_windows_script_in_path(program) {
                let mut fallback = Command::new(&resolved);
                fallback
                    .args(args)
                    .current_dir(cwd)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                configure_no_window(&mut fallback);
                fallback.spawn().map_err(|source| ExecError::SpawnFailed {
                    program: program.to_string(),
                    source,
                })
            } else {
                Err(ExecError::SpawnFailed {
                    program: program.to_string(),
                    source: err,
                })
            }
        }
        Err(source) => Err(ExecError::SpawnFailed {
            program: program.to_string(),
            source,
        }),
    }
}

#[cfg(windows)]
fn resolve_windows_script_in_path(program: &str) -> Option<PathBuf> {
    let p = Path::new(program);
    if p.extension().is_some() || program.contains(['/', '\\']) {
        return None;
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for ext in ["cmd", "bat", "exe"] {
            let candidate = dir.join(format!("{program}.{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn read_all_bytes<R: Read>(mut reader: Option<R>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(ref mut r) = reader {
        let _ = r.read_to_end(&mut buf);
    }
    buf
}

fn format_meta_cwd(project_root: &ProjectRoot, exec_cwd: &Path) -> String {
    let canon = std::fs::canonicalize(exec_cwd).unwrap_or_else(|_| exec_cwd.to_path_buf());
    if canon == project_root.root() {
        return ".".to_string();
    }
    if let Ok(rel) = canon.strip_prefix(project_root.root()) {
        let s = rel.to_string_lossy().replace('\\', "/");
        if s.is_empty() { ".".to_string() } else { s }
    } else {
        canon.to_string_lossy().replace('\\', "/")
    }
}

fn format_command_display(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| {
            if arg.contains([' ', '\t', '"']) {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_create_no_window_constant_matches_win32_spec() {
        assert_eq!(WINDOWS_CREATE_NO_WINDOW, 0x0800_0000);
    }
}
