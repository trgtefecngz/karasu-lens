//! Leaf core-crate bridge helpers for `klens-ui` routes (zero circular dependencies).
//!
//! Connects `klens-code`, `klens-memory`, `klens-exec`, `klens-blueprint`, and `klens-adapters`
//! without coupling `klens-ui` to `klens-mcp`:
//! - Lazy AST-backed `UiCodeSymbolResolver` for `klens-memory`.
//! - AST-aware `upgrade_doctor_with_ast_memory` and `upgrade_health_with_memory`.
//! - Pure read-only `collect_handoff_input` for `klens_blueprint::compose_handoff`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use klens_adapters::DoctorReport;
use klens_blueprint::{
    BubbleStatus, ContractSummary, FailedRunSummary, GitCommitSummary, GitStatusSummary,
    HandoffInput, MemoryEntrySummary, MemorySummary, TaskStatus, load_blueprint_optional,
    load_contract_optional, load_tasks_optional, next_ready_task,
};
use klens_code::{
    CodeIndex, FileSyncOutcome, HealthCheck, HealthPayload, ParseStatus, TrafficLight,
};
use klens_core::{
    CheckSeverity, DoctorCheck, ProjectConfig, ProjectRoot, ProvenanceEnvelope, RelPath,
    TrustLevel, normalize_line_endings,
};
use klens_exec::{RunStore, show_stored_run};
use klens_memory::{
    MEMORY_DIR_REL, SymbolLookupResult, SymbolResolver, list_memory_index, verify_all_notes,
};

use crate::error::UiError;
use crate::state::UiState;

/// Open a `CodeIndex` honoring read-only mode and any configured `readonly_cache_dir`.
pub fn open_code_index(
    state: &UiState,
    project_root: &ProjectRoot,
    read_only: bool,
) -> Result<CodeIndex, UiError> {
    let idx = match &state.readonly_cache_dir {
        Some(dir) => CodeIndex::open_with_readonly_cache_dir(project_root.clone(), read_only, dir)?,
        None => CodeIndex::open(project_root.clone(), read_only)?,
    };
    Ok(idx)
}

/// Lazy Tree-sitter AST symbol resolver bridging `klens-memory` and `klens-code` inside `klens-ui`.
pub struct UiCodeSymbolResolver<'a> {
    project_root: &'a ProjectRoot,
    read_only: bool,
    readonly_cache_dir: Option<&'a Path>,
    index: Option<CodeIndex>,
}

impl<'a> UiCodeSymbolResolver<'a> {
    pub fn new(
        project_root: &'a ProjectRoot,
        read_only: bool,
        readonly_cache_dir: Option<&'a Path>,
    ) -> Self {
        Self {
            project_root,
            read_only,
            readonly_cache_dir,
            index: None,
        }
    }

    fn ensure_index(&mut self) -> Option<&mut CodeIndex> {
        if self.index.is_none() {
            let opened = match self.readonly_cache_dir {
                Some(dir) => CodeIndex::open_with_readonly_cache_dir(
                    self.project_root.clone(),
                    self.read_only,
                    dir,
                )
                .ok(),
                None => CodeIndex::open(self.project_root.clone(), self.read_only).ok(),
            };
            self.index = opened;
        }
        self.index.as_mut()
    }
}

impl SymbolResolver for UiCodeSymbolResolver<'_> {
    fn resolve_symbol(&mut self, path: &RelPath, symbol: &str) -> SymbolLookupResult {
        let Some(index) = self.ensure_index() else {
            return SymbolLookupResult::Unparsed("failed to open AST index".to_string());
        };

        match index.sync_file(path) {
            Ok(FileSyncOutcome::SkippedBinary) => {
                return SymbolLookupResult::Unparsed("binary or non-UTF-8 file".to_string());
            }
            Ok(FileSyncOutcome::Parsed | FileSyncOutcome::Unchanged) => {}
            Err(err) => return SymbolLookupResult::Unparsed(err.to_string()),
        }

        if let Ok(Some(rec)) = index.store().get_file(path)
            && rec.parse_status == ParseStatus::Fallback
        {
            return SymbolLookupResult::Unparsed(
                rec.parse_warning
                    .unwrap_or_else(|| "unsupported language or syntax error".to_string()),
            );
        }

        let Ok(symbols) = index.store().get_symbols_for_file(path) else {
            return SymbolLookupResult::Missing;
        };

        let query = symbol.trim();
        let exact: Vec<_> = symbols
            .iter()
            .filter(|s| s.qualified_name == query)
            .collect();
        let candidates = if !exact.is_empty() {
            exact
        } else {
            symbols.iter().filter(|s| s.name == query).collect()
        };

        match candidates.as_slice() {
            [] => SymbolLookupResult::Missing,
            [sym] => {
                let Ok((abs, _)) = self.project_root.resolve_existing(path.as_str()) else {
                    return SymbolLookupResult::Missing;
                };
                let Ok(raw) = fs::read_to_string(&abs) else {
                    return SymbolLookupResult::Missing;
                };
                let normalized = normalize_line_endings(&raw);
                let lines: Vec<&str> = normalized.lines().collect();
                if sym.start_line == 0
                    || sym.end_line < sym.start_line
                    || sym.end_line > lines.len()
                {
                    return SymbolLookupResult::Missing;
                }
                let snippet = lines[sym.start_line - 1..sym.end_line].join("\n");
                SymbolLookupResult::Found {
                    qualified_name: sym.qualified_name.clone(),
                    source_snippet: snippet,
                    start_line: sym.start_line,
                    end_line: sym.end_line,
                }
            }
            many => SymbolLookupResult::Ambiguous(
                many.iter().map(|s| s.qualified_name.clone()).collect(),
            ),
        }
    }
}

/// Upgrade a `klens_adapters::DoctorReport` with AST-aware `klens_memory::verify_all_notes`
/// (exact parity with `klens doctor` CLI).
pub fn upgrade_doctor_with_ast_memory(
    report: &mut DoctorReport,
    project_root: &ProjectRoot,
    readonly_cache_dir: Option<&Path>,
) {
    if !project_root.root().join(MEMORY_DIR_REL).is_dir() {
        return;
    }
    let mut resolver = UiCodeSymbolResolver::new(project_root, true, readonly_cache_dir);
    let Ok(verify_env) = verify_all_notes(project_root, &mut resolver) else {
        return;
    };
    let data = verify_env.data;
    let parse_warnings: Vec<String> = verify_env
        .warnings
        .into_iter()
        .filter(|w| !w.contains("memory note(s) are STALE"))
        .collect();

    let upgraded = if data.stale_count == 0 && parse_warnings.is_empty() {
        DoctorCheck {
            name: "Memory staleness (.klens/memory/)".to_string(),
            severity: CheckSeverity::Ok,
            message: format!("{} memory note(s) checked, 0 stale", data.total_notes),
        }
    } else if data.stale_count == 0 {
        DoctorCheck {
            name: "Memory staleness (.klens/memory/)".to_string(),
            severity: CheckSeverity::Warning,
            message: format!(
                "{} malformed/unreadable memory file(s) detected ({} valid note(s) fresh): {}",
                parse_warnings.len(),
                data.total_notes,
                parse_warnings.join("; ")
            ),
        }
    } else {
        let mut items: Vec<String> = data.stale_notes.iter().map(|s| s.id.clone()).collect();
        items.extend(parse_warnings);
        DoctorCheck {
            name: "Memory staleness (.klens/memory/)".to_string(),
            severity: CheckSeverity::Warning,
            message: format!(
                "{} stale memory note(s) out of {}: {}",
                data.stale_count,
                data.total_notes,
                items.join(", ")
            ),
        }
    };

    if let Some(existing) = report
        .checks
        .iter_mut()
        .find(|c| c.name == "Memory staleness (.klens/memory/)")
    {
        *existing = upgraded;
    } else {
        report.checks.push(upgraded);
    }
    report.overall = report
        .checks
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(CheckSeverity::Ok);
}

/// Append `.klens/memory/` BLAKE3 staleness check onto a `klens_code::HealthPayload`
/// (exact parity with `klens health` CLI).
pub fn upgrade_health_with_memory(
    envelope: &mut ProvenanceEnvelope<HealthPayload>,
    project_root: &ProjectRoot,
    read_only: bool,
    readonly_cache_dir: Option<&Path>,
) {
    if !project_root.root().join(MEMORY_DIR_REL).is_dir() {
        return;
    }
    let mut resolver = UiCodeSymbolResolver::new(project_root, read_only, readonly_cache_dir);
    let Ok(verify_env) = verify_all_notes(project_root, &mut resolver) else {
        return;
    };
    let data = verify_env.data;
    let parse_warnings: Vec<String> = verify_env
        .warnings
        .into_iter()
        .filter(|w| !w.contains("memory note(s) are STALE"))
        .collect();

    let check = if data.stale_count == 0 && parse_warnings.is_empty() {
        HealthCheck {
            id: "memory_staleness".to_string(),
            title: "Memory Anchors (.klens/memory/)".to_string(),
            light: TrafficLight::Green,
            summary: format!(
                "{} memory note(s) verified fresh (0 stale)",
                data.total_notes
            ),
            details: Vec::new(),
        }
    } else if data.stale_count == 0 {
        HealthCheck {
            id: "memory_staleness".to_string(),
            title: "Memory Anchors (.klens/memory/)".to_string(),
            light: TrafficLight::Yellow,
            summary: format!(
                "{} malformed/unreadable memory file(s) detected ({} valid note(s) fresh)",
                parse_warnings.len(),
                data.total_notes
            ),
            details: parse_warnings,
        }
    } else {
        let mut details: Vec<String> = data
            .stale_notes
            .iter()
            .map(|s| format!("{} ({}) — {}", s.id, s.rel_path, s.stale_reasons.join("; ")))
            .collect();
        details.extend(parse_warnings);
        HealthCheck {
            id: "memory_staleness".to_string(),
            title: "Memory Anchors (.klens/memory/)".to_string(),
            light: TrafficLight::Yellow,
            summary: format!(
                "{} stale memory note(s) out of {}",
                data.stale_count, data.total_notes
            ),
            details,
        }
    };
    envelope.data.push_check(check);
}

/// Gather real verified project facts into [`HandoffInput`] for `klens_blueprint::compose_handoff`.
///
/// Strictly read-only when `read_only == true` and keeps `klens-ui` decoupled from `klens-mcp`.
pub fn collect_handoff_input(
    project_root: &ProjectRoot,
    read_only: bool,
    readonly_cache_dir: Option<&Path>,
) -> HandoffInput {
    let default_name = project_root
        .root()
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    let cfg_path = project_root.root().join(".klens").join("config.toml");
    let protected_paths = ProjectConfig::load_or_default(&cfg_path)
        .map(|c| c.protected_paths)
        .unwrap_or_default();

    let blueprint_opt = load_blueprint_optional(project_root).ok().flatten();
    let contract_text = load_contract_optional(project_root).ok().flatten();

    let (project_name, contract) = match blueprint_opt {
        Some(bp) => {
            let mut decisions = Vec::new();
            for bubble in &bp.bubbles {
                if bubble.status == BubbleStatus::Skipped {
                    continue;
                }
                let choice = bubble
                    .selected_option_ref()
                    .map(|o| format!("{} ({})", o.label, o.id))
                    .or_else(|| bubble.selected_option.clone())
                    .unwrap_or_else(|| "pending".to_string());
                let mut line = format!("{}: {choice}", bubble.id);
                let note = bubble.user_vision_note.trim();
                if !note.is_empty() {
                    line.push_str(&format!(" — {note}"));
                }
                decisions.push(line);
            }
            decisions.sort();

            let name = if bp.project_name.trim().is_empty() {
                default_name.clone()
            } else {
                bp.project_name.clone()
            };
            (
                name,
                Some(ContractSummary {
                    project_name: bp.project_name,
                    goal: bp.goal,
                    locked: bp.locked,
                    locked_at: bp.locked_at,
                    decisions,
                    contract_excerpt: contract_text,
                }),
            )
        }
        None => {
            let fallback_contract = contract_text.map(|excerpt| ContractSummary {
                project_name: default_name.clone(),
                goal: String::new(),
                locked: true,
                locked_at: None,
                decisions: Vec::new(),
                contract_excerpt: Some(excerpt),
            });
            (default_name, fallback_contract)
        }
    };

    let tasks = load_tasks_optional(project_root).unwrap_or_default();
    let completed_tasks_count = tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Done)
        .count();
    let remaining_tasks_count = tasks.len().saturating_sub(completed_tasks_count);
    let next_ready = next_ready_task(&tasks);

    let git = collect_git_summary(project_root.root());
    let last_failed_run = collect_last_failed_run(project_root);
    let memory = collect_memory_summary(project_root, read_only, readonly_cache_dir);

    HandoffInput {
        project_id: project_root.project_id().to_string(),
        project_name,
        contract,
        protected_paths,
        git,
        last_failed_run,
        next_ready_task: next_ready,
        completed_tasks_count,
        remaining_tasks_count,
        memory,
    }
}

fn collect_git_summary(root: &Path) -> Option<GitStatusSummary> {
    let inside = run_git_readonly(root, &["rev-parse", "--is-inside-work-tree"])?;
    if inside.trim() != "true" {
        return None;
    }

    let branch = run_git_readonly(root, &["symbolic-ref", "--short", "HEAD"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            run_git_readonly(root, &["rev-parse", "--short", "HEAD"])
                .map(|s| format!("DETACHED@{}", s.trim()))
        })
        .unwrap_or_else(|| "UNBORN".to_string());

    let recent_commits = run_git_readonly(root, &["log", "-n", "5", "--pretty=format:%h%x09%s"])
        .map(|raw| {
            raw.lines()
                .filter_map(|line| {
                    let (sha, msg) = line.split_once('\t')?;
                    Some(GitCommitSummary {
                        sha: sha.trim().to_string(),
                        message: msg.trim().to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let mut dirty_files: Vec<String> = run_git_readonly(root, &["status", "--porcelain=v1"])
        .map(|raw| {
            raw.lines()
                .map(str::trim_end)
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.trim().replace('\\', "/"))
                .collect()
        })
        .unwrap_or_default();
    dirty_files.sort();
    dirty_files.dedup();

    Some(GitStatusSummary {
        branch,
        recent_commits,
        dirty_files,
    })
}

fn run_git_readonly(root: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.quotepath=false"])
        .args(args)
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(klens_exec::WINDOWS_CREATE_NO_WINDOW);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub(crate) fn collect_last_failed_run(project_root: &ProjectRoot) -> Option<FailedRunSummary> {
    let store = RunStore::new(project_root.clone());
    let runs = store.list_runs(Some(25)).ok()?;

    let mut passed_commands: BTreeSet<&str> = BTreeSet::new();
    let mut active_failure = None;
    for run in &runs {
        let cmd_key = run.command.trim();
        if run.exit_code == 0 {
            passed_commands.insert(cmd_key);
        } else if !passed_commands.contains(cmd_key) {
            active_failure = Some(run);
            break;
        }
    }
    let failed_meta = active_failure?.clone();

    let error_excerpt = match show_stored_run(project_root, &failed_meta.run_id, false) {
        Ok(env) => env.data.content,
        Err(_) => String::new(),
    };

    Some(FailedRunSummary {
        run_id: failed_meta.run_id,
        command: failed_meta.command,
        exit_code: failed_meta.exit_code,
        raw_log_path: failed_meta.raw_log_path,
        error_excerpt,
    })
}

fn collect_memory_summary(
    project_root: &ProjectRoot,
    read_only: bool,
    readonly_cache_dir: Option<&Path>,
) -> MemorySummary {
    let mut resolver = UiCodeSymbolResolver::new(project_root, read_only, readonly_cache_dir);
    let Ok(env) = list_memory_index(project_root, None, None, false, &mut resolver) else {
        return MemorySummary::default();
    };

    let mut active_notes = Vec::new();
    let mut stale_notes = Vec::new();

    for entry in env.data.entries {
        let is_stale = entry.trust == TrustLevel::Stale;
        let stale_details: Vec<String> = entry
            .stale_anchors
            .iter()
            .map(|chk| {
                let target = match &chk.symbol {
                    Some(sym) => format!("{}#{sym}", chk.path),
                    None => chk.path.clone(),
                };
                let reason = chk.stale_reason.map(|r| r.as_str()).unwrap_or("stale");
                format!("{target}: {reason}")
            })
            .collect();

        let item = MemoryEntrySummary {
            id: entry.id,
            title: entry.title,
            kind: entry.kind.as_str().to_string(),
            is_stale,
            stale_details,
        };
        if is_stale {
            stale_notes.push(item);
        } else {
            active_notes.push(item);
        }
    }

    let parse_warnings: Vec<String> = env
        .warnings
        .into_iter()
        .filter(|w| !w.contains("memory note(s) have STALE BLAKE3 anchors"))
        .collect();

    MemorySummary {
        total_notes: env.data.total_notes,
        active_notes,
        stale_notes,
        parse_warnings,
    }
}
