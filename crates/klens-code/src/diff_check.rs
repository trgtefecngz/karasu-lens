use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;

use klens_core::{
    CheckSeverity, ProvenanceEnvelope, RelPath, SecretKind, SymbolKind, TrustLevel,
    normalize_line_endings, redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::deps::{
    DependencyEntry, diff_added_external_dependencies, extract_cargo_workspace_versions,
    is_dependency_manifest, parse_manifest_dependencies,
};
use crate::diff_parse::{ParsedFileDiff, is_internal_klens_path, parse_unified_diff};
use crate::error::CodeError;
use crate::git::{has_head_commit, is_git_repo, run_git, show_head_file, show_staged_file};
use crate::graph::build_code_graph;
use crate::impact::{ImpactHit, compute_direct_and_transitive_file_hits};
use crate::index::{CodeIndex, MAX_INDEXABLE_BYTES, is_binary_bytes};

/// Category of security or architectural alert produced by `klens diff-check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffAlertKind {
    ProtectedPathViolation,
    NewExternalDependency,
    SecretLeak,
    SensitiveFileChanged,
    StaleMemory,
}

/// Structured alert emitted by `klens diff-check`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DiffAlert {
    pub kind: DiffAlertKind,
    pub severity: CheckSeverity,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub message: String,
}

/// AST symbol overlapping changed lines in a modified file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChangedSymbolRef {
    pub qualified_name: String,
    pub kind: SymbolKind,
    pub start_line: usize,
    pub end_line: usize,
}

/// Summary of a single changed file mapped to its AST symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedFileSummary {
    pub path: String,
    pub change_kind: String,
    pub changed_lines: Vec<usize>,
    pub changed_symbols: Vec<ChangedSymbolRef>,
    pub is_protected: bool,
}

/// Secret leak finding detected on added diff lines (never echoes raw secret bytes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecretLeakFinding {
    pub path: String,
    pub line: usize,
    pub kinds: Vec<SecretKind>,
    pub count: usize,
}

/// Complete payload returned by `klens diff-check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffCheckPayload {
    pub is_git_repo: bool,
    pub overall_severity: CheckSeverity,
    pub alerts: Vec<DiffAlert>,
    pub changed_files: Vec<ChangedFileSummary>,
    pub protected_violations: Vec<String>,
    pub added_dependencies: Vec<DependencyEntry>,
    pub secret_leaks: Vec<SecretLeakFinding>,
    pub impacted_files: Vec<ImpactHit>,
}

impl DiffCheckPayload {
    /// Attach an additional alert (e.g., stale memory note detected at the CLI layer)
    /// while keeping alert ordering deterministic and updating `overall_severity`.
    pub fn add_alert(&mut self, alert: DiffAlert) {
        if alert.severity > self.overall_severity {
            self.overall_severity = alert.severity;
        }
        self.alerts.push(alert);
        self.alerts.sort();
        self.alerts.dedup();
    }
}

/// Execution options for [`run_diff_check_with_options`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiffCheckOptions {
    /// Inspect only staged git index changes (`git diff --cached` and index status column).
    pub staged_only: bool,
}

/// Run smart `git diff` analysis mapped to AST symbols, protected paths, dependency diffs,
/// secret leaks, and blast-radius impact.
pub fn run_diff_check(
    index: &mut CodeIndex,
) -> Result<ProvenanceEnvelope<DiffCheckPayload>, CodeError> {
    run_diff_check_with_options(index, DiffCheckOptions::default())
}

/// Run smart `git diff` analysis with explicit [`DiffCheckOptions`] (such as `--staged`).
pub fn run_diff_check_with_options(
    index: &mut CodeIndex,
    opts: DiffCheckOptions,
) -> Result<ProvenanceEnvelope<DiffCheckPayload>, CodeError> {
    let root = index.project_root().root().to_path_buf();
    let project_id = index.project_root().project_id().to_string();

    if !is_git_repo(&root) {
        let payload = DiffCheckPayload {
            is_git_repo: false,
            overall_severity: CheckSeverity::Warning,
            alerts: Vec::new(),
            changed_files: Vec::new(),
            protected_violations: Vec::new(),
            added_dependencies: Vec::new(),
            secret_leaks: Vec::new(),
            impacted_files: Vec::new(),
        };
        return Ok(
            ProvenanceEnvelope::new(TrustLevel::VerifiedRaw, project_id, payload)
                .with_warning("project is not a git repository; diff-check skipped"),
        );
    }

    let status_entries = collect_git_status_entries(&root, opts.staged_only);
    let diff_parsed = collect_parsed_git_diffs(&root, opts.staged_only);

    // Union of all changed paths (tracked diffs + staged/unstaged/untracked status entries).
    let mut all_changed_paths: BTreeMap<String, String> = BTreeMap::new();
    for (path, kind) in status_entries {
        all_changed_paths.insert(path, kind);
    }
    for path in diff_parsed.keys() {
        all_changed_paths
            .entry(path.clone())
            .or_insert_with(|| "modified".to_string());
    }

    let mut alerts: Vec<DiffAlert> = Vec::new();
    let mut protected_violations: BTreeSet<String> = BTreeSet::new();
    let mut added_dependencies: Vec<DependencyEntry> = Vec::new();
    let mut secret_leaks: Vec<SecretLeakFinding> = Vec::new();
    let mut changed_files: Vec<ChangedFileSummary> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut total_redactions = 0usize;

    // Load current workspace Cargo.toml versions if present for resolving `workspace = true`.
    let mut current_ws_cargo: BTreeMap<String, String> = BTreeMap::new();
    if opts.staged_only {
        if let Some(staged_cargo) = show_staged_file(&root, "Cargo.toml") {
            extract_cargo_workspace_versions(&staged_cargo, &mut current_ws_cargo);
        }
    } else if let Ok((abs, _)) = index.project_root().resolve_existing_with_extra(
        "Cargo.toml",
        &index.project_config().extra_sensitive_patterns,
    ) && let Ok(text) = fs::read_to_string(abs)
    {
        extract_cargo_workspace_versions(&text, &mut current_ws_cargo);
    }
    let mut head_ws_cargo: BTreeMap<String, String> = BTreeMap::new();
    if let Some(head_cargo) = show_head_file(&root, "Cargo.toml") {
        extract_cargo_workspace_versions(&head_cargo, &mut head_ws_cargo);
    }

    // Sync workspace once so AST symbols & code graph reflect the working tree.
    let graph_env = build_code_graph(index)?;
    let graph = graph_env.data;

    let mut changed_file_paths_for_impact: BTreeSet<String> = BTreeSet::new();

    for (path_str, change_kind) in &all_changed_paths {
        let Ok(rel) = RelPath::normalize(path_str) else {
            continue;
        };
        let norm_path = rel.as_str().to_string();

        // Check 1: Sensitive file modified/staged/untracked (never read its contents!).
        if index.project_config().is_sensitive_file(&rel) {
            alerts.push(DiffAlert {
                kind: DiffAlertKind::SensitiveFileChanged,
                severity: CheckSeverity::Error,
                path: norm_path.clone(),
                line: None,
                message: format!(
                    "RED ALERT: sensitive secret file `{norm_path}` appears in git changes ({change_kind})"
                ),
            });
            changed_files.push(ChangedFileSummary {
                path: norm_path,
                change_kind: change_kind.clone(),
                changed_lines: Vec::new(),
                changed_symbols: Vec::new(),
                is_protected: false,
            });
            continue;
        }

        // Check 2: Protected code path violation (`protected_paths`).
        let is_protected = index.project_config().is_protected_code_path(&rel);
        if is_protected {
            protected_violations.insert(norm_path.clone());
            alerts.push(DiffAlert {
                kind: DiffAlertKind::ProtectedPathViolation,
                severity: CheckSeverity::Error,
                path: norm_path.clone(),
                line: None,
                message: format!(
                    "RED ALERT: locked protected_path `{norm_path}` was {change_kind}"
                ),
            });
        }

        // Check 3: Newly added external dependencies (`deps.rs` diff).
        if is_dependency_manifest(&norm_path) {
            let before_text = show_head_file(&root, &norm_path).unwrap_or_default();
            let after_text = if change_kind == "deleted" {
                Some(String::new())
            } else if opts.staged_only {
                let staged = show_staged_file(&root, &norm_path);
                if staged.is_none() {
                    warnings.push(format!(
                        "could not read staged manifest `{norm_path}` from git index; dependency diff skipped"
                    ));
                }
                staged
            } else {
                Some(
                    index
                        .project_root()
                        .resolve_existing_with_extra(
                            &norm_path,
                            &index.project_config().extra_sensitive_patterns,
                        )
                        .ok()
                        .and_then(|(abs, _)| fs::read_to_string(abs).ok())
                        .unwrap_or_default(),
                )
            };

            if let Some(after_text) = after_text {
                let before_deps =
                    parse_manifest_dependencies(&norm_path, &before_text, &head_ws_cargo);
                let after_deps =
                    parse_manifest_dependencies(&norm_path, &after_text, &current_ws_cargo);
                let newly_added = diff_added_external_dependencies(&before_deps, &after_deps);

                for dep in newly_added {
                    alerts.push(DiffAlert {
                        kind: DiffAlertKind::NewExternalDependency,
                        severity: CheckSeverity::Error,
                        path: norm_path.clone(),
                        line: None,
                        message: format!(
                            "RED ALERT: new external {} dependency `{}` ({}) added in `{norm_path}`",
                            dep.ecosystem.as_str(),
                            dep.name,
                            dep.version
                        ),
                    });
                    added_dependencies.push(dep);
                }
            }
        }

        // Check 4: Secret leak scan on added diff lines (or full untracked file lines).
        let mut changed_line_set: BTreeSet<usize> = BTreeSet::new();
        if let Some(file_diff) = diff_parsed.get(&norm_path) {
            for &ln in &file_diff.changed_lines {
                changed_line_set.insert(ln);
            }
            for (line_no, added_text) in &file_diff.added_lines {
                let red = redact_secrets(added_text);
                if red.redactions_count > 0 {
                    total_redactions += red.redactions_count;
                    let kinds: Vec<SecretKind> = red.by_kind.keys().copied().collect();
                    let kind_names: Vec<String> = kinds.iter().map(|k| format!("{k:?}")).collect();
                    alerts.push(DiffAlert {
                        kind: DiffAlertKind::SecretLeak,
                        severity: CheckSeverity::Error,
                        path: norm_path.clone(),
                        line: Some(*line_no),
                        message: format!(
                            "RED ALERT: potential secret leak ({}) in `{norm_path}:L{line_no}`",
                            kind_names.join(", ")
                        ),
                    });
                    secret_leaks.push(SecretLeakFinding {
                        path: norm_path.clone(),
                        line: *line_no,
                        kinds,
                        count: red.redactions_count,
                    });
                }
            }
        } else if !opts.staged_only
            && change_kind == "untracked"
            && let Ok((abs, _)) = index.project_root().resolve_existing_with_extra(
                &norm_path,
                &index.project_config().extra_sensitive_patterns,
            )
            && let Ok(meta) = fs::metadata(&abs)
            && meta.is_file()
        {
            if meta.len() > MAX_INDEXABLE_BYTES {
                warnings.push(format!(
                    "untracked file `{norm_path}` exceeds maximum indexable size ({} bytes > {MAX_INDEXABLE_BYTES} bytes); skipped RAM load and secret scan",
                    meta.len()
                ));
            } else if let Ok(bytes) = fs::read(&abs)
                && !is_binary_bytes(&bytes)
                && let Ok(text) = std::str::from_utf8(&bytes)
            {
                let normalized = normalize_line_endings(text);
                for (idx, line_text) in normalized.lines().enumerate() {
                    let line_no = idx + 1;
                    changed_line_set.insert(line_no);
                    let red = redact_secrets(line_text);
                    if red.redactions_count > 0 {
                        total_redactions += red.redactions_count;
                        let kinds: Vec<SecretKind> = red.by_kind.keys().copied().collect();
                        let kind_names: Vec<String> =
                            kinds.iter().map(|k| format!("{k:?}")).collect();
                        alerts.push(DiffAlert {
                            kind: DiffAlertKind::SecretLeak,
                            severity: CheckSeverity::Error,
                            path: norm_path.clone(),
                            line: Some(line_no),
                            message: format!(
                                "RED ALERT: potential secret leak ({}) in untracked `{norm_path}:L{line_no}`",
                                kind_names.join(", ")
                            ),
                        });
                        secret_leaks.push(SecretLeakFinding {
                            path: norm_path.clone(),
                            line: line_no,
                            kinds,
                            count: red.redactions_count,
                        });
                    }
                }
            }
        }

        // Map changed line numbers to overlapping AST symbols in SQLite index.
        let mut changed_symbols: Vec<ChangedSymbolRef> = Vec::new();
        if change_kind != "deleted"
            && let Ok(file_syms) = index.store().get_symbols_for_file(&rel)
        {
            for sym in file_syms {
                let overlaps = if changed_line_set.is_empty() {
                    false
                } else {
                    changed_line_set
                        .range(sym.start_line..=sym.end_line)
                        .next()
                        .is_some()
                };
                if overlaps {
                    changed_symbols.push(ChangedSymbolRef {
                        qualified_name: sym.qualified_name,
                        kind: sym.kind,
                        start_line: sym.start_line,
                        end_line: sym.end_line,
                    });
                }
            }
        }
        changed_symbols.sort();
        changed_symbols.dedup();

        changed_file_paths_for_impact.insert(norm_path.clone());
        changed_files.push(ChangedFileSummary {
            path: norm_path,
            change_kind: change_kind.clone(),
            changed_lines: changed_line_set.into_iter().collect(),
            changed_symbols,
            is_protected,
        });
    }

    // Check 5: Aggregate blast-radius impact for all changed files.
    let mut impacted_raw: Vec<ImpactHit> = Vec::new();
    for changed_path in &changed_file_paths_for_impact {
        for hit in compute_direct_and_transitive_file_hits(&graph, changed_path) {
            if !changed_file_paths_for_impact.contains(&hit.path) {
                impacted_raw.push(hit);
            }
        }
    }
    impacted_raw.sort_by(|a, b| {
        a.distance
            .cmp(&b.distance)
            .then_with(|| a.confidence.cmp(&b.confidence))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
    let mut seen_impact_paths: BTreeSet<String> = BTreeSet::new();
    impacted_raw.retain(|h| seen_impact_paths.insert(h.path.clone()));

    alerts.sort();
    alerts.dedup();
    added_dependencies.sort();
    added_dependencies.dedup();
    secret_leaks.sort();
    secret_leaks.dedup();
    changed_files.sort_by(|a, b| a.path.cmp(&b.path));

    let overall_severity = if alerts.iter().any(|a| a.severity == CheckSeverity::Error) {
        CheckSeverity::Error
    } else if alerts.iter().any(|a| a.severity == CheckSeverity::Warning) {
        CheckSeverity::Warning
    } else {
        CheckSeverity::Ok
    };

    let payload = DiffCheckPayload {
        is_git_repo: true,
        overall_severity,
        alerts,
        changed_files,
        protected_violations: protected_violations.into_iter().collect(),
        added_dependencies,
        secret_leaks,
        impacted_files: impacted_raw,
    };

    let mut env = ProvenanceEnvelope::new(TrustLevel::VerifiedAst, project_id, payload)
        .with_redactions_count(total_redactions);
    for w in warnings {
        env = env.with_warning(w);
    }
    Ok(env)
}

/// Shared helper for `health.rs`: returns `(is_git_repo, violated_protected_paths)`.
pub(crate) fn find_protected_path_violations(index: &CodeIndex) -> (bool, Vec<String>) {
    let root = index.project_root().root();
    if !is_git_repo(root) {
        return (false, Vec::new());
    }
    let status = collect_git_status_entries(root, false);
    let mut violations: BTreeSet<String> = BTreeSet::new();
    for (path, _) in status {
        if let Ok(rel) = RelPath::normalize(&path)
            && index.project_config().is_protected_code_path(&rel)
        {
            violations.insert(rel.as_str().to_string());
        }
    }
    (true, violations.into_iter().collect())
}

/// Render `klens diff-check` envelope into deterministic human/AI plain text.
pub fn format_diff_check_text(envelope: &ProvenanceEnvelope<DiffCheckPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    let light = match data.overall_severity {
        CheckSeverity::Ok => "GREEN",
        CheckSeverity::Warning => "YELLOW",
        CheckSeverity::Error => "RED",
    };
    let _ = writeln!(
        out,
        "[{}] diff-check status={light} changed_files={} alerts={} protected_violations={} added_deps={} secret_leaks={} impacted_files={}",
        crate::trust_label(envelope.trust),
        data.changed_files.len(),
        data.alerts.len(),
        data.protected_violations.len(),
        data.added_dependencies.len(),
        data.secret_leaks.len(),
        data.impacted_files.len()
    );

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    if !data.alerts.is_empty() {
        let _ = writeln!(out, "\n## Alerts");
        for alert in &data.alerts {
            let sev = match alert.severity {
                CheckSeverity::Error => "RED",
                CheckSeverity::Warning => "YELLOW",
                CheckSeverity::Ok => "GREEN",
            };
            let _ = writeln!(out, "  [{sev}] {}", alert.message);
        }
    }

    if !data.changed_files.is_empty() {
        let _ = writeln!(out, "\n## Changed Files & AST Symbols");
        for file in &data.changed_files {
            let prot = if file.is_protected {
                " [PROTECTED]"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "  - {} ({}, {} changed lines){prot}",
                file.path,
                file.change_kind,
                file.changed_lines.len()
            );
            for sym in &file.changed_symbols {
                let _ = writeln!(
                    out,
                    "      * {} [L{}-L{}]",
                    sym.qualified_name, sym.start_line, sym.end_line
                );
            }
        }
    }

    if !data.impacted_files.is_empty() {
        let _ = writeln!(out, "\n## Blast Radius (Impacted Files)");
        for hit in &data.impacted_files {
            let _ = writeln!(
                out,
                "  - [d={} | {:?}] {} ({})",
                hit.distance, hit.confidence, hit.path, hit.evidence
            );
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Git status & unified diff (`--unified=0`) parsing
// ---------------------------------------------------------------------------

fn collect_git_status_entries(
    root: &std::path::Path,
    staged_only: bool,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let args: &[&str] = if staged_only {
        &["status", "--porcelain=v1", "-z", "-uno"]
    } else {
        &["status", "--porcelain=v1", "-z", "-uall"]
    };
    let Some(res) = run_git(root, args) else {
        return out;
    };
    if !res.success || res.stdout.is_empty() {
        return out;
    }

    let entries: Vec<&str> = res.stdout.split('\0').collect();
    let mut i = 0usize;
    while i < entries.len() {
        let entry = entries[i];
        i += 1;
        if entry.len() < 4 {
            continue;
        }
        let xy = &entry[..2];
        let x = entry.as_bytes()[0] as char;
        let raw_path = &entry[3..];

        // For renames/copies (`R`/`C`), `-z` emits the old path as the next NUL-delimited record.
        let old_path_opt = if xy.contains('R') || xy.contains('C') {
            let old = entries.get(i).copied();
            if old.is_some() {
                i += 1;
            }
            old
        } else {
            None
        };

        if staged_only {
            let change_kind = match x {
                'A' => "added",
                'M' | 'T' => "modified",
                'D' => "deleted",
                'R' => "renamed",
                'C' => "copied",
                _ => continue,
            };
            if (x == 'R' || x == 'C')
                && let Some(old_path) = old_path_opt
                && let Ok(old_rel) = RelPath::normalize(old_path)
                && !is_internal_klens_path(old_rel.as_str())
            {
                out.insert(old_rel.as_str().to_string(), "renamed_from".to_string());
            }
            if let Ok(rel) = RelPath::normalize(raw_path)
                && !is_internal_klens_path(rel.as_str())
            {
                out.insert(rel.as_str().to_string(), change_kind.to_string());
            }
            continue;
        }

        let change_kind = match xy {
            "??" => "untracked",
            s if s.contains('D') => "deleted",
            s if s.contains('R') => "renamed",
            s if s.contains('A') => "added",
            _ => "modified",
        };
        if let Some(old_path) = old_path_opt
            && let Ok(old_rel) = RelPath::normalize(old_path)
            && !is_internal_klens_path(old_rel.as_str())
        {
            out.insert(old_rel.as_str().to_string(), "renamed_from".to_string());
        }
        if let Ok(rel) = RelPath::normalize(raw_path)
            && !is_internal_klens_path(rel.as_str())
        {
            out.insert(rel.as_str().to_string(), change_kind.to_string());
        }
    }

    out
}

fn collect_parsed_git_diffs(
    root: &std::path::Path,
    staged_only: bool,
) -> BTreeMap<String, ParsedFileDiff> {
    let mut combined = BTreeMap::new();
    if staged_only {
        if let Some(res) = run_git(
            root,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--cached",
                "--unified=0",
                "--no-color",
            ],
        ) && res.success
        {
            parse_unified_diff(&res.stdout, &mut combined);
        }
        return combined;
    }
    if has_head_commit(root) {
        if let Some(res) = run_git(
            root,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--unified=0",
                "--no-color",
                "HEAD",
            ],
        ) && res.success
        {
            parse_unified_diff(&res.stdout, &mut combined);
        }
    } else {
        if let Some(res) = run_git(
            root,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--unified=0",
                "--no-color",
                "--cached",
            ],
        ) && res.success
        {
            parse_unified_diff(&res.stdout, &mut combined);
        }
        if let Some(res) = run_git(
            root,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--unified=0",
                "--no-color",
            ],
        ) && res.success
        {
            parse_unified_diff(&res.stdout, &mut combined);
        }
    }
    combined
}
