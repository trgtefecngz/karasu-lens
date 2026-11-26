//! Pure deterministic session handoff composer (`compose_handoff`).
//!
//! Architectural isolation guarantee:
//! - `klens-blueprint` NEVER depends on `klens-code`, `klens-exec`, `klens-memory`, or `klens-adapters`.
//! - Higher layers (`klens-cli`, `klens-mcp`, `klens-ui`) collect real project facts into [`HandoffInput`]
//!   and invoke [`compose_handoff`] as a 100% pure function.
//!
//! Constitutional guarantees:
//! - Byte-for-byte deterministic output across repeated invocations.
//! - Strict token budget adherence (`estimate_tokens(&summary_markdown) <= budget`) with explicit
//!   `Omission` markers (Constitution Article 2: No Silent Truncation).
//! - 100% UTF-8 char-boundary safe truncation (`char_indices` — never panics on Turkish / multi-byte text).
//! - Output-gate secret redaction via `klens_core::redact_secrets` (Constitution Article 8).

use std::collections::BTreeSet;

use klens_core::{
    CHARS_PER_TOKEN, Omission, OmissionKind, ProvenanceEnvelope, TrustLevel, estimate_tokens,
    redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::model::BlueprintTask;

/// Default token budget for `klens handoff` (~400–800 tokens target window).
pub const DEFAULT_HANDOFF_BUDGET_TOKENS: usize = 800;

/// One recent Git commit included in the handoff snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCommitSummary {
    pub sha: String,
    pub message: String,
}

/// Read-only Git repository state collected by the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitStatusSummary {
    pub branch: String,
    #[serde(default)]
    pub recent_commits: Vec<GitCommitSummary>,
    #[serde(default)]
    pub dirty_files: Vec<String>,
}

/// Summary of the most recent failed `klens run` recorded under `.klens/runs/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedRunSummary {
    pub run_id: String,
    pub command: String,
    pub exit_code: i32,
    pub raw_log_path: String,
    pub error_excerpt: String,
}

/// Compact summary of one memory note (active or stale).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemoryEntrySummary {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub is_stale: bool,
    #[serde(default)]
    pub stale_details: Vec<String>,
}

/// Aggregated memory state collected by the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySummary {
    pub total_notes: usize,
    #[serde(default)]
    pub active_notes: Vec<MemoryEntrySummary>,
    #[serde(default)]
    pub stale_notes: Vec<MemoryEntrySummary>,
    #[serde(default)]
    pub parse_warnings: Vec<String>,
}

/// Locked or draft architectural contract summary collected from `.klens/blueprint/`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSummary {
    pub project_name: String,
    pub goal: String,
    pub locked: bool,
    pub locked_at: Option<String>,
    #[serde(default)]
    pub decisions: Vec<String>,
    #[serde(default)]
    pub contract_excerpt: Option<String>,
}

/// Pure input DTO passed into [`compose_handoff`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffInput {
    pub project_id: String,
    pub project_name: String,
    #[serde(default)]
    pub contract: Option<ContractSummary>,
    #[serde(default)]
    pub protected_paths: Vec<String>,
    #[serde(default)]
    pub git: Option<GitStatusSummary>,
    #[serde(default)]
    pub last_failed_run: Option<FailedRunSummary>,
    #[serde(default)]
    pub next_ready_task: Option<BlueprintTask>,
    #[serde(default)]
    pub completed_tasks_count: usize,
    #[serde(default)]
    pub remaining_tasks_count: usize,
    #[serde(default)]
    pub memory: MemorySummary,
}

/// Structured output payload produced by [`compose_handoff`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffPayload {
    pub budget_tokens: usize,
    pub estimated_tokens: usize,
    pub summary_markdown: String,
    pub sections_included: Vec<String>,
    pub contract_locked: bool,
    pub protected_paths_count: usize,
    pub has_failed_run: bool,
    pub next_ready_task_id: Option<String>,
    pub stale_memory_count: usize,
    pub active_memory_count: usize,
}

/// Pure, byte-for-byte deterministic session handoff composer.
///
/// Guarantees:
/// - `estimate_tokens(&envelope.data.summary_markdown) <= budget` for every `budget`.
/// - Never panics on multi-byte UTF-8 (Turkish `ğüşiöç`, emoji, CJK).
/// - Applies `klens_core::redact_secrets` at the output gate and reports `redactions_count`.
/// - Emits explicit `Omission` entries whenever any section or field is truncated/omitted.
pub fn compose_handoff(input: HandoffInput, budget: usize) -> ProvenanceEnvelope<HandoffPayload> {
    let max_chars = budget.saturating_mul(CHARS_PER_TOKEN);
    let mut redactions_count: usize = 0;
    let mut omissions: Vec<Omission> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let project_name = redact_field(&input.project_name, &mut redactions_count);
    let display_name = if project_name.trim().is_empty() {
        "project"
    } else {
        project_name.trim()
    };

    let contract_locked = input.contract.as_ref().is_some_and(|c| c.locked);
    let mut protected_paths: Vec<String> = input
        .protected_paths
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for p in &mut protected_paths {
        *p = redact_field(p, &mut redactions_count);
    }

    // Surface stale memory & parse warnings explicitly on the envelope.
    let mut stale_notes = input.memory.stale_notes.clone();
    stale_notes.sort();
    stale_notes.dedup();
    if !stale_notes.is_empty() {
        let stale_ids: Vec<&str> = stale_notes.iter().map(|n| n.id.as_str()).collect();
        warnings.push(format!(
            "{} STALE memory note(s) require code re-verification: {}",
            stale_notes.len(),
            stale_ids.join(", ")
        ));
    }

    let mut parse_warnings: Vec<String> = input
        .memory
        .parse_warnings
        .iter()
        .map(|w| redact_field(w, &mut redactions_count))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for w in &parse_warnings {
        warnings.push(w.clone());
    }

    let mut active_notes = input.memory.active_notes.clone();
    active_notes.sort();
    active_notes.dedup();

    // Proportional soft caps for verbose sections so high-signal blocks (next task, git, stale memory)
    // still fit cleanly inside a typical 400–800 token handoff.
    let error_char_cap = (max_chars / 3).max(160);
    let contract_excerpt_cap = (max_chars / 4).max(120);

    let mut sections: Vec<(&'static str, String)> = Vec::new();

    // 1. Header
    sections.push(("header", format!("# Session Handoff — {display_name}\n")));

    // 2. Contract & Protected Paths
    let mut contract_block = String::new();
    if let Some(ref c) = input.contract {
        let state = if c.locked {
            "USER_LOCKED"
        } else {
            "DRAFT / UNLOCKED"
        };
        contract_block.push_str(&format!("## Contract ({state})\n"));
        let goal = redact_field(c.goal.trim(), &mut redactions_count);
        if !goal.is_empty() {
            contract_block.push_str(&format!("- Goal: {goal}\n"));
        }
        if let Some(ref ts) = c.locked_at {
            contract_block.push_str(&format!("- Locked At: {ts}\n"));
        }
        for dec in &c.decisions {
            let clean_dec = redact_field(dec.trim(), &mut redactions_count);
            if !clean_dec.is_empty() {
                contract_block.push_str(&format!("- {clean_dec}\n"));
            }
        }
        if c.decisions.is_empty()
            && let Some(ref excerpt) = c.contract_excerpt
        {
            let clean_exc = redact_field(excerpt.trim(), &mut redactions_count);
            if !clean_exc.is_empty() {
                let (trimmed, was_cut) = truncate_utf8_with_marker(
                    &clean_exc,
                    contract_excerpt_cap,
                    " ... [contract excerpt truncated]",
                );
                if was_cut {
                    omissions.push(Omission {
                        kind: OmissionKind::Bytes,
                        path: Some(".klens/blueprint/PROJECT_CONTRACT.md".to_string()),
                        start_line: None,
                        end_line: None,
                        count: clean_exc.len().saturating_sub(trimmed.len()),
                        reason: "handoff_contract_budget".to_string(),
                    });
                }
                contract_block.push_str(&format!("- Excerpt: {trimmed}\n"));
            }
        }
    } else {
        contract_block.push_str("## Contract (None)\n- No locked blueprint contract yet.\n");
    }

    if !protected_paths.is_empty() {
        contract_block.push_str(&format!(
            "- PROTECTED PATHS (do not edit without approval): {}\n",
            protected_paths.join(", ")
        ));
    }
    sections.push(("contract", contract_block));

    // 3. Next Ready Task
    let total_tasks = input
        .completed_tasks_count
        .saturating_add(input.remaining_tasks_count);
    let mut task_block = String::new();
    if let Some(ref task) = input.next_ready_task {
        let title = redact_field(&task.title, &mut redactions_count);
        task_block.push_str(&format!(
            "## Next Ready Task ({}/{} done)\n",
            input.completed_tasks_count, total_tasks
        ));
        task_block.push_str(&format!("- `{}`: {title}\n", task.id));
        if !task.expected_files.is_empty() {
            let mut files = task.expected_files.clone();
            files.sort();
            task_block.push_str(&format!("- Expected Files: {}\n", files.join(", ")));
        }
        if let Some(ref cmd) = task.verification_cmd {
            let clean_cmd = redact_field(cmd.trim(), &mut redactions_count);
            if !clean_cmd.is_empty() {
                task_block.push_str(&format!("- Verify: `{clean_cmd}`\n"));
            }
        }
        sections.push(("next_task", task_block));
    } else if total_tasks > 0 {
        task_block.push_str(&format!(
            "## Tasks ({}/{} done)\n- All compiled blueprint tasks are completed.\n",
            input.completed_tasks_count, total_tasks
        ));
        sections.push(("next_task", task_block));
    }

    // 4. Last Failed Run
    if let Some(ref run) = input.last_failed_run {
        let cmd = redact_field(&run.command, &mut redactions_count);
        let raw_excerpt = redact_field(run.error_excerpt.trim(), &mut redactions_count);
        let mut run_block = String::new();
        run_block.push_str(&format!(
            "## Last Failed Run (`{}` exit={})\n",
            run.run_id, run.exit_code
        ));
        run_block.push_str(&format!("- Command: `{cmd}`\n"));
        run_block.push_str(&format!("- Raw Log: `{}`\n", run.raw_log_path));
        if !raw_excerpt.is_empty() {
            let marker = format!(" ... [truncated; inspect {}]", run.raw_log_path);
            let (excerpt, was_cut) =
                truncate_utf8_with_marker(&raw_excerpt, error_char_cap, &marker);
            if was_cut {
                omissions.push(Omission {
                    kind: OmissionKind::Bytes,
                    path: Some(run.raw_log_path.clone()),
                    start_line: None,
                    end_line: None,
                    count: raw_excerpt.len().saturating_sub(excerpt.len()),
                    reason: "handoff_failed_run_excerpt_budget".to_string(),
                });
            }
            run_block.push_str("```text\n");
            run_block.push_str(&excerpt);
            run_block.push_str("\n```\n");
        }
        sections.push(("last_failed_run", run_block));
    }

    // 5. Git Status
    if let Some(ref git) = input.git {
        let mut git_block = String::new();
        let branch = if git.branch.trim().is_empty() {
            "HEAD"
        } else {
            git.branch.trim()
        };
        git_block.push_str(&format!("## Git (`{branch}`)\n"));

        let mut dirty: Vec<String> = git
            .dirty_files
            .iter()
            .map(|f| redact_field(f.trim(), &mut redactions_count))
            .filter(|f| !f.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if dirty.is_empty() {
            git_block.push_str("- Working Tree: clean\n");
        } else {
            const MAX_DIRTY_SHOWN: usize = 12;
            let omitted_dirty = dirty.len().saturating_sub(MAX_DIRTY_SHOWN);
            dirty.truncate(MAX_DIRTY_SHOWN);
            git_block.push_str(&format!(
                "- Dirty ({}): {}",
                dirty.len() + omitted_dirty,
                dirty.join(", ")
            ));
            if omitted_dirty > 0 {
                git_block.push_str(&format!(" ... [+{omitted_dirty} more]"));
                omissions.push(Omission::items(omitted_dirty, "handoff_dirty_files_capped"));
            }
            git_block.push('\n');
        }

        if !git.recent_commits.is_empty() {
            const MAX_COMMITS_SHOWN: usize = 5;
            let omitted_commits = git.recent_commits.len().saturating_sub(MAX_COMMITS_SHOWN);
            git_block.push_str("- Recent Commits:\n");
            for c in git.recent_commits.iter().take(MAX_COMMITS_SHOWN) {
                let msg = redact_field(c.message.trim(), &mut redactions_count);
                let (short_msg, _) = truncate_utf8_with_marker(&msg, 96, "...");
                git_block.push_str(&format!("  - `{}` {short_msg}\n", c.sha.trim()));
            }
            if omitted_commits > 0 {
                git_block.push_str(&format!(
                    "  - ... [+{omitted_commits} more commits omitted]\n"
                ));
                omissions.push(Omission::items(
                    omitted_commits,
                    "handoff_recent_commits_capped",
                ));
            }
        }
        sections.push(("git", git_block));
    }

    // 6. Memory Summary (STALE alerts first, then active notes)
    if !stale_notes.is_empty() || !active_notes.is_empty() || !parse_warnings.is_empty() {
        let mut mem_block = String::new();
        mem_block.push_str(&format!(
            "## Memory ({} active, {} STALE)\n",
            active_notes.len(),
            stale_notes.len()
        ));

        for note in &stale_notes {
            let title = redact_field(&note.title, &mut redactions_count);
            let detail = if note.stale_details.is_empty() {
                String::new()
            } else {
                let joined = note
                    .stale_details
                    .iter()
                    .map(|d| redact_field(d, &mut redactions_count))
                    .collect::<Vec<_>>()
                    .join("; ");
                format!(" ({joined})")
            };
            mem_block.push_str(&format!(
                "- [STALE] `{}` [{}] {title}{detail}\n",
                note.id, note.kind
            ));
        }

        for warn in parse_warnings.drain(..) {
            mem_block.push_str(&format!("- [WARN] {warn}\n"));
        }

        const MAX_ACTIVE_SHOWN: usize = 8;
        let omitted_active = active_notes.len().saturating_sub(MAX_ACTIVE_SHOWN);
        for note in active_notes.iter().take(MAX_ACTIVE_SHOWN) {
            let title = redact_field(&note.title, &mut redactions_count);
            mem_block.push_str(&format!(
                "- [active] `{}` [{}] {title}\n",
                note.id, note.kind
            ));
        }
        if omitted_active > 0 {
            mem_block.push_str(&format!(
                "- ... [+{omitted_active} active memory notes omitted; run `klens memory list`]\n"
            ));
            omissions.push(Omission::items(
                omitted_active,
                "handoff_active_memory_capped",
            ));
        }
        sections.push(("memory", mem_block));
    }

    // Assemble sections greedily within `max_chars` (guaranteeing `estimate_tokens <= budget`).
    let mut assembled = String::new();
    let mut sections_included: Vec<String> = Vec::new();
    let mut omitted_sections: usize = 0;

    for (sec_name, sec_body) in sections {
        let sep = if assembled.is_empty() { "" } else { "\n" };
        let current_chars = assembled.chars().count();
        let needed_chars = sep.chars().count() + sec_body.chars().count();

        if current_chars + needed_chars <= max_chars {
            assembled.push_str(sep);
            assembled.push_str(&sec_body);
            sections_included.push(sec_name.to_string());
        } else {
            // Fit as much of this section as safely possible while respecting `max_chars`.
            let remaining = max_chars.saturating_sub(current_chars + sep.chars().count());
            let marker = "\n... [truncated to fit handoff budget]";
            if remaining > marker.chars().count() + 16 {
                let (partial, _) = truncate_utf8_with_marker(&sec_body, remaining, marker);
                assembled.push_str(sep);
                assembled.push_str(&partial);
                sections_included.push(sec_name.to_string());
                omissions.push(Omission {
                    kind: OmissionKind::Bytes,
                    path: None,
                    start_line: None,
                    end_line: None,
                    count: sec_body.len().saturating_sub(partial.len()),
                    reason: format!("handoff_section_{sec_name}_truncated_to_budget"),
                });
            } else {
                omitted_sections += 1;
            }
            // Any subsequent sections cannot fit either once budget is exhausted.
            // Count them honestly below.
            continue;
        }
    }

    if omitted_sections > 0 {
        omissions.push(Omission::items(
            omitted_sections,
            "handoff_sections_omitted_to_fit_budget",
        ));
    }

    // Final output-gate secret redaction pass.
    let final_redacted = redact_secrets(assembled.trim_end());
    redactions_count = redactions_count.saturating_add(final_redacted.redactions_count);

    // Final hard budget clamp (UTF-8 char-boundary safe, guarantees `estimate_tokens <= budget`).
    let mut final_text = final_redacted.text;
    if estimate_tokens(&final_text) > budget {
        let marker = "... [truncated]";
        let (clamped, _) = truncate_utf8_with_marker(&final_text, max_chars, marker);
        omissions.push(Omission {
            kind: OmissionKind::Bytes,
            path: None,
            start_line: None,
            end_line: None,
            count: final_text.len().saturating_sub(clamped.len()),
            reason: "handoff_final_budget_clamp".to_string(),
        });
        final_text = clamped;
    }

    let estimated_tokens = estimate_tokens(&final_text);
    let trust = if contract_locked {
        TrustLevel::UserLocked
    } else {
        TrustLevel::VerifiedRaw
    };

    let payload = HandoffPayload {
        budget_tokens: budget,
        estimated_tokens,
        summary_markdown: final_text,
        sections_included,
        contract_locked,
        protected_paths_count: protected_paths.len(),
        has_failed_run: input.last_failed_run.is_some(),
        next_ready_task_id: input.next_ready_task.map(|t| t.id),
        stale_memory_count: stale_notes.len(),
        active_memory_count: active_notes.len(),
    };

    let mut env = ProvenanceEnvelope::new(trust, input.project_id, payload)
        .with_redactions_count(redactions_count);
    for w in warnings {
        env = env.with_warning(w);
    }
    for o in omissions {
        env = env.with_omission(o);
    }
    env
}

fn redact_field(text: &str, redactions_count: &mut usize) -> String {
    let res = redact_secrets(text);
    *redactions_count = redactions_count.saturating_add(res.redactions_count);
    res.text
}

/// Strictly UTF-8 char-boundary safe truncation to at most `max_chars` Unicode scalar values.
///
/// Uses `char_indices()` so multi-byte characters (`ğüşiöç`, emoji, CJK) are NEVER split.
/// Returns `(result, was_truncated)`.
pub fn truncate_utf8_with_marker(text: &str, max_chars: usize, marker: &str) -> (String, bool) {
    let total_chars = text.chars().count();
    if total_chars <= max_chars {
        return (text.to_string(), false);
    }
    if max_chars == 0 {
        return (String::new(), true);
    }

    let marker_chars = marker.chars().count();
    if max_chars <= marker_chars {
        let end_byte = char_boundary_byte_index(text, max_chars);
        return (text[..end_byte].to_string(), true);
    }

    let keep_chars = max_chars - marker_chars;
    let end_byte = char_boundary_byte_index(text, keep_chars);
    let mut out = String::with_capacity(end_byte + marker.len());
    out.push_str(&text[..end_byte]);
    out.push_str(marker);
    (out, true)
}

/// Return the exact UTF-8 byte index after `char_count` Unicode scalar values (never mid-char).
fn char_boundary_byte_index(text: &str, char_count: usize) -> usize {
    match text.char_indices().nth(char_count) {
        Some((byte_idx, _)) => byte_idx,
        None => text.len(),
    }
}
