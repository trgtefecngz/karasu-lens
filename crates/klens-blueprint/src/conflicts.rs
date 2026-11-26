//! Pure deterministic conflict detection engine (ZERO LLM).
//!
//! Enforces the 4 mandatory constitutional checks from `docs/phases/phase-5a.md`:
//! 1. Tag collision: selected option A `provides` tag T while selected option B `conflicts_with` T -> `error`.
//! 2. Missing prerequisite: selected option `requires` tag T, not provided by any selected option -> `error`.
//! 3. Circular bubble dependency (`depends_on` cycle) -> `error`.
//! 4. Unresolved mandatory decision (`status == pending`) -> `error`.
//!
//! Also performs fail-closed structural checks (duplicate bubble IDs, invalid `selected_option`,
//! `user_confirmed` with no selection, unknown `depends_on` target, empty blueprint).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::model::{
    Blueprint, BlueprintBubble, BlueprintConflict, BlueprintOption, BubbleStatus, ConflictKind,
    ConflictSeverity,
};

/// Deterministic report produced by [`check_conflicts`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictReport {
    pub conflicts: Vec<BlueprintConflict>,
    pub error_count: usize,
    pub warning_count: usize,
    pub can_lock: bool,
}

impl ConflictReport {
    /// Summarize error-level conflict messages in deterministic order for diagnostics.
    pub fn error_summary(&self) -> String {
        let msgs: Vec<&str> = self
            .conflicts
            .iter()
            .filter(|c| c.severity == ConflictSeverity::Error)
            .map(|c| c.message.as_str())
            .collect();
        if msgs.is_empty() {
            "none".to_string()
        } else {
            msgs.join("; ")
        }
    }
}

/// Run all deterministic conflict checks on a [`Blueprint`].
///
/// Pure function: byte-for-byte deterministic regardless of input ordering.
pub fn check_conflicts(blueprint: &Blueprint) -> ConflictReport {
    let mut conflicts: Vec<BlueprintConflict> = Vec::new();

    if blueprint.bubbles.is_empty() {
        conflicts.push(BlueprintConflict {
            severity: ConflictSeverity::Error,
            kind: Some(ConflictKind::EmptyBlueprint),
            bubble_ids: Vec::new(),
            message: "Blueprint has no decision bubbles to lock.".to_string(),
        });
        return finalize_report(conflicts);
    }

    // Index bubbles by ID and detect duplicate bubble IDs.
    let mut bubbles_by_id: BTreeMap<&str, &BlueprintBubble> = BTreeMap::new();
    let mut duplicate_ids: BTreeSet<String> = BTreeSet::new();
    for bubble in &blueprint.bubbles {
        if bubbles_by_id.insert(bubble.id.as_str(), bubble).is_some() {
            duplicate_ids.insert(bubble.id.clone());
        }
    }
    for dup_id in duplicate_ids {
        conflicts.push(BlueprintConflict {
            severity: ConflictSeverity::Error,
            kind: Some(ConflictKind::DuplicateBubbleId),
            bubble_ids: vec![dup_id.clone()],
            message: format!("Duplicate bubble id `{dup_id}` found in blueprint."),
        });
    }

    // Check 4 (mandatory): Unresolved pending decisions + selection validity.
    // Also collect selected options for Checks 1 & 2.
    let mut selected_options: BTreeMap<&str, &BlueprintOption> = BTreeMap::new();
    let mut provided_by_tag: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for (&bubble_id, &bubble) in &bubbles_by_id {
        if bubble.status == BubbleStatus::Pending {
            conflicts.push(BlueprintConflict {
                severity: ConflictSeverity::Error,
                kind: Some(ConflictKind::PendingDecision),
                bubble_ids: vec![bubble_id.to_string()],
                message: format!(
                    "Decision bubble `{bubble_id}` (\"{}\") is still `pending` user confirmation.",
                    bubble.title
                ),
            });
        }

        if let Some(sel_id) = bubble.selected_option.as_deref() {
            match bubble.options.iter().find(|o| o.id == sel_id) {
                Some(opt) => {
                    if bubble.status != BubbleStatus::Skipped {
                        selected_options.insert(bubble_id, opt);
                        for tag in &opt.provides {
                            let clean = tag.trim();
                            if !clean.is_empty() {
                                provided_by_tag
                                    .entry(clean.to_string())
                                    .or_default()
                                    .insert(bubble_id.to_string());
                            }
                        }
                    }
                }
                None => {
                    conflicts.push(BlueprintConflict {
                        severity: ConflictSeverity::Error,
                        kind: Some(ConflictKind::InvalidSelection),
                        bubble_ids: vec![bubble_id.to_string()],
                        message: format!("Bubble `{bubble_id}` selects unknown option `{sel_id}`."),
                    });
                }
            }
        } else if bubble.status == BubbleStatus::UserConfirmed && !bubble.options.is_empty() {
            conflicts.push(BlueprintConflict {
                severity: ConflictSeverity::Error,
                kind: Some(ConflictKind::InvalidSelection),
                bubble_ids: vec![bubble_id.to_string()],
                message: format!(
                    "Bubble `{bubble_id}` is marked `user_confirmed` but has no `selected_option`."
                ),
            });
        }

        // Validate `depends_on` targets exist.
        for dep in &bubble.depends_on {
            if !bubbles_by_id.contains_key(dep.as_str()) {
                conflicts.push(BlueprintConflict {
                    severity: ConflictSeverity::Error,
                    kind: Some(ConflictKind::UnknownDependency),
                    bubble_ids: vec![bubble_id.to_string(), dep.clone()],
                    message: format!("Bubble `{bubble_id}` depends on unknown bubble `{dep}`."),
                });
            }
        }
    }

    // Check 1 (mandatory): `provides` vs `conflicts_with` tag collision.
    let mut seen_tag_conflicts: BTreeSet<(Vec<String>, String)> = BTreeSet::new();
    for (&bubble_id, &opt) in &selected_options {
        for conflict_tag in &opt.conflicts_with {
            let tag = conflict_tag.trim();
            if tag.is_empty() {
                continue;
            }
            if let Some(providers) = provided_by_tag.get(tag) {
                for provider_id in providers {
                    let mut pair = vec![bubble_id.to_string(), provider_id.clone()];
                    pair.sort();
                    pair.dedup();
                    if seen_tag_conflicts.insert((pair.clone(), tag.to_string())) {
                        conflicts.push(BlueprintConflict {
                            severity: ConflictSeverity::Error,
                            kind: Some(ConflictKind::TagConflict),
                            bubble_ids: pair,
                            message: format!(
                                "Option `{}` in bubble `{bubble_id}` conflicts with tag `{tag}` provided by bubble `{provider_id}`.",
                                opt.id
                            ),
                        });
                    }
                }
            }
        }
    }

    // Check 2 (mandatory): Missing `requires` prerequisite.
    for (&bubble_id, &opt) in &selected_options {
        let sorted_reqs: BTreeSet<&str> = opt
            .requires
            .iter()
            .map(|r| r.trim())
            .filter(|r| !r.is_empty())
            .collect();
        for req_tag in sorted_reqs {
            if !provided_by_tag.contains_key(req_tag) {
                conflicts.push(BlueprintConflict {
                    severity: ConflictSeverity::Error,
                    kind: Some(ConflictKind::MissingRequirement),
                    bubble_ids: vec![bubble_id.to_string()],
                    message: format!(
                        "Option `{}` in bubble `{bubble_id}` requires tag `{req_tag}`, which is not provided by any selected option.",
                        opt.id
                    ),
                });
            }
        }
    }

    // Check 3 (mandatory): Circular `depends_on` dependency cycles.
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (&bubble_id, &bubble) in &bubbles_by_id {
        let mut deps: BTreeSet<String> = BTreeSet::new();
        for dep in &bubble.depends_on {
            if bubbles_by_id.contains_key(dep.as_str()) {
                deps.insert(dep.clone());
            }
        }
        adjacency.insert(bubble_id.to_string(), deps.into_iter().collect());
    }

    for cycle in detect_cycles(&adjacency) {
        let chain = format!("{} -> {}", cycle.join(" -> "), cycle[0]);
        let mut sorted_ids = cycle.clone();
        sorted_ids.sort();
        sorted_ids.dedup();
        conflicts.push(BlueprintConflict {
            severity: ConflictSeverity::Error,
            kind: Some(ConflictKind::DependencyCycle),
            bubble_ids: sorted_ids,
            message: format!("Circular bubble dependency detected: {chain}"),
        });
    }

    finalize_report(conflicts)
}

/// Deterministically detect elementary cycles in a directed graph represented by `adjacency`.
///
/// Each returned cycle is rotated so its lexicographically smallest node ID comes first,
/// deduplicated, and sorted lexicographically.
pub(crate) fn detect_cycles(adjacency: &BTreeMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let mut cycles: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut state: BTreeMap<&str, u8> = BTreeMap::new(); // 0=unvisited, 1=visiting, 2=done
    let mut stack: Vec<String> = Vec::new();

    for start in adjacency.keys() {
        if *state.get(start.as_str()).unwrap_or(&0) == 0 {
            dfs_cycles(start, adjacency, &mut state, &mut stack, &mut cycles);
        }
    }

    cycles.into_iter().collect()
}

fn dfs_cycles<'a>(
    node: &'a str,
    adjacency: &'a BTreeMap<String, Vec<String>>,
    state: &mut BTreeMap<&'a str, u8>,
    stack: &mut Vec<String>,
    cycles: &mut BTreeSet<Vec<String>>,
) {
    state.insert(node, 1);
    stack.push(node.to_string());

    if let Some(neighbors) = adjacency.get(node) {
        for next in neighbors {
            let next_state = *state.get(next.as_str()).unwrap_or(&0);
            if next_state == 0 {
                dfs_cycles(next.as_str(), adjacency, state, stack, cycles);
            } else if next_state == 1
                && let Some(pos) = stack.iter().position(|n| n == next)
            {
                let canonical = canonicalize_cycle(&stack[pos..]);
                if !canonical.is_empty() {
                    cycles.insert(canonical);
                }
            }
        }
    }

    stack.pop();
    state.insert(node, 2);
}

fn canonicalize_cycle(slice: &[String]) -> Vec<String> {
    if slice.is_empty() {
        return Vec::new();
    }
    let mut min_idx = 0usize;
    for (idx, item) in slice.iter().enumerate().skip(1) {
        if item < &slice[min_idx] {
            min_idx = idx;
        }
    }
    let mut rotated = Vec::with_capacity(slice.len());
    rotated.extend_from_slice(&slice[min_idx..]);
    rotated.extend_from_slice(&slice[..min_idx]);
    rotated
}

fn finalize_report(mut conflicts: Vec<BlueprintConflict>) -> ConflictReport {
    conflicts.sort();
    conflicts.dedup();
    let error_count = conflicts
        .iter()
        .filter(|c| c.severity == ConflictSeverity::Error)
        .count();
    let warning_count = conflicts
        .iter()
        .filter(|c| c.severity == ConflictSeverity::Warning)
        .count();
    ConflictReport {
        conflicts,
        error_count,
        warning_count,
        can_lock: error_count == 0,
    }
}
