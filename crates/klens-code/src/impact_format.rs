//! Compact, budgeted rendering of impact hits for agents.
//!
//! The raw hit list can reach hundreds of kilobytes (every reference along a transitive import
//! chain). Agents need the closest, most certain dependents first, one line per file, inside a
//! token budget. Both the text form and an explicitly bounded JSON form rank files the same way
//! and always say what they left out: omit honestly, never silently.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use klens_core::{
    CHARS_PER_TOKEN, EdgeConfidence, EdgeRelation, ProvenanceEnvelope, estimate_tokens,
};

use crate::impact::{ImpactHit, ImpactPayload, ImpactStatus};

/// Default token budget for impact text output (MCP `budget`, CLI `--budget`).
pub const DEFAULT_IMPACT_BUDGET_TOKENS: usize = 1_500;
/// Smallest budget honoured; lower requests are raised so the header and footer always fit.
pub const MIN_IMPACT_BUDGET_TOKENS: usize = 200;
/// Line numbers listed per file before `+N more`.
pub const MAX_LINES_PER_FILE: usize = 6;
/// Tokens kept back for the JSON envelope around a bounded `hits` array.
const JSON_ENVELOPE_RESERVE_TOKENS: usize = 150;
/// Extra indentation per line of a hit nested in the pretty envelope (`data.hits[i]`).
const JSON_NESTED_INDENT: usize = 6;

/// Output caps for impact results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactOutputLimits {
    /// Token budget; `None` means no cap.
    pub budget_tokens: Option<usize>,
    /// Maximum number of files listed; `None` means no file cap.
    pub max_files: Option<usize>,
}

impl Default for ImpactOutputLimits {
    fn default() -> Self {
        Self {
            budget_tokens: Some(DEFAULT_IMPACT_BUDGET_TOKENS),
            max_files: None,
        }
    }
}

impl ImpactOutputLimits {
    /// No budget and no file cap: every hit.
    pub const fn unbounded() -> Self {
        Self {
            budget_tokens: None,
            max_files: None,
        }
    }

    /// Build limits from user input: `budget` `0` means no cap, missing means the default, and
    /// small values are raised to [`MIN_IMPACT_BUDGET_TOKENS`]. `limit` `0` means no file cap.
    pub fn from_request(budget: Option<usize>, limit: Option<usize>) -> Self {
        let budget_tokens = match budget {
            None => Some(DEFAULT_IMPACT_BUDGET_TOKENS),
            Some(0) => None,
            Some(b) => Some(b.max(MIN_IMPACT_BUDGET_TOKENS)),
        };
        Self {
            budget_tokens,
            max_files: limit.filter(|&n| n > 0),
        }
    }
}

fn confidence_rank(confidence: EdgeConfidence) -> u8 {
    match confidence {
        EdgeConfidence::VerifiedLsp => 0,
        EdgeConfidence::Extracted => 1,
        EdgeConfidence::Inferred => 2,
        EdgeConfidence::Ambiguous => 3,
    }
}

const fn relation_label(relation: EdgeRelation) -> &'static str {
    match relation {
        EdgeRelation::Imports => "imports",
        EdgeRelation::Calls => "calls",
        EdgeRelation::Implements => "implements",
        EdgeRelation::Extends => "extends",
        EdgeRelation::References => "refs",
    }
}

struct FileGroup<'a> {
    path: &'a str,
    distance: usize,
    confidence: EdgeConfidence,
    relations: Vec<&'static str>,
    /// Line numbers grouped by enclosing symbol, in first-seen order (`None` = top level).
    scopes: Vec<(Option<&'a str>, Vec<usize>)>,
    lines: BTreeSet<usize>,
    hits: usize,
}

/// Group hits by file and rank: closest first, then most certain, then path.
fn ranked_groups(hits: &[ImpactHit]) -> Vec<FileGroup<'_>> {
    let mut groups: BTreeMap<&str, FileGroup<'_>> = BTreeMap::new();
    for hit in hits {
        let group = groups
            .entry(hit.path.as_str())
            .or_insert_with(|| FileGroup {
                path: hit.path.as_str(),
                distance: hit.distance,
                confidence: hit.confidence,
                relations: Vec::new(),
                scopes: Vec::new(),
                lines: BTreeSet::new(),
                hits: 0,
            });
        group.hits += 1;
        // The confidence shown belongs to the closest hits, never to a farther, more certain one.
        if hit.distance < group.distance {
            group.distance = hit.distance;
            group.confidence = hit.confidence;
        } else if hit.distance == group.distance
            && confidence_rank(hit.confidence) < confidence_rank(group.confidence)
        {
            group.confidence = hit.confidence;
        }
        let relation = relation_label(hit.relation);
        if !group.relations.contains(&relation) {
            group.relations.push(relation);
        }
        if let Some(line) = hit.line
            && group.lines.insert(line)
        {
            let scope = hit.enclosing_symbol.as_deref();
            match group.scopes.iter_mut().find(|(s, _)| *s == scope) {
                Some((_, lines)) => lines.push(line),
                None => group.scopes.push((scope, vec![line])),
            }
        }
    }

    let mut ordered: Vec<FileGroup<'_>> = groups.into_values().collect();
    ordered.sort_by(|a, b| {
        a.distance
            .cmp(&b.distance)
            .then(confidence_rank(a.confidence).cmp(&confidence_rank(b.confidence)))
            .then(a.path.cmp(b.path))
    });
    ordered
}

/// `  [d1 Extracted imports+calls] src/a.rs: L5, L7; `fn run` L40,41 +3 more`
fn render_group(group: &FileGroup<'_>) -> String {
    let mut line = format!(
        "  [d{} {:?} {}] {}",
        group.distance,
        group.confidence,
        group.relations.join("+"),
        group.path
    );
    if group.lines.is_empty() {
        line.push('\n');
        return line;
    }

    let mut segments: Vec<String> = Vec::new();
    let mut shown = 0usize;
    for (scope, lines) in &group.scopes {
        if shown >= MAX_LINES_PER_FILE {
            break;
        }
        let take = (MAX_LINES_PER_FILE - shown).min(lines.len());
        shown += take;
        let numbers: Vec<String> = lines[..take].iter().map(usize::to_string).collect();
        match scope {
            Some(symbol) => segments.push(format!("`{symbol}` L{}", numbers.join(","))),
            None => segments.push(format!("L{}", numbers.join(","))),
        }
    }
    let _ = write!(line, ": {}", segments.join("; "));
    if group.lines.len() > shown {
        let _ = write!(line, " +{} more", group.lines.len() - shown);
    }
    line.push('\n');
    line
}

fn omission_footer(rest: &[FileGroup<'_>]) -> String {
    let rest_hits: usize = rest.iter().map(|g| g.hits).sum();
    let deep = rest.iter().filter(|g| g.distance >= 3).count();
    let shallow = rest.len() - deep;
    format!(
        "  +{} more files ({rest_hits} hits): {shallow} at d1-2, {deep} at d3+. \
         Raise `budget` (0 = no cap), or target `path#symbol` to narrow.\n",
        rest.len()
    )
}

/// One line per affected file, closest and most certain first, inside `limits`.
///
/// Tokens already in `out` (the header) count against the budget. The footer's worst case is
/// reserved up front, so the output never exceeds the budget and the omission is always stated.
pub(crate) fn write_grouped_hits(out: &mut String, hits: &[ImpactHit], limits: ImpactOutputLimits) {
    let ordered = ranked_groups(hits);
    // Footer text only gets shorter as more files are shown, so the all-omitted form is the
    // upper bound to reserve.
    let footer_reserve = estimate_tokens(&omission_footer(&ordered));
    let mut used = estimate_tokens(out);
    let mut shown = 0usize;

    for group in &ordered {
        if limits.max_files.is_some_and(|max| shown >= max) {
            break;
        }
        let line = render_group(group);
        let cost = estimate_tokens(&line);
        if let Some(budget) = limits.budget_tokens {
            let reserve = if shown + 1 < ordered.len() {
                footer_reserve
            } else {
                0
            };
            if used + cost + reserve > budget {
                break;
            }
        }
        out.push_str(&line);
        used += cost;
        shown += 1;
    }

    if shown < ordered.len() {
        out.push_str(&omission_footer(&ordered[shown..]));
    }
}

/// Trim `payload.hits` to the highest-ranked hits that fit `limits` (JSON output).
///
/// Hits are taken file by file in the same order as the text form (the last file may be cut
/// short); `omitted_files` (files with no hit kept) and `omitted_hits` record what was left out.
/// With [`ImpactOutputLimits::unbounded`] nothing changes.
pub fn bound_impact_payload(payload: &mut ImpactPayload, limits: ImpactOutputLimits) {
    if limits.budget_tokens.is_none() && limits.max_files.is_none() {
        return;
    }
    let rank: BTreeMap<&str, usize> = ranked_groups(&payload.hits)
        .iter()
        .enumerate()
        .map(|(i, g)| (g.path, i))
        .collect();
    let mut order: Vec<usize> = (0..payload.hits.len()).collect();
    order.sort_by_key(|&i| (rank[payload.hits[i].path.as_str()], i));

    let mut keep = vec![false; payload.hits.len()];
    let mut kept_files: BTreeSet<&str> = BTreeSet::new();
    let mut used = JSON_ENVELOPE_RESERVE_TOKENS;
    for i in order {
        let hit = &payload.hits[i];
        let new_file = !kept_files.contains(hit.path.as_str());
        if new_file && limits.max_files.is_some_and(|max| kept_files.len() >= max) {
            break;
        }
        // Priced as pretty JSON nested in the envelope (the CLI's form), so the compact MCP form
        // is always smaller: each line gains JSON_NESTED_INDENT more spaces of indentation.
        let json = serde_json::to_string_pretty(hit).unwrap_or_default();
        let indent = json.lines().count() * JSON_NESTED_INDENT;
        let cost = estimate_tokens(&json) + indent.div_ceil(CHARS_PER_TOKEN) + 1;
        if limits
            .budget_tokens
            .is_some_and(|budget| used + cost > budget)
        {
            break;
        }
        used += cost;
        keep[i] = true;
        kept_files.insert(hit.path.as_str());
    }

    let total_files = rank.len();
    let kept_file_count = kept_files.len();
    let before = payload.hits.len();
    let mut flags = keep.into_iter();
    payload.hits.retain(|_| flags.next().unwrap_or(false));
    payload.omitted_hits = before - payload.hits.len();
    payload.omitted_files = total_files - kept_file_count;
}

/// Render an impact analysis envelope into deterministic plain text within the default budget.
pub fn format_impact_text(envelope: &ProvenanceEnvelope<ImpactPayload>) -> String {
    format_impact_text_with(envelope, ImpactOutputLimits::default())
}

/// Render an impact analysis envelope into deterministic plain text within `limits`.
pub fn format_impact_text_with(
    envelope: &ProvenanceEnvelope<ImpactPayload>,
    limits: ImpactOutputLimits,
) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] impact query=\"{}\" status={:?} affected_files={} hits={}",
        crate::trust_label(envelope.trust),
        data.query,
        data.status,
        data.affected_files_count,
        data.hits.len() + data.omitted_hits
    );

    if let Some(tp) = &data.target_path {
        match &data.target_symbol {
            Some(ts) => {
                let _ = writeln!(out, "TARGET: {tp}#{ts}");
            }
            None => {
                let _ = writeln!(out, "TARGET: {tp}");
            }
        }
    }

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    match data.status {
        ImpactStatus::Ok => write_grouped_hits(&mut out, &data.hits, limits),
        ImpactStatus::AmbiguousTarget => {
            if let Some(msg) = &data.message {
                let _ = writeln!(out, "AMBIGUOUS_TARGET: {msg}");
            }
            for c in &data.candidates {
                match (&c.qualified_name, c.start_line, c.end_line) {
                    (Some(q), Some(s), Some(e)) => {
                        let _ = writeln!(out, "  - {}#{} [L{s}-L{e}]", c.path, q);
                    }
                    _ => {
                        let _ = writeln!(out, "  - {}", c.path);
                    }
                }
            }
        }
        ImpactStatus::NotFound => {
            if let Some(msg) = &data.message {
                let _ = writeln!(out, "{msg}");
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use klens_core::EdgeRelation;

    use super::*;
    use crate::impact::ImpactTargetKind;

    fn hit(path: &str, line: usize, distance: usize, confidence: EdgeConfidence) -> ImpactHit {
        ImpactHit {
            path: path.to_string(),
            enclosing_symbol: None,
            line: Some(line),
            relation: EdgeRelation::References,
            confidence,
            distance,
            evidence: format!("{path}:L{line}"),
            snippet: None,
        }
    }

    fn many_hits() -> Vec<ImpactHit> {
        let mut hits = Vec::new();
        for file in 0..120 {
            let distance = 1 + file % 5;
            for line in 1..=10 {
                hits.push(hit(
                    &format!("src/f{file:03}.rs"),
                    line,
                    distance,
                    EdgeConfidence::Inferred,
                ));
            }
        }
        hits.push(hit("src/zz_direct.rs", 7, 1, EdgeConfidence::Extracted));
        hits
    }

    fn render(hits: &[ImpactHit], limits: ImpactOutputLimits) -> String {
        let mut out = String::from("[INFERRED] impact query=\"x\" status=Ok\n");
        write_grouped_hits(&mut out, hits, limits);
        out
    }

    #[test]
    fn budget_caps_output_ranks_closest_first_and_ends_with_an_honest_tail() {
        let hits = many_hits();
        let limits = ImpactOutputLimits::from_request(Some(400), None);
        let out = render(&hits, limits);
        let lines: Vec<&str> = out.lines().collect();

        assert!(
            estimate_tokens(&out) <= 400,
            "{} tokens:\n{out}",
            estimate_tokens(&out)
        );
        assert!(
            lines[1].contains("src/zz_direct.rs"),
            "extracted d1 first: {}",
            lines[1]
        );
        let listed: Vec<&&str> = lines.iter().filter(|l| l.starts_with("  [d")).collect();
        assert!(
            listed
                .iter()
                .all(|l| l.starts_with("  [d1 ") || l.starts_with("  [d2 ")),
            "only d1-2 fit in a small budget:\n{out}"
        );
        let footer = lines.last().unwrap();
        let omitted = 121 - listed.len();
        assert!(
            footer.starts_with(&format!("  +{omitted} more files (")),
            "{footer}"
        );
        // 120 files, distance 1..=5 round-robin: 72 files at d3+, none of them listed.
        assert!(footer.contains(", 72 at d3+."), "{footer}");
        assert!(footer.contains("Raise `budget`"), "{footer}");
    }

    #[test]
    fn tail_counts_shallow_files_when_most_omitted_files_are_direct() {
        // The real `paths.rs` case: almost every omitted file is a direct (d1) dependent.
        let mut hits: Vec<ImpactHit> = (0..80)
            .map(|i| hit(&format!("src/d{i:02}.rs"), 3, 1, EdgeConfidence::Inferred))
            .collect();
        hits.push(hit("src/deep.rs", 1, 4, EdgeConfidence::Extracted));
        let out = render(&hits, ImpactOutputLimits::from_request(Some(300), None));
        let footer = out.lines().last().unwrap();
        assert!(footer.contains(" at d1-2, 1 at d3+."), "{footer}");
        assert!(!footer.contains(" 0 at d1-2"), "{footer}");
    }

    #[test]
    fn limit_caps_files_and_zero_budget_lists_everything() {
        let hits = many_hits();
        let out = render(&hits, ImpactOutputLimits::from_request(Some(0), Some(5)));
        let listed = out.lines().filter(|l| l.starts_with("  [d")).count();
        assert_eq!(listed, 5, "{out}");
        assert!(out.contains("  +116 more files (1160 hits)"), "{out}");

        let all = render(&hits, ImpactOutputLimits::unbounded());
        assert_eq!(all.lines().filter(|l| l.starts_with("  [d")).count(), 121);
        assert!(!all.contains("more files"), "{all}");
    }

    #[test]
    fn small_budgets_are_raised_to_the_minimum() {
        let limits = ImpactOutputLimits::from_request(Some(10), Some(0));
        assert_eq!(limits.budget_tokens, Some(MIN_IMPACT_BUDGET_TOKENS));
        assert_eq!(limits.max_files, None);
        assert_eq!(
            ImpactOutputLimits::from_request(None, None),
            ImpactOutputLimits::default()
        );
    }

    #[test]
    fn line_lists_each_location_once_and_names_a_scope_once() {
        let mut hits = vec![
            hit("src/a.rs", 5, 1, EdgeConfidence::Extracted),
            hit("src/a.rs", 5, 1, EdgeConfidence::Inferred),
        ];
        for line in [40, 41, 42] {
            let mut h = hit("src/a.rs", line, 1, EdgeConfidence::Inferred);
            h.enclosing_symbol = Some("fn run".to_string());
            h.relation = EdgeRelation::Calls;
            hits.push(h);
        }
        let out = render(&hits, ImpactOutputLimits::default());
        let line = out.lines().nth(1).unwrap();
        assert_eq!(
            line, "  [d1 Extracted refs+calls] src/a.rs: L5; `fn run` L40,41,42",
            "{out}"
        );
        assert_eq!(line.matches("src/a.rs").count(), 1, "{line}");
        assert_eq!(line.matches("fn run").count(), 1, "{line}");
    }

    #[test]
    fn per_file_line_numbers_are_capped_with_a_count() {
        let hits: Vec<ImpactHit> = (1..=10)
            .map(|l| hit("src/a.rs", l, 1, EdgeConfidence::Inferred))
            .collect();
        let out = render(&hits, ImpactOutputLimits::default());
        assert!(out.contains("src/a.rs: L1,2,3,4,5,6 +4 more"), "{out}");
    }

    #[test]
    fn confidence_shown_is_the_one_of_the_closest_hits() {
        let hits = vec![
            hit("src/a.rs", 3, 3, EdgeConfidence::Extracted),
            hit("src/a.rs", 9, 1, EdgeConfidence::Inferred),
        ];
        let out = render(&hits, ImpactOutputLimits::default());
        assert!(out.contains("[d1 Inferred "), "{out}");
    }

    #[test]
    fn json_budget_holds_for_the_pretty_envelope() {
        let payload = ImpactPayload {
            status: ImpactStatus::Ok,
            query: "src/x.rs".to_string(),
            target_kind: Some(ImpactTargetKind::File),
            target_path: Some("src/x.rs".to_string()),
            target_symbol: None,
            affected_files_count: 121,
            hits: many_hits(),
            omitted_files: 0,
            omitted_hits: 0,
            candidates: Vec::new(),
            message: None,
        };
        let mut env = klens_core::ProvenanceEnvelope::new(
            klens_core::TrustLevel::Inferred,
            "p".to_string(),
            payload,
        )
        .with_warning("some impact entries use INFERRED/AMBIGUOUS identifier matching without LSP");
        bound_impact_payload(
            &mut env.data,
            ImpactOutputLimits::from_request(Some(1_000), None),
        );
        assert!(env.data.omitted_files > 0);
        assert!(!env.data.hits.is_empty());
        let pretty = env.to_deterministic_json_pretty().unwrap();
        let compact = env.to_deterministic_json().unwrap();
        assert!(
            estimate_tokens(&pretty) <= 1_000,
            "{}",
            estimate_tokens(&pretty)
        );
        assert!(compact.len() < pretty.len());
    }

    #[test]
    fn json_bounding_keeps_whole_top_files_and_counts_the_rest() {
        let mut payload = ImpactPayload {
            status: ImpactStatus::Ok,
            query: "x".to_string(),
            target_kind: Some(ImpactTargetKind::File),
            target_path: Some("src/x.rs".to_string()),
            target_symbol: None,
            affected_files_count: 121,
            hits: many_hits(),
            omitted_files: 0,
            omitted_hits: 0,
            candidates: Vec::new(),
            message: None,
        };
        let full = payload.clone();
        bound_impact_payload(&mut payload, ImpactOutputLimits::unbounded());
        assert_eq!(payload, full, "unbounded leaves the payload untouched");

        bound_impact_payload(
            &mut payload,
            ImpactOutputLimits::from_request(Some(0), Some(3)),
        );
        let files: BTreeSet<&str> = payload.hits.iter().map(|h| h.path.as_str()).collect();
        assert_eq!(files.len(), 3);
        assert!(files.contains("src/zz_direct.rs"));
        assert_eq!(payload.omitted_files, 118);
        assert_eq!(payload.omitted_hits, 1201 - payload.hits.len());
        assert_eq!(
            payload.affected_files_count, 121,
            "total stays the real total"
        );

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"omitted_files\":118"), "{json}");
        assert!(!serde_json::to_string(&full).unwrap().contains("omitted_"));
    }

    #[test]
    fn evidence_reason_drops_the_repeated_location() {
        let mut h = hit("src/a.rs", 5, 1, EdgeConfidence::Extracted);
        assert_eq!(h.evidence_reason(), None);
        h.evidence = "src/a.rs:L5 (identifier match in importing file without LSP)".to_string();
        assert_eq!(
            h.evidence_reason(),
            Some("identifier match in importing file without LSP")
        );
        h.line = None;
        h.evidence = "src/a.rs imports src/b.rs (transitive depth 2)".to_string();
        assert_eq!(
            h.evidence_reason(),
            Some("imports src/b.rs (transitive depth 2)")
        );
    }
}
