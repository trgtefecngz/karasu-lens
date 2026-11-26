use std::collections::BTreeMap;
use std::fmt::Write as _;

use klens_core::{Omission, ProvenanceEnvelope, SymbolKind, TrustLevel, redact_secrets};
use serde::{Deserialize, Serialize};

use crate::error::CodeError;
use crate::index::CodeIndex;

/// Default maximum number of deduplicated search hits returned by `klens find`.
pub const DEFAULT_FIND_LIMIT: usize = 50;

/// Maximum candidate files fetched from FTS5 before line-level ranking.
const MAX_FTS_CANDIDATE_FILES: usize = 500;

/// Classification of a `klens find` match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindMatchKind {
    Symbol,
    Text,
}

/// A single deduplicated search match with exact 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindMatch {
    pub path: String,
    pub line: usize,
    pub match_kind: FindMatchKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_kind: Option<SymbolKind>,
    pub snippet: String,
}

/// Complete payload returned by `klens find`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindPayload {
    pub query: String,
    pub limit: usize,
    pub total_matches: usize,
    pub matches: Vec<FindMatch>,
}

#[derive(Debug, Clone)]
struct RankedHit {
    tier: u8,
    hit: FindMatch,
}

/// Fast, `.gitignore`-compliant, deduplicated symbol + FTS5 full-text search with exact line numbers.
pub fn find_in_workspace(
    index: &mut CodeIndex,
    query: &str,
    limit: usize,
) -> Result<ProvenanceEnvelope<FindPayload>, CodeError> {
    index.sync_workspace()?;
    let project_id = index.project_root().project_id().to_string();
    let trimmed = query.trim();

    if trimmed.is_empty() {
        let payload = FindPayload {
            query: String::new(),
            limit,
            total_matches: 0,
            matches: Vec::new(),
        };
        return Ok(
            ProvenanceEnvelope::new(TrustLevel::VerifiedAst, project_id, payload)
                .with_warning("empty search query"),
        );
    }

    let query_lower = trimmed.to_lowercase();
    let tokens = extract_fts_tokens(trimmed);
    let mut redactions_count = 0usize;

    // Deduplicate hits by `(path, line)` keeping the best (lowest tier) match.
    let mut best_by_loc: BTreeMap<(String, usize), RankedHit> = BTreeMap::new();

    // 1. AST symbol search (exact + partial across `name`, `qualified_name`, `signature`).
    let symbol_rows = index.store().search_symbols(trimmed)?;
    for row in symbol_rows {
        let path_str = row.file_path.as_str().to_string();
        let line = row.symbol.start_line;
        let is_exact = row.symbol.name.to_lowercase() == query_lower
            || row.symbol.qualified_name.to_lowercase() == query_lower;
        let tier = if is_exact { 0 } else { 1 };

        let redacted = redact_secrets(&row.symbol.signature);
        redactions_count += redacted.redactions_count;
        let candidate = RankedHit {
            tier,
            hit: FindMatch {
                path: path_str.clone(),
                line,
                match_kind: FindMatchKind::Symbol,
                qualified_name: Some(row.symbol.qualified_name),
                symbol_kind: Some(row.symbol.kind),
                snippet: truncate_snippet(&redacted.text, 200),
            },
        };
        insert_best(&mut best_by_loc, (path_str, line), candidate);
    }

    // 2. FTS5 prefix search + safe SQLite substring fallback (strictly scoped to indexed
    // non-ignored, non-sensitive files). Using prefix FTS5 (`"tok"*`) together with substring
    // fallback guarantees camelCase / mid-word matches (e.g. `"Timeout"` inside `handleTimeout`)
    // are never missed even when another file already has an exact token hit.
    let mut candidate_files: BTreeMap<String, String> = BTreeMap::new();
    if let Some(prefix_expr) = build_safe_fts_prefix_query(&tokens) {
        if let Ok(rows) = index
            .store()
            .search_fts(&prefix_expr, MAX_FTS_CANDIDATE_FILES)
        {
            for hit in rows {
                candidate_files
                    .entry(hit.path.as_str().to_string())
                    .or_insert(hit.content);
            }
        }
        // Catch camelCase / mid-word / punctuation substrings that FTS5 `unicode61` does not split.
        if let Ok(sub_rows) = index
            .store()
            .search_fts_substring(trimmed, MAX_FTS_CANDIDATE_FILES)
        {
            for hit in sub_rows {
                candidate_files
                    .entry(hit.path.as_str().to_string())
                    .or_insert(hit.content);
            }
        }
        // For multi-token queries where tokens appear on the same line inside camelCase identifiers,
        // also pull files containing the most selective (longest) token as a substring.
        if tokens.len() >= 2
            && let Some(longest_tok) = tokens.iter().max_by_key(|t| t.len())
            && let Ok(sub_rows) = index
                .store()
                .search_fts_substring(longest_tok, MAX_FTS_CANDIDATE_FILES)
        {
            for hit in sub_rows {
                candidate_files
                    .entry(hit.path.as_str().to_string())
                    .or_insert(hit.content);
            }
        }
    } else {
        // Pure-punctuation query (e.g. `::`, `->`): scan already-indexed FTS content deterministically.
        for hit in index
            .store()
            .search_fts_substring(trimmed, MAX_FTS_CANDIDATE_FILES)?
        {
            candidate_files
                .entry(hit.path.as_str().to_string())
                .or_insert(hit.content);
        }
    }

    let lower_tokens: Vec<String> = tokens.iter().map(|t| t.to_lowercase()).collect();

    for (path_str, content) in &candidate_files {
        for (idx, raw_line) in content.lines().enumerate() {
            let line_lower = raw_line.to_lowercase();
            let tier = if line_lower.contains(&query_lower) {
                2
            } else if lower_tokens.len() >= 2
                && lower_tokens
                    .iter()
                    .all(|tok| line_lower.contains(tok.as_str()))
            {
                3
            } else {
                continue;
            };

            let line_no = idx + 1;
            let key = (path_str.to_string(), line_no);
            // Skip if we already have an equal-or-better match at `(path, line)`.
            if let Some(existing) = best_by_loc.get(&key)
                && existing.tier <= tier
            {
                continue;
            }

            let redacted = redact_secrets(raw_line.trim());
            redactions_count += redacted.redactions_count;
            let candidate = RankedHit {
                tier,
                hit: FindMatch {
                    path: path_str.to_string(),
                    line: line_no,
                    match_kind: FindMatchKind::Text,
                    qualified_name: None,
                    symbol_kind: None,
                    snippet: truncate_snippet(&redacted.text, 200),
                },
            };
            insert_best(&mut best_by_loc, key, candidate);
        }
    }

    let mut ranked: Vec<RankedHit> = best_by_loc.into_values().collect();
    ranked.sort_by(|a, b| {
        a.tier
            .cmp(&b.tier)
            .then_with(|| a.hit.path.cmp(&b.hit.path))
            .then_with(|| a.hit.line.cmp(&b.hit.line))
            .then_with(|| a.hit.qualified_name.cmp(&b.hit.qualified_name))
    });

    let total_matches = ranked.len();
    let effective_limit = limit.max(1);
    let kept: Vec<FindMatch> = ranked
        .into_iter()
        .take(effective_limit)
        .map(|r| r.hit)
        .collect();

    let trust = if kept.iter().all(|m| m.match_kind == FindMatchKind::Symbol) && !kept.is_empty() {
        let mut has_external = false;
        for m in &kept {
            if let Ok(rel) = klens_core::RelPath::normalize(&m.path)
                && let Ok(Some(rec)) = index.store().get_file(&rel)
                && rec.parse_status.is_external()
            {
                has_external = true;
                break;
            }
        }
        if has_external {
            TrustLevel::ExternalParser
        } else {
            TrustLevel::VerifiedAst
        }
    } else {
        TrustLevel::VerifiedRaw
    };

    let payload = FindPayload {
        query: trimmed.to_string(),
        limit: effective_limit,
        total_matches,
        matches: kept,
    };

    let mut env =
        ProvenanceEnvelope::new(trust, project_id, payload).with_redactions_count(redactions_count);

    if total_matches > effective_limit {
        env = env.with_omission(Omission::items(
            total_matches - effective_limit,
            "result_limit_exceeded",
        ));
    }

    Ok(env)
}

fn insert_best(
    map: &mut BTreeMap<(String, usize), RankedHit>,
    key: (String, usize),
    cand: RankedHit,
) {
    match map.get(&key) {
        Some(existing) if existing.tier <= cand.tier => {}
        _ => {
            map.insert(key, cand);
        }
    }
}

/// Extract Unicode alphanumeric tokens matching SQLite FTS5 `unicode61` tokenization.
fn extract_fts_tokens(query: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in query.chars() {
        if ch.is_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn build_safe_fts_prefix_query(tokens: &[String]) -> Option<String> {
    if tokens.is_empty() {
        return None;
    }
    let parts: Vec<String> = tokens
        .iter()
        .map(|t| format!("\"{}\"*", t.replace('"', "\"\"")))
        .collect();
    Some(parts.join(" AND "))
}

fn truncate_snippet(s: &str, max_chars: usize) -> String {
    let mut byte_end = s.len();
    for (count, (idx, _)) in s.char_indices().enumerate() {
        if count == max_chars {
            byte_end = idx;
            break;
        }
    }
    if byte_end < s.len() {
        format!("{}...", &s[..byte_end])
    } else {
        s.to_string()
    }
}

/// Render a `klens find` envelope into deterministic plain text.
pub fn format_find_text(envelope: &ProvenanceEnvelope<FindPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] find query=\"{}\" showing={}/{}",
        crate::trust_label(envelope.trust),
        data.query,
        data.matches.len(),
        data.total_matches
    );

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    for hit in &data.matches {
        match hit.match_kind {
            FindMatchKind::Symbol => {
                let qname = hit.qualified_name.as_deref().unwrap_or("");
                let _ = writeln!(
                    out,
                    "  {}:L{} [symbol] {} :: {}",
                    hit.path, hit.line, qname, hit.snippet
                );
            }
            FindMatchKind::Text => {
                let _ = writeln!(out, "  {}:L{} [text] {}", hit.path, hit.line, hit.snippet);
            }
        }
    }

    for om in &envelope.omissions {
        let _ = writeln!(out, "// ... [omitted {} matches ({})]", om.count, om.reason);
    }

    out
}
