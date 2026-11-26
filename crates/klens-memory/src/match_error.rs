//! Error → Bugfix note matcher (`match_error`) — "Never hit the same bug twice".
//!
//! Crate Isolation (`docs/phases/phase-4.md`):
//! `klens-exec` NEVER depends on `klens-memory`. Higher layers (`klens-cli` and `klens-mcp`)
//! call [`match_error`] whenever `klens run` exits non-zero and attach verified bugfix notes
//! (title, path, and honest `Taze` / `STALE` status) without speculation.

use std::collections::{BTreeMap, BTreeSet};

use klens_core::{ProjectRoot, TrustLevel, redact_secrets};
use rusqlite::params;

use crate::error::MemoryError;
use crate::index::{build_fts5_or_query, open_memory_fts_connection};
use crate::types::{
    BugfixMatch, DEFAULT_BUGFIX_MATCH_LIMIT, MEMORY_DIR_REL, MemoryKind, MemoryNote, SymbolResolver,
};
use crate::verify::{load_vault_notes, verify_note};

/// Common noisy words ignored when extracting error signatures so generic failures
/// never produce false-positive bugfix matches.
const ERROR_STOPWORDS: &[&str] = &[
    "error",
    "errors",
    "failed",
    "failure",
    "warning",
    "warnings",
    "fatal",
    "command",
    "process",
    "exit",
    "code",
    "status",
    "line",
    "file",
    "test",
    "tests",
    "running",
    "finished",
    "compiling",
    "could",
    "because",
    "previous",
    "aborting",
    "found",
    "expected",
    "cannot",
    "with",
    "from",
    "that",
    "this",
    "have",
    "been",
    "into",
    "your",
    "more",
    "info",
    "help",
    "note",
    "cargo",
    "rustc",
    "stderr",
    "stdout",
    "thread",
    "main",
    "panicked",
];

/// Match a failing command's cleaned error output against `kind: bugfix` notes in `.klens/memory/`.
///
/// - Fast no-op when `.klens/memory/` does not exist or contains no `bugfix` notes.
/// - Searches exclusively `kind: bugfix` notes via SQLite FTS5 (`unicode61`) plus explicit
///   error-code and anchored-file correlation.
/// - Verifies every matched note's BLAKE3 anchors so `is_stale` / `trust` are always honest.
pub fn match_error(
    project_root: &ProjectRoot,
    error_output: &str,
    limit: usize,
    resolver: &mut dyn SymbolResolver,
) -> Result<Vec<BugfixMatch>, MemoryError> {
    let trimmed = error_output.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Fast path: avoid scanning if vault directory doesn't exist yet.
    if !project_root.root().join(MEMORY_DIR_REL).is_dir() {
        return Ok(Vec::new());
    }

    let (notes, _warnings) = load_vault_notes(project_root)?;
    let bugfixes: Vec<&MemoryNote> = notes
        .iter()
        .filter(|n| n.frontmatter.kind == MemoryKind::Bugfix)
        .collect();
    if bugfixes.is_empty() {
        return Ok(Vec::new());
    }

    let sig = extract_error_signature(trimmed);
    if sig.fts_terms.is_empty() && sig.error_codes.is_empty() && sig.mentioned_paths.is_empty() {
        return Ok(Vec::new());
    }

    let conn = open_memory_fts_connection(&bugfixes)?;
    let mut scores: BTreeMap<String, (i64, BTreeSet<String>)> = BTreeMap::new();

    // 1. SQLite FTS5 query across `kind: bugfix` notes using distinctive extracted terms.
    let mut query_tokens: Vec<String> = Vec::new();
    for code in &sig.error_codes {
        query_tokens.push(code.clone());
    }
    for term in &sig.fts_terms {
        if !query_tokens.iter().any(|t| t.eq_ignore_ascii_case(term)) {
            query_tokens.push(term.clone());
        }
    }

    // Column weights match all 6 table columns:
    // (note_id UNINDEXED = 0.0, title = 10.0, tags = 6.0, wikilinks = 4.0, anchor_paths = 5.0, body = 3.0).
    if let Some(fts_query) = build_fts5_or_query(&query_tokens) {
        let mut stmt = conn.prepare(
            "SELECT note_id, bm25(memory_fts, 0.0, 10.0, 6.0, 4.0, 5.0, 3.0) AS rank
             FROM memory_fts
             WHERE memory_fts MATCH ?1
             ORDER BY rank ASC, note_id ASC",
        )?;
        let rows = stmt.query_map(params![fts_query], |row| {
            let id: String = row.get(0)?;
            let rank: f64 = row.get(1)?;
            Ok((id, rank))
        })?;
        for row in rows.flatten() {
            let (id, bm25_rank) = row;
            let boost = ((-bm25_rank * 100.0).round() as i64).clamp(10, 50_000);
            let entry = scores.entry(id).or_insert_with(|| (0, BTreeSet::new()));
            entry.0 = entry.0.saturating_add(boost);
        }
    }

    // 2. Deterministic error-code, distinctive term, and anchored-path correlation.
    for note in &bugfixes {
        let haystack = format!(
            "{}\n{}\n{}\n{}",
            note.frontmatter.id,
            note.frontmatter.title,
            note.frontmatter.tags.join(" "),
            note.body
        )
        .to_lowercase();

        let mut bonus: i64 = 0;
        let mut matched_terms: BTreeSet<String> = BTreeSet::new();

        for code in &sig.error_codes {
            if haystack.contains(&code.to_lowercase()) {
                bonus += 400;
                matched_terms.insert(code.clone());
            }
        }

        for term in &sig.fts_terms {
            if haystack.contains(&term.to_lowercase()) {
                bonus += 60;
                matched_terms.insert(term.clone());
            }
        }

        for anchor in &note.frontmatter.anchors {
            let anchor_lower = anchor.path.to_lowercase();
            let file_name = anchor_lower.rsplit('/').next().unwrap_or(&anchor_lower);
            if sig.mentioned_paths.iter().any(|p| {
                p == &anchor_lower
                    || p.ends_with(&format!("/{anchor_lower}"))
                    || p.ends_with(&format!("/{file_name}"))
                    || p == file_name
            }) {
                bonus += 150;
                matched_terms.insert(anchor.path.clone());
            }
        }

        if bonus > 0 {
            let entry = scores
                .entry(note.frontmatter.id.clone())
                .or_insert_with(|| (0, BTreeSet::new()));
            entry.0 = entry.0.saturating_add(bonus);
            entry.1.extend(matched_terms);
        }
    }

    // Rank deterministically: score DESC, id ASC.
    let mut ranked: Vec<(&MemoryNote, i64, Vec<String>)> = bugfixes
        .into_iter()
        .filter_map(|note| {
            let (score, terms) = scores.get(&note.frontmatter.id)?;
            // Require meaningful evidence (either FTS5 hit + matched term or high-confidence code/path).
            if *score < 60 && terms.is_empty() {
                return None;
            }
            Some((note, *score, terms.iter().cloned().collect()))
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.frontmatter.id.cmp(&b.0.frontmatter.id))
    });

    let effective_limit = if limit == 0 {
        DEFAULT_BUGFIX_MATCH_LIMIT
    } else {
        limit
    };

    let mut out = Vec::new();
    for (note, _score, matched_terms) in ranked.into_iter().take(effective_limit) {
        let verification = verify_note(project_root, note, resolver);
        let title_clean = redact_secrets(&note.frontmatter.title).text;
        out.push(BugfixMatch {
            id: note.frontmatter.id.clone(),
            title: title_clean,
            rel_path: note.rel_path.clone(),
            trust: verification.trust,
            is_stale: verification.trust == TrustLevel::Stale,
            matched_terms,
            stale_reasons: verification.stale_reasons,
        });
    }

    Ok(out)
}

#[derive(Debug, Default)]
struct ErrorSignature {
    error_codes: Vec<String>,
    fts_terms: Vec<String>,
    mentioned_paths: Vec<String>,
}

fn extract_error_signature(error_output: &str) -> ErrorSignature {
    let mut codes = BTreeSet::new();
    let mut terms = BTreeSet::new();
    let mut paths = BTreeSet::new();

    for line in error_output.lines().take(200) {
        for raw_tok in line.split_whitespace() {
            let clean = raw_tok.trim_matches(|c: char| {
                matches!(
                    c,
                    '(' | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | ','
                        | ';'
                        | '"'
                        | '\''
                        | '`'
                        | '<'
                        | '>'
                        | ':'
                )
            });
            if clean.is_empty() {
                continue;
            }

            // Detect normalized source file paths (e.g. `src/world/save.rs:42:5`).
            if let Some(norm_path) = extract_source_path(clean) {
                paths.insert(norm_path.to_lowercase());
            }

            // Detect compiler / OS / SQLite error codes (`E0382`, `TS2322`, `SQLITE_BUSY`, `EPERM`).
            if is_error_code_token(clean) {
                codes.insert(clean.to_string());
                continue;
            }

            // Split sub-tokens safely on punctuation while keeping UTF-8 letters/digits/underscores.
            let mut cur = String::new();
            for ch in clean.chars() {
                if ch.is_alphanumeric() || ch == '_' {
                    cur.push(ch);
                } else {
                    consider_error_term(&cur, &mut codes, &mut terms);
                    cur.clear();
                }
            }
            consider_error_term(&cur, &mut codes, &mut terms);
        }
    }

    ErrorSignature {
        error_codes: codes.into_iter().take(12).collect(),
        fts_terms: terms.into_iter().take(20).collect(),
        mentioned_paths: paths.into_iter().take(16).collect(),
    }
}

fn consider_error_term(tok: &str, codes: &mut BTreeSet<String>, terms: &mut BTreeSet<String>) {
    let trimmed = tok.trim_matches('_');
    if trimmed.is_empty() {
        return;
    }
    if is_error_code_token(trimmed) {
        codes.insert(trimmed.to_string());
        return;
    }
    let char_len = trimmed.chars().count();
    if !(4..=64).contains(&char_len) {
        return;
    }
    // Skip pure numbers (line numbers, exit codes, PIDs).
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return;
    }
    let lower = trimmed.to_lowercase();
    if ERROR_STOPWORDS.contains(&lower.as_str()) {
        return;
    }
    terms.insert(trimmed.to_string());
}

fn is_error_code_token(tok: &str) -> bool {
    let bytes = tok.as_bytes();
    if bytes.len() < 4 || bytes.len() > 32 || !bytes.is_ascii() {
        return false;
    }
    // Rust error codes: `E0382`
    if bytes[0] == b'E' && bytes.len() == 5 && bytes[1..].iter().all(u8::is_ascii_digit) {
        return true;
    }
    // TypeScript error codes: `TS2322`
    if tok.starts_with("TS") && bytes.len() >= 5 && bytes[2..].iter().all(u8::is_ascii_digit) {
        return true;
    }
    // Uppercase underscore error constants: `SQLITE_BUSY`, `CREATE_NO_WINDOW`, `ERR_CONNECTION_REFUSED`
    if tok.contains('_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        && bytes.iter().any(u8::is_ascii_uppercase)
    {
        return true;
    }
    // Standard POSIX/Windows errno tokens
    matches!(
        tok,
        "ENOENT" | "EACCES" | "EPERM" | "EADDRINUSE" | "ECONNREFUSED" | "ETIMEDOUT"
    )
}

fn extract_source_path(tok: &str) -> Option<String> {
    let normalized = tok.replace('\\', "/");
    // Peel trailing numeric `:line` / `:col` suffixes from the right so Windows drive
    // letters (`C:/repo/src/db.rs:14:5`) are never split at `C:`.
    let mut base = normalized.as_str();
    while let Some((prefix, suffix)) = base.rsplit_once(':') {
        if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
            base = prefix;
        } else {
            break;
        }
    }
    if base.ends_with(':') && base.len() > 2 {
        base = base.trim_end_matches(':');
    }
    let ext = base.rsplit('.').next()?;
    if matches!(
        ext,
        "rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "go" | "toml" | "json" | "md"
    ) && base.len() > ext.len() + 1
    {
        Some(base.trim_start_matches("./").to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_windows_drive_letter_and_relative_source_paths_with_line_col_suffixes() {
        assert_eq!(
            extract_source_path(r"C:\repo\src\db.rs:14:5").as_deref(),
            Some("C:/repo/src/db.rs")
        );
        assert_eq!(
            extract_source_path(r"D:\proj\crates\klens-memory\src\index.rs:240").as_deref(),
            Some("D:/proj/crates/klens-memory/src/index.rs")
        );
        assert_eq!(
            extract_source_path(r"C:\Users\dev\app\src\save.rs").as_deref(),
            Some("C:/Users/dev/app/src/save.rs")
        );
        assert_eq!(
            extract_source_path("./src/world/save.rs:42:9").as_deref(),
            Some("src/world/save.rs")
        );
        assert_eq!(extract_source_path("C:\\no_ext:14"), None);
    }
}
