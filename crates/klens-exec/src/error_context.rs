//! Automatic error source-code context extraction (`auto_context`) for failing `klens run` calls.
//!
//! Constitutional guarantees:
//! - Crate DAG lock: depends strictly on `klens-core` (never `klens-code` or `klens-memory`).
//!   Enclosing AST symbol names are attached via [`enrich_error_context_symbols`] from higher layers.
//! - Zero-leak security gate: EVERY extracted `path:line` candidate MUST pass through
//!   [`ProjectRoot::resolve_existing_with_extra`] with `.klens/config.toml`
//!   `extra_sensitive_patterns` plus `credentials.json`. Escaping paths, symlinks outside root,
//!   sensitive files, binary files, and invalid UTF-8 are silently skipped.
//! - Output gate redaction: every extracted snippet runs through [`klens_core::redact_secrets`]
//!   and reports its exact redaction count.
//! - Article 2 (No Silent Truncation): bounded strictly to [`MAX_ERROR_CONTEXT_LOCATIONS`] (3)
//!   and [`MAX_ERROR_CONTEXT_TOKENS`] (400), emitting explicit [`Omission`] records whenever
//!   valid in-project locations are skipped due to slot or token limits.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use klens_core::{
    Omission, ProjectConfig, ProjectRoot, RelPath, TokenBudget, estimate_tokens,
    normalize_line_endings, redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::ansi::strip_ansi;

/// Maximum number of distinct source locations attached automatically on a failing run.
pub const MAX_ERROR_CONTEXT_LOCATIONS: usize = 3;

/// Hard token budget across all automatically attached error source snippets.
pub const MAX_ERROR_CONTEXT_TOKENS: usize = 400;

/// Default line radius around each error line (`±5` lines -> at most 11 lines per location).
pub const ERROR_CONTEXT_RADIUS_LINES: usize = 5;

/// Upper bound on file size (4 MiB) read for automatic error context extraction.
const MAX_CONTEXT_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Additional sensitive filename always blocked by `auto_context` alongside `klens-core` defaults.
const EXTRA_BUILTIN_SENSITIVE: &[&str] = &["credentials.json"];

/// Fallback radius progression attempted when the full `±5` window exceeds remaining token budget.
const RADIUS_FALLBACKS: &[usize] = &[ERROR_CONTEXT_RADIUS_LINES, 2, 1, 0];

/// A single confined, secret-redacted source-code window attached to a failing `klens_run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorSourceContext {
    /// Canonical project-relative forward-slash path.
    pub path: String,
    /// 1-based error line reported by the tool/compiler.
    pub line: usize,
    /// 1-based inclusive start line of [`Self::snippet`].
    pub start_line: usize,
    /// 1-based inclusive end line of [`Self::snippet`].
    pub end_line: usize,
    /// Optional enclosing AST symbol name populated by higher layers (`klens-mcp` / `klens-cli`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Line-numbered, secret-redacted source snippet (`  L<n>| ` / `> L<n>| `).
    pub snippet: String,
}

/// Output of [`collect_error_contexts`] including redaction counts and explicit omissions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorContextResult {
    pub contexts: Vec<ErrorSourceContext>,
    pub redactions_count: usize,
    pub omissions: Vec<Omission>,
}

/// Extract `(raw_path, line)` candidates from terminal error output in deterministic
/// first-appearance order across Rust/Cargo, Go, GCC/Clang, ESLint, Vitest/Jest,
/// TypeScript (`tsc`), and Python (`pytest` / traceback) formats.
///
/// ANSI escape sequences are stripped defensively before scanning.
pub fn extract_error_locations(output: &str) -> Vec<(String, usize)> {
    let cleaned = strip_ansi(output);
    let mut locations: Vec<(String, usize)> = Vec::new();
    let mut seen_raw: BTreeSet<(String, usize)> = BTreeSet::new();

    for line in cleaned.lines() {
        let mut line_hits: Vec<(usize, String, usize)> = Vec::new();
        scan_python_traceback_line(line, &mut line_hits);
        scan_tsc_parens_line(line, &mut line_hits);
        scan_colon_locations_line(line, &mut line_hits);

        line_hits.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });

        for (_, raw_path, line_no) in line_hits {
            let key = (raw_path.clone(), line_no);
            if seen_raw.insert(key) {
                locations.push((raw_path, line_no));
            }
        }
    }

    locations
}

/// Extract confined, secret-redacted source-code windows for up to
/// [`MAX_ERROR_CONTEXT_LOCATIONS`] error locations within [`MAX_ERROR_CONTEXT_TOKENS`].
///
/// Loads `.klens/config.toml` `extra_sensitive_patterns` (falling back to defaults if absent)
/// and enforces [`ProjectRoot::resolve_existing_with_extra`] on every single candidate.
pub fn collect_error_contexts(project_root: &ProjectRoot, output: &str) -> ErrorContextResult {
    let cfg_path = project_root.root().join(".klens").join("config.toml");
    let project_config = ProjectConfig::load_or_default(&cfg_path).unwrap_or_default();

    let mut effective_extra = project_config.extra_sensitive_patterns;
    for builtin in EXTRA_BUILTIN_SENSITIVE {
        if !effective_extra
            .iter()
            .any(|p| p.eq_ignore_ascii_case(builtin))
        {
            effective_extra.push((*builtin).to_string());
        }
    }

    let raw_locations = extract_error_locations(output);
    if raw_locations.is_empty() {
        return ErrorContextResult::default();
    }

    let mut file_cache: BTreeMap<RelPath, Option<Vec<String>>> = BTreeMap::new();
    let mut seen_canonical: BTreeSet<(RelPath, usize)> = BTreeSet::new();
    let mut budget = TokenBudget::new(MAX_ERROR_CONTEXT_TOKENS);
    let mut contexts: Vec<ErrorSourceContext> = Vec::new();
    let mut redactions_count = 0usize;
    let mut omitted_by_limit = 0usize;
    let mut omitted_by_budget = 0usize;

    for (raw_path, line) in raw_locations {
        if line == 0 {
            continue;
        }
        let Some(rel_candidate) = normalize_candidate_to_rel_path(project_root, &raw_path) else {
            continue;
        };
        let Ok((abs_path, canonical_rel)) =
            project_root.resolve_existing_with_extra(&rel_candidate, &effective_extra)
        else {
            continue;
        };

        if !seen_canonical.insert((canonical_rel.clone(), line)) {
            continue;
        }

        let lines_opt = file_cache
            .entry(canonical_rel.clone())
            .or_insert_with(|| read_utf8_source_lines(&abs_path));
        let Some(lines) = lines_opt.as_deref() else {
            continue;
        };
        if lines.is_empty() || line > lines.len() {
            continue;
        }

        // Deduplicate: if an already-captured window for this file already covers `line`,
        // do not consume another slot or emit a false omission.
        if contexts.iter().any(|existing| {
            existing.path == canonical_rel.as_str()
                && existing.start_line <= line
                && line <= existing.end_line
        }) {
            continue;
        }

        if contexts.len() >= MAX_ERROR_CONTEXT_LOCATIONS {
            omitted_by_limit += 1;
            continue;
        }

        let mut fitted = None;
        for &radius in RADIUS_FALLBACKS {
            let start_line = line.saturating_sub(radius).max(1);
            let end_line = line.saturating_add(radius).min(lines.len());
            let raw_snippet = render_snippet_window(lines, line, start_line, end_line);
            let redacted = redact_secrets(&raw_snippet);
            let snippet_tokens = estimate_tokens(&redacted.text);
            if budget.can_fit(snippet_tokens) {
                let _ = budget.try_consume(snippet_tokens);
                fitted = Some((
                    start_line,
                    end_line,
                    redacted.text,
                    redacted.redactions_count,
                ));
                break;
            }
        }

        if let Some((start_line, end_line, snippet, redactions)) = fitted {
            redactions_count += redactions;
            contexts.push(ErrorSourceContext {
                path: canonical_rel.as_str().to_string(),
                line,
                start_line,
                end_line,
                symbol: None,
                snippet,
            });
        } else {
            omitted_by_budget += 1;
        }
    }

    let mut omissions = Vec::new();
    if omitted_by_limit > 0 {
        omissions.push(Omission::items(omitted_by_limit, "error_context_limit"));
    }
    if omitted_by_budget > 0 {
        omissions.push(Omission::items(
            omitted_by_budget,
            "error_context_budget_exceeded",
        ));
    }

    ErrorContextResult {
        contexts,
        redactions_count,
        omissions,
    }
}

/// Populate [`ErrorSourceContext::symbol`] using a caller-supplied enclosing-symbol resolver
/// (keeps `klens-exec` decoupled from `klens-code`).
pub fn enrich_error_context_symbols<F>(contexts: &mut [ErrorSourceContext], mut resolve_symbol: F)
where
    F: FnMut(&RelPath, usize) -> Option<String>,
{
    for ctx in contexts {
        if let Ok(rel) = RelPath::normalize(&ctx.path) {
            ctx.symbol = resolve_symbol(&rel, ctx.line);
        }
    }
}

/// Format automatically extracted error contexts into a compact `## Error Context` block.
pub fn format_error_contexts_text(contexts: &[ErrorSourceContext]) -> String {
    if contexts.is_empty() {
        return String::new();
    }

    let mut out = String::from("## Error Context");
    for ctx in contexts {
        let _ = write!(out, "\n### {}:{}", ctx.path, ctx.line);
        if let Some(sym) = &ctx.symbol {
            let _ = write!(out, " ({sym})");
        }
        let _ = write!(
            out,
            " [L{}-L{}]\n{}",
            ctx.start_line, ctx.end_line, ctx.snippet
        );
    }
    out
}

fn render_snippet_window(
    lines: &[String],
    error_line: usize,
    start_line: usize,
    end_line: usize,
) -> String {
    let mut out = String::new();
    for line_no in start_line..=end_line {
        if line_no > start_line {
            out.push('\n');
        }
        let text = &lines[line_no - 1];
        if line_no == error_line {
            let _ = write!(out, "> L{line_no}| {text}");
        } else {
            let _ = write!(out, "  L{line_no}| {text}");
        }
    }
    out
}

fn read_utf8_source_lines(abs_path: &Path) -> Option<Vec<String>> {
    let meta = fs::metadata(abs_path).ok()?;
    if !meta.is_file() || meta.len() > MAX_CONTEXT_FILE_BYTES {
        return None;
    }
    let bytes = fs::read(abs_path).ok()?;
    let sample_len = bytes.len().min(8192);
    if bytes[..sample_len].contains(&0) {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    let normalized = normalize_line_endings(text);
    Some(normalized.lines().map(str::to_string).collect())
}

fn normalize_candidate_to_rel_path(project_root: &ProjectRoot, raw_path: &str) -> Option<String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return None;
    }

    let is_abs =
        trimmed.starts_with('/') || trimmed.starts_with('\\') || has_windows_drive_prefix(trimmed);
    if !is_abs {
        return Some(trimmed.to_string());
    }

    // Reject explicit parent-traversal segments in absolute paths before touching the filesystem.
    if trimmed.split(['/', '\\']).any(|seg| seg == "..") {
        return None;
    }

    let root_str = project_root.root().to_string_lossy();
    let root_norm = strip_win_verbatim(&root_str)
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string();
    let cand_norm = strip_win_verbatim(trimmed).replace('\\', "/");

    if let Some(rel) = strip_root_prefix(&cand_norm, &root_norm) {
        return Some(rel.to_string());
    }

    // Fallback for symlinked temp directories (e.g. macOS `/var` -> `/private/var`)
    // or Windows 8.3 short paths: canonicalize and verify containment under `project_root.root()`.
    let canon = fs::canonicalize(Path::new(trimmed)).ok()?;
    let stripped = canon.strip_prefix(project_root.root()).ok()?;
    let rel = RelPath::from_relative_path(stripped).ok()?;
    Some(rel.as_str().to_string())
}

fn strip_win_verbatim(s: &str) -> &str {
    s.strip_prefix(r"\\?\")
        .or_else(|| s.strip_prefix("//?/"))
        .unwrap_or(s)
}

fn strip_root_prefix<'a>(cand_norm: &'a str, root_norm: &str) -> Option<&'a str> {
    if root_norm.is_empty() || cand_norm.len() <= root_norm.len() {
        return None;
    }
    if cand_norm.as_bytes().get(root_norm.len()) != Some(&b'/') {
        return None;
    }
    let prefix = &cand_norm[..root_norm.len()];
    let matches = {
        #[cfg(windows)]
        {
            prefix.eq_ignore_ascii_case(root_norm)
        }
        #[cfg(not(windows))]
        {
            prefix == root_norm
        }
    };
    if matches {
        let rest = &cand_norm[root_norm.len() + 1..];
        if !rest.is_empty() {
            return Some(rest);
        }
    }
    None
}

fn has_windows_drive_prefix(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn scan_python_traceback_line(line: &str, out: &mut Vec<(usize, String, usize)>) {
    let mut search_from = 0usize;
    while let Some(rel_pos) = line[search_from..].find("File ") {
        let pos = search_from + rel_pos;
        let after_file = pos + "File ".len();
        search_from = after_file;

        let Some(&quote_byte) = line.as_bytes().get(after_file) else {
            break;
        };
        if quote_byte != b'"' && quote_byte != b'\'' {
            continue;
        }
        let quote_char = quote_byte as char;
        let path_start = after_file + 1;
        let Some(rel_end) = line[path_start..].find(quote_char) else {
            continue;
        };
        let path_end = path_start + rel_end;
        let raw_path = &line[path_start..path_end];

        let rest = line[path_end + 1..].trim_start();
        let rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
        let Some(after_line_kw) = rest.strip_prefix("line ") else {
            continue;
        };
        let after_line_kw = after_line_kw.trim_start();
        let digit_len = after_line_kw.bytes().take_while(u8::is_ascii_digit).count();
        if digit_len == 0 {
            continue;
        }
        if let Ok(line_no) = after_line_kw[..digit_len].parse::<usize>()
            && line_no >= 1
            && looks_like_file_path(raw_path)
        {
            out.push((pos, raw_path.to_string(), line_no));
        }
    }
}

fn scan_tsc_parens_line(line: &str, out: &mut Vec<(usize, String, usize)>) {
    let bytes = line.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b != b'(' || idx == 0 {
            continue;
        }
        let rest = &line[idx + 1..];
        let line_digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if line_digits == 0 {
            continue;
        }
        let after_line = rest[line_digits..].trim_start();
        let Some(after_comma) = after_line.strip_prefix(',') else {
            continue;
        };
        let after_comma = after_comma.trim_start();
        let col_digits = after_comma.bytes().take_while(u8::is_ascii_digit).count();
        if col_digits == 0 {
            continue;
        }
        if !after_comma[col_digits..].starts_with(')') {
            continue;
        }
        let Ok(line_no) = rest[..line_digits].parse::<usize>() else {
            continue;
        };
        if line_no == 0 {
            continue;
        }
        if let Some((start, raw_path)) = extract_path_before(line, idx)
            && looks_like_file_path(raw_path)
        {
            out.push((start, raw_path.to_string(), line_no));
        }
    }
}

fn scan_colon_locations_line(line: &str, out: &mut Vec<(usize, String, usize)>) {
    let bytes = line.as_bytes();
    let len = bytes.len();

    for idx in 1..len {
        if bytes[idx] != b':' {
            continue;
        }
        let digits_start = idx + 1;
        if digits_start >= len || !bytes[digits_start].is_ascii_digit() {
            continue;
        }
        let digit_len = bytes[digits_start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        let digits_end = digits_start + digit_len;
        if digits_end < len && !is_after_line_delim(bytes[digits_end]) {
            continue;
        }

        // Skip the `:col` colon in `path:line:col` because the first colon already captured `path:line`.
        if preceded_by_colon_digits(&line[..idx]) {
            continue;
        }

        let Ok(line_no) = line[digits_start..digits_end].parse::<usize>() else {
            continue;
        };
        if line_no == 0 || line_no > 10_000_000 {
            continue;
        }

        if let Some((start, raw_path)) = extract_path_before(line, idx)
            && looks_like_file_path(raw_path)
        {
            out.push((start, raw_path.to_string(), line_no));
        }
    }
}

fn is_after_line_delim(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b':' | b')' | b']' | b'>' | b',' | b';' | b'"' | b'\'' | b'`'
        )
}

fn preceded_by_colon_digits(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    let mut i = bytes.len();
    while i > 0 && bytes[i - 1].is_ascii_digit() {
        i -= 1;
    }
    i < bytes.len() && i > 0 && bytes[i - 1] == b':'
}

fn extract_path_before(line: &str, end_idx: usize) -> Option<(usize, &str)> {
    let prefix = &line[..end_idx];
    if prefix.is_empty() {
        return None;
    }

    // Case 1: Quoted path immediately before `:` or `(` (e.g. `"src/lib.rs":42`).
    let last = *prefix.as_bytes().last()?;
    if last == b'"' || last == b'\'' {
        let quote_char = last as char;
        let inner = &prefix[..prefix.len() - 1];
        let open = inner.rfind(quote_char)?;
        let candidate = &inner[open + 1..];
        if !candidate.is_empty() {
            return Some((open + 1, candidate));
        }
        return None;
    }

    // Case 2: Windows absolute path (including paths with spaces such as `C:\My Proj\src\lib.rs`).
    if let Some((start, candidate)) = extract_windows_abs_path_before(prefix) {
        return Some((start, candidate));
    }

    // Case 3: Standard delimiter/whitespace-bounded path token.
    let mut start = end_idx;
    for (i, ch) in prefix.char_indices().rev() {
        if ch.is_whitespace() || is_path_token_stop(ch) {
            break;
        }
        start = i;
    }
    let candidate = &line[start..end_idx];
    if candidate.is_empty() {
        None
    } else {
        Some((start, candidate))
    }
}

fn extract_windows_abs_path_before(prefix: &str) -> Option<(usize, &str)> {
    let mut stop = prefix.len();
    for (i, ch) in prefix.char_indices().rev() {
        if is_windows_path_stop(ch) {
            break;
        }
        stop = i;
    }
    let window = &prefix[stop..];
    let wb = window.as_bytes();
    if wb.len() < 4 {
        return None;
    }

    // Walk right-to-left to find the nearest drive root (`X:\` or `X:/`) at a token boundary.
    for i in (0..=wb.len() - 3).rev() {
        if wb[i].is_ascii_alphabetic()
            && wb[i + 1] == b':'
            && (wb[i + 2] == b'\\' || wb[i + 2] == b'/')
        {
            if i >= 4 && (&wb[i - 4..i] == br"\\?\" || &wb[i - 4..i] == b"//?/") {
                let abs_start = stop + i - 4;
                if abs_start == stop || prefix.as_bytes()[abs_start - 1].is_ascii_whitespace() {
                    return Some((abs_start, &prefix[abs_start..]));
                }
            } else if i == 0 || wb[i - 1].is_ascii_whitespace() {
                let abs_start = stop + i;
                return Some((abs_start, &prefix[abs_start..]));
            }
        }
    }

    None
}

fn is_path_token_stop(ch: char) -> bool {
    matches!(
        ch,
        '(' | ')' | '[' | ']' | '<' | '>' | '"' | '\'' | '`' | ',' | ';'
    )
}

fn is_windows_path_stop(ch: char) -> bool {
    matches!(
        ch,
        '(' | ')'
            | '['
            | ']'
            | '<'
            | '>'
            | '"'
            | '\''
            | '`'
            | ','
            | ';'
            | '|'
            | '*'
            | '\r'
            | '\n'
            | '\t'
    )
}

fn looks_like_file_path(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 512 {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    for scheme in ["http://", "https://", "ftp://", "ws://", "wss://"] {
        if lower.starts_with(scheme) {
            return false;
        }
    }
    if trimmed.ends_with(':') || trimmed.ends_with('/') || trimmed.ends_with('\\') {
        return false;
    }
    // Reject pure numeric strings like IP addresses (`127.0.0.1`) or versions (`1.2.3`).
    if trimmed.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }
    trimmed.contains('.')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.eq_ignore_ascii_case("id_rsa")
}
