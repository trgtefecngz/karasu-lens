//! Opt-in context bundle (`include: ["imports", "memory", "impact"]`) for surgical `klens_read`.
//!
//! Crate DAG lock: `klens-code` never depends on `klens-memory`. This leaf module owns the
//! language-aware import extractor, bounded impact collector, shared plain-data structs,
//! UTF-8 safe secret-redacted snippet sanitizer, and deterministic text formatter; higher
//! layers (`klens-mcp`, `klens-cli`) populate `ReadContextBundle::memory` via `klens-memory`.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use klens_core::{
    EdgeConfidence, Omission, OmissionKind, RelPath, TrustLevel, normalize_line_endings,
    redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::error::CodeError;
use crate::impact::{ImpactHit, ImpactStatus, analyze_impact};
use crate::index::{CodeIndex, is_binary_bytes};

/// Maximum number of top-of-file import lines returned in a `ReadImportsContext`.
pub const MAX_CONTEXT_IMPORT_LINES: usize = 40;

/// Maximum number of callers/dependents returned in a `ReadImpactContext`.
pub const MAX_CONTEXT_IMPACT_HITS: usize = 10;

/// Maximum number of linked memory notes returned in a `ReadContextBundle`.
pub const MAX_CONTEXT_MEMORY_NOTES: usize = 10;

/// Maximum UTF-8 character length of a single memory note snippet in a `ReadContextBundle`.
pub const MAX_CONTEXT_MEMORY_SNIPPET_CHARS: usize = 280;

const OTHER_LANG_SCAN_LIMIT: usize = 200;

/// Opt-in context section requested via `klens_read(include: [...])` or `klens read --include`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadInclude {
    Imports,
    Memory,
    Impact,
}

impl ReadInclude {
    /// Fail-closed parser for `imports`, `memory`, or `impact`.
    pub fn parse(input: &str) -> Result<Self, CodeError> {
        match input.trim().to_ascii_lowercase().as_str() {
            "imports" => Ok(Self::Imports),
            "memory" => Ok(Self::Memory),
            "impact" => Ok(Self::Impact),
            other => Err(CodeError::InvalidReadInclude(other.to_string())),
        }
    }

    /// Canonical lowercase identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Imports => "imports",
            Self::Memory => "memory",
            Self::Impact => "impact",
        }
    }
}

/// Top-of-file language-aware import lines attached to a surgical read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadImportsContext {
    pub lines: Vec<String>,
    pub total_import_lines: usize,
    pub truncated: bool,
}

/// Compact BLAKE3-verified memory note linked to the read file/symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMemoryNote {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub trust: TrustLevel,
    pub is_stale: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_reasons: Vec<String>,
    pub snippet: String,
}

/// Bounded blast-radius impact hits attached to a surgical read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadImpactContext {
    pub target: String,
    pub total_hits: usize,
    pub hits: Vec<ImpactHit>,
    pub truncated: bool,
}

/// Optional context bundle attached to a `ReadStatus::Ok` read result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadContextBundle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<ReadImportsContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory: Vec<ReadMemoryNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_omitted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<ReadImpactContext>,
}

impl ReadContextBundle {
    /// Returns `true` when no context sections are populated.
    pub fn is_empty(&self) -> bool {
        self.imports.is_none()
            && self.memory.is_empty()
            && self.memory_omitted.is_none()
            && self.impact.is_none()
    }
}

/// Result of extracting top-of-file imports with provenance counts and optional omission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedImports {
    pub context: ReadImportsContext,
    pub redactions_count: usize,
    pub omission: Option<Omission>,
}

/// Result of collecting bounded impact context with provenance counts and optional omission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedImpact {
    pub context: ReadImpactContext,
    pub redactions_count: usize,
    pub omission: Option<Omission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportLanguage {
    Rust,
    TsJs,
    Python,
    Go,
    Other,
}

fn detect_import_language(rel_path: &str) -> ImportLanguage {
    let ext = Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("rs") => ImportLanguage::Rust,
        Some("ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs") => ImportLanguage::TsJs,
        Some("py" | "pyi") => ImportLanguage::Python,
        Some("go") => ImportLanguage::Go,
        _ => ImportLanguage::Other,
    }
}

/// Extract language-aware top-of-file import lines from a confined project file.
pub fn extract_file_imports(
    index: &CodeIndex,
    rel: &RelPath,
) -> Result<ExtractedImports, CodeError> {
    let (abs_path, canonical_rel) = index.project_root().resolve_existing_with_extra(
        rel.as_str(),
        &index.project_config().extra_sensitive_patterns,
    )?;
    let meta = fs::metadata(&abs_path).map_err(|source| CodeError::Io {
        path: abs_path.clone(),
        source,
    })?;
    if !meta.is_file() {
        return Err(CodeError::NotAFile(canonical_rel.as_str().to_string()));
    }
    crate::read::ensure_readable_size(canonical_rel.as_str(), meta.len())?;
    let bytes = fs::read(&abs_path).map_err(|source| CodeError::Io {
        path: abs_path.clone(),
        source,
    })?;
    if is_binary_bytes(&bytes) {
        return Err(CodeError::BinaryFile(abs_path.display().to_string()));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CodeError::BinaryFile(abs_path.display().to_string()))?;
    Ok(extract_imports_from_source(canonical_rel.as_str(), text))
}

/// Pure language-aware top-of-file import extractor operating on normalized source text.
pub fn extract_imports_from_source(rel_path: &str, source: &str) -> ExtractedImports {
    let normalized = normalize_line_endings(source);
    let raw_lines: Vec<&str> = normalized.lines().collect();
    let collected: Vec<(usize, &str)> = match detect_import_language(rel_path) {
        ImportLanguage::Rust => extract_rust_imports(&raw_lines),
        ImportLanguage::TsJs => extract_ts_js_imports(&raw_lines),
        ImportLanguage::Python => extract_python_imports(&raw_lines),
        ImportLanguage::Go => extract_go_imports(&raw_lines),
        ImportLanguage::Other => extract_other_imports(&raw_lines),
    };

    let total_import_lines = collected.len();
    let truncated = total_import_lines > MAX_CONTEXT_IMPORT_LINES;
    let omission = truncated.then(|| {
        let omitted = &collected[MAX_CONTEXT_IMPORT_LINES..];
        Omission {
            kind: OmissionKind::Lines,
            path: Some(rel_path.to_string()),
            start_line: omitted.first().map(|(n, _)| *n),
            end_line: omitted.last().map(|(n, _)| *n),
            count: omitted.len(),
            reason: "read_context_imports_limit".to_string(),
        }
    });

    let mut redactions_count = 0usize;
    let mut lines = Vec::with_capacity(total_import_lines.min(MAX_CONTEXT_IMPORT_LINES));
    for (line_no, raw_line) in collected.into_iter().take(MAX_CONTEXT_IMPORT_LINES) {
        let redacted = redact_secrets(raw_line);
        redactions_count += redacted.redactions_count;
        lines.push(format!("L{line_no}| {}", redacted.text));
    }

    ExtractedImports {
        context: ReadImportsContext {
            lines,
            total_import_lines,
            truncated,
        },
        redactions_count,
        omission,
    }
}

fn strip_line_comment<'a>(line: &'a str, marker: &str) -> &'a str {
    let mbytes = marker.as_bytes();
    let bytes = line.as_bytes();
    let (mut in_double, mut in_single, mut escaped, mut i) = (false, false, false, 0usize);
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
        } else if b == b'\\' && (in_double || in_single) {
            escaped = true;
        } else if b == b'"' && !in_single {
            in_double = !in_double;
        } else if b == b'\'' && !in_double {
            in_single = !in_single;
        } else if !in_double && !in_single && bytes[i..].starts_with(mbytes) {
            return &line[..i];
        }
        i += 1;
    }
    line
}

fn scan_c_block_and_braces(line: &str, in_block: &mut bool, depth: &mut usize) {
    let bytes = line.as_bytes();
    let (mut i, mut in_double, mut escaped) = (0usize, false, false);
    while i < bytes.len() {
        if *in_block {
            if bytes[i..].starts_with(b"*/") {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        let b = bytes[i];
        if escaped {
            escaped = false;
        } else if b == b'\\' && in_double {
            escaped = true;
        } else if b == b'"' {
            in_double = !in_double;
        } else if !in_double {
            if bytes[i..].starts_with(b"//") {
                break;
            }
            if bytes[i..].starts_with(b"/*") {
                *in_block = true;
                i += 2;
                continue;
            }
            if b == b'{' {
                *depth = depth.saturating_add(1);
            } else if b == b'}' {
                *depth = depth.saturating_sub(1);
            }
        }
        i += 1;
    }
}

fn is_indented(line: &str) -> bool {
    line.starts_with(' ') || line.starts_with('\t')
}

fn is_rust_import_start(trimmed: &str) -> bool {
    if trimmed.starts_with("use ")
        || trimmed.starts_with("pub use ")
        || trimmed.starts_with("extern crate ")
        || trimmed.starts_with("pub extern crate ")
    {
        return true;
    }
    if let Some(after_pub) = trimmed.strip_prefix("pub(")
        && let Some(close_idx) = after_pub.find(')')
    {
        let rest = after_pub[close_idx + 1..].trim_start();
        return rest.starts_with("use ") || rest.starts_with("extern crate ");
    }
    false
}

fn extract_rust_imports<'a>(lines: &[&'a str]) -> Vec<(usize, &'a str)> {
    let (mut out, mut in_multi, mut in_block, mut depth) = (Vec::new(), false, false, 0usize);
    for (idx, &line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        if in_multi {
            out.push((line_no, line));
            if strip_line_comment(line, "//").contains(';') {
                in_multi = false;
            }
            continue;
        }
        if !in_block && depth == 0 && !is_indented(line) {
            let trimmed = line.trim();
            if trimmed.starts_with("#[cfg(test)]") {
                break;
            }
            if is_rust_import_start(trimmed) {
                out.push((line_no, line));
                if !strip_line_comment(trimmed, "//").contains(';') {
                    in_multi = true;
                }
                continue;
            }
        }
        scan_c_block_and_braces(line, &mut in_block, &mut depth);
    }
    out
}

fn ts_has_from(code: &str) -> bool {
    [" from '", " from \"", "}from '", "}from \""]
        .iter()
        .any(|pat| code.contains(pat))
        || code.starts_with("from '")
        || code.starts_with("from \"")
}

fn ts_multiline_export_has_from(lines: &[&str], start_idx: usize) -> bool {
    for &line in lines.iter().skip(start_idx + 1).take(60) {
        let code = strip_line_comment(line, "//").trim();
        if ts_has_from(code) {
            return true;
        }
        if code.contains('}') {
            return false;
        }
    }
    false
}

fn extract_ts_js_imports<'a>(lines: &[&'a str]) -> Vec<(usize, &'a str)> {
    let (mut out, mut in_multi, mut in_block, mut depth, mut top) =
        (Vec::new(), false, false, 0usize, true);
    for (idx, &line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        if in_multi {
            out.push((line_no, line));
            let code = strip_line_comment(line, "//").trim();
            if ts_has_from(code) || (!code.contains('{') && code.ends_with(';')) {
                in_multi = false;
            }
            continue;
        }
        let trimmed = line.trim();
        if in_block
            || trimmed.is_empty()
            || trimmed.starts_with("//")
            || matches!(
                trimmed,
                "\"use strict\";"
                    | "'use strict';"
                    | "\"use client\";"
                    | "'use client';"
                    | "\"use server\";"
                    | "'use server';"
            )
        {
            if in_block {
                scan_c_block_and_braces(line, &mut in_block, &mut depth);
            }
            continue;
        }
        if trimmed.starts_with("/*") {
            scan_c_block_and_braces(line, &mut in_block, &mut depth);
            continue;
        }
        if depth == 0 && !is_indented(line) {
            let code = strip_line_comment(trimmed, "//").trim();
            if ["import ", "import{", "import\"", "import'"]
                .iter()
                .any(|p| code.starts_with(p))
            {
                out.push((line_no, line));
                let has_quote = code.contains('\'') || code.contains('"');
                let done = ts_has_from(code)
                    || (has_quote && !code.contains('{'))
                    || (code.contains("= require(") && code.ends_with(';'));
                in_multi = !done;
                continue;
            }
            if code.starts_with("export ") {
                if ts_has_from(code) {
                    out.push((line_no, line));
                    continue;
                }
                let brace_exp = (code.starts_with("export {") || code.starts_with("export type {"))
                    && !code.contains('}');
                if brace_exp && ts_multiline_export_has_from(lines, idx) {
                    out.push((line_no, line));
                    in_multi = true;
                    continue;
                }
            }
            let is_req = (code.starts_with("const ")
                || code.starts_with("let ")
                || code.starts_with("var "))
                && code.contains("require(");
            if top && is_req {
                out.push((line_no, line));
                continue;
            }
            top = false;
        }
        scan_c_block_and_braces(line, &mut in_block, &mut depth);
    }
    out
}

fn paren_delta(code: &str) -> isize {
    code.chars().fold(0isize, |acc, c| match c {
        '(' => acc + 1,
        ')' => acc - 1,
        _ => acc,
    })
}

fn extract_python_imports<'a>(lines: &[&'a str]) -> Vec<(usize, &'a str)> {
    let (mut out, mut in_multi, mut parens, mut docstring) =
        (Vec::new(), false, 0isize, None::<&'static str>);
    for (idx, &line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if let Some(delim) = docstring {
            if trimmed.contains(delim) {
                docstring = None;
            }
            continue;
        }
        if in_multi {
            out.push((line_no, line));
            let code = strip_line_comment(line, "#");
            parens += paren_delta(code);
            if parens <= 0 && !code.trim_end().ends_with('\\') {
                parens = 0;
                in_multi = false;
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || is_indented(line) {
            continue;
        }
        if let Some(delim) = ["\"\"\"", "'''"]
            .into_iter()
            .find(|d| trimmed.starts_with(d))
        {
            if !trimmed[delim.len()..].contains(delim) {
                docstring = Some(delim);
            }
            continue;
        }
        if ["def ", "async def ", "class ", "if __name__"]
            .iter()
            .any(|p| trimmed.starts_with(p))
        {
            break;
        }
        if trimmed.starts_with("import ")
            || (trimmed.starts_with("from ") && trimmed.contains(" import "))
        {
            out.push((line_no, line));
            let code = strip_line_comment(trimmed, "#");
            parens = paren_delta(code);
            in_multi = parens > 0 || code.trim_end().ends_with('\\');
        }
    }
    out
}

fn extract_go_imports<'a>(lines: &[&'a str]) -> Vec<(usize, &'a str)> {
    let (mut out, mut in_imp, mut in_block, mut dummy) = (Vec::new(), false, false, 0usize);
    for (idx, &line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        if in_imp {
            out.push((line_no, line));
            if strip_line_comment(line, "//").trim().starts_with(')') {
                in_imp = false;
            }
            continue;
        }
        let trimmed = line.trim();
        if in_block || trimmed.starts_with("/*") {
            scan_c_block_and_braces(line, &mut in_block, &mut dummy);
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") || is_indented(line) {
            continue;
        }
        if ["func ", "type ", "var ", "const "]
            .iter()
            .any(|p| trimmed.starts_with(p))
        {
            break;
        }
        let code = strip_line_comment(trimmed, "//").trim();
        if code.starts_with("import (") || code.starts_with("import(") {
            out.push((line_no, line));
            in_imp = !code.contains(')');
        } else if code.starts_with("import ") || code.starts_with("import\"") {
            out.push((line_no, line));
        }
    }
    out
}

fn extract_other_imports<'a>(lines: &[&'a str]) -> Vec<(usize, &'a str)> {
    const PREFIXES: &[&str] = &[
        "import ",
        "#include ",
        "#include\"",
        "#include<",
        "using ",
        "use ",
        "require ",
        "require(",
        "require_relative",
        "require_once",
    ];
    lines
        .iter()
        .take(OTHER_LANG_SCAN_LIMIT)
        .enumerate()
        .filter_map(|(idx, &line)| {
            if is_indented(line) {
                return None;
            }
            let trimmed = line.trim();
            let matched = PREFIXES.iter().any(|p| trimmed.starts_with(p))
                || (trimmed.starts_with("from ") && trimmed.contains(" import "));
            matched.then_some((idx + 1, line))
        })
        .collect()
}

/// Collect bounded blast-radius impact context for a file path (and optional qualified symbol).
pub fn collect_read_impact(
    index: &mut CodeIndex,
    path: &str,
    qualified_name: Option<&str>,
) -> Result<CollectedImpact, CodeError> {
    let primary_target = match qualified_name.map(str::trim).filter(|s| !s.is_empty()) {
        Some(qname) => format!("{path}#{qname}"),
        None => path.to_string(),
    };
    let mut env = analyze_impact(index, &primary_target)?;
    let mut effective_target = primary_target;
    if qualified_name.is_some() && env.data.status != ImpactStatus::Ok {
        effective_target = path.to_string();
        env = analyze_impact(index, &effective_target)?;
    }

    let total_hits = env.data.hits.len();
    let truncated = total_hits > MAX_CONTEXT_IMPACT_HITS;
    let hits: Vec<ImpactHit> = env
        .data
        .hits
        .into_iter()
        .take(MAX_CONTEXT_IMPACT_HITS)
        .collect();
    let omission = truncated.then(|| Omission {
        kind: OmissionKind::Items,
        path: Some(effective_target.clone()),
        start_line: None,
        end_line: None,
        count: total_hits - MAX_CONTEXT_IMPACT_HITS,
        reason: "read_context_impact_limit".to_string(),
    });

    Ok(CollectedImpact {
        context: ReadImpactContext {
            target: effective_target,
            total_hits,
            hits,
            truncated,
        },
        redactions_count: env.redactions_count,
        omission,
    })
}

/// Populate `imports` and/or `impact` into a [`ReadContextBundle`] for a single file/symbol target.
pub(crate) fn populate_code_context_bundle(
    index: &mut CodeIndex,
    path: &str,
    qualified_name: Option<&str>,
    existing: Option<ReadContextBundle>,
    want_imports: bool,
    want_impact: bool,
    omissions: &mut Vec<Omission>,
) -> Result<(Option<ReadContextBundle>, usize), CodeError> {
    if !want_imports && !want_impact {
        return Ok((existing, 0));
    }
    let mut bundle = existing.unwrap_or_default();
    let mut redactions = 0usize;

    if want_imports {
        let rel = RelPath::normalize(path)?;
        let extracted = extract_file_imports(index, &rel)?;
        redactions += extracted.redactions_count;
        if let Some(om) = extracted.omission {
            omissions.push(om);
        }
        bundle.imports = Some(extracted.context);
    }

    if want_impact {
        let collected = collect_read_impact(index, path, qualified_name)?;
        redactions += collected.redactions_count;
        if let Some(om) = collected.omission {
            omissions.push(om);
        }
        bundle.impact = Some(collected.context);
    }

    let out = (!bundle.is_empty()).then_some(bundle);
    Ok((out, redactions))
}

/// Redact secrets and truncate a memory note body into a UTF-8 char-safe snippet
/// (`<= MAX_CONTEXT_MEMORY_SNIPPET_CHARS` characters).
pub fn sanitize_memory_snippet(raw_body: &str) -> (String, usize) {
    let normalized = normalize_line_endings(raw_body);
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    let redacted = redact_secrets(&collapsed);
    let snippet = if redacted.text.chars().count() <= MAX_CONTEXT_MEMORY_SNIPPET_CHARS {
        redacted.text
    } else {
        let mut cut: String = redacted
            .text
            .chars()
            .take(MAX_CONTEXT_MEMORY_SNIPPET_CHARS.saturating_sub(1))
            .collect();
        cut.push('…');
        cut
    };
    (snippet, redacted.redactions_count)
}

const fn confidence_label(confidence: EdgeConfidence) -> &'static str {
    match confidence {
        EdgeConfidence::Extracted => "EXTRACTED",
        EdgeConfidence::Inferred => "INFERRED",
        EdgeConfidence::Ambiguous => "AMBIGUOUS",
        EdgeConfidence::VerifiedLsp => "VERIFIED_LSP",
    }
}

/// Render a [`ReadContextBundle`] into compact, deterministic plain text.
pub fn format_read_context_text(bundle: &ReadContextBundle) -> String {
    let mut out = String::new();

    if let Some(imports) = &bundle.imports {
        let trunc = if imports.truncated { ", truncated" } else { "" };
        let _ = writeln!(
            out,
            "\n## Context: Imports ({}/{}{trunc})",
            imports.lines.len(),
            imports.total_import_lines
        );
        if imports.lines.is_empty() {
            let _ = writeln!(out, "  (none)");
        } else {
            for line in &imports.lines {
                let _ = writeln!(out, "  {line}");
            }
        }
    }

    if !bundle.memory.is_empty() || bundle.memory_omitted.is_some() {
        let shown = bundle.memory.len();
        let total = shown + bundle.memory_omitted.unwrap_or(0);
        let _ = writeln!(out, "\n## Context: Linked Memory ({shown}/{total})");
        for note in &bundle.memory {
            let freshness = if note.is_stale { "STALE" } else { "FRESH" };
            let _ = writeln!(
                out,
                "  - [{}] {} ({}) [{}]",
                note.kind, note.title, note.id, freshness
            );
            if !note.stale_reasons.is_empty() {
                let _ = writeln!(out, "    stale: {}", note.stale_reasons.join("; "));
            }
            if !note.snippet.is_empty() {
                let _ = writeln!(out, "    {}", note.snippet);
            }
        }
        if let Some(omitted) = bundle.memory_omitted
            && omitted > 0
        {
            let _ = writeln!(out, "  ... ({omitted} more linked memory note(s) omitted)");
        }
    }

    if let Some(impact) = &bundle.impact {
        let trunc = if impact.truncated { ", truncated" } else { "" };
        let _ = writeln!(
            out,
            "\n## Context: Impact ({}/{}{trunc}) [{}]",
            impact.hits.len(),
            impact.total_hits,
            impact.target
        );
        if impact.hits.is_empty() {
            let _ = writeln!(out, "  (none)");
        } else {
            for hit in &impact.hits {
                let loc = match hit.line {
                    Some(l) => format!("{}:L{l}", hit.path),
                    None => hit.path.clone(),
                };
                let scope = hit
                    .enclosing_symbol
                    .as_deref()
                    .map(|s| format!(" in `{s}`"))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "  - [d={} | {}] {loc}{scope} — {}",
                    hit.distance,
                    confidence_label(hit.confidence),
                    hit.evidence
                );
            }
        }
    }

    out
}
