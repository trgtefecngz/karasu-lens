//! BLAKE3 file/symbol anchor verification engine and standalone heuristic symbol resolver.
//!
//! Guarantees (Constitution Article 1 & Phase 4 spec):
//! - Every anchor hash uses `\r\n` -> `\n` normalization (`klens_core::hash`).
//! - Fresh notes carry `TrustLevel::VerifiedRaw`.
//! - Any changed hash, missing file, or deleted symbol immediately flags `TrustLevel::Stale`
//!   with explicit machine-readable `StaleReason` (`changed_hash`, `missing_file`, `missing_symbol`).

use std::fs;

use klens_core::{
    ProjectRoot, ProvenanceEnvelope, RelPath, TrustLevel, blake3_file, blake3_text,
    normalize_line_endings,
};

use crate::error::MemoryError;
use crate::markdown::parse_markdown_note;
use crate::types::{
    AnchorCheck, AnchorSpec, MEMORY_DIR_REL, MemoryAnchor, MemoryNote, MemoryStatus,
    MemoryVerifyPayload, NoteVerification, StaleNoteReport, StaleReason, SymbolLookupResult,
    SymbolResolver,
};

/// Compute a fresh [`MemoryAnchor`] by resolving the target path (and optional symbol)
/// inside `project_root` and hashing its LF-normalized contents with BLAKE3.
pub fn compute_anchor(
    project_root: &ProjectRoot,
    spec: &AnchorSpec,
    resolver: &mut dyn SymbolResolver,
) -> Result<MemoryAnchor, MemoryError> {
    let rel = RelPath::normalize(&spec.path)?;
    let (abs, canonical_rel) = project_root.resolve_existing(rel.as_str())?;

    if let Some(ref sym_query) = spec.symbol {
        match resolver.resolve_symbol(&canonical_rel, sym_query) {
            SymbolLookupResult::Found {
                qualified_name,
                source_snippet,
                ..
            } => Ok(MemoryAnchor {
                path: canonical_rel.as_str().to_string(),
                symbol: Some(qualified_name),
                blake3: blake3_text(&source_snippet),
            }),
            SymbolLookupResult::Ambiguous(candidates) => Err(MemoryError::AnchorResolveFailed {
                path: canonical_rel.as_str().to_string(),
                symbol: Some(sym_query.clone()),
                reason: format!(
                    "ambiguous symbol; specify one of: {}",
                    candidates.join(", ")
                ),
            }),
            SymbolLookupResult::Missing => Err(MemoryError::AnchorResolveFailed {
                path: canonical_rel.as_str().to_string(),
                symbol: Some(sym_query.clone()),
                reason: "symbol not found in file".to_string(),
            }),
            SymbolLookupResult::Unparsed(reason) => Err(MemoryError::AnchorResolveFailed {
                path: canonical_rel.as_str().to_string(),
                symbol: Some(sym_query.clone()),
                reason: format!("file could not be parsed: {reason}"),
            }),
        }
    } else {
        let digest = blake3_file(&abs).map_err(|source| MemoryError::Io { path: abs, source })?;
        Ok(MemoryAnchor {
            path: canonical_rel.as_str().to_string(),
            symbol: None,
            blake3: digest,
        })
    }
}

/// Verify a single persisted [`MemoryAnchor`] against the live workspace filesystem.
pub fn verify_anchor(
    project_root: &ProjectRoot,
    anchor: &MemoryAnchor,
    resolver: &mut dyn SymbolResolver,
) -> AnchorCheck {
    let expected = anchor
        .blake3
        .strip_prefix("blake3:")
        .unwrap_or(&anchor.blake3)
        .trim()
        .to_string();

    let rel = match RelPath::normalize(&anchor.path) {
        Ok(r) => r,
        Err(err) => {
            return AnchorCheck {
                path: anchor.path.clone(),
                symbol: anchor.symbol.clone(),
                expected_blake3: expected,
                actual_blake3: None,
                fresh: false,
                stale_reason: Some(StaleReason::InvalidAnchorPath),
                detail: Some(err.to_string()),
            };
        }
    };

    let (abs, canonical_rel) = match project_root.resolve_existing(rel.as_str()) {
        Ok(pair) => pair,
        Err(err) => {
            return AnchorCheck {
                path: rel.as_str().to_string(),
                symbol: anchor.symbol.clone(),
                expected_blake3: expected,
                actual_blake3: None,
                fresh: false,
                stale_reason: Some(StaleReason::MissingFile),
                detail: Some(format!("anchored file missing or inaccessible: {err}")),
            };
        }
    };

    if let Some(ref sym) = anchor.symbol {
        match resolver.resolve_symbol(&canonical_rel, sym) {
            SymbolLookupResult::Found { source_snippet, .. } => {
                let actual = blake3_text(&source_snippet);
                let fresh = actual.eq_ignore_ascii_case(&expected);
                AnchorCheck {
                    path: canonical_rel.as_str().to_string(),
                    symbol: Some(sym.clone()),
                    expected_blake3: expected,
                    actual_blake3: Some(actual),
                    fresh,
                    stale_reason: if fresh {
                        None
                    } else {
                        Some(StaleReason::ChangedHash)
                    },
                    detail: if fresh {
                        None
                    } else {
                        Some(format!(
                            "symbol `{sym}` in `{}` changed (BLAKE3 mismatch)",
                            canonical_rel.as_str()
                        ))
                    },
                }
            }
            SymbolLookupResult::Missing => AnchorCheck {
                path: canonical_rel.as_str().to_string(),
                symbol: Some(sym.clone()),
                expected_blake3: expected,
                actual_blake3: None,
                fresh: false,
                stale_reason: Some(StaleReason::MissingSymbol),
                detail: Some(format!(
                    "anchored symbol `{sym}` was deleted or renamed in `{}`",
                    canonical_rel.as_str()
                )),
            },
            SymbolLookupResult::Ambiguous(candidates) => AnchorCheck {
                path: canonical_rel.as_str().to_string(),
                symbol: Some(sym.clone()),
                expected_blake3: expected,
                actual_blake3: None,
                fresh: false,
                stale_reason: Some(StaleReason::AmbiguousSymbol),
                detail: Some(format!(
                    "anchored symbol `{sym}` is ambiguous in `{}` (candidates: {})",
                    canonical_rel.as_str(),
                    candidates.join(", ")
                )),
            },
            SymbolLookupResult::Unparsed(reason) => AnchorCheck {
                path: canonical_rel.as_str().to_string(),
                symbol: Some(sym.clone()),
                expected_blake3: expected,
                actual_blake3: None,
                fresh: false,
                stale_reason: Some(StaleReason::MissingSymbol),
                detail: Some(format!(
                    "anchored file `{}` could not be parsed for symbol `{sym}`: {reason}",
                    canonical_rel.as_str()
                )),
            },
        }
    } else {
        match blake3_file(&abs) {
            Ok(actual) => {
                let fresh = actual.eq_ignore_ascii_case(&expected);
                AnchorCheck {
                    path: canonical_rel.as_str().to_string(),
                    symbol: None,
                    expected_blake3: expected,
                    actual_blake3: Some(actual),
                    fresh,
                    stale_reason: if fresh {
                        None
                    } else {
                        Some(StaleReason::ChangedHash)
                    },
                    detail: if fresh {
                        None
                    } else {
                        Some(format!(
                            "file `{}` changed (BLAKE3 mismatch)",
                            canonical_rel.as_str()
                        ))
                    },
                }
            }
            Err(err) => AnchorCheck {
                path: canonical_rel.as_str().to_string(),
                symbol: None,
                expected_blake3: expected,
                actual_blake3: None,
                fresh: false,
                stale_reason: Some(StaleReason::MissingFile),
                detail: Some(format!(
                    "failed to read `{}`: {err}",
                    canonical_rel.as_str()
                )),
            },
        }
    }
}

/// Verify all anchors and frontmatter status of a single [`MemoryNote`].
pub fn verify_note(
    project_root: &ProjectRoot,
    note: &MemoryNote,
    resolver: &mut dyn SymbolResolver,
) -> NoteVerification {
    let mut anchor_checks = Vec::with_capacity(note.frontmatter.anchors.len());
    let mut stale_reasons = Vec::new();

    for anchor in &note.frontmatter.anchors {
        let check = verify_anchor(project_root, anchor, resolver);
        if !check.fresh {
            let reason_code = check.stale_reason.map_or("stale", StaleReason::as_str);
            let target = match &check.symbol {
                Some(sym) => format!("{}#{sym}", check.path),
                None => check.path.clone(),
            };
            stale_reasons.push(format!("{target}: {reason_code}"));
        }
        anchor_checks.push(check);
    }

    if note.frontmatter.status == MemoryStatus::Stale && stale_reasons.is_empty() {
        stale_reasons.push("frontmatter status is marked stale".to_string());
    }

    let fresh = stale_reasons.is_empty();
    let trust = if fresh {
        TrustLevel::VerifiedRaw
    } else {
        TrustLevel::Stale
    };

    NoteVerification {
        trust,
        fresh,
        anchor_checks,
        stale_reasons,
    }
}

/// Load all valid notes from `.klens/memory/*.md` in deterministic lexicographical order.
///
/// Malformed `.md` files are reported in the returned warnings vector instead of aborting
/// verification of healthy notes.
pub(crate) fn load_vault_notes(
    project_root: &ProjectRoot,
) -> Result<(Vec<MemoryNote>, Vec<String>), MemoryError> {
    let memory_dir = project_root.root().join(MEMORY_DIR_REL);
    if !memory_dir.is_dir() {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut file_names: Vec<String> = Vec::new();
    let read_dir = fs::read_dir(&memory_dir).map_err(|source| MemoryError::Io {
        path: memory_dir.clone(),
        source,
    })?;

    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
        {
            file_names.push(name.to_string());
        }
    }
    file_names.sort();

    let mut notes = Vec::new();
    let mut warnings = Vec::new();

    for name in file_names {
        let rel_str = format!("{MEMORY_DIR_REL}/{name}");
        let (abs, rel) = match project_root.resolve_existing(&rel_str) {
            Ok(pair) => pair,
            Err(err) => {
                warnings.push(format!("skipped `{rel_str}`: {err}"));
                continue;
            }
        };
        let raw = match fs::read_to_string(&abs) {
            Ok(text) => text,
            Err(err) => {
                warnings.push(format!("failed to read `{}`: {err}", rel.as_str()));
                continue;
            }
        };
        match parse_markdown_note(rel.as_str(), &raw) {
            Ok(note) => notes.push(note),
            Err(err) => warnings.push(err.to_string()),
        }
    }

    notes.sort_by(|a, b| {
        a.frontmatter
            .id
            .cmp(&b.frontmatter.id)
            .then_with(|| a.rel_path.cmp(&b.rel_path))
    });

    Ok((notes, warnings))
}

/// Verify every note under `.klens/memory/` against live workspace files and symbols.
pub fn verify_all_notes(
    project_root: &ProjectRoot,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryVerifyPayload>, MemoryError> {
    let (notes, warnings) = load_vault_notes(project_root)?;
    let mut stale_notes = Vec::new();
    let mut fresh_ids = Vec::new();

    for note in &notes {
        let verification = verify_note(project_root, note, resolver);
        if verification.fresh {
            fresh_ids.push(note.frontmatter.id.clone());
        } else {
            let stale_anchors = verification
                .anchor_checks
                .into_iter()
                .filter(|c| !c.fresh)
                .collect();
            stale_notes.push(StaleNoteReport {
                id: note.frontmatter.id.clone(),
                title: note.frontmatter.title.clone(),
                kind: note.frontmatter.kind,
                rel_path: note.rel_path.clone(),
                trust: TrustLevel::Stale,
                stale_anchors,
                stale_reasons: verification.stale_reasons,
            });
        }
    }

    let total_notes = notes.len();
    let stale_count = stale_notes.len();
    let fresh_count = fresh_ids.len();
    let trust = if stale_count > 0 {
        TrustLevel::Stale
    } else {
        TrustLevel::VerifiedRaw
    };

    let payload = MemoryVerifyPayload {
        total_notes,
        fresh_count,
        stale_count,
        stale_notes,
        fresh_ids,
    };

    let mut env = ProvenanceEnvelope::new(trust, project_root.project_id(), payload);
    for w in warnings {
        env = env.with_warning(w);
    }
    if stale_count > 0 {
        env = env.with_warning(format!(
            "{stale_count} of {total_notes} memory note(s) are STALE; review and run `klens memory refresh <id>`"
        ));
    }

    Ok(env)
}

// ---------------------------------------------------------------------------
// Standalone Pure-Rust Heuristic Symbol Resolver (zero `klens-code` dependency)
// ---------------------------------------------------------------------------

/// Lightweight pure-Rust [`SymbolResolver`] for standalone `klens-memory` callers and tests.
///
/// Higher layers (`klens-cli`, `klens-mcp`) pass a Tree-sitter AST resolver backed by `klens-code`.
pub struct HeuristicSymbolResolver<'a> {
    project_root: &'a ProjectRoot,
}

impl<'a> HeuristicSymbolResolver<'a> {
    pub fn new(project_root: &'a ProjectRoot) -> Self {
        Self { project_root }
    }
}

impl SymbolResolver for HeuristicSymbolResolver<'_> {
    fn resolve_symbol(&mut self, path: &RelPath, symbol: &str) -> SymbolLookupResult {
        let Ok((abs, _)) = self.project_root.resolve_existing(path.as_str()) else {
            return SymbolLookupResult::Missing;
        };
        let Ok(raw) = fs::read_to_string(&abs) else {
            return SymbolLookupResult::Missing;
        };
        let normalized = normalize_line_endings(&raw);
        let lines: Vec<&str> = normalized.lines().collect();
        if lines.is_empty() {
            return SymbolLookupResult::Missing;
        }

        let is_python = path.as_str().ends_with(".py");
        let query = symbol.trim();
        let symbols = scan_heuristic_symbols(&lines, is_python);

        let exact: Vec<&HeuristicSym> = symbols
            .iter()
            .filter(|s| s.qualified_name == query)
            .collect();
        let candidates = if !exact.is_empty() {
            exact
        } else {
            symbols.iter().filter(|s| s.short_name == query).collect()
        };

        match candidates.as_slice() {
            [] => SymbolLookupResult::Missing,
            [one] => {
                let snippet = lines[one.start_idx..=one.end_idx].join("\n");
                SymbolLookupResult::Found {
                    qualified_name: one.qualified_name.clone(),
                    source_snippet: snippet,
                    start_line: one.start_idx + 1,
                    end_line: one.end_idx + 1,
                }
            }
            many => SymbolLookupResult::Ambiguous(
                many.iter().map(|s| s.qualified_name.clone()).collect(),
            ),
        }
    }
}

struct HeuristicSym {
    short_name: String,
    qualified_name: String,
    start_idx: usize,
    end_idx: usize,
}

fn scan_heuristic_symbols(lines: &[&str], is_python: bool) -> Vec<HeuristicSym> {
    let mut out = Vec::new();
    let mut current_container: Option<(String, usize)> = None; // (label, end_idx)

    for (idx, &raw_line) in lines.iter().enumerate() {
        if let Some((_, end_i)) = &current_container
            && idx > *end_i
        {
            current_container = None;
        }

        let trimmed = raw_line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        if is_python {
            if let Some((kind_kw, name)) = parse_python_decl(trimmed) {
                let indent = leading_indent(raw_line);
                let end_idx = find_python_block_end(lines, idx, indent);
                let qualified_name = if let Some((ref parent, _)) = current_container
                    && indent > 0
                {
                    format!("{parent}.{name}")
                } else {
                    format!("{kind_kw} {name}")
                };
                if kind_kw == "class" && indent == 0 {
                    current_container = Some((format!("class {name}"), end_idx));
                }
                out.push(HeuristicSym {
                    short_name: name,
                    qualified_name,
                    start_idx: idx,
                    end_idx,
                });
            }
            continue;
        }

        // Brace-delimited languages (Rust, TS/JS, Go).
        if let Some(impl_header) = parse_rust_impl_header(trimmed) {
            let end_idx = find_brace_block_end(lines, idx);
            current_container = Some((impl_header, end_idx));
            continue;
        }
        if let Some((kind_kw, name)) = parse_brace_decl(trimmed) {
            let end_idx = find_brace_block_end(lines, idx);
            let qualified_name = if let Some((ref parent, _)) = current_container {
                if parent.starts_with("impl ") || parent.starts_with("trait ") {
                    format!("{parent}::{name}")
                } else {
                    format!("{parent}.{name}")
                }
            } else {
                format!("{kind_kw} {name}")
            };
            if matches!(kind_kw, "trait" | "class") && current_container.is_none() {
                current_container = Some((format!("{kind_kw} {name}"), end_idx));
            }
            out.push(HeuristicSym {
                short_name: name,
                qualified_name,
                start_idx: idx,
                end_idx,
            });
        }
    }

    out
}

fn parse_python_decl(trimmed: &str) -> Option<(&'static str, String)> {
    if let Some(rest) = trimmed.strip_prefix("async def ") {
        return extract_ident(rest).map(|n| ("async def", n));
    }
    if let Some(rest) = trimmed.strip_prefix("def ") {
        return extract_ident(rest).map(|n| ("def", n));
    }
    if let Some(rest) = trimmed.strip_prefix("class ") {
        return extract_ident(rest).map(|n| ("class", n));
    }
    None
}

fn parse_rust_impl_header(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("impl")?.trim_start();
    if rest.is_empty() || !trimmed.contains('{') {
        return None;
    }
    let before_brace = rest.split('{').next()?.trim();
    if before_brace.is_empty() {
        return None;
    }
    Some(format!("impl {before_brace}"))
}

fn parse_brace_decl(trimmed: &str) -> Option<(&'static str, String)> {
    // Strip common visibility / async / export prefixes safely.
    let mut s = trimmed;
    loop {
        let next = s
            .strip_prefix("pub(crate) ")
            .or_else(|| s.strip_prefix("pub(super) "))
            .or_else(|| s.strip_prefix("pub "))
            .or_else(|| s.strip_prefix("export default "))
            .or_else(|| s.strip_prefix("export "))
            .or_else(|| s.strip_prefix("async "))
            .or_else(|| s.strip_prefix("unsafe "))
            .or_else(|| s.strip_prefix("const "))
            .map(str::trim_start);
        match next {
            Some(stripped) => s = stripped,
            None => break,
        }
    }

    for (prefix, kw) in [
        ("fn ", "fn"),
        ("function ", "function"),
        ("func ", "func"),
        ("struct ", "struct"),
        ("enum ", "enum"),
        ("trait ", "trait"),
        ("class ", "class"),
        ("interface ", "interface"),
        ("macro_rules! ", "macro_rules!"),
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            // Go receiver method: `func (w *World) Save(...)`
            if kw == "func" && rest.trim_start().starts_with('(') {
                if let Some(close_paren) = rest.find(')') {
                    let after_recv = rest[close_paren + 1..].trim_start();
                    if let Some(name) = extract_ident(after_recv) {
                        return Some(("func", name));
                    }
                }
                return None;
            }
            if let Some(name) = extract_ident(rest) {
                return Some((kw, name));
            }
        }
    }
    None
}

fn extract_ident(s: &str) -> Option<String> {
    let trimmed = s.trim_start();
    let ident: String = trimmed
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() { None } else { Some(ident) }
}

fn find_brace_block_end(lines: &[&str], start_idx: usize) -> usize {
    let mut depth: i32 = 0;
    let mut saw_brace = false;
    for (i, line) in lines.iter().enumerate().skip(start_idx) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                saw_brace = true;
            } else if ch == '}' {
                depth -= 1;
                if saw_brace && depth <= 0 {
                    return i;
                }
            }
        }
        if !saw_brace && line.trim_end().ends_with(';') {
            return i;
        }
    }
    start_idx
}

fn leading_indent(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

fn find_python_block_end(lines: &[&str], start_idx: usize, base_indent: usize) -> usize {
    let mut end = start_idx;
    for (i, line) in lines.iter().enumerate().skip(start_idx + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if leading_indent(line) <= base_indent {
            break;
        }
        end = i;
    }
    end
}
