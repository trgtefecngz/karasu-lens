use std::collections::{BTreeMap, BTreeSet};

use klens_core::{CodeEdge, EdgeConfidence, EdgeRelation, SymbolInfo, SymbolKind};

use crate::store::{FtsFileHit, IndexedFileRecord, ParseStatus};

/// Maximum targets an ambiguous identifier may match to be included in global graph edges.
const MAX_GLOBAL_AMBIGUOUS_TARGETS: usize = 4;

/// Maximum inferred/ambiguous symbol edges emitted per source file to keep global graphs crisp.
const MAX_INFERRED_EDGES_PER_FILE: usize = 120;

#[derive(Debug, Clone)]
struct GlobalSymbolRef {
    file_path: String,
    qualified_name: String,
    kind: SymbolKind,
}

/// Extract deterministic `INFERRED` and `AMBIGUOUS` symbol call/reference edges without LSP.
pub(crate) fn extract_inferred_symbol_edges(
    files: &[IndexedFileRecord],
    file_records: &BTreeMap<String, &IndexedFileRecord>,
    symbols_by_file: &BTreeMap<String, Vec<SymbolInfo>>,
    fts_rows: &[FtsFileHit],
    file_imports_map: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<CodeEdge> {
    let mut code_files: BTreeSet<String> = BTreeSet::new();
    for rec in files {
        if rec.parse_status != ParseStatus::Fallback
            && is_programming_language(rec.language_id.as_deref())
        {
            code_files.insert(rec.path.as_str().to_string());
        }
    }

    let mut defs_by_name: BTreeMap<String, Vec<GlobalSymbolRef>> = BTreeMap::new();
    for (file_path, syms) in symbols_by_file {
        if !code_files.contains(file_path) {
            continue;
        }
        for sym in syms {
            if matches!(sym.kind, SymbolKind::Module | SymbolKind::Other)
                || !is_indexable_ident_for_graph(&sym.name)
            {
                continue;
            }
            defs_by_name
                .entry(sym.name.clone())
                .or_default()
                .push(GlobalSymbolRef {
                    file_path: file_path.clone(),
                    qualified_name: sym.qualified_name.clone(),
                    kind: sym.kind,
                });
        }
    }

    defs_by_name.retain(|_, defs| {
        let unique_files: BTreeSet<&str> = defs.iter().map(|d| d.file_path.as_str()).collect();
        unique_files.len() <= 6
    });

    if defs_by_name.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for fts in fts_rows {
        let from_path = fts.path.as_str();
        if !code_files.contains(from_path) || fts.content.is_empty() {
            continue;
        }

        let hash_is_comment = file_records
            .get(from_path)
            .and_then(|r| r.language_id.as_deref())
            == Some("python");
        let imported_files = file_imports_map.get(from_path);
        let file_syms = symbols_by_file
            .get(from_path)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut emitted_for_file = 0usize;
        let mut seen_pair: BTreeSet<(String, String, EdgeRelation)> = BTreeSet::new();

        for (line_idx, raw_line) in fts.content.lines().enumerate() {
            if emitted_for_file >= MAX_INFERRED_EDGES_PER_FILE {
                break;
            }
            let line_no = line_idx + 1;
            let trimmed = raw_line.trim_start();
            if trimmed.starts_with("//")
                || (hash_is_comment && trimmed.starts_with('#'))
                || trimmed.starts_with("use ")
                || trimmed.starts_with("import ")
                || trimmed.starts_with("from ")
            {
                continue;
            }

            let tokens = scan_code_identifiers(raw_line, hash_is_comment);
            for (ident, is_call, is_member_access) in tokens {
                if emitted_for_file >= MAX_INFERRED_EDGES_PER_FILE {
                    break;
                }
                let Some(all_defs) = defs_by_name.get(ident) else {
                    continue;
                };

                let external_defs: Vec<&GlobalSymbolRef> = all_defs
                    .iter()
                    .filter(|d| {
                        d.file_path != from_path
                            && (!is_member_access || d.kind == SymbolKind::Method)
                    })
                    .collect();
                if external_defs.is_empty() {
                    continue;
                }

                let narrowed: Vec<&GlobalSymbolRef> = if let Some(imports) = imported_files {
                    let in_imports: Vec<&GlobalSymbolRef> = external_defs
                        .iter()
                        .copied()
                        .filter(|d| imports.contains(&d.file_path))
                        .collect();
                    if in_imports.is_empty() {
                        external_defs
                    } else {
                        in_imports
                    }
                } else {
                    external_defs
                };

                let (confidence, targets, note) = if narrowed.len() == 1 {
                    (
                        EdgeConfidence::Inferred,
                        narrowed,
                        "identifier match without LSP",
                    )
                } else if narrowed.len() <= MAX_GLOBAL_AMBIGUOUS_TARGETS {
                    (
                        EdgeConfidence::Ambiguous,
                        narrowed,
                        "ambiguous identifier match without LSP",
                    )
                } else {
                    continue;
                };

                let from_node = enclosing_symbol_for_line(file_syms, line_no)
                    .map(|s| format!("sym:{from_path}#{}", s.qualified_name))
                    .unwrap_or_else(|| format!("file:{from_path}"));
                let relation = if is_call {
                    EdgeRelation::Calls
                } else {
                    EdgeRelation::References
                };

                for target in targets {
                    let to_node = format!("sym:{}#{}", target.file_path, target.qualified_name);
                    let key = (from_node.clone(), to_node.clone(), relation);
                    if !seen_pair.insert(key) {
                        continue;
                    }
                    out.push(CodeEdge {
                        from: from_node.clone(),
                        to: to_node,
                        relation,
                        confidence,
                        evidence: format!("{from_path}:L{line_no} ({note})"),
                    });
                    emitted_for_file += 1;
                    if emitted_for_file >= MAX_INFERRED_EDGES_PER_FILE {
                        break;
                    }
                }
            }
        }
    }

    out
}

/// Find the innermost symbol covering 1-based `line_no`.
pub(crate) fn enclosing_symbol_for_line(
    symbols: &[SymbolInfo],
    line_no: usize,
) -> Option<&SymbolInfo> {
    symbols
        .iter()
        .filter(|s| s.start_line <= line_no && line_no <= s.end_line)
        .min_by_key(|s| (s.end_line.saturating_sub(s.start_line), s.start_line))
}

/// Lightweight lexical scanner yielding `(identifier, followed_by_call_paren, preceded_by_dot)`
/// tuples on one line, skipping string literals, Rust raw strings (`r#"..."#`), and
/// language-appropriate single-line comments (`//`, plus `#` only when `hash_is_comment` is true).
pub(crate) fn scan_code_identifiers(line: &str, hash_is_comment: bool) -> Vec<(&str, bool, bool)> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut out = Vec::new();
    let mut in_quote: Option<u8> = None;

    while i < len {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' && i + 1 < len {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }

        // Trailing single-line comments (`//` always; `#` only for Python).
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            break;
        }
        if hash_is_comment && b == b'#' {
            break;
        }

        // Rust raw strings (`r"..."`, `r#"..."#`, `br#"..."#`, `cr#"..."#`).
        if !hash_is_comment && let Some(after_raw) = skip_rust_raw_string(bytes, i) {
            i = after_raw;
            continue;
        }

        if b == b'"' || b == b'\'' || b == b'`' {
            // Avoid treating Rust lifetime `'a` as a string literal.
            if b == b'\''
                && i + 1 < len
                && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_')
                && bytes.get(i + 2).copied() != Some(b'\'')
            {
                i += 1;
                continue;
            }
            in_quote = Some(b);
            i += 1;
            continue;
        }

        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            let mut prev = start;
            // Treat TypeScript `this.#private` as member access as well.
            if !hash_is_comment && prev > 0 && bytes[prev - 1] == b'#' {
                prev -= 1;
            }
            while prev > 0 && (bytes[prev - 1] == b' ' || bytes[prev - 1] == b'\t') {
                prev -= 1;
            }
            let is_member_access = prev > 0 && bytes[prev - 1] == b'.';

            i += 1;
            while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let ident = &line[start..i];
            let mut look = i;
            while look < len && (bytes[look] == b' ' || bytes[look] == b'\t') {
                look += 1;
            }
            let is_call = look < len
                && (bytes[look] == b'('
                    || (bytes[look] == b'!' && bytes.get(look + 1) == Some(&b'(')));
            out.push((ident, is_call, is_member_access));
            continue;
        }

        i += 1;
    }

    out
}

/// If `bytes[start..]` begins a Rust raw string (`r"..."`, `r#"..."#`, `br#"..."#`, `cr#"..."#`),
/// return the byte index immediately after its closing delimiter (or `bytes.len()` if unclosed on this line).
fn skip_rust_raw_string(bytes: &[u8], start: usize) -> Option<usize> {
    if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        return None;
    }
    let len = bytes.len();
    let mut pos = if bytes[start] == b'r' {
        start + 1
    } else if (bytes[start] == b'b' || bytes[start] == b'c')
        && start + 1 < len
        && bytes[start + 1] == b'r'
    {
        start + 2
    } else {
        return None;
    };

    let mut hashes = 0usize;
    while pos < len && bytes[pos] == b'#' {
        hashes += 1;
        pos += 1;
    }
    if pos >= len || bytes[pos] != b'"' {
        return None;
    }
    pos += 1;

    while pos < len {
        if bytes[pos] == b'"' {
            let mut matched = 0usize;
            while matched < hashes && pos + 1 + matched < len && bytes[pos + 1 + matched] == b'#' {
                matched += 1;
            }
            if matched == hashes {
                return Some(pos + 1 + hashes);
            }
        }
        pos += 1;
    }

    Some(len)
}

fn is_programming_language(lang: Option<&str>) -> bool {
    matches!(lang, Some("rust" | "typescript" | "python" | "go"))
}

fn is_indexable_ident_for_graph(name: &str) -> bool {
    if name.len() < 3 {
        return false;
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    !matches!(
        name,
        "new"
            | "default"
            | "from"
            | "into"
            | "clone"
            | "fmt"
            | "drop"
            | "len"
            | "is_empty"
            | "get"
            | "set"
            | "run"
            | "main"
            | "test"
            | "tests"
            | "init"
            | "open"
            | "close"
            | "read"
            | "write"
            | "save"
            | "load"
            | "parse"
            | "build"
            | "index"
            | "error"
            | "Error"
            | "Result"
            | "Option"
            | "String"
            | "Vec"
            | "Self"
            | "self"
            | "super"
            | "crate"
            | "None"
            | "Some"
            | "true"
            | "false"
            | "as_str"
            | "to_string"
            | "value"
            | "name"
            | "path"
            | "data"
            | "config"
            | "Config"
            | "Mode"
            | "Status"
            | "Props"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_code_identifiers_preserves_rust_raw_string_and_ts_private_while_respecting_python_hash()
    {
        // Rust raw string containing `#` and quotes MUST NOT truncate calls after `"#`.
        let rust_line = r##"let _s = r#"hello "world" # not a comment"#; after_raw_call();"##;
        let rust_tokens = scan_code_identifiers(rust_line, false);
        assert!(
            rust_tokens
                .iter()
                .any(|&(id, is_call, _)| id == "after_raw_call" && is_call),
            "expected after_raw_call() after Rust raw string, got: {rust_tokens:?}"
        );
        assert!(
            !rust_tokens.iter().any(|&(id, _, _)| id == "hello"),
            "text inside Rust raw string must be skipped: {rust_tokens:?}"
        );

        // TypeScript `#private` field access MUST NOT be truncated at `#`.
        let ts_line = "return this.#secretHelper() + afterHash();";
        let ts_tokens = scan_code_identifiers(ts_line, false);
        assert!(
            ts_tokens
                .iter()
                .any(|&(id, is_call, is_member)| id == "secretHelper" && is_call && is_member),
            "expected TS #secretHelper() as member call, got: {ts_tokens:?}"
        );
        assert!(
            ts_tokens
                .iter()
                .any(|&(id, is_call, _)| id == "afterHash" && is_call),
            "expected afterHash() in TS line, got: {ts_tokens:?}"
        );

        // Python `#` MUST still act as a single-line comment.
        let py_line = "real_call() # commented_call()";
        let py_tokens = scan_code_identifiers(py_line, true);
        assert!(
            py_tokens
                .iter()
                .any(|&(id, is_call, _)| id == "real_call" && is_call)
        );
        assert!(!py_tokens.iter().any(|&(id, _, _)| id == "commented_call"));
    }
}
