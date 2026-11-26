use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;

use klens_core::{
    EdgeConfidence, EdgeRelation, ProvenanceEnvelope, RelPath, SymbolInfo, SymbolKind, TrustLevel,
    redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::error::CodeError;
use crate::graph::{
    CodeGraph, build_code_graph, edge_owner_file, enclosing_symbol_for_line, scan_code_identifiers,
};
use crate::index::CodeIndex;
use crate::store::IndexedSymbolRow;

/// Status of an impact analysis request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImpactStatus {
    Ok,
    AmbiguousTarget,
    NotFound,
}

/// Kind of resolved target for impact analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactTargetKind {
    File,
    Symbol,
}

/// Disambiguation candidate returned on `AMBIGUOUS_TARGET` (Constitution Article 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactCandidate {
    pub kind: ImpactTargetKind,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_kind: Option<SymbolKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A single impacted location with explicit Graphify confidence and evidence line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactHit {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub relation: EdgeRelation,
    pub confidence: EdgeConfidence,
    /// `1` = direct dependent, `2+` = transitive dependent along import chain.
    pub distance: usize,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// Complete blast-radius impact payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactPayload {
    pub status: ImpactStatus,
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<ImpactTargetKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_symbol: Option<String>,
    pub affected_files_count: usize,
    pub hits: Vec<ImpactHit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ImpactCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Compute the deterministic blast radius for a file path or symbol target.
pub fn analyze_impact(
    index: &mut CodeIndex,
    target_query: &str,
) -> Result<ProvenanceEnvelope<ImpactPayload>, CodeError> {
    let graph_env = build_code_graph(index)?;
    let graph = graph_env.data;
    let project_id = index.project_root().project_id().to_string();
    let query = target_query.trim();

    if query.is_empty() {
        return Ok(ProvenanceEnvelope::new(
            TrustLevel::VerifiedAst,
            project_id,
            ImpactPayload {
                status: ImpactStatus::NotFound,
                query: String::new(),
                target_kind: None,
                target_path: None,
                target_symbol: None,
                affected_files_count: 0,
                hits: Vec::new(),
                candidates: Vec::new(),
                message: Some("empty impact target".to_string()),
            },
        ));
    }

    let all_symbols = index.store().list_all_symbols()?;
    let file_set: BTreeSet<&str> = graph.nodes.iter().map(|n| n.path.as_str()).collect();

    // 1. Check `<file>#<symbol>` explicit format first.
    if let Some((raw_file, raw_sym)) = query.split_once('#')
        && !raw_file.trim().is_empty()
        && !raw_sym.trim().is_empty()
    {
        let norm_file = raw_file.trim().trim_start_matches("file:");
        if let Ok(rel) = RelPath::normalize(norm_file)
            && file_set.contains(rel.as_str())
        {
            let file_syms: Vec<&IndexedSymbolRow> =
                all_symbols.iter().filter(|r| r.file_path == rel).collect();
            let matched = resolve_symbol_rows(&file_syms, raw_sym.trim());
            return finish_symbol_impact(index, &graph, &all_symbols, query, matched, project_id);
        }
    }

    // 2. Check exact file path (`src/a.rs` or `file:src/a.rs`).
    let stripped_file = query.strip_prefix("file:").unwrap_or(query);
    if let Ok(rel) = RelPath::normalize(stripped_file)
        && file_set.contains(rel.as_str())
    {
        return compute_file_impact(&graph, rel.as_str(), query, project_id);
    }

    // 3. Check symbol matches across the full untruncated workspace symbol table.
    let all_sym_refs: Vec<&IndexedSymbolRow> = all_symbols.iter().collect();
    let sym_matches = resolve_symbol_rows(&all_sym_refs, query);
    if !sym_matches.is_empty() {
        return finish_symbol_impact(index, &graph, &all_symbols, query, sym_matches, project_id);
    }

    // 4. Fallback: file suffix / basename match (e.g. `save.rs`), failing closed on ambiguity.
    let suffix = format!("/{stripped_file}");
    let matching_files: Vec<&str> = file_set
        .iter()
        .copied()
        .filter(|p| *p == stripped_file || p.ends_with(&suffix))
        .collect();
    if matching_files.len() == 1 {
        return compute_file_impact(&graph, matching_files[0], query, project_id);
    }
    if matching_files.len() > 1 {
        let candidates = matching_files
            .into_iter()
            .map(|p| ImpactCandidate {
                kind: ImpactTargetKind::File,
                path: p.to_string(),
                qualified_name: None,
                symbol_kind: None,
                start_line: None,
                end_line: None,
                signature: None,
            })
            .collect();
        return Ok(ProvenanceEnvelope::new(
            TrustLevel::VerifiedAst,
            project_id,
            ImpactPayload {
                status: ImpactStatus::AmbiguousTarget,
                query: query.to_string(),
                target_kind: Some(ImpactTargetKind::File),
                target_path: None,
                target_symbol: None,
                affected_files_count: 0,
                hits: Vec::new(),
                candidates,
                message: Some(format!(
                    "ambiguous file target `{query}`; pass a full normalized relative path"
                )),
            },
        ));
    }

    Ok(ProvenanceEnvelope::new(
        TrustLevel::VerifiedAst,
        project_id,
        ImpactPayload {
            status: ImpactStatus::NotFound,
            query: query.to_string(),
            target_kind: None,
            target_path: None,
            target_symbol: None,
            affected_files_count: 0,
            hits: Vec::new(),
            candidates: Vec::new(),
            message: Some(format!("no indexed file or symbol matched `{query}`")),
        },
    ))
}

/// Compute direct + transitive dependents of a set of files using an already-built [`CodeGraph`].
pub(crate) fn compute_direct_and_transitive_file_hits(
    graph: &CodeGraph,
    target_file: &str,
) -> Vec<ImpactHit> {
    let target_file_id = format!("file:{target_file}");
    let target_sym_prefix = format!("sym:{target_file}#");
    let mut hits = Vec::new();
    let mut direct_files: BTreeSet<String> = BTreeSet::new();

    for edge in &graph.edges {
        let targets_this = edge.to == target_file_id || edge.to.starts_with(&target_sym_prefix);
        if !targets_this {
            continue;
        }
        let Some(from_file) = edge_owner_file(&edge.from) else {
            continue;
        };
        if from_file == target_file {
            continue;
        }
        let enclosing = edge
            .from
            .strip_prefix("sym:")
            .and_then(|rest| rest.split_once('#').map(|(_, s)| s.to_string()));
        let line = parse_evidence_line(&edge.evidence);
        direct_files.insert(from_file.to_string());
        hits.push(ImpactHit {
            path: from_file.to_string(),
            enclosing_symbol: enclosing,
            line,
            relation: edge.relation,
            confidence: edge.confidence,
            distance: 1,
            evidence: edge.evidence.clone(),
            snippet: None,
        });
    }

    // Walk reverse `EXTRACTED` file import edges for transitive blast radius (distance >= 2).
    let rev_imports = build_reverse_extracted_imports(graph);
    append_transitive_dependents(&rev_imports, target_file, &direct_files, &mut hits);

    dedup_and_sort_hits(hits)
}

fn compute_file_impact(
    graph: &CodeGraph,
    target_file: &str,
    query: &str,
    project_id: String,
) -> Result<ProvenanceEnvelope<ImpactPayload>, CodeError> {
    let hits = compute_direct_and_transitive_file_hits(graph, target_file);
    let affected_files_count = hits
        .iter()
        .map(|h| h.path.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let has_non_extracted = hits
        .iter()
        .any(|h| h.confidence != EdgeConfidence::Extracted);
    let trust = if has_non_extracted {
        TrustLevel::Inferred
    } else {
        TrustLevel::VerifiedAst
    };

    let payload = ImpactPayload {
        status: ImpactStatus::Ok,
        query: query.to_string(),
        target_kind: Some(ImpactTargetKind::File),
        target_path: Some(target_file.to_string()),
        target_symbol: None,
        affected_files_count,
        hits,
        candidates: Vec::new(),
        message: None,
    };

    let mut env = ProvenanceEnvelope::new(trust, project_id, payload);
    if has_non_extracted {
        env = env.with_warning(
            "some impact entries use INFERRED/AMBIGUOUS identifier matching without LSP",
        );
    }
    Ok(env)
}

fn finish_symbol_impact(
    index: &CodeIndex,
    graph: &CodeGraph,
    all_symbols: &[IndexedSymbolRow],
    query: &str,
    matches: Vec<&IndexedSymbolRow>,
    project_id: String,
) -> Result<ProvenanceEnvelope<ImpactPayload>, CodeError> {
    if matches.is_empty() {
        return Ok(ProvenanceEnvelope::new(
            TrustLevel::VerifiedAst,
            project_id,
            ImpactPayload {
                status: ImpactStatus::NotFound,
                query: query.to_string(),
                target_kind: Some(ImpactTargetKind::Symbol),
                target_path: None,
                target_symbol: None,
                affected_files_count: 0,
                hits: Vec::new(),
                candidates: Vec::new(),
                message: Some(format!("symbol `{query}` not found")),
            },
        ));
    }

    if matches.len() > 1 {
        let mut redactions = 0usize;
        let candidates: Vec<ImpactCandidate> = matches
            .into_iter()
            .map(|row| {
                let red = redact_secrets(&row.symbol.signature);
                redactions += red.redactions_count;
                ImpactCandidate {
                    kind: ImpactTargetKind::Symbol,
                    path: row.file_path.as_str().to_string(),
                    qualified_name: Some(row.symbol.qualified_name.clone()),
                    symbol_kind: Some(row.symbol.kind),
                    start_line: Some(row.symbol.start_line),
                    end_line: Some(row.symbol.end_line),
                    signature: Some(red.text),
                }
            })
            .collect();

        return Ok(ProvenanceEnvelope::new(
            TrustLevel::VerifiedAst,
            project_id,
            ImpactPayload {
                status: ImpactStatus::AmbiguousTarget,
                query: query.to_string(),
                target_kind: Some(ImpactTargetKind::Symbol),
                target_path: None,
                target_symbol: None,
                affected_files_count: 0,
                hits: Vec::new(),
                candidates,
                message: Some(format!(
                    "ambiguous symbol target `{query}`; re-run with `<path>#<qualified_name>`"
                )),
            },
        )
        .with_redactions_count(redactions));
    }

    let target = matches[0];
    let target_file = target.file_path.as_str();
    let target_name = target.symbol.name.as_str();
    let target_qname = target.symbol.qualified_name.as_str();

    // Count how many distinct symbols share `target_name` across the workspace.
    let same_name_count = all_symbols
        .iter()
        .filter(|r| r.symbol.name == target_name)
        .count();

    let mut symbols_by_file: BTreeMap<&str, Vec<&SymbolInfo>> = BTreeMap::new();
    for row in all_symbols {
        symbols_by_file
            .entry(row.file_path.as_str())
            .or_default()
            .push(&row.symbol);
    }

    let rev_imports = build_reverse_extracted_imports(graph);
    let direct_importers: BTreeSet<&str> = rev_imports
        .get(target_file)
        .map(|s| s.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let file_langs: BTreeMap<String, Option<String>> = index
        .store()
        .list_files()?
        .into_iter()
        .map(|f| (f.path.as_str().to_string(), f.language_id))
        .collect();
    let fts_rows = index.store().list_all_fts_contents()?;
    let mut hits = Vec::new();
    let mut direct_files: BTreeSet<String> = BTreeSet::new();
    let mut redactions = 0usize;

    for fts in &fts_rows {
        let path_str = fts.path.as_str();
        if fts.content.is_empty() {
            continue;
        }
        let hash_is_comment =
            file_langs.get(path_str).and_then(|opt| opt.as_deref()) == Some("python");
        let file_syms: Vec<SymbolInfo> = symbols_by_file
            .get(path_str)
            .map(|v| v.iter().map(|s| (*s).clone()).collect())
            .unwrap_or_default();

        for (idx, raw_line) in fts.content.lines().enumerate() {
            let line_no = idx + 1;
            // Skip lines inside the target symbol's own definition span.
            if path_str == target_file
                && target.symbol.start_line <= line_no
                && line_no <= target.symbol.end_line
            {
                continue;
            }

            let idents = scan_code_identifiers(raw_line, hash_is_comment);
            let Some((_, is_call, _)) = idents.into_iter().find(|(id, _, _)| *id == target_name)
            else {
                continue;
            };

            let trimmed = raw_line.trim_start();
            let is_import_line = trimmed.starts_with("use ")
                || trimmed.starts_with("pub use ")
                || trimmed.starts_with("import ")
                || trimmed.starts_with("from ");

            let imports_target_file = direct_importers.contains(path_str);
            let (relation, confidence, reason) = if is_import_line && imports_target_file {
                (
                    EdgeRelation::Imports,
                    EdgeConfidence::Extracted,
                    "explicit import of symbol from target file",
                )
            } else if path_str == target_file {
                (
                    if is_call {
                        EdgeRelation::Calls
                    } else {
                        EdgeRelation::References
                    },
                    EdgeConfidence::Inferred,
                    "same-file identifier match without LSP",
                )
            } else if imports_target_file {
                (
                    if is_call {
                        EdgeRelation::Calls
                    } else {
                        EdgeRelation::References
                    },
                    EdgeConfidence::Inferred,
                    "identifier match in importing file without LSP",
                )
            } else if same_name_count <= 1 {
                (
                    if is_call {
                        EdgeRelation::Calls
                    } else {
                        EdgeRelation::References
                    },
                    EdgeConfidence::Inferred,
                    "unique workspace identifier match without LSP",
                )
            } else {
                (
                    if is_call {
                        EdgeRelation::Calls
                    } else {
                        EdgeRelation::References
                    },
                    EdgeConfidence::Ambiguous,
                    "ambiguous identifier match without LSP",
                )
            };

            let enclosing =
                enclosing_symbol_for_line(&file_syms, line_no).map(|s| s.qualified_name.clone());
            let red = redact_secrets(raw_line.trim());
            redactions += red.redactions_count;

            if path_str != target_file {
                direct_files.insert(path_str.to_string());
            }

            hits.push(ImpactHit {
                path: path_str.to_string(),
                enclosing_symbol: enclosing,
                line: Some(line_no),
                relation,
                confidence,
                distance: 1,
                evidence: format!("{path_str}:L{line_no} ({reason})"),
                snippet: Some(red.text),
            });
        }
    }

    // Add transitive file dependents of files that directly reference/import the target symbol.
    append_transitive_dependents(&rev_imports, target_file, &direct_files, &mut hits);

    let hits = dedup_and_sort_hits(hits);
    let affected_files_count = hits
        .iter()
        .map(|h| h.path.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let has_non_extracted = hits
        .iter()
        .any(|h| h.confidence != EdgeConfidence::Extracted);
    let trust = if has_non_extracted {
        TrustLevel::Inferred
    } else {
        TrustLevel::VerifiedAst
    };

    let payload = ImpactPayload {
        status: ImpactStatus::Ok,
        query: query.to_string(),
        target_kind: Some(ImpactTargetKind::Symbol),
        target_path: Some(target_file.to_string()),
        target_symbol: Some(target_qname.to_string()),
        affected_files_count,
        hits,
        candidates: Vec::new(),
        message: None,
    };

    let mut env =
        ProvenanceEnvelope::new(trust, project_id, payload).with_redactions_count(redactions);
    if has_non_extracted {
        env = env.with_warning(
            "symbol impact includes INFERRED/AMBIGUOUS identifier matches without LSP; check per-hit confidence",
        );
    }
    Ok(env)
}

fn build_reverse_extracted_imports(graph: &CodeGraph) -> BTreeMap<String, BTreeSet<String>> {
    let mut rev: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in &graph.edges {
        if edge.relation != EdgeRelation::Imports || edge.confidence != EdgeConfidence::Extracted {
            continue;
        }
        if let (Some(from_f), Some(to_f)) = (edge_owner_file(&edge.from), edge_owner_file(&edge.to))
            && from_f != to_f
        {
            rev.entry(to_f.to_string())
                .or_default()
                .insert(from_f.to_string());
        }
    }
    rev
}

fn append_transitive_dependents(
    rev_imports: &BTreeMap<String, BTreeSet<String>>,
    target_file: &str,
    direct_files: &BTreeSet<String>,
    hits: &mut Vec<ImpactHit>,
) {
    const MAX_DEPTH: usize = 6;
    let mut visited: BTreeSet<String> = BTreeSet::new();
    visited.insert(target_file.to_string());
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();

    for df in direct_files {
        visited.insert(df.clone());
        queue.push_back((df.clone(), 1));
    }

    while let Some((cur, dist)) = queue.pop_front() {
        if dist >= MAX_DEPTH {
            continue;
        }
        let Some(importers) = rev_imports.get(&cur) else {
            continue;
        };
        for imp in importers {
            if visited.insert(imp.clone()) {
                hits.push(ImpactHit {
                    path: imp.clone(),
                    enclosing_symbol: None,
                    line: None,
                    relation: EdgeRelation::Imports,
                    confidence: EdgeConfidence::Extracted,
                    distance: dist + 1,
                    evidence: format!("{imp} imports {cur} (transitive depth {})", dist + 1),
                    snippet: None,
                });
                queue.push_back((imp.clone(), dist + 1));
            }
        }
    }
}

fn resolve_symbol_rows<'a>(
    symbols: &[&'a IndexedSymbolRow],
    query: &str,
) -> Vec<&'a IndexedSymbolRow> {
    let exact_q: Vec<&IndexedSymbolRow> = symbols
        .iter()
        .copied()
        .filter(|r| r.symbol.qualified_name == query)
        .collect();
    if !exact_q.is_empty() {
        return exact_q;
    }

    let exact_n: Vec<&IndexedSymbolRow> = symbols
        .iter()
        .copied()
        .filter(|r| r.symbol.name == query)
        .collect();
    if !exact_n.is_empty() {
        return exact_n;
    }

    let suffix_colon = format!("::{query}");
    let suffix_dot = format!(".{query}");
    let suffix_space = format!(" {query}");
    symbols
        .iter()
        .copied()
        .filter(|r| {
            r.symbol.qualified_name.ends_with(&suffix_colon)
                || r.symbol.qualified_name.ends_with(&suffix_dot)
                || r.symbol.qualified_name.ends_with(&suffix_space)
        })
        .collect()
}

fn parse_evidence_line(evidence: &str) -> Option<usize> {
    let idx = evidence.find(":L")?;
    let rest = &evidence[idx + 2..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn dedup_and_sort_hits(mut hits: Vec<ImpactHit>) -> Vec<ImpactHit> {
    hits.sort_by(|a, b| {
        a.distance
            .cmp(&b.distance)
            .then_with(|| a.confidence.cmp(&b.confidence))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
    let mut seen: BTreeSet<(String, Option<usize>, EdgeRelation, usize)> = BTreeSet::new();
    hits.retain(|h| seen.insert((h.path.clone(), h.line, h.relation, h.distance)));
    hits
}

/// Render an impact analysis envelope into deterministic plain text.
pub fn format_impact_text(envelope: &ProvenanceEnvelope<ImpactPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] impact query=\"{}\" status={:?} affected_files={} hits={}",
        crate::trust_label(envelope.trust),
        data.query,
        data.status,
        data.affected_files_count,
        data.hits.len()
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
        ImpactStatus::Ok => {
            for hit in &data.hits {
                let line_suffix = hit.line.map(|l| format!(":L{l}")).unwrap_or_default();
                let scope = hit
                    .enclosing_symbol
                    .as_deref()
                    .map(|s| format!(" in `{s}`"))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "  [d={} | {:?} | {:?}] {}{}{scope} — {}",
                    hit.distance, hit.confidence, hit.relation, hit.path, line_suffix, hit.evidence
                );
            }
        }
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
