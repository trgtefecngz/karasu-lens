mod cycles;
mod imports;
mod inferred;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, Omission, ProvenanceEnvelope, SymbolInfo, TrustLevel,
};
use serde::{Deserialize, Serialize};

use crate::error::CodeError;
use crate::git::head_short_commit;
use crate::index::CodeIndex;
use crate::store::IndexedFileRecord;

use self::cycles::detect_cycles_deterministic;
use self::imports::ImportResolverContext;
pub(crate) use self::inferred::{
    enclosing_symbol_for_line, extract_inferred_symbol_edges, scan_code_identifiers,
};

/// Files strictly exceeding this line count are always flagged as God Nodes.
pub const GOD_NODE_LINE_THRESHOLD: usize = 800;

/// High-coupling threshold combined with [`GOD_NODE_COUPLING_MIN_LINES`] to flag God Nodes.
pub const GOD_NODE_DEGREE_THRESHOLD: usize = 15;

/// Minimum line count required for degree-based God Node detection.
pub const GOD_NODE_COUPLING_MIN_LINES: usize = 300;

/// Node kind in the code graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeKind {
    File,
}

/// File node in the Graphify-inspired code graph (`docs/02-DATA-SCHEMAS.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: GraphNodeKind,
    pub path: String,
    pub label: String,
    pub cluster: String,
    pub hash: String,
    pub lines: usize,
    pub symbol_count: usize,
    pub in_degree: usize,
    pub out_degree: usize,
    pub is_god_node: bool,
    pub is_protected: bool,
}

/// Complete deterministic code graph payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeGraph {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_from_commit: Option<String>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<CodeEdge>,
    pub cycles: Vec<Vec<String>>,
    pub clusters: BTreeMap<String, Vec<String>>,
    pub god_nodes: Vec<String>,
}

/// Build the complete deterministic code graph for the workspace.
pub fn build_code_graph(index: &mut CodeIndex) -> Result<ProvenanceEnvelope<CodeGraph>, CodeError> {
    index.sync_workspace()?;
    let project_id = index.project_root().project_id().to_string();
    let generated_from_commit = head_short_commit(index.project_root().root());

    let files = index.store().list_files()?;
    let all_symbols = index.store().list_all_symbols()?;
    let raw_edges = index.store().list_all_edges()?;
    let fts_rows = index.store().list_all_fts_contents()?;

    let file_set: BTreeSet<String> = files.iter().map(|f| f.path.as_str().to_string()).collect();
    let file_records: BTreeMap<String, &IndexedFileRecord> = files
        .iter()
        .map(|f| (f.path.as_str().to_string(), f))
        .collect();

    let mut symbols_by_file: BTreeMap<String, Vec<SymbolInfo>> = BTreeMap::new();
    for row in all_symbols {
        symbols_by_file
            .entry(row.file_path.as_str().to_string())
            .or_default()
            .push(row.symbol);
    }

    let resolver_ctx = ImportResolverContext::load(index, &files);

    // 1. Resolve AST-extracted imports/mod statements into workspace file edges.
    let mut resolved_edges: Vec<CodeEdge> = Vec::new();
    let mut extracted_file_adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut file_imports_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for (from_rel, edge) in &raw_edges {
        if edge.relation != EdgeRelation::Imports {
            continue;
        }
        let from_path = from_rel.as_str();
        let lang = file_records
            .get(from_path)
            .and_then(|r| r.language_id.as_deref())
            .unwrap_or("");
        let resolved_targets = resolver_ctx.resolve_import(from_path, lang, &edge.to, &file_set);

        if resolved_targets.is_empty() {
            continue;
        }

        let is_external = file_records
            .get(from_path)
            .is_some_and(|r| r.parse_status.is_external());
        let confidence = if resolved_targets.len() == 1 {
            if is_external || edge.confidence == EdgeConfidence::Inferred {
                EdgeConfidence::Inferred
            } else {
                EdgeConfidence::Extracted
            }
        } else {
            EdgeConfidence::Ambiguous
        };

        for target_path in resolved_targets {
            if target_path == from_path {
                continue;
            }
            let from_id = format!("file:{from_path}");
            let to_id = format!("file:{target_path}");
            resolved_edges.push(CodeEdge {
                from: from_id.clone(),
                to: to_id.clone(),
                relation: EdgeRelation::Imports,
                confidence,
                evidence: edge.evidence.clone(),
            });
            file_imports_map
                .entry(from_path.to_string())
                .or_default()
                .insert(target_path.clone());
            if confidence == EdgeConfidence::Extracted {
                extracted_file_adj.entry(from_id).or_default().insert(to_id);
            }
        }
    }

    // 2. Extract deterministic `INFERRED` and `AMBIGUOUS` symbol call/reference edges.
    let inferred_edges = extract_inferred_symbol_edges(
        &files,
        &file_records,
        &symbols_by_file,
        &fts_rows,
        &file_imports_map,
    );
    resolved_edges.extend(inferred_edges);
    resolved_edges = dedup_edges_deterministically(resolved_edges);

    // 3. Compute file-level degrees from deduplicated file-to-file connections.
    let mut file_pair_edges: BTreeSet<(String, String)> = BTreeSet::new();
    for edge in &resolved_edges {
        if let (Some(f_from), Some(f_to)) = (edge_owner_file(&edge.from), edge_owner_file(&edge.to))
            && f_from != f_to
        {
            file_pair_edges.insert((f_from.to_string(), f_to.to_string()));
        }
    }

    let mut in_deg: BTreeMap<String, usize> = BTreeMap::new();
    let mut out_deg: BTreeMap<String, usize> = BTreeMap::new();
    for (from_f, to_f) in &file_pair_edges {
        *out_deg.entry(from_f.clone()).or_insert(0) += 1;
        *in_deg.entry(to_f.clone()).or_insert(0) += 1;
    }

    // 4. Build deterministic nodes, clusters, and god-node list.
    let mut nodes = Vec::with_capacity(files.len());
    let mut clusters: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut god_nodes = Vec::new();
    let has_inferred_or_ambiguous = resolved_edges.iter().any(|e| {
        matches!(
            e.confidence,
            EdgeConfidence::Inferred | EdgeConfidence::Ambiguous
        )
    });

    for rec in &files {
        let path_str = rec.path.as_str().to_string();
        let label = rec
            .path
            .file_name()
            .unwrap_or(rec.path.as_str())
            .to_string();
        let cluster = cluster_for_path(&path_str);
        let sym_count = symbols_by_file.get(&path_str).map_or(0, Vec::len);
        let in_d = in_deg.get(&path_str).copied().unwrap_or(0);
        let out_d = out_deg.get(&path_str).copied().unwrap_or(0);
        let is_god =
            !is_generated_lockfile_path(&path_str) && is_god_node(rec.line_count, in_d, out_d);
        let is_protected = index.project_config().is_protected_code_path(&rec.path);

        if is_god {
            god_nodes.push(path_str.clone());
        }
        clusters
            .entry(cluster.clone())
            .or_default()
            .push(path_str.clone());

        nodes.push(GraphNode {
            id: format!("file:{path_str}"),
            kind: GraphNodeKind::File,
            path: path_str,
            label,
            cluster,
            hash: format!("blake3:{}", rec.blake3),
            lines: rec.line_count,
            symbol_count: sym_count,
            in_degree: in_d,
            out_degree: out_d,
            is_god_node: is_god,
            is_protected,
        });
    }

    for paths in clusters.values_mut() {
        paths.sort();
    }
    god_nodes.sort();

    // 5. Deterministic cycle detection on extracted file dependency edges.
    let (cycles, truncated_cycles) = detect_cycles_deterministic(&extracted_file_adj);

    let graph = CodeGraph {
        generated_from_commit,
        nodes,
        edges: resolved_edges,
        cycles,
        clusters,
        god_nodes,
    };

    let mut builtin_parsed_count = 0usize;
    let mut external_parsed_count = 0usize;
    let mut external_parser_ids: BTreeSet<String> = BTreeSet::new();
    for rec in &files {
        if rec.parse_status.is_external() {
            external_parsed_count += 1;
            external_parser_ids.insert(rec.parser_id.clone());
        } else if rec.parse_status.is_builtin_parsed() {
            builtin_parsed_count += 1;
        }
    }

    let trust = if !files.is_empty() && builtin_parsed_count == 0 && external_parsed_count == 0 {
        TrustLevel::UnparsedFallback
    } else if external_parsed_count > 0 {
        TrustLevel::ExternalParser
    } else {
        TrustLevel::VerifiedAst
    };

    let mut env = ProvenanceEnvelope::new(trust, project_id, graph);
    if external_parsed_count > 0 {
        let ids: Vec<String> = external_parser_ids.into_iter().collect();
        env = env.with_warning(format!(
            "{external_parsed_count} file(s) parsed via external language sidecar(s) [{}]; trust downgraded from VERIFIED_AST to EXTERNAL_PARSER",
            ids.join(", ")
        ));
    }
    if has_inferred_or_ambiguous {
        env = env.with_warning(
            "graph includes INFERRED/AMBIGUOUS call edges based on identifier matching without LSP; verify confidence tag per edge",
        );
    }
    if truncated_cycles > 0 {
        env = env.with_omission(Omission::items(
            truncated_cycles,
            "cycle_report_limit_exceeded",
        ));
    }

    Ok(env)
}

/// Deterministic folder/module hierarchy clustering (`docs/02-DATA-SCHEMAS.md`).
pub fn cluster_for_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() <= 1 {
        return "root".to_string();
    }
    let dirs = &parts[..parts.len() - 1];
    match dirs {
        ["src"] | ["lib"] | ["app"] => dirs[0].to_string(),
        ["src", sub, ..] | ["lib", sub, ..] | ["app", sub, ..] => (*sub).to_string(),
        [container, pkg, "src", sub, ..]
            if matches!(*container, "crates" | "packages" | "apps" | "services") =>
        {
            format!("{pkg}/{sub}")
        }
        [container, pkg, ..]
            if matches!(*container, "crates" | "packages" | "apps" | "services") =>
        {
            (*pkg).to_string()
        }
        [first] => (*first).to_string(),
        [first, second, ..] => format!("{first}/{second}"),
        [] => "root".to_string(),
    }
}

/// Returns `true` for auto-generated package lockfiles that should never be flagged as God Nodes.
pub fn is_generated_lockfile_path(path: &str) -> bool {
    let file_name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    matches!(
        file_name.as_str(),
        "cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "uv.lock"
            | "go.sum"
            | "gemfile.lock"
            | "composer.lock"
    )
}

/// Check whether a file node qualifies as an architectural God Node.
pub const fn is_god_node(lines: usize, in_degree: usize, out_degree: usize) -> bool {
    lines > GOD_NODE_LINE_THRESHOLD
        || (lines >= GOD_NODE_COUPLING_MIN_LINES
            && in_degree.saturating_add(out_degree) >= GOD_NODE_DEGREE_THRESHOLD)
}

/// Extract the owning relative file path from a `file:<path>` or `sym:<path>#...` node ID.
pub fn edge_owner_file(node_id: &str) -> Option<&str> {
    if let Some(rest) = node_id.strip_prefix("file:") {
        Some(rest)
    } else if let Some(rest) = node_id.strip_prefix("sym:") {
        rest.split('#').next()
    } else {
        None
    }
}

/// Render a code graph envelope as deterministic plain text.
pub fn format_graph_text(envelope: &ProvenanceEnvelope<CodeGraph>) -> String {
    let g = &envelope.data;
    let mut out = String::new();
    let commit = g.generated_from_commit.as_deref().unwrap_or("none");
    let _ = writeln!(
        out,
        "[{}] graph nodes={} edges={} clusters={} cycles={} god_nodes={} commit={commit}",
        crate::trust_label(envelope.trust),
        g.nodes.len(),
        g.edges.len(),
        g.clusters.len(),
        g.cycles.len(),
        g.god_nodes.len()
    );

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    if !g.god_nodes.is_empty() {
        let _ = writeln!(out, "\n## God Nodes");
        for path in &g.god_nodes {
            if let Some(node) = g.nodes.iter().find(|n| &n.path == path) {
                let _ = writeln!(
                    out,
                    "  - {} ({} lines, in={}, out={}, cluster={})",
                    node.path, node.lines, node.in_degree, node.out_degree, node.cluster
                );
            }
        }
    }

    if !g.cycles.is_empty() {
        let _ = writeln!(out, "\n## Cycles ({})", g.cycles.len());
        for cycle in &g.cycles {
            let readable: Vec<&str> = cycle
                .iter()
                .map(|id| id.strip_prefix("file:").unwrap_or(id.as_str()))
                .collect();
            let _ = writeln!(out, "  - {}", readable.join(" -> "));
        }
    }

    let _ = writeln!(out, "\n## Clusters");
    for (cluster, paths) in &g.clusters {
        let _ = writeln!(out, "  [{cluster}] ({} files)", paths.len());
        for path in paths {
            if let Some(node) = g.nodes.iter().find(|n| &n.path == path) {
                let mut tags = Vec::new();
                if node.is_god_node {
                    tags.push("GOD_NODE");
                }
                if node.is_protected {
                    tags.push("PROTECTED");
                }
                let tag_str = if tags.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", tags.join(", "))
                };
                let _ = writeln!(
                    out,
                    "    - {} ({}L, {} syms, in={}, out={}){tag_str}",
                    node.path, node.lines, node.symbol_count, node.in_degree, node.out_degree
                );
            }
        }
    }

    if !g.edges.is_empty() {
        let _ = writeln!(out, "\n## Edges ({})", g.edges.len());
        for edge in &g.edges {
            let _ = writeln!(
                out,
                "  {} --[{}|{}]--> {} ({})",
                edge.from,
                relation_label(edge.relation),
                confidence_label(edge.confidence),
                edge.to,
                edge.evidence
            );
        }
    }

    out
}

fn dedup_edges_deterministically(mut edges: Vec<CodeEdge>) -> Vec<CodeEdge> {
    edges.sort();
    let mut best: BTreeMap<(String, String, EdgeRelation), CodeEdge> = BTreeMap::new();
    for edge in edges {
        let key = (edge.from.clone(), edge.to.clone(), edge.relation);
        best.entry(key)
            .and_modify(|cur| {
                if edge.confidence < cur.confidence {
                    *cur = edge.clone();
                }
            })
            .or_insert(edge);
    }
    let mut result: Vec<CodeEdge> = best.into_values().collect();
    result.sort();
    result
}

fn relation_label(rel: EdgeRelation) -> &'static str {
    match rel {
        EdgeRelation::Imports => "imports",
        EdgeRelation::Calls => "calls",
        EdgeRelation::Implements => "implements",
        EdgeRelation::Extends => "extends",
        EdgeRelation::References => "references",
    }
}

fn confidence_label(conf: EdgeConfidence) -> &'static str {
    match conf {
        EdgeConfidence::Extracted => "EXTRACTED",
        EdgeConfidence::Inferred => "INFERRED",
        EdgeConfidence::Ambiguous => "AMBIGUOUS",
        EdgeConfidence::VerifiedLsp => "VERIFIED_LSP",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_for_path_is_deterministic_and_human_readable() {
        assert_eq!(cluster_for_path("src/world/save.rs"), "world");
        assert_eq!(cluster_for_path("src/main.rs"), "src");
        assert_eq!(
            cluster_for_path("crates/klens-code/src/map.rs"),
            "klens-code"
        );
        assert_eq!(
            cluster_for_path("crates/klens-code/src/languages/go.rs"),
            "klens-code/languages"
        );
        assert_eq!(cluster_for_path("Cargo.toml"), "root");
    }
}
