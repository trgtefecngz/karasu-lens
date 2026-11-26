use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use klens_core::paths::is_sensitive_path_with_extra;
use klens_core::{
    EdgeConfidence, Omission, OmissionKind, PathError, ProvenanceEnvelope, RelPath, SymbolInfo,
    TokenBudget, estimate_tokens, redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::deps::{DependencyEntry, collect_dependencies, summarize_unique_external_deps};
use crate::error::CodeError;
use crate::graph::{CodeGraph, build_code_graph, edge_owner_file};
use crate::index::CodeIndex;
use crate::outline::format_symbol_line;

/// Default token budget for `klens map` when `--budget` is not explicitly provided.
pub const DEFAULT_MAP_BUDGET_TOKENS: usize = 2000;

/// Direction of a dependency edge crossing the focused module boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryDirection {
    /// External file depends on a file inside the focused subtree.
    Incoming,
    /// A file inside the focused subtree depends on an external file.
    Outgoing,
}

/// Dependency link crossing the boundary of a focused `klens map` subtree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapBoundaryLink {
    pub direction: BoundaryDirection,
    pub internal_path: String,
    pub external_path: String,
    pub confidence: EdgeConfidence,
}

/// Ranked file entry inside the PageRank project map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapFileEntry {
    pub path: String,
    pub cluster: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_id: Option<String>,
    /// Deterministic PageRank weight in basis points (`0..=10000`).
    pub rank_score_bps: u32,
    pub lines: usize,
    pub in_degree: usize,
    pub out_degree: usize,
    pub is_god_node: bool,
    pub is_protected: bool,
    pub total_symbols: usize,
    pub symbols: Vec<SymbolInfo>,
}

/// Complete deterministic PageRank project map payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMapPayload {
    pub budget_tokens: usize,
    pub used_tokens: usize,
    pub total_files: usize,
    pub included_files: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focus_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundary_links: Vec<MapBoundaryLink>,
    pub protected_files: Vec<String>,
    pub total_external_dependencies: usize,
    pub dependencies: Vec<DependencyEntry>,
    pub files: Vec<MapFileEntry>,
}

/// Build an Aider-style deterministic PageRank project map fitted into `budget_tokens`.
pub fn build_project_map(
    index: &mut CodeIndex,
    budget_tokens: usize,
) -> Result<ProvenanceEnvelope<ProjectMapPayload>, CodeError> {
    build_project_map_focused(index, budget_tokens, None)
}

/// Build a deterministic PageRank project map optionally focused on a relative subdirectory or file.
///
/// Global PageRank is always computed over the full project graph so architectural importance
/// rankings stay consistent; when `focus` is `Some(rel)`, only matching files are included and
/// cross-boundary dependencies are summarized in `boundary_links`.
pub fn build_project_map_focused(
    index: &mut CodeIndex,
    budget_tokens: usize,
    focus: Option<&RelPath>,
) -> Result<ProvenanceEnvelope<ProjectMapPayload>, CodeError> {
    if let Some(rel) = focus
        && is_sensitive_path_with_extra(rel, &index.project_config().extra_sensitive_patterns)
    {
        return Err(CodeError::Path(PathError::SensitiveFileBlocked(
            rel.as_str().to_string(),
        )));
    }

    let graph_env = build_code_graph(index)?;
    let graph = graph_env.data;
    let project_id = index.project_root().project_id().to_string();

    let dep_inventory = collect_dependencies(index)?;
    let unique_deps = summarize_unique_external_deps(&dep_inventory);
    let total_external_dependencies = unique_deps.len();

    let ranks = compute_deterministic_pagerank(&graph);

    let focus_prefix = focus.map(|rel| format!("{}/", rel.as_str()));
    let selected_indices: Vec<usize> = match (focus, focus_prefix.as_deref()) {
        (Some(rel), Some(prefix)) => {
            let matches: Vec<usize> = graph
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| node.path == rel.as_str() || node.path.starts_with(prefix))
                .map(|(idx, _)| idx)
                .collect();
            if matches.is_empty() {
                return Err(CodeError::PathNotFound(rel.as_str().to_string()));
            }
            matches
        }
        _ => (0..graph.nodes.len()).collect(),
    };

    let mut ranked_indices: Vec<(usize, u64, u32)> = selected_indices
        .iter()
        .map(|&idx| {
            let score = ranks[idx];
            let micros = (score * 1_000_000.0).round().max(0.0) as u64;
            let bps = (score * 10_000.0).round().clamp(0.0, 10_000.0) as u32;
            (idx, micros, bps)
        })
        .collect();

    // Sort strictly deterministically: highest PageRank first, then lexical path order.
    ranked_indices.sort_by(|a, b| {
        Reverse(a.1)
            .cmp(&Reverse(b.1))
            .then_with(|| graph.nodes[a.0].path.cmp(&graph.nodes[b.0].path))
    });

    let mut protected_files: Vec<String> = selected_indices
        .iter()
        .map(|&idx| &graph.nodes[idx])
        .filter(|n| n.is_protected)
        .map(|n| n.path.clone())
        .collect();
    protected_files.sort();

    let all_boundary_links = if focus.is_some() {
        collect_boundary_links(&graph, &selected_indices)
    } else {
        Vec::new()
    };

    let mut budget = TokenBudget::new(budget_tokens);
    let mut omissions: Vec<Omission> = Vec::new();
    let mut redactions_count = 0usize;

    // Reserve a bounded slice for dependency summary (tighter when focused on a module).
    let dep_budget_cap = if focus.is_some() {
        (budget_tokens / 10).min(180)
    } else {
        (budget_tokens / 5).min(400)
    };
    let mut dep_used = 0usize;
    let mut kept_deps = Vec::new();
    for dep in &unique_deps {
        let dep_line = format!(
            "  - [{}] {} {}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.version
        );
        let cost = estimate_tokens(&dep_line);
        if dep_used.saturating_add(cost) <= dep_budget_cap && budget.try_consume(cost) {
            dep_used += cost;
            kept_deps.push(dep.clone());
        } else {
            let omitted_deps = unique_deps.len().saturating_sub(kept_deps.len());
            if omitted_deps > 0 {
                omissions.push(Omission::items(
                    omitted_deps,
                    "dependency_summary_budget_exceeded",
                ));
            }
            break;
        }
    }

    // Reserve a small bounded slice for cross-boundary links in focused mode.
    let boundary_budget_cap = (budget_tokens / 8).min(250);
    let mut boundary_used = 0usize;
    let mut kept_boundary_links = Vec::new();
    for link in &all_boundary_links {
        let link_line = format_boundary_link_line(link);
        let cost = estimate_tokens(&link_line);
        if boundary_used.saturating_add(cost) <= boundary_budget_cap && budget.try_consume(cost) {
            boundary_used += cost;
            kept_boundary_links.push(link.clone());
        } else {
            let omitted_links = all_boundary_links
                .len()
                .saturating_sub(kept_boundary_links.len());
            if omitted_links > 0 {
                omissions.push(Omission::items(
                    omitted_links,
                    "boundary_links_budget_exceeded",
                ));
            }
            break;
        }
    }

    let mut included_entries = Vec::new();
    let mut omitted_files = Vec::new();
    // Prevent a single symbol-heavy file from monopolizing the entire map budget on multi-file maps.
    let per_file_symbol_cap = if ranked_indices.len() > 3 {
        Some((budget_tokens / 5).max(80))
    } else {
        None
    };

    for (rank_pos, &(node_idx, _, rank_bps)) in ranked_indices.iter().enumerate() {
        let node = &graph.nodes[node_idx];
        let rel = RelPath::normalize(&node.path)?;
        let record = index.store().get_file(&rel)?;
        let parser_id = record
            .as_ref()
            .filter(|r| r.parse_status.is_external())
            .map(|r| r.parser_id.clone());
        let language_id = record.and_then(|r| r.language_id);
        let all_symbols = index.store().get_symbols_for_file(&rel)?;

        let header_line = format_file_header(node, rank_bps, language_id.as_deref());
        let header_cost = estimate_tokens(&header_line);
        if !budget.try_consume(header_cost) {
            for &(rem_idx, _, _) in &ranked_indices[rank_pos..] {
                omitted_files.push(graph.nodes[rem_idx].path.clone());
            }
            break;
        }

        let total_symbols = all_symbols.len();
        let mut kept_symbols = Vec::new();
        let mut file_sym_tokens_used = 0usize;
        let mut omitted_sym_count = 0usize;
        let mut omitted_start: Option<usize> = None;
        let mut omitted_end: Option<usize> = None;

        for mut sym in all_symbols {
            let redacted = redact_secrets(&sym.signature);
            if redacted.redactions_count > 0 {
                redactions_count += redacted.redactions_count;
                sym.signature = redacted.text;
            }
            let cost = estimate_tokens(&format_symbol_line(&sym));
            let within_file_cap = per_file_symbol_cap
                .is_none_or(|cap| file_sym_tokens_used.saturating_add(cost) <= cap);
            if within_file_cap && budget.try_consume(cost) {
                file_sym_tokens_used = file_sym_tokens_used.saturating_add(cost);
                kept_symbols.push(sym);
            } else {
                omitted_sym_count += 1;
                omitted_start =
                    Some(omitted_start.map_or(sym.start_line, |c| c.min(sym.start_line)));
                omitted_end = Some(omitted_end.map_or(sym.end_line, |c| c.max(sym.end_line)));
            }
        }

        if omitted_sym_count > 0 {
            omissions.push(Omission {
                kind: OmissionKind::Symbols,
                path: Some(node.path.clone()),
                start_line: omitted_start,
                end_line: omitted_end,
                count: omitted_sym_count,
                reason: "token_budget_exceeded".to_string(),
            });
        }

        included_entries.push(MapFileEntry {
            path: node.path.clone(),
            cluster: node.cluster.clone(),
            language_id,
            parser_id,
            rank_score_bps: rank_bps,
            lines: node.lines,
            in_degree: node.in_degree,
            out_degree: node.out_degree,
            is_god_node: node.is_god_node,
            is_protected: node.is_protected,
            total_symbols,
            symbols: kept_symbols,
        });
    }

    if !omitted_files.is_empty() {
        let preview_count = omitted_files.len().min(5);
        let preview = omitted_files[..preview_count].join(", ");
        let suffix = if omitted_files.len() > preview_count {
            format!(", +{} more", omitted_files.len() - preview_count)
        } else {
            String::new()
        };
        omissions.push(Omission::items(
            omitted_files.len(),
            format!("token_budget_exceeded: omitted files [{preview}{suffix}]"),
        ));
    }

    let payload = ProjectMapPayload {
        budget_tokens,
        used_tokens: budget.used(),
        total_files: selected_indices.len(),
        included_files: included_entries.len(),
        focus_path: focus.map(|rel| rel.as_str().to_string()),
        boundary_links: kept_boundary_links,
        protected_files,
        total_external_dependencies,
        dependencies: kept_deps,
        files: included_entries,
    };

    let mut env = ProvenanceEnvelope::new(graph_env.trust, project_id, payload)
        .with_redactions_count(redactions_count);
    for w in graph_env.warnings {
        env = env.with_warning(w);
    }
    for om in omissions {
        env = env.with_omission(om);
    }
    if let Some(fb) = graph_env.raw_fallback {
        env = env.with_raw_fallback(fb);
    }

    Ok(env)
}

const fn confidence_priority(confidence: EdgeConfidence) -> u8 {
    match confidence {
        EdgeConfidence::VerifiedLsp => 4,
        EdgeConfidence::Extracted => 3,
        EdgeConfidence::Inferred => 2,
        EdgeConfidence::Ambiguous => 1,
    }
}

const fn confidence_label(confidence: EdgeConfidence) -> &'static str {
    match confidence {
        EdgeConfidence::Extracted => "EXTRACTED",
        EdgeConfidence::Inferred => "INFERRED",
        EdgeConfidence::Ambiguous => "AMBIGUOUS",
        EdgeConfidence::VerifiedLsp => "VERIFIED_LSP",
    }
}

fn collect_boundary_links(graph: &CodeGraph, selected_indices: &[usize]) -> Vec<MapBoundaryLink> {
    let all_paths: BTreeSet<&str> = graph.nodes.iter().map(|n| n.path.as_str()).collect();
    let focused_paths: BTreeSet<&str> = selected_indices
        .iter()
        .map(|&idx| graph.nodes[idx].path.as_str())
        .collect();

    let mut dedup: BTreeMap<(BoundaryDirection, String, String), EdgeConfidence> = BTreeMap::new();
    for edge in &graph.edges {
        let (Some(from_file), Some(to_file)) =
            (edge_owner_file(&edge.from), edge_owner_file(&edge.to))
        else {
            continue;
        };
        if from_file == to_file || !all_paths.contains(from_file) || !all_paths.contains(to_file) {
            continue;
        }
        let from_in = focused_paths.contains(from_file);
        let to_in = focused_paths.contains(to_file);
        if from_in == to_in {
            continue;
        }
        let key = if !from_in && to_in {
            (
                BoundaryDirection::Incoming,
                to_file.to_string(),
                from_file.to_string(),
            )
        } else {
            (
                BoundaryDirection::Outgoing,
                from_file.to_string(),
                to_file.to_string(),
            )
        };
        dedup
            .entry(key)
            .and_modify(|cur| {
                if confidence_priority(edge.confidence) > confidence_priority(*cur) {
                    *cur = edge.confidence;
                }
            })
            .or_insert(edge.confidence);
    }

    dedup
        .into_iter()
        .map(
            |((direction, internal_path, external_path), confidence)| MapBoundaryLink {
                direction,
                internal_path,
                external_path,
                confidence,
            },
        )
        .collect()
}

fn format_boundary_link_line(link: &MapBoundaryLink) -> String {
    let tag = confidence_label(link.confidence);
    match link.direction {
        BoundaryDirection::Incoming => {
            format!(
                "  <- {} -> {} [{tag}]",
                link.external_path, link.internal_path
            )
        }
        BoundaryDirection::Outgoing => {
            format!(
                "  -> {} -> {} [{tag}]",
                link.internal_path, link.external_path
            )
        }
    }
}

/// Deterministic damped PageRank over resolved file-to-file reference edges.
fn compute_deterministic_pagerank(graph: &CodeGraph) -> Vec<f64> {
    let n = graph.nodes.len();
    if n == 0 {
        return Vec::new();
    }

    let path_to_idx: BTreeMap<&str, usize> = graph
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| (node.path.as_str(), i))
        .collect();

    // Aggregate file-to-file edge weights deterministically using `BTreeMap`.
    let mut adj_weights: Vec<BTreeMap<usize, f64>> = vec![BTreeMap::new(); n];
    for edge in &graph.edges {
        let (Some(from_file), Some(to_file)) =
            (edge_owner_file(&edge.from), edge_owner_file(&edge.to))
        else {
            continue;
        };
        if from_file == to_file {
            continue;
        }
        let (Some(&u), Some(&v)) = (path_to_idx.get(from_file), path_to_idx.get(to_file)) else {
            continue;
        };
        let weight = match edge.confidence {
            EdgeConfidence::Extracted | EdgeConfidence::VerifiedLsp => 1.0,
            EdgeConfidence::Inferred => 0.5,
            EdgeConfidence::Ambiguous => 0.25,
        };
        adj_weights[u]
            .entry(v)
            .and_modify(|cur| {
                if weight > *cur {
                    *cur = weight;
                }
            })
            .or_insert(weight);
    }

    let out_sums: Vec<f64> = adj_weights.iter().map(|m| m.values().sum()).collect();

    const DAMPING: f64 = 0.85;
    const ITERATIONS: usize = 30;
    let n_f = n as f64;
    let mut rank = vec![1.0 / n_f; n];

    for _ in 0..ITERATIONS {
        let mut dangling_sum = 0.0;
        for (i, &out_sum) in out_sums.iter().enumerate() {
            if out_sum == 0.0 {
                dangling_sum += rank[i];
            }
        }

        let base = (1.0 - DAMPING) / n_f + DAMPING * (dangling_sum / n_f);
        let mut next = vec![base; n];

        for u in 0..n {
            let denom = out_sums[u];
            if denom == 0.0 {
                continue;
            }
            let contrib_unit = DAMPING * rank[u] / denom;
            for (&v, &w) in &adj_weights[u] {
                next[v] += contrib_unit * w;
            }
        }

        rank = next;
    }

    rank
}

fn format_file_header(
    node: &crate::graph::GraphNode,
    rank_bps: u32,
    language_id: Option<&str>,
) -> String {
    let lang = language_id.unwrap_or("unknown");
    let mut flags = Vec::new();
    if node.is_protected {
        flags.push("PROTECTED");
    }
    if node.is_god_node {
        flags.push("GOD_NODE");
    }
    let flag_str = if flags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", flags.join(", "))
    };
    format!(
        "# {} ({lang}, cluster={}, rank={}bps, {}L, in={}, out={}){flag_str}",
        node.path, node.cluster, rank_bps, node.lines, node.in_degree, node.out_degree
    )
}

/// Render a project map envelope into deterministic plain text.
pub fn format_map_text(envelope: &ProvenanceEnvelope<ProjectMapPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    match &data.focus_path {
        Some(focus) => {
            let _ = writeln!(
                out,
                "[{}] map focus={} files={}/{} tokens={}/{} deps={}",
                crate::trust_label(envelope.trust),
                focus,
                data.included_files,
                data.total_files,
                data.used_tokens,
                data.budget_tokens,
                data.total_external_dependencies
            );
        }
        None => {
            let _ = writeln!(
                out,
                "[{}] map files={}/{} tokens={}/{} deps={}",
                crate::trust_label(envelope.trust),
                data.included_files,
                data.total_files,
                data.used_tokens,
                data.budget_tokens,
                data.total_external_dependencies
            );
        }
    }

    if !data.protected_files.is_empty() {
        let _ = writeln!(
            out,
            "PROTECTED_PATHS ({}): {}",
            data.protected_files.len(),
            data.protected_files.join(", ")
        );
    }

    if !data.dependencies.is_empty() {
        let _ = writeln!(out, "\n## Dependencies (version-locked)");
        for dep in &data.dependencies {
            let _ = writeln!(
                out,
                "  - [{}] {} {}",
                dep.ecosystem.as_str(),
                dep.name,
                dep.version
            );
        }
    }

    if !data.boundary_links.is_empty() {
        let _ = writeln!(out, "\n## Boundary Links");
        for link in &data.boundary_links {
            let _ = writeln!(out, "{}", format_boundary_link_line(link));
        }
    }

    for file in &data.files {
        let lang = file.language_id.as_deref().unwrap_or("unknown");
        let mut flags = Vec::new();
        if file.is_protected {
            flags.push("PROTECTED");
        }
        if file.is_god_node {
            flags.push("GOD_NODE");
        }
        let flag_str = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(", "))
        };
        let _ = writeln!(
            out,
            "\n# {} ({lang}, cluster={}, rank={}bps, {}L, in={}, out={}){flag_str}",
            file.path,
            file.cluster,
            file.rank_score_bps,
            file.lines,
            file.in_degree,
            file.out_degree
        );
        for sym in &file.symbols {
            let _ = writeln!(out, "{}", format_symbol_line(sym));
        }
    }

    if !envelope.omissions.is_empty() {
        let _ = writeln!(out, "\n## Omissions");
        for om in &envelope.omissions {
            match &om.path {
                Some(path) => {
                    let _ = writeln!(
                        out,
                        "  // ... [omitted {} {:?} in {} ({})]",
                        om.count, om.kind, path, om.reason
                    );
                }
                None => {
                    let _ = writeln!(
                        out,
                        "  // ... [omitted {} {:?} ({})]",
                        om.count, om.kind, om.reason
                    );
                }
            }
        }
    }

    out
}
