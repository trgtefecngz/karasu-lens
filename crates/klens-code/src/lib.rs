#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

//! Incremental Tree-sitter AST engine, SQLite WAL+FTS5 cache, surgical
//! `outline` / `read`, PageRank project map, FTS5 search, code graph,
//! impact analysis, smart `diff-check`, and project health for Karasu Lens (`klens-code`).

pub mod deps;
pub mod diff_check;
mod diff_parse;
pub mod error;
pub mod find;
mod git;
pub mod graph;
pub mod health;
pub mod impact;
mod impact_format;
pub mod index;
pub mod languages;
pub mod map;
pub mod outline;
pub mod read;
pub mod read_context;
pub mod sidecar;
pub mod store;
mod store_schema;

pub use deps::{
    DependencyEcosystem, DependencyEntry, DependencyInventory, collect_dependencies,
    diff_added_external_dependencies, is_dependency_manifest, parse_manifest_dependencies,
    summarize_unique_external_deps,
};
pub use diff_check::{
    ChangedFileSummary, ChangedSymbolRef, DiffAlert, DiffAlertKind, DiffCheckOptions,
    DiffCheckPayload, SecretLeakFinding, format_diff_check_text, run_diff_check,
    run_diff_check_with_options,
};
pub use error::CodeError;
pub use find::{
    DEFAULT_FIND_LIMIT, FindMatch, FindMatchKind, FindPayload, find_in_workspace, format_find_text,
};
pub use graph::{
    CodeGraph, GOD_NODE_COUPLING_MIN_LINES, GOD_NODE_DEGREE_THRESHOLD, GOD_NODE_LINE_THRESHOLD,
    GraphNode, GraphNodeKind, build_code_graph, cluster_for_path, edge_owner_file,
    format_graph_text, is_god_node,
};
pub use health::{HealthCheck, HealthPayload, TrafficLight, format_health_text, run_health_check};
pub use impact::{
    ImpactCandidate, ImpactHit, ImpactPayload, ImpactStatus, ImpactTargetKind, analyze_impact,
};
pub use impact_format::{
    DEFAULT_IMPACT_BUDGET_TOKENS, ImpactOutputLimits, MIN_IMPACT_BUDGET_TOKENS,
    bound_impact_payload, format_impact_text, format_impact_text_with,
};
pub use index::{
    CodeIndex, FileSyncOutcome, MAX_INDEXABLE_BYTES, SyncStats, default_readonly_cache_root,
};
pub use languages::{
    AnalyzerRegistry, CAnalyzer, CSharpAnalyzer, CppAnalyzer, GoAnalyzer, GrammarAbiInfo,
    JavaAnalyzer, PhpAnalyzer, PythonAnalyzer, RubyAnalyzer, RustAnalyzer, StructuredDocAnalyzer,
    TsJsAnalyzer, verify_tree_sitter_abi,
};
pub use map::{
    BoundaryDirection, DEFAULT_MAP_BUDGET_TOKENS, MapBoundaryLink, MapFileEntry, ProjectMapPayload,
    build_project_map, build_project_map_focused, format_map_text,
};
pub use outline::{
    FileOutline, OutlinePayload, format_outline_text, format_symbol_line, outline_file,
    outline_path,
};
pub use read::{
    BatchReadData, BatchReadItem, LineRange, ReadResultData, ReadStatus, ReadTarget,
    SymbolCandidate, attach_code_context_to_batch, attach_code_context_to_read,
    format_batch_read_text, format_read_text, read_batch, read_lines, read_symbol,
};
pub use read_context::{
    CollectedImpact, ExtractedImports, MAX_CONTEXT_IMPACT_HITS, MAX_CONTEXT_IMPORT_LINES,
    MAX_CONTEXT_MEMORY_NOTES, MAX_CONTEXT_MEMORY_SNIPPET_CHARS, ReadContextBundle,
    ReadImpactContext, ReadImportsContext, ReadInclude, ReadMemoryNote, collect_read_impact,
    extract_file_imports, extract_imports_from_source, format_read_context_text,
    sanitize_memory_snippet,
};
pub use sidecar::{
    CIRCUIT_BREAKER_THRESHOLD, CapabilitiesLanguage, CapabilitiesResult, CtagsConfig,
    CtagsProbeInfo, DEFAULT_PARSE_TIMEOUT_MS, MAX_RPC_FRAME_BYTES, builtin_language_extensions,
    enrich_extension_list_health, inspect_language_extensions_doctor, probe_ctags,
    probe_rpc_sidecar,
};
pub use store::{FtsFileHit, IndexStore, IndexedFileRecord, IndexedSymbolRow, ParseStatus};
pub use store_schema::INDEX_DB_SCHEMA_VERSION;

/// Canonical string label for a [`klens_core::TrustLevel`] in plain-text formatters.
pub(crate) const fn trust_label(trust: klens_core::TrustLevel) -> &'static str {
    match trust {
        klens_core::TrustLevel::VerifiedAst => "VERIFIED_AST",
        klens_core::TrustLevel::ExternalParser => "EXTERNAL_PARSER",
        klens_core::TrustLevel::VerifiedRaw => "VERIFIED_RAW",
        klens_core::TrustLevel::UserLocked => "USER_LOCKED",
        klens_core::TrustLevel::Inferred => "INFERRED",
        klens_core::TrustLevel::Stale => "STALE",
        klens_core::TrustLevel::UnparsedFallback => "UNPARSED_FALLBACK",
    }
}
