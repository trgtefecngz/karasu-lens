use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::envelope::Omission;
use crate::error::KlensError;
use crate::paths::RelPath;

// ---------------------------------------------------------------------------
// 1. LanguageAnalyzer — Pluggable language parsing slot (Phase 1+)
// ---------------------------------------------------------------------------

/// Outcome of parsing a source file into symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseOutcome<T> {
    /// Clean, complete AST parse (`TrustLevel::VerifiedAst`).
    Parsed(T),
    /// Partial parse with syntax errors; warnings describe affected regions.
    Partial { value: T, warnings: Vec<String> },
    /// Unsupported syntax or unrecoverable parse error (`TrustLevel::UnparsedFallback`).
    Fallback { reason: String },
}

/// Language-agnostic symbol classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Method,
    Struct,
    Enum,
    Trait,
    Interface,
    Class,
    TypeAlias,
    Const,
    Static,
    Module,
    Macro,
    Variable,
    Other,
}

/// Indexed symbol metadata extracted from a source file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub qualified_name: String,
    pub kind: SymbolKind,
    pub signature: String,
    pub start_line: usize,
    pub end_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// Complete, untruncated symbol table for a single source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSymbols {
    pub path: RelPath,
    pub language_id: String,
    pub symbols: Vec<SymbolInfo>,
}

/// Relationship type between two nodes in the code graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeRelation {
    Imports,
    Calls,
    Implements,
    Extends,
    References,
}

/// Evidence-backed confidence tag on a code graph edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeConfidence {
    Extracted,
    Inferred,
    Ambiguous,
    VerifiedLsp,
}

/// Directed edge in the code dependency / call graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CodeEdge {
    pub from: String,
    pub to: String,
    pub relation: EdgeRelation,
    pub confidence: EdgeConfidence,
    pub evidence: String,
}

/// Contract for adding new programming language analyzers without modifying core.
pub trait LanguageAnalyzer: Send + Sync {
    fn language_id(&self) -> &'static str;
    fn extensions(&self) -> &'static [&'static str];
    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols>;
    fn extract_edges(&self, source: &str, symbols: &FileSymbols) -> Vec<CodeEdge>;
}

// ---------------------------------------------------------------------------
// 2. CommandFilter — Pluggable deterministic terminal filter slot (Phase 2+)
// ---------------------------------------------------------------------------

/// Filtered terminal command execution result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilteredRun {
    pub filter_id: String,
    pub summary: String,
    pub exit_code: i32,
    pub raw_bytes: usize,
    pub filtered_bytes: usize,
    pub est_raw_tokens: usize,
    pub est_filtered_tokens: usize,
    pub omissions: Vec<Omission>,
    /// Constitutional invariant (Article 4): must remain `false` on error runs.
    pub truncated_errors: bool,
}

/// Contract for adding new deterministic terminal output filters.
///
/// Implementors always receive ANSI-stripped stdout and stderr text.
pub trait CommandFilter: Send + Sync {
    fn id(&self) -> &'static str;
    fn matches(&self, program: &str, args: &[String]) -> bool;
    fn filter(&self, raw_clean_stdout: &str, raw_clean_stderr: &str, exit_code: i32)
    -> FilteredRun;
}

// ---------------------------------------------------------------------------
// 3. HostAdapter — Pluggable AI host integration slot (Phase 3B+)
// ---------------------------------------------------------------------------

/// Detection state of an AI coding host on the user's machine or project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostDetectStatus {
    NotDetected,
    Detected { config_path: PathBuf },
    Installed { config_path: PathBuf },
}

/// Shared context passed to [`HostAdapter`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterContext {
    pub project_root: PathBuf,
    pub binary_path: PathBuf,
    pub dry_run: bool,
}

/// Summary report returned by [`HostAdapter::install_or_update`] and [`HostAdapter::uninstall`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    pub host_id: String,
    pub changed: bool,
    pub dry_run: bool,
    pub files_touched: Vec<PathBuf>,
    pub notes: Vec<String>,
}

/// Severity of a diagnostic check returned by `klens doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckSeverity {
    Ok,
    Warning,
    Error,
}

/// Single diagnostic check item for a host adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub severity: CheckSeverity,
    pub message: String,
}

/// Contract for integrating AI coding hosts (Antigravity, Claude Code, Codex, Generic).
pub trait HostAdapter: Send + Sync {
    fn host_id(&self) -> &'static str;
    fn detect(&self, project_root: &Path) -> HostDetectStatus;
    fn install_or_update(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError>;
    fn uninstall(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError>;
    fn doctor(&self, ctx: &AdapterContext) -> Vec<DoctorCheck>;
}

// ---------------------------------------------------------------------------
// 4. ExtensionSlot — Opt-in out-of-core extensions (Phase 6+)
// ---------------------------------------------------------------------------

/// Contract for opt-in, default-disabled extensions (e.g., LSP bridge, LLM provider).
pub trait ExtensionSlot: Send + Sync {
    fn extension_id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn description(&self) -> &'static str;

    /// Core extensions are always opt-in and disabled by default.
    fn is_enabled_by_default(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHostAdapter;

    impl HostAdapter for MockHostAdapter {
        fn host_id(&self) -> &'static str {
            "mock"
        }

        fn detect(&self, _project_root: &Path) -> HostDetectStatus {
            HostDetectStatus::NotDetected
        }

        fn install_or_update(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError> {
            Ok(InstallReport {
                host_id: self.host_id().to_string(),
                changed: !ctx.dry_run,
                dry_run: ctx.dry_run,
                files_touched: vec![ctx.project_root.join(".mock-config.json")],
                notes: vec!["planned install".to_string()],
            })
        }

        fn uninstall(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError> {
            Ok(InstallReport {
                host_id: self.host_id().to_string(),
                changed: !ctx.dry_run,
                dry_run: ctx.dry_run,
                files_touched: vec![ctx.project_root.join(".mock-config.json")],
                notes: vec!["dry-run uninstall preview".to_string()],
            })
        }

        fn doctor(&self, _ctx: &AdapterContext) -> Vec<DoctorCheck> {
            Vec::new()
        }
    }

    #[test]
    fn host_adapter_uninstall_reports_dry_run_plan() {
        let adapter = MockHostAdapter;
        let ctx = AdapterContext {
            project_root: PathBuf::from("project"),
            binary_path: PathBuf::from("klens"),
            dry_run: true,
        };
        let report = adapter.uninstall(&ctx).unwrap();
        assert_eq!(report.host_id, "mock");
        assert!(report.dry_run);
        assert!(!report.changed);
        assert_eq!(report.files_touched.len(), 1);
    }
}
