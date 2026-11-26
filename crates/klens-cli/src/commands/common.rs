use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use klens_adapters::AdapterError;
use klens_blueprint::BlueprintError;
use klens_code::{CodeError, CodeIndex, FileSyncOutcome, ParseStatus};
use klens_core::{KlensError, ProjectRoot, RelPath, normalize_line_endings};
use klens_exec::ExecError;
use klens_mcp::McpError;
use klens_memory::{MemoryError, SymbolLookupResult, SymbolResolver};
use klens_ui::UiError;

pub(crate) struct CliOutcome {
    pub output: Option<String>,
    pub exit_code: ExitCode,
}

impl CliOutcome {
    pub(crate) fn ok(output: String) -> Self {
        Self {
            output: Some(output),
            exit_code: ExitCode::SUCCESS,
        }
    }

    pub(crate) fn silent_ok() -> Self {
        Self {
            output: None,
            exit_code: ExitCode::SUCCESS,
        }
    }
}

#[derive(Debug)]
pub(crate) enum CliError {
    Adapter(AdapterError),
    Blueprint(BlueprintError),
    Code(CodeError),
    Exec(ExecError),
    Mcp(McpError),
    Memory(MemoryError),
    Ui(UiError),
    Core(KlensError),
    InvalidArgument(String),
    ReadOnly(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adapter(e) => write!(f, "{e}"),
            Self::Blueprint(e) => write!(f, "{e}"),
            Self::Code(e) => write!(f, "{e}"),
            Self::Exec(e) => write!(f, "{e}"),
            Self::Mcp(e) => write!(f, "{e}"),
            Self::Memory(e) => write!(f, "{e}"),
            Self::Ui(e) => write!(f, "{e}"),
            Self::Core(e) => write!(f, "{e}"),
            Self::InvalidArgument(msg) => write!(f, "{msg}"),
            Self::ReadOnly(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<AdapterError> for CliError {
    fn from(value: AdapterError) -> Self {
        Self::Adapter(value)
    }
}

impl From<BlueprintError> for CliError {
    fn from(value: BlueprintError) -> Self {
        Self::Blueprint(value)
    }
}

impl From<CodeError> for CliError {
    fn from(value: CodeError) -> Self {
        Self::Code(value)
    }
}

impl From<ExecError> for CliError {
    fn from(value: ExecError) -> Self {
        Self::Exec(value)
    }
}

impl From<McpError> for CliError {
    fn from(value: McpError) -> Self {
        Self::Mcp(value)
    }
}

impl From<MemoryError> for CliError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<UiError> for CliError {
    fn from(value: UiError) -> Self {
        Self::Ui(value)
    }
}

/// Tree-sitter AST symbol resolver borrowing an already-open [`CodeIndex`].
pub(crate) struct BorrowedCodeSymbolResolver<'a> {
    index: &'a mut CodeIndex,
}

impl<'a> BorrowedCodeSymbolResolver<'a> {
    pub(crate) fn new(index: &'a mut CodeIndex) -> Self {
        Self { index }
    }
}

impl SymbolResolver for BorrowedCodeSymbolResolver<'_> {
    fn resolve_symbol(&mut self, path: &RelPath, symbol: &str) -> SymbolLookupResult {
        match self.index.sync_file(path) {
            Ok(FileSyncOutcome::SkippedBinary) => {
                return SymbolLookupResult::Unparsed("binary or non-UTF-8 file".to_string());
            }
            Ok(FileSyncOutcome::Parsed | FileSyncOutcome::Unchanged) => {}
            Err(err) => return SymbolLookupResult::Unparsed(err.to_string()),
        }

        if let Ok(Some(rec)) = self.index.store().get_file(path)
            && rec.parse_status == ParseStatus::Fallback
        {
            return SymbolLookupResult::Unparsed(
                rec.parse_warning
                    .unwrap_or_else(|| "unsupported language or syntax error".to_string()),
            );
        }

        let Ok(symbols) = self.index.store().get_symbols_for_file(path) else {
            return SymbolLookupResult::Missing;
        };

        let query = symbol.trim();
        let exact: Vec<_> = symbols
            .iter()
            .filter(|s| s.qualified_name == query)
            .collect();
        let candidates = if !exact.is_empty() {
            exact
        } else {
            symbols.iter().filter(|s| s.name == query).collect()
        };

        match candidates.as_slice() {
            [] => SymbolLookupResult::Missing,
            [sym] => {
                let Ok((abs, _)) = self.index.project_root().resolve_existing(path.as_str()) else {
                    return SymbolLookupResult::Missing;
                };
                let Ok(raw) = fs::read_to_string(&abs) else {
                    return SymbolLookupResult::Missing;
                };
                let normalized = normalize_line_endings(&raw);
                let lines: Vec<&str> = normalized.lines().collect();
                if sym.start_line == 0
                    || sym.end_line < sym.start_line
                    || sym.end_line > lines.len()
                {
                    return SymbolLookupResult::Missing;
                }
                let snippet = lines[sym.start_line - 1..sym.end_line].join("\n");
                SymbolLookupResult::Found {
                    qualified_name: sym.qualified_name.clone(),
                    source_snippet: snippet,
                    start_line: sym.start_line,
                    end_line: sym.end_line,
                }
            }
            many => SymbolLookupResult::Ambiguous(
                many.iter().map(|s| s.qualified_name.clone()).collect(),
            ),
        }
    }
}

impl From<KlensError> for CliError {
    fn from(value: KlensError) -> Self {
        Self::Core(value)
    }
}

pub(crate) fn resolve_project_root(
    positional: Option<&Path>,
    explicit_root: Option<&Path>,
) -> Result<ProjectRoot, CodeError> {
    let dir = match (explicit_root, positional) {
        (Some(root), _) => root.to_path_buf(),
        (None, Some(path)) => path.to_path_buf(),
        (None, None) => std::env::current_dir().map_err(|source| CodeError::Io {
            path: PathBuf::from("."),
            source,
        })?,
    };
    Ok(ProjectRoot::new(dir)?)
}

pub(crate) fn resolve_root_and_rel(
    target: &Path,
    explicit_root: Option<&Path>,
) -> Result<(ProjectRoot, Option<RelPath>), CodeError> {
    if let Some(root_arg) = explicit_root {
        let project_root = ProjectRoot::new(root_arg)?;
        if target == Path::new(".") || target.as_os_str().is_empty() {
            return Ok((project_root, None));
        }
        if target.is_absolute() {
            let canonical_target =
                std::fs::canonicalize(target).map_err(|source| CodeError::Io {
                    path: target.to_path_buf(),
                    source,
                })?;
            if canonical_target == project_root.root() {
                return Ok((project_root, None));
            }
            let stripped = canonical_target
                .strip_prefix(project_root.root())
                .map_err(|_| klens_core::PathError::EscapesRoot(target.display().to_string()))?;
            let rel = RelPath::from_relative_path(stripped)?;
            return Ok((project_root, Some(rel)));
        }
        let rel = RelPath::from_relative_path(target)?;
        return Ok((project_root, Some(rel)));
    }

    if target.is_absolute() {
        let meta = std::fs::metadata(target).map_err(|source| CodeError::Io {
            path: target.to_path_buf(),
            source,
        })?;
        if meta.is_dir() {
            let project_root = ProjectRoot::new(target)?;
            return Ok((project_root, None));
        }
        let inferred_root = infer_project_root_for_file(target);
        let project_root = ProjectRoot::new(&inferred_root)?;
        let canonical_target = std::fs::canonicalize(target).map_err(|source| CodeError::Io {
            path: target.to_path_buf(),
            source,
        })?;
        let stripped = canonical_target
            .strip_prefix(project_root.root())
            .map_err(|_| klens_core::PathError::EscapesRoot(target.display().to_string()))?;
        let rel = RelPath::from_relative_path(stripped)?;
        return Ok((project_root, Some(rel)));
    }

    let cwd = std::env::current_dir().map_err(|source| CodeError::Io {
        path: PathBuf::from("."),
        source,
    })?;
    let project_root = ProjectRoot::new(cwd)?;
    if target == Path::new(".") || target.as_os_str().is_empty() {
        return Ok((project_root, None));
    }
    let rel = RelPath::from_relative_path(target)?;
    Ok((project_root, Some(rel)))
}

fn infer_project_root_for_file(file_path: &Path) -> PathBuf {
    let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
    const MARKERS: &[&str] = &[
        ".git",
        ".klens",
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
    ];
    for ancestor in parent.ancestors() {
        if MARKERS.iter().any(|m| ancestor.join(m).exists()) {
            return ancestor.to_path_buf();
        }
    }
    parent.to_path_buf()
}
