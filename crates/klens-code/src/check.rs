//! `klens check`: re-parse files right after an edit and report every syntax error
//! (`ERROR` / `MISSING` node) with line, column, enclosing symbol, and a short snippet.
//!
//! Honesty rules: only files really parsed by a built-in grammar (or a strict JSON/TOML parser)
//! can be reported `OK`. Files without a built-in parser are listed as "not checked"
//! (`UNPARSED_FALLBACK`); files owned by an external sidecar (ctags or a custom `ext-lang-*`)
//! are `EXTERNAL_PARSER`, which cannot detect syntax errors, and are never reported `OK`.

use std::fs;

use klens_core::{
    PathError, ProvenanceEnvelope, RelPath, TrustLevel, normalize_line_endings, redact_secrets,
};
use serde::{Deserialize, Serialize};
use tree_sitter::{Language, Node};

use crate::check_quirks::{
    is_header_path, is_jsonc_config_path, near_preprocessor_conditional, strip_jsonc,
};
use crate::diff_check::changed_paths;
use crate::error::CodeError;
use crate::git::{is_git_repo, show_staged_file};
use crate::index::{CodeIndex, MAX_INDEXABLE_BYTES, is_binary_bytes};
use crate::languages::AnalyzerRegistry;
use crate::languages::common::{collect_syntax_problem_nodes, parse_tree_lenient};
use crate::languages::ts_js::parse_ts_js_tree_lenient;
use crate::sidecar::ExternalParserSlot;

/// Problems listed per file; the rest are counted and reported as omitted.
pub const MAX_PROBLEMS_PER_FILE: usize = 20;

/// Longest snippet of the offending line shown per problem (in characters).
const SNIPPET_MAX_CHARS: usize = 80;

/// Longest unexpected-token excerpt shown in a problem message (in characters).
const TOKEN_MAX_CHARS: usize = 24;

/// What `klens check` validates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckTarget {
    /// Explicit files, as typed by the user or agent (relative, or absolute inside the project).
    Paths(Vec<String>),
    /// Files changed in the current git diff; `staged` checks the staged (index) content.
    Diff { staged: bool },
}

impl CheckTarget {
    /// Build a target from raw inputs: `["diff"]`, `["diff:staged"]`, or a list of paths.
    pub fn from_inputs(inputs: &[String]) -> Result<Self, String> {
        let cleaned: Vec<String> = inputs
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if cleaned.is_empty() {
            return Err("give at least one file path, or `diff` / `diff:staged`".to_string());
        }
        let is_diff = |s: &str| s == "diff" || s == "diff:staged";
        if cleaned.iter().any(|s| is_diff(s)) {
            if cleaned.len() > 1 {
                return Err("`diff` / `diff:staged` cannot be combined with file paths".to_string());
            }
            return Ok(Self::Diff {
                staged: cleaned[0] == "diff:staged",
            });
        }
        Ok(Self::Paths(cleaned))
    }

    fn mode_label(&self) -> &'static str {
        match self {
            Self::Paths(_) => "paths",
            Self::Diff { staged: false } => "diff",
            Self::Diff { staged: true } => "diff:staged",
        }
    }
}

/// Outcome for one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckFileStatus {
    /// Parsed by a built-in parser with no syntax errors.
    Ok,
    /// Parsed by a built-in parser; syntax errors found.
    SyntaxErrors,
    /// Read, but no parser here can detect syntax errors in it (never means OK).
    NotChecked,
    /// Not read at all (sensitive, missing, outside the project, unreadable).
    Skipped,
}

/// Kind of syntax problem reported by Tree-sitter or a strict document parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxProblemKind {
    /// Unexpected text the grammar could not place (`ERROR` node, or a JSON/TOML parse error).
    Error,
    /// A token the grammar expected but did not find (`MISSING` node).
    Missing,
}

/// One syntax problem with its position (1-based line and character column).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntaxProblem {
    pub line: usize,
    pub column: usize,
    pub kind: SyntaxProblemKind,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub snippet: String,
}

/// Result for one checked (or skipped) file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckedFile {
    pub path: String,
    pub status: CheckFileStatus,
    pub trust: TrustLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Listed problems (at most [`MAX_PROBLEMS_PER_FILE`]).
    pub problems: Vec<SyntaxProblem>,
    /// All problems found, including the ones not listed.
    pub problems_total: usize,
    /// Why a file is `not_checked` or `skipped`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload returned by `klens check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckPayload {
    /// `paths`, `diff`, or `diff:staged`.
    pub mode: String,
    /// `false` only when diff mode ran outside a git repository.
    pub is_git_repo: bool,
    pub files: Vec<CheckedFile>,
    pub ok_files: usize,
    pub error_files: usize,
    pub problems_total: usize,
    pub not_checked_files: usize,
}

impl CheckPayload {
    /// `true` when at least one file has syntax errors.
    pub fn has_syntax_errors(&self) -> bool {
        self.error_files > 0
    }
}

/// Re-parse the target files and report syntax errors with honest trust levels.
pub fn check_files(
    index: &mut CodeIndex,
    target: &CheckTarget,
) -> Result<ProvenanceEnvelope<CheckPayload>, CodeError> {
    let root = index.project_root().root().to_path_buf();
    let project_id = index.project_root().project_id().to_string();
    let registry = AnalyzerRegistry::new();
    let mut files: Vec<CheckedFile> = Vec::new();
    let mut redactions = 0usize;
    let mut warnings: Vec<String> = Vec::new();
    let mut is_repo = true;

    match target {
        CheckTarget::Paths(inputs) => {
            let mut seen = std::collections::BTreeSet::new();
            for raw in inputs {
                let file = check_input_path(index, &registry, raw, &mut redactions);
                if seen.insert(file.path.clone()) {
                    files.push(file);
                }
            }
        }
        CheckTarget::Diff { staged } => {
            if is_git_repo(&root) {
                for (path, kind) in changed_paths(&root, *staged) {
                    if kind == "deleted" || kind == "renamed_from" {
                        continue;
                    }
                    let Ok(rel) = RelPath::normalize(&path) else {
                        continue;
                    };
                    let file = if *staged {
                        check_staged_path(index, &registry, &rel, &mut redactions)
                    } else {
                        check_rel_path(index, &registry, &rel, &mut redactions)
                    };
                    files.push(file);
                }
                if files.is_empty() {
                    warnings.push("no changed files in the git diff; nothing to check".to_string());
                }
            } else {
                is_repo = false;
                warnings.push("project is not a git repository; diff mode checked nothing".into());
            }
        }
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));

    let ok_files = count_status(&files, CheckFileStatus::Ok);
    let error_files = count_status(&files, CheckFileStatus::SyntaxErrors);
    let not_checked_files = files.len() - ok_files - error_files;
    let problems_total = files.iter().map(|f| f.problems_total).sum();

    // The envelope is only as trustworthy as its weakest file (`TrustLevel` orders strongest first).
    let trust = if files.is_empty() {
        TrustLevel::UnparsedFallback
    } else {
        files
            .iter()
            .map(|f| f.trust)
            .max()
            .unwrap_or(TrustLevel::UnparsedFallback)
    };

    let payload = CheckPayload {
        mode: target.mode_label().to_string(),
        is_git_repo: is_repo,
        files,
        ok_files,
        error_files,
        problems_total,
        not_checked_files,
    };
    let mut env =
        ProvenanceEnvelope::new(trust, project_id, payload).with_redactions_count(redactions);
    for w in warnings {
        env = env.with_warning(w);
    }
    Ok(env)
}

fn count_status(files: &[CheckedFile], status: CheckFileStatus) -> usize {
    files.iter().filter(|f| f.status == status).count()
}

fn skipped(path: &str, reason: impl Into<String>) -> CheckedFile {
    CheckedFile {
        path: path.to_string(),
        status: CheckFileStatus::Skipped,
        trust: TrustLevel::UnparsedFallback,
        language: None,
        problems: Vec::new(),
        problems_total: 0,
        reason: Some(reason.into()),
    }
}

fn not_checked(
    path: &str,
    trust: TrustLevel,
    language: Option<String>,
    reason: impl Into<String>,
) -> CheckedFile {
    CheckedFile {
        path: path.to_string(),
        status: CheckFileStatus::NotChecked,
        trust,
        language,
        problems: Vec::new(),
        problems_total: 0,
        reason: Some(reason.into()),
    }
}

fn check_input_path(
    index: &mut CodeIndex,
    registry: &AnalyzerRegistry,
    raw: &str,
    redactions: &mut usize,
) -> CheckedFile {
    match index.project_root().relative_input(raw) {
        Ok(rel) => check_rel_path(index, registry, &rel, redactions),
        Err(PathError::OutsideProject { .. }) => skipped(raw, "outside the project; not read"),
        Err(_) => skipped(raw, "invalid path; not read"),
    }
}

/// Check the working-tree content of a project file (confined, sensitive files never read).
fn check_rel_path(
    index: &mut CodeIndex,
    registry: &AnalyzerRegistry,
    rel: &RelPath,
    redactions: &mut usize,
) -> CheckedFile {
    let display = rel.as_str().to_string();
    if index.project_config().is_sensitive_file(rel) {
        return skipped(&display, "sensitive file; not read");
    }
    let resolved = index.project_root().resolve_existing_with_extra(
        rel.as_str(),
        &index.project_config().extra_sensitive_patterns,
    );
    let (abs, canonical) = match resolved {
        Ok(pair) => pair,
        Err(PathError::SensitiveFileBlocked(_)) => {
            return skipped(&display, "sensitive file; not read");
        }
        Err(PathError::Io { .. }) => return skipped(&display, "file not found"),
        Err(_) => return skipped(&display, "outside the project; not read"),
    };
    let display = canonical.as_str().to_string();
    let Ok(meta) = fs::metadata(&abs) else {
        return skipped(&display, "file not found");
    };
    if !meta.is_file() {
        return skipped(&display, "not a regular file");
    }
    if meta.len() > MAX_INDEXABLE_BYTES {
        return not_checked(
            &display,
            TrustLevel::UnparsedFallback,
            None,
            "file too large",
        );
    }
    let Ok(bytes) = fs::read(&abs) else {
        return skipped(&display, "file could not be read");
    };
    if is_binary_bytes(&bytes) {
        return not_checked(&display, TrustLevel::UnparsedFallback, None, "binary file");
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return not_checked(
            &display,
            TrustLevel::UnparsedFallback,
            None,
            "not UTF-8 text",
        );
    };
    check_source(index, registry, &canonical, text, redactions)
}

/// Check the staged (git index) content of a changed file.
fn check_staged_path(
    index: &mut CodeIndex,
    registry: &AnalyzerRegistry,
    rel: &RelPath,
    redactions: &mut usize,
) -> CheckedFile {
    let display = rel.as_str().to_string();
    if index.project_config().is_sensitive_file(rel) {
        return skipped(&display, "sensitive file; not read");
    }
    let root = index.project_root().root().to_path_buf();
    let Some(text) = show_staged_file(&root, rel.as_str()) else {
        return skipped(&display, "staged content could not be read");
    };
    if text.len() as u64 > MAX_INDEXABLE_BYTES {
        return not_checked(
            &display,
            TrustLevel::UnparsedFallback,
            None,
            "file too large",
        );
    }
    if text.as_bytes().contains(&0) {
        return not_checked(&display, TrustLevel::UnparsedFallback, None, "binary file");
    }
    check_source(index, registry, rel, &text, redactions)
}

/// Route source text to the right parser and collect its syntax problems.
fn check_source(
    index: &mut CodeIndex,
    registry: &AnalyzerRegistry,
    rel: &RelPath,
    raw_text: &str,
    redactions: &mut usize,
) -> CheckedFile {
    let path = rel.as_str();
    let source = normalize_line_endings(raw_text);

    let Some(analyzer) = registry.analyzer_for_path(rel) else {
        return match index.external_parser_slot(rel) {
            Some(ExternalParserSlot::Ctags { .. }) => not_checked(
                path,
                TrustLevel::ExternalParser,
                Some("ctags".to_string()),
                "ctags sidecar cannot detect syntax errors",
            ),
            Some(ExternalParserSlot::CustomRpc { parser_id, .. }) => not_checked(
                path,
                TrustLevel::ExternalParser,
                Some(parser_id),
                "external parser sidecar cannot detect syntax errors",
            ),
            Some(ExternalParserSlot::CtagsUnavailable { .. }) | None => not_checked(
                path,
                TrustLevel::UnparsedFallback,
                None,
                "no built-in parser",
            ),
        };
    };

    let language_id = analyzer.language_id();
    if language_id == "structured_doc" {
        return check_structured_doc(rel, &source, redactions);
    }

    let tree = if language_id == "typescript" {
        parse_ts_js_tree_lenient(&source, rel)
    } else {
        match builtin_grammar(language_id) {
            Some(lang) => parse_tree_lenient(&lang, &source),
            None => Err(format!("no grammar registered for `{language_id}`")),
        }
    };
    let mut tree = match tree {
        Ok(tree) => tree,
        Err(reason) => {
            return not_checked(
                path,
                TrustLevel::UnparsedFallback,
                Some(language_id.to_string()),
                reason,
            );
        }
    };

    // A `.h` header may be C++: when the C grammar fails, accept a clean C++ parse.
    let mut language = language_id;
    if language_id == "c" && tree.root_node().has_error() && is_header_path(path) {
        let cpp: Language = tree_sitter_cpp::LANGUAGE.into();
        if let Ok(cpp_tree) = parse_tree_lenient(&cpp, &source)
            && !cpp_tree.root_node().has_error()
        {
            tree = cpp_tree;
            language = "cpp";
        }
    }

    let lines: Vec<&str> = source.lines().collect();
    let mut nodes = collect_syntax_problem_nodes(tree.root_node());

    // C/C++ grammars parse without running the preprocessor, so `#if`/`#ifdef` blocks that split
    // a construct (e.g. the `extern "C" {` guard) produce errors that are not real. Never report
    // those as certain errors.
    let mut preprocessor_doubtful = 0usize;
    if matches!(language, "c" | "cpp") {
        let before = nodes.len();
        nodes.retain(|n| !near_preprocessor_conditional(*n));
        preprocessor_doubtful = before - nodes.len();
        if nodes.is_empty() && preprocessor_doubtful > 0 {
            return not_checked(
                path,
                TrustLevel::UnparsedFallback,
                Some(language.to_string()),
                "#if/#ifdef blocks confuse the C/C++ parser",
            );
        }
    }

    let problems_total = nodes.len();
    let problems: Vec<SyntaxProblem> = nodes
        .into_iter()
        .take(MAX_PROBLEMS_PER_FILE)
        .map(|node| problem_from_node(node, &source, &lines, redactions))
        .collect();

    CheckedFile {
        path: path.to_string(),
        status: if problems_total == 0 {
            CheckFileStatus::Ok
        } else {
            CheckFileStatus::SyntaxErrors
        },
        trust: TrustLevel::VerifiedAst,
        language: Some(language.to_string()),
        problems,
        problems_total,
        reason: (preprocessor_doubtful > 0).then(|| {
            format!("{preprocessor_doubtful} more possible errors next to #if/#ifdef not listed")
        }),
    }
}

/// Tree-sitter grammar for a built-in language id (TypeScript/JavaScript handled separately).
fn builtin_grammar(language_id: &str) -> Option<Language> {
    let lang: Language = match language_id {
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "csharp" => tree_sitter_c_sharp::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        _ => return None,
    };
    Some(lang)
}

fn problem_from_node(
    node: Node<'_>,
    source: &str,
    lines: &[&str],
    redactions: &mut usize,
) -> SyntaxProblem {
    let pos = node.start_position();
    let line_text = lines.get(pos.row).copied().unwrap_or("");
    let column = char_column(line_text, pos.column);

    let (kind, raw_message) = if node.is_missing() {
        (
            SyntaxProblemKind::Missing,
            format!("missing `{}`", node.kind()),
        )
    } else {
        // First leaf token inside the ERROR node (e.g. `(` rather than `(1`).
        let mut cursor = node.walk();
        while cursor.goto_first_child() {}
        let leaf = cursor.node();
        let text = source.get(leaf.byte_range()).unwrap_or("");
        let token = text.split_whitespace().next().unwrap_or("");
        let message = if token.is_empty() {
            "syntax error".to_string()
        } else {
            format!("unexpected `{}`", truncate_chars(token, TOKEN_MAX_CHARS))
        };
        (SyntaxProblemKind::Error, message)
    };

    let message = redact_secrets(&raw_message);
    let snippet = redact_secrets(line_text.trim());
    *redactions += message.redactions_count + snippet.redactions_count;

    SyntaxProblem {
        line: pos.row + 1,
        column,
        kind,
        message: message.text,
        symbol: enclosing_symbol(node, source),
        snippet: truncate_chars(&snippet.text, SNIPPET_MAX_CHARS),
    }
}

/// Node kinds that name a scope worth reporting (functions, types, modules).
const SCOPE_KIND_HINTS: &[&str] = &[
    "function",
    "method",
    "class",
    "struct",
    "impl",
    "trait",
    "enum",
    "interface",
    "module",
    "namespace",
    "mod_item",
    "constructor",
    "union",
];

/// Names of the enclosing scopes (outermost first, `::`-joined), if the tree still has them.
fn enclosing_symbol(node: Node<'_>, source: &str) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        let kind = ancestor.kind();
        let is_scope = SCOPE_KIND_HINTS.iter().any(|hint| kind.contains(hint))
            && !kind.contains("call")
            && !kind.contains("invocation");
        if is_scope {
            let name_node = ancestor.child_by_field_name("name").or_else(|| {
                if kind == "impl_item" {
                    ancestor.child_by_field_name("type")
                } else {
                    None
                }
            });
            if let Some(name_node) = name_node
                && !name_node.has_error()
                && let Some(name) = source.get(name_node.byte_range())
            {
                let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
                if !name.is_empty() && name.len() <= 80 {
                    names.push(name);
                }
            }
        }
        if names.len() >= 3 {
            break;
        }
        current = ancestor.parent();
    }
    if names.is_empty() {
        return None;
    }
    names.reverse();
    let joined = names.join("::");
    Some(redact_secrets(&joined).text)
}

/// Strict JSON parse error as `(line, column, message)`, or `None` when valid.
fn json_failure(source: &str) -> Option<(usize, usize, String)> {
    serde_json::from_str::<serde_json::Value>(source)
        .err()
        .map(|err| {
            let full = err.to_string();
            let message = full
                .rfind(" at line ")
                .map_or(full.as_str(), |idx| &full[..idx])
                .to_string();
            (err.line().max(1), err.column().max(1), message)
        })
}

/// JSON and TOML get a strict parser; Markdown and YAML have no validator here.
fn check_structured_doc(rel: &RelPath, source: &str, redactions: &mut usize) -> CheckedFile {
    let path = rel.as_str();
    let ext = path
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let lines: Vec<&str> = source.lines().collect();

    let (language, failure): (&str, Option<(usize, usize, String)>) = match ext.as_str() {
        "json" => match json_failure(source) {
            None => ("json", None),
            Some(strict_err) => {
                // JSON with comments / trailing commas (JSONC) is normal for tsconfig, VS Code
                // settings, devcontainers...: validate those as JSONC instead of failing them.
                let (stripped, had_comments) = strip_jsonc(source);
                let config = is_jsonc_config_path(path);
                if !had_comments && !config {
                    ("json", Some(strict_err))
                } else {
                    match json_failure(&stripped) {
                        None if config => ("jsonc", None),
                        None => {
                            return not_checked(
                                path,
                                TrustLevel::UnparsedFallback,
                                Some("jsonc".to_string()),
                                "JSON with comments; fine only if its reader accepts JSONC",
                            );
                        }
                        Some(err) => ("jsonc", Some(err)),
                    }
                }
            }
        },
        "toml" => (
            "toml",
            toml::from_str::<toml::Value>(source).err().map(|err| {
                let message = err
                    .message()
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                match err.span() {
                    Some(span) => {
                        let before = source.get(..span.start.min(source.len())).unwrap_or("");
                        let line = before.matches('\n').count() + 1;
                        let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
                        (line, column, message)
                    }
                    None => (1, 1, message),
                }
            }),
        ),
        "md" | "markdown" => {
            return not_checked(
                path,
                TrustLevel::UnparsedFallback,
                Some("markdown".to_string()),
                "Markdown has no syntax to validate",
            );
        }
        _ => {
            return not_checked(
                path,
                TrustLevel::UnparsedFallback,
                Some("yaml".to_string()),
                "no YAML validator",
            );
        }
    };

    let Some((line, column, raw_message)) = failure else {
        return CheckedFile {
            path: path.to_string(),
            status: CheckFileStatus::Ok,
            trust: TrustLevel::VerifiedAst,
            language: Some(language.to_string()),
            problems: Vec::new(),
            problems_total: 0,
            reason: None,
        };
    };

    let line_text = lines.get(line.saturating_sub(1)).copied().unwrap_or("");
    let message = redact_secrets(if raw_message.is_empty() {
        "syntax error"
    } else {
        &raw_message
    });
    let snippet = redact_secrets(line_text.trim());
    *redactions += message.redactions_count + snippet.redactions_count;

    CheckedFile {
        path: path.to_string(),
        status: CheckFileStatus::SyntaxErrors,
        trust: TrustLevel::VerifiedAst,
        language: Some(language.to_string()),
        problems: vec![SyntaxProblem {
            line,
            column,
            kind: SyntaxProblemKind::Error,
            message: message.text,
            symbol: None,
            snippet: truncate_chars(&snippet.text, SNIPPET_MAX_CHARS),
        }],
        problems_total: 1,
        reason: None,
    }
}

/// Convert a Tree-sitter byte column into a 1-based character column.
fn char_column(line_text: &str, byte_column: usize) -> usize {
    let mut cut = byte_column.min(line_text.len());
    while cut > 0 && !line_text.is_char_boundary(cut) {
        cut -= 1;
    }
    line_text[..cut].chars().count() + 1
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_code_extension_has_a_grammar() {
        let registry = AnalyzerRegistry::new();
        for ext in registry.all_extensions() {
            let rel = RelPath::normalize(&format!("sample.{ext}")).unwrap();
            let analyzer = registry.analyzer_for_path(&rel).unwrap();
            let id = analyzer.language_id();
            if id == "structured_doc" {
                continue;
            }
            if id == "typescript" {
                assert!(parse_ts_js_tree_lenient("let a = 1;\n", &rel).is_ok());
                continue;
            }
            assert!(
                builtin_grammar(id).is_some(),
                "extension `{ext}` ({id}) has no grammar in klens check"
            );
        }
    }

    #[test]
    fn target_inputs_parse_diff_and_paths() {
        assert_eq!(
            CheckTarget::from_inputs(&["diff".to_string()]).unwrap(),
            CheckTarget::Diff { staged: false }
        );
        assert_eq!(
            CheckTarget::from_inputs(&[" diff:staged ".to_string()]).unwrap(),
            CheckTarget::Diff { staged: true }
        );
        assert!(CheckTarget::from_inputs(&[]).is_err());
        assert!(CheckTarget::from_inputs(&["diff".to_string(), "a.rs".to_string()]).is_err());
        assert_eq!(
            CheckTarget::from_inputs(&["a.rs".to_string()]).unwrap(),
            CheckTarget::Paths(vec!["a.rs".to_string()])
        );
    }

    #[test]
    fn char_column_handles_multibyte_text() {
        assert_eq!(char_column("ğüş x", "ğüş ".len()), 5);
        assert_eq!(char_column("abc", 99), 4);
    }
}
