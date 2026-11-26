//! Shared wire protocol DTOs, safety constants, minimal environment hygiene,
//! Windows `CREATE_NO_WINDOW` + process-tree termination, and core validation/redaction
//! gate for out-of-core `ext-lang-*` language parser sidecars.
//!
//! Strict leaf module: depends only on `std`, `serde`, `serde_json`, `klens_core`, and `store`.

use std::collections::BTreeSet;
use std::process::Command;

use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, RelPath, SymbolInfo, SymbolKind, redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::store::ParseStatus;

/// Hard ceiling for a single JSON-RPC line / ctags frame (4 MiB).
pub const MAX_RPC_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Wall-clock timeout for `ext/initialize` and `ext/capabilities` handshakes (ms).
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 3_000;

/// Wall-clock timeout for graceful `ext/shutdown` (ms).
pub const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 2_000;

/// Default wall-clock timeout for `ext/parse_file` (ms).
pub const DEFAULT_PARSE_TIMEOUT_MS: u64 = 3_000;

/// Wall-clock timeout for `ctags --version` / `--list-features` probes (ms).
pub const CTAGS_PROBE_TIMEOUT_MS: u64 = 2_000;

/// Maximum stderr diagnostic bytes captured per sidecar session (64 KiB).
pub const MAX_STDERR_BYTES: usize = 64 * 1024;

/// Maximum symbols accepted from a single external sidecar parse response (DoS guard).
pub const MAX_SYMBOLS_PER_FILE: usize = 10_000;

/// Maximum imports accepted from a single external sidecar parse response (DoS guard).
pub const MAX_IMPORTS_PER_FILE: usize = 5_000;

/// Maximum symbol short name length in bytes.
pub const MAX_SYMBOL_NAME_BYTES: usize = 256;

/// Maximum symbol qualified_name / parent_symbol length in bytes.
pub const MAX_QUALIFIED_NAME_BYTES: usize = 512;

/// Maximum symbol signature length in bytes before UTF-8-safe truncation.
pub const MAX_SIGNATURE_BYTES: usize = 1024;

/// Maximum import specifier length in bytes.
pub const MAX_IMPORT_SPECIFIER_BYTES: usize = 512;

/// Consecutive hard failures (crash, timeout, protocol violation) before opening circuit breaker.
pub const CIRCUIT_BREAKER_THRESHOLD: u32 = 3;

/// Windows `CREATE_NO_WINDOW` creation flag (`0x0800_0000`).
pub const WINDOWS_CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Configure a subprocess command so Windows never flashes a console window.
pub(crate) fn configure_no_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(WINDOWS_CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

/// Terminate a subprocess and its entire descendant tree without flashing a console window.
pub(crate) fn kill_process_tree(pid: u32) {
    #[cfg(windows)]
    {
        use std::process::Stdio;
        let mut kill_cmd = Command::new("taskkill");
        kill_cmd
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_no_window(&mut kill_cmd);
        let _ = kill_cmd.status();
    }
    #[cfg(not(windows))]
    {
        use std::process::Stdio;
        let _ = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Strip parent environment (`env_clear`), pass only minimal OS baseline variables plus
/// `KLENS_PROTOCOL_VERSION=1`, `KLENS_READ_ONLY=1`, `KLENS_EXTENSION_ID=<id>`,
/// and isolate working directory to `std::env::temp_dir()`.
pub(crate) fn apply_minimal_sidecar_env(cmd: &mut Command, extension_id: &str) {
    cmd.env_clear();
    #[cfg(windows)]
    const BASELINE_VARS: &[&str] = &["SYSTEMROOT", "PATH", "PATHEXT", "TEMP", "TMP"];
    #[cfg(not(windows))]
    const BASELINE_VARS: &[&str] = &["PATH", "TMPDIR", "LANG", "LC_ALL"];

    for var in BASELINE_VARS {
        if let Some(val) = std::env::var_os(var) {
            cmd.env(var, val);
        }
    }
    cmd.env("KLENS_PROTOCOL_VERSION", "1");
    cmd.env("KLENS_READ_ONLY", "1");
    cmd.env("KLENS_EXTENSION_ID", extension_id);
    cmd.current_dir(std::env::temp_dir());
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 Wire DTOs (`docs/05-LANGUAGE-SIDECAR-SPEC.md` §4)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcRequest<P> {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'static str,
    pub params: P,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcResponse<R> {
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub result: Option<R>,
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct InitializeParams<'a> {
    pub protocol_version: u32,
    pub klens_version: &'a str,
    pub project_root: Option<&'a str>,
    pub read_only: bool,
    pub capabilities_requested: Vec<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct InitializeResult {
    pub protocol_version: u32,
    pub extension_id: String,
    pub version: String,
    pub requires_network: bool,
    pub supports_read_only: bool,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EmptyParams {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitiesLanguage {
    pub language_id: String,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitiesResult {
    pub protocol_version: u32,
    pub extension_id: String,
    pub parser_id: String,
    pub parser_version: String,
    #[serde(default)]
    pub languages: Vec<CapabilitiesLanguage>,
    #[serde(default)]
    pub supports_byte_ranges: bool,
    #[serde(default)]
    pub supports_imports: bool,
    #[serde(default = "default_cap_max_file_bytes")]
    pub max_file_bytes: u64,
}

const fn default_cap_max_file_bytes() -> u64 {
    klens_core::DEFAULT_MAX_FILE_BYTES
}

#[derive(Debug, Serialize)]
pub(crate) struct ParseFileParams<'a> {
    pub path: &'a str,
    pub language_hint: &'a str,
    pub content: &'a str,
    pub content_blake3: &'a str,
    pub line_ending: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawSidecarSymbol {
    pub name: String,
    #[serde(default)]
    pub qualified_name: Option<String>,
    pub kind: String,
    #[serde(default)]
    pub signature: String,
    pub start_line: usize,
    pub end_line: usize,
    #[serde(default)]
    pub start_byte: Option<usize>,
    #[serde(default)]
    pub end_byte: Option<usize>,
    #[serde(default)]
    pub parent_symbol: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawSidecarImport {
    pub specifier: String,
    pub line: usize,
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ParseFileResult {
    pub schema_version: u32,
    pub trust: String,
    pub status: String,
    pub language_id: String,
    pub parser_id: String,
    pub parser_version: String,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub omissions: Vec<serde_json::Value>,
    #[serde(default)]
    pub symbols: Vec<RawSidecarSymbol>,
    #[serde(default)]
    pub imports: Vec<RawSidecarImport>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ShutdownResult {
    #[serde(default)]
    pub _ok: Option<bool>,
}

// ---------------------------------------------------------------------------
// Validated, Normalized Core Output Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExternalImport {
    pub line: usize,
    pub specifier: String,
    pub kind: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ExternalParseSuccess {
    pub status: ParseStatus,
    pub language_id: String,
    pub parser_id: String,
    pub parser_version: String,
    pub symbols: Vec<SymbolInfo>,
    pub byte_ranges: Vec<Option<(usize, usize)>>,
    pub imports: Vec<ExternalImport>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum ExternalParseOutcome {
    Parsed(ExternalParseSuccess),
    Fallback {
        language_id: Option<String>,
        reason: String,
        /// `true` for crashes, timeouts, and protocol violations (counts toward circuit breaker).
        count_as_failure: bool,
    },
}

/// Validate that `language_id` is non-empty ASCII `[a-z0-9_-]` (`<= 64` bytes).
pub(crate) fn is_valid_language_id(lang: &str) -> bool {
    !lang.is_empty()
        && lang.len() <= 64
        && lang
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Safely truncate a UTF-8 string to at most `max_bytes` along a valid char boundary.
pub(crate) fn truncate_utf8_bytes(input: &str, max_bytes: usize) -> (&str, bool) {
    if input.len() <= max_bytes {
        return (input, false);
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    (&input[..end], true)
}

/// Map a wire `kind` string to [`SymbolKind`], returning `(kind, is_known)`.
pub(crate) fn parse_wire_symbol_kind(raw: &str) -> (SymbolKind, bool) {
    match raw {
        "function" => (SymbolKind::Function, true),
        "method" => (SymbolKind::Method, true),
        "struct" => (SymbolKind::Struct, true),
        "enum" => (SymbolKind::Enum, true),
        "trait" => (SymbolKind::Trait, true),
        "interface" => (SymbolKind::Interface, true),
        "class" => (SymbolKind::Class, true),
        "type_alias" => (SymbolKind::TypeAlias, true),
        "const" => (SymbolKind::Const, true),
        "static" => (SymbolKind::Static, true),
        "module" => (SymbolKind::Module, true),
        "macro" => (SymbolKind::Macro, true),
        "variable" => (SymbolKind::Variable, true),
        "other" => (SymbolKind::Other, true),
        _ => (SymbolKind::Other, false),
    }
}

/// Core validation, redaction, and deterministic sorting gate for `ext/parse_file` responses
/// (`docs/05-LANGUAGE-SIDECAR-SPEC.md` §4.6).
pub(crate) fn validate_and_normalize_parse_result(
    result: ParseFileResult,
    active_parser_id: &str,
    active_parser_version: &str,
    normalized_content: &str,
    file_line_count: usize,
) -> ExternalParseOutcome {
    if result.schema_version != klens_core::SCHEMA_VERSION {
        return protocol_violation(format!(
            "protocol violation: unsupported schema_version {} (expected {})",
            result.schema_version,
            klens_core::SCHEMA_VERSION
        ));
    }
    if result.parser_id != active_parser_id || result.parser_version != active_parser_version {
        return protocol_violation(format!(
            "protocol violation: parser identity mismatch (got {}@{}, expected {active_parser_id}@{active_parser_version})",
            result.parser_id, result.parser_version
        ));
    }
    if !is_valid_language_id(&result.language_id) {
        return protocol_violation(format!(
            "protocol violation: invalid language_id `{}`",
            result.language_id
        ));
    }

    let mut warnings: Vec<String> = result
        .warnings
        .into_iter()
        .map(|w| redact_secrets(&w).text)
        .filter(|w| !w.trim().is_empty())
        .collect();
    if !result.omissions.is_empty() {
        warnings.push(format!(
            "external sidecar reported {} omission(s)",
            result.omissions.len()
        ));
    }

    let parse_status = match result.status.as_str() {
        "parsed" => {
            if result.trust != "EXTERNAL_PARSER" {
                return protocol_violation(format!(
                    "protocol violation: external sidecar claimed {} instead of EXTERNAL_PARSER",
                    result.trust
                ));
            }
            ParseStatus::ExternalParsed
        }
        "partial" => {
            if result.trust != "EXTERNAL_PARSER" {
                return protocol_violation(format!(
                    "protocol violation: external sidecar claimed {} instead of EXTERNAL_PARSER",
                    result.trust
                ));
            }
            ParseStatus::ExternalPartial
        }
        "fallback" => {
            if result.trust != "UNPARSED_FALLBACK" {
                return protocol_violation(format!(
                    "protocol violation: fallback status claimed trust {} instead of UNPARSED_FALLBACK",
                    result.trust
                ));
            }
            let reason = if warnings.is_empty() {
                format!(
                    "external parser `{active_parser_id}` reported unrecoverable fallback status"
                )
            } else {
                warnings.join("; ")
            };
            return ExternalParseOutcome::Fallback {
                language_id: Some(result.language_id),
                reason,
                count_as_failure: false,
            };
        }
        other => {
            return protocol_violation(format!(
                "protocol violation: unsupported parse status `{other}`"
            ));
        }
    };

    if result.symbols.len() > MAX_SYMBOLS_PER_FILE {
        return protocol_violation(format!(
            "protocol violation: symbol count {} exceeds limit {MAX_SYMBOLS_PER_FILE}",
            result.symbols.len()
        ));
    }
    if result.imports.len() > MAX_IMPORTS_PER_FILE {
        return protocol_violation(format!(
            "protocol violation: import count {} exceeds limit {MAX_IMPORTS_PER_FILE}",
            result.imports.len()
        ));
    }

    let mut paired_symbols: Vec<(SymbolInfo, Option<(usize, usize)>)> =
        Vec::with_capacity(result.symbols.len());
    let mut truncated_sig_count = 0usize;
    let mut unknown_kinds = BTreeSet::new();

    for raw in result.symbols {
        if raw.name.is_empty() || raw.name.len() > MAX_SYMBOL_NAME_BYTES {
            return protocol_violation(format!(
                "protocol violation: invalid symbol name length ({} bytes)",
                raw.name.len()
            ));
        }
        if let Some(parent) = &raw.parent_symbol
            && (parent.is_empty() || parent.len() > MAX_QUALIFIED_NAME_BYTES)
        {
            return protocol_violation("protocol violation: invalid parent_symbol length".into());
        }

        let qualified_name = match raw.qualified_name {
            Some(q) => {
                if q.is_empty() || q.len() > MAX_QUALIFIED_NAME_BYTES {
                    return protocol_violation(
                        "protocol violation: invalid qualified_name length".into(),
                    );
                }
                q
            }
            None => {
                let synthesized = match &raw.parent_symbol {
                    Some(p) => format!("{p}::{}", raw.name),
                    None => raw.name.clone(),
                };
                if synthesized.len() > MAX_QUALIFIED_NAME_BYTES {
                    return protocol_violation(
                        "protocol violation: synthesized qualified_name exceeds max bytes".into(),
                    );
                }
                synthesized
            }
        };

        if file_line_count == 0
            || raw.start_line < 1
            || raw.end_line < raw.start_line
            || raw.end_line > file_line_count
        {
            return protocol_violation(format!(
                "protocol violation: symbol `{}` line range L{}-L{} out of bounds (file has {file_line_count} lines)",
                raw.name, raw.start_line, raw.end_line
            ));
        }

        let byte_range = match (raw.start_byte, raw.end_byte) {
            (Some(sb), Some(eb)) => {
                if sb > eb
                    || eb > normalized_content.len()
                    || !normalized_content.is_char_boundary(sb)
                    || !normalized_content.is_char_boundary(eb)
                {
                    return protocol_violation(format!(
                        "protocol violation: symbol `{}` byte range {sb}..{eb} invalid or not on UTF-8 char boundary",
                        raw.name
                    ));
                }
                Some((sb, eb))
            }
            (None, None) => None,
            _ => {
                return protocol_violation(format!(
                    "protocol violation: symbol `{}` provided only one of start_byte/end_byte",
                    raw.name
                ));
            }
        };

        let (kind, is_known_kind) = parse_wire_symbol_kind(&raw.kind);
        if !is_known_kind {
            unknown_kinds.insert(raw.kind.clone());
        }

        let redacted_sig = redact_secrets(&raw.signature).text;
        let (sig_slice, was_truncated) = truncate_utf8_bytes(&redacted_sig, MAX_SIGNATURE_BYTES);
        if was_truncated {
            truncated_sig_count += 1;
        }

        paired_symbols.push((
            SymbolInfo {
                name: raw.name,
                qualified_name,
                kind,
                signature: sig_slice.to_string(),
                start_line: raw.start_line,
                end_line: raw.end_line,
                parent: raw.parent_symbol,
            },
            byte_range,
        ));
    }

    if !unknown_kinds.is_empty() {
        warnings.push(format!(
            "mapped unknown external symbol kind(s) [{}] to `other`",
            unknown_kinds.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if truncated_sig_count > 0 {
        warnings.push(format!(
            "omissions: truncated {truncated_sig_count} oversized symbol signature(s) at {MAX_SIGNATURE_BYTES} bytes"
        ));
    }

    // Deterministic sort and dedup (`docs/05-LANGUAGE-SIDECAR-SPEC.md` §4.6 #5).
    paired_symbols.sort_by(|(a, _), (b, _)| {
        a.start_line
            .cmp(&b.start_line)
            .then_with(|| a.end_line.cmp(&b.end_line))
            .then_with(|| a.qualified_name.cmp(&b.qualified_name))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    paired_symbols.dedup_by(|(a, _), (b, _)| {
        a.start_line == b.start_line
            && a.end_line == b.end_line
            && a.qualified_name == b.qualified_name
            && a.name == b.name
            && a.kind == b.kind
    });

    let mut symbols = Vec::with_capacity(paired_symbols.len());
    let mut byte_ranges = Vec::with_capacity(paired_symbols.len());
    for (sym, br) in paired_symbols {
        symbols.push(sym);
        byte_ranges.push(br);
    }

    let mut imports = Vec::with_capacity(result.imports.len());
    for imp in result.imports {
        let spec = imp.specifier.trim();
        if spec.is_empty() || spec.len() > MAX_IMPORT_SPECIFIER_BYTES {
            return protocol_violation(format!(
                "protocol violation: invalid import specifier length ({} bytes)",
                spec.len()
            ));
        }
        if file_line_count == 0 || imp.line < 1 || imp.line > file_line_count {
            return protocol_violation(format!(
                "protocol violation: import line {} out of bounds (file has {file_line_count} lines)",
                imp.line
            ));
        }
        let kind = match imp.kind.as_deref().unwrap_or("import") {
            "import" | "include" | "using" | "require" | "use" | "other" => {
                imp.kind.unwrap_or_else(|| "import".to_string())
            }
            _ => "other".to_string(),
        };
        imports.push(ExternalImport {
            line: imp.line,
            specifier: spec.to_string(),
            kind,
        });
    }
    imports.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then_with(|| a.specifier.cmp(&b.specifier))
    });
    imports.dedup_by(|a, b| a.line == b.line && a.specifier == b.specifier);

    ExternalParseOutcome::Parsed(ExternalParseSuccess {
        status: parse_status,
        language_id: result.language_id,
        parser_id: result.parser_id,
        parser_version: result.parser_version,
        symbols,
        byte_ranges,
        imports,
        warnings,
    })
}

/// Convert validated external imports into raw `CodeEdge` records with `EdgeConfidence::Inferred`
/// and constitutional evidence provenance (`<rel_path>:L<line> (external:<parser_id>@<parser_version>)`).
pub(crate) fn build_external_import_edges(
    from_path: &RelPath,
    parser_id: &str,
    parser_version: &str,
    imports: &[ExternalImport],
) -> Vec<CodeEdge> {
    imports
        .iter()
        .map(|imp| CodeEdge {
            from: format!("file:{}", from_path.as_str()),
            to: format!("import:{}", imp.specifier),
            relation: EdgeRelation::Imports,
            confidence: EdgeConfidence::Inferred,
            evidence: format!(
                "{}:L{} (external:{parser_id}@{parser_version})",
                from_path.as_str(),
                imp.line
            ),
        })
        .collect()
}

fn protocol_violation(reason: String) -> ExternalParseOutcome {
    ExternalParseOutcome::Fallback {
        language_id: None,
        reason,
        count_as_failure: true,
    }
}
