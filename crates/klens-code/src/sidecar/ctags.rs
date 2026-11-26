//! Reference Universal Ctags (`ext-lang-ctags`) offline language parser adapter.
//!
//! Enforces all `ext-lang-*` safety boundaries:
//! - Universal Ctags + `+json` feature verification (`ctags --version` & `--list-features`)
//! - RAII isolated temp file (`<temp>/klens-ctags-<pid>-<seq>/input.<ext>`) cleaned on `Drop`
//! - `--options=NONE --output-format=json --fields=+neKSz --extras=-q -o -` (no shell, no `tags` file)
//! - Windows `CREATE_NO_WINDOW` (`0x0800_0000`), `env_clear()`, wall-clock timeout + process-tree kill
//! - Bounded output cap (4 MiB), `redact_secrets`, deterministic symbol sorting, honest `UNPARSED_FALLBACK`

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use klens_core::{
    CTAGS_EXTENSION_ID, DEFAULT_CTAGS_EXTENSIONS, DEFAULT_MAX_FILE_BYTES, DEFAULT_TIMEOUT_MS,
    LanguageExtensionManifest, MAX_FRAME_BYTES, RelPath, SymbolInfo, SymbolKind, redact_secrets,
};
use serde::Deserialize;

use crate::sidecar::common::{
    CTAGS_PROBE_TIMEOUT_MS, ExternalParseOutcome, ExternalParseSuccess, MAX_QUALIFIED_NAME_BYTES,
    MAX_SIGNATURE_BYTES, MAX_STDERR_BYTES, MAX_SYMBOL_NAME_BYTES, MAX_SYMBOLS_PER_FILE,
    apply_minimal_sidecar_env, configure_no_window, is_valid_language_id, kill_process_tree,
    truncate_utf8_bytes,
};
use crate::store::ParseStatus;

static CTAGS_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Resolved configuration for the `ext-lang-ctags` adapter (defaults or user override manifest).
#[derive(Debug, Clone)]
pub struct CtagsConfig {
    pub command: String,
    pub extensions: Vec<String>,
    pub max_file_bytes: u64,
    pub timeout_ms: u64,
    pub max_frame_bytes: usize,
}

impl Default for CtagsConfig {
    fn default() -> Self {
        Self {
            command: "ctags".to_string(),
            extensions: DEFAULT_CTAGS_EXTENSIONS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_frame_bytes: MAX_FRAME_BYTES,
        }
    }
}

impl CtagsConfig {
    pub fn from_override_manifest(manifest: &LanguageExtensionManifest) -> Self {
        Self {
            command: manifest.command.clone(),
            extensions: manifest.extensions.clone(),
            max_file_bytes: manifest.max_file_bytes,
            timeout_ms: manifest.timeout_ms,
            max_frame_bytes: manifest.max_frame_bytes,
        }
    }

    pub fn matches_path(&self, path: &RelPath) -> bool {
        let lower = path.as_str().to_ascii_lowercase();
        let file_name = lower.rsplit('/').next().unwrap_or(&lower);
        for ext in &self.extensions {
            if ext.contains('.') {
                let suffix = format!(".{ext}");
                if file_name.ends_with(&suffix) {
                    return true;
                }
            }
        }
        let Some((_, ext)) = file_name.rsplit_once('.') else {
            return false;
        };
        self.extensions.iter().any(|candidate| candidate == ext)
    }
}

/// Verified Universal Ctags installation metadata from a one-time session probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtagsProbeInfo {
    pub ctags_version: String,
    pub parser_version: String,
    pub command: String,
}

/// Verify that `command` points to Universal Ctags compiled with JSON (`+json`) support.
pub fn probe_ctags(command: &str) -> Result<CtagsProbeInfo, String> {
    let ver_out = run_bounded_process(
        command,
        &["--version"],
        CTAGS_PROBE_TIMEOUT_MS,
        MAX_STDERR_BYTES,
    )
    .map_err(|err| format!("Universal Ctags (+json) not found in PATH ({err})"))?;

    if ver_out.exit_code != 0 {
        return Err(format!(
            "`{command} --version` exited with code {}",
            ver_out.exit_code
        ));
    }

    if !ver_out.stdout.contains("Universal Ctags") {
        return Err(
            "found non-Universal ctags; Universal Ctags with +json feature is required".to_string(),
        );
    }

    let ctags_version = parse_ctags_version(&ver_out.stdout);

    let feat_out = run_bounded_process(
        command,
        &["--list-features"],
        CTAGS_PROBE_TIMEOUT_MS,
        MAX_STDERR_BYTES,
    )
    .map_err(|err| format!("failed running `{command} --list-features`: {err}"))?;

    if feat_out.exit_code != 0 || !has_json_feature(&feat_out.stdout) {
        return Err("Universal Ctags binary was compiled without JSON (+json) support".to_string());
    }

    Ok(CtagsProbeInfo {
        parser_version: format!("{}+ctags-{ctags_version}", env!("CARGO_PKG_VERSION")),
        ctags_version,
        command: command.to_string(),
    })
}

/// RAII isolated temp directory holding a single CRLF-normalized input file for `ctags`.
///
/// Guarantees cleanup on normal return, error, timeout, or panic.
struct IsolatedTempFile {
    dir: PathBuf,
    file_path: PathBuf,
}

impl IsolatedTempFile {
    fn create(extension: &str, normalized_content: &str) -> Result<Self, String> {
        let seq = CTAGS_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("klens-ctags-{}-{seq}", std::process::id()));
        fs::create_dir_all(&dir)
            .map_err(|err| format!("failed to create isolated ctags temp dir: {err}"))?;

        let safe_ext: String = extension
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
            .collect();
        let file_name = if safe_ext.is_empty() {
            "input.txt".to_string()
        } else {
            format!("input.{safe_ext}")
        };
        let file_path = dir.join(file_name);
        if let Err(err) = fs::write(&file_path, normalized_content.as_bytes()) {
            let _ = fs::remove_dir_all(&dir);
            return Err(format!("failed to write isolated ctags input: {err}"));
        }

        Ok(Self { dir, file_path })
    }

    fn path(&self) -> &Path {
        &self.file_path
    }
}

impl Drop for IsolatedTempFile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[derive(Debug, Deserialize)]
struct CtagsJsonTag {
    #[serde(rename = "_type", default)]
    entry_type: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    line: Option<usize>,
    #[serde(default)]
    end: Option<usize>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(rename = "scopeKind", default)]
    scope_kind: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

/// Parse a single CRLF-normalized file via Universal Ctags (`--output-format=json`)
/// inside an isolated temp directory with full `ext-lang-*` safety bounds.
pub(crate) fn parse_file_with_ctags(
    config: &CtagsConfig,
    probe: &CtagsProbeInfo,
    rel: &RelPath,
    normalized_content: &str,
    file_line_count: usize,
) -> ExternalParseOutcome {
    let content_bytes = normalized_content.len() as u64;
    if content_bytes > config.max_file_bytes {
        return ExternalParseOutcome::Fallback {
            language_id: None,
            reason: format!(
                "file size ({content_bytes} bytes) exceeds ext-lang-ctags max_file_bytes ({})",
                config.max_file_bytes
            ),
            count_as_failure: false,
        };
    }

    let ext = extract_file_extension(rel);
    let temp_file = match IsolatedTempFile::create(ext, normalized_content) {
        Ok(f) => f,
        Err(reason) => {
            return ExternalParseOutcome::Fallback {
                language_id: None,
                reason,
                count_as_failure: true,
            };
        }
    };

    let temp_path_str = temp_file.path().to_string_lossy().into_owned();
    let args = [
        "--options=NONE",
        "--output-format=json",
        "--fields=+neKSz",
        "--extras=-q",
        "-o",
        "-",
        &temp_path_str,
    ];

    let output = match run_bounded_process(
        &config.command,
        &args,
        config.timeout_ms,
        config.max_frame_bytes,
    ) {
        Ok(out) => out,
        Err(reason) => {
            return ExternalParseOutcome::Fallback {
                language_id: None,
                reason: format!("ext-lang-ctags execution failed: {reason}"),
                count_as_failure: true,
            };
        }
    };

    // Explicitly drop temp file as soon as ctags finishes.
    drop(temp_file);

    if output.exit_code != 0 {
        let stderr_note = redact_secrets(output.stderr.trim()).text;
        return ExternalParseOutcome::Fallback {
            language_id: None,
            reason: format!(
                "ext-lang-ctags exited with code {}{}",
                output.exit_code,
                if stderr_note.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr_note}")
                }
            ),
            count_as_failure: true,
        };
    }

    let source_lines: Vec<&str> = normalized_content.lines().collect();
    let mut symbols: Vec<SymbolInfo> = Vec::new();
    let mut detected_lang: Option<String> = None;

    for raw_line in output.stdout.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tag: CtagsJsonTag = match serde_json::from_str(trimmed) {
            Ok(t) => t,
            Err(err) => {
                return ExternalParseOutcome::Fallback {
                    language_id: None,
                    reason: format!("ext-lang-ctags emitted malformed JSON: {err}"),
                    count_as_failure: true,
                };
            }
        };

        if tag.entry_type != "tag" {
            continue;
        }
        if detected_lang.is_none()
            && let Some(raw_lang) = &tag.language
        {
            let norm_lang = normalize_ctags_language(raw_lang);
            if is_valid_language_id(&norm_lang) {
                detected_lang = Some(norm_lang);
            }
        }

        if tag.name.is_empty() || tag.name.len() > MAX_SYMBOL_NAME_BYTES {
            continue;
        }
        let Some(start_line) = tag.line else {
            continue;
        };
        if start_line < 1 || file_line_count == 0 || start_line > file_line_count {
            continue;
        }

        let end_line = tag
            .end
            .unwrap_or(start_line)
            .max(start_line)
            .min(file_line_count);
        let kind = map_ctags_kind(tag.kind.as_deref().unwrap_or(""));

        let parent = tag
            .scope
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|scope| {
                let raw_parent = match tag
                    .scope_kind
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    Some(sk) => format!("{sk} {scope}"),
                    None => scope.to_string(),
                };
                let (clipped, _) = truncate_utf8_bytes(&raw_parent, MAX_QUALIFIED_NAME_BYTES);
                clipped.to_string()
            });

        let raw_qname = match &parent {
            Some(p) => format!("{p}::{}", tag.name),
            None => tag.name.clone(),
        };
        let (qname_slice, _) = truncate_utf8_bytes(&raw_qname, MAX_QUALIFIED_NAME_BYTES);

        let raw_sig = source_lines
            .get(start_line - 1)
            .map(|l| l.trim())
            .unwrap_or(&tag.name);
        let redacted_sig = redact_secrets(raw_sig).text;
        let (sig_slice, _) = truncate_utf8_bytes(&redacted_sig, MAX_SIGNATURE_BYTES);

        symbols.push(SymbolInfo {
            name: tag.name,
            qualified_name: qname_slice.to_string(),
            kind,
            signature: sig_slice.to_string(),
            start_line,
            end_line,
            parent,
        });

        if symbols.len() > MAX_SYMBOLS_PER_FILE {
            return ExternalParseOutcome::Fallback {
                language_id: detected_lang,
                reason: format!(
                    "ext-lang-ctags symbol count exceeded limit {MAX_SYMBOLS_PER_FILE}"
                ),
                count_as_failure: true,
            };
        }
    }

    symbols.sort_by(|a, b| {
        a.start_line
            .cmp(&b.start_line)
            .then_with(|| a.end_line.cmp(&b.end_line))
            .then_with(|| a.qualified_name.cmp(&b.qualified_name))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    symbols.dedup_by(|a, b| {
        a.start_line == b.start_line
            && a.end_line == b.end_line
            && a.qualified_name == b.qualified_name
            && a.name == b.name
            && a.kind == b.kind
    });

    let language_id = detected_lang.unwrap_or_else(|| {
        let fallback_lang = ext.replace('.', "_");
        if is_valid_language_id(&fallback_lang) {
            fallback_lang
        } else {
            "ctags".to_string()
        }
    });
    let byte_ranges = vec![None; symbols.len()];

    ExternalParseOutcome::Parsed(ExternalParseSuccess {
        status: ParseStatus::ExternalParsed,
        language_id,
        parser_id: CTAGS_EXTENSION_ID.to_string(),
        parser_version: probe.parser_version.clone(),
        symbols,
        byte_ranges,
        imports: Vec::new(),
        warnings: Vec::new(),
    })
}

/// Standard honest fallback warning when `ext-lang-ctags` is enabled without Universal Ctags.
pub(crate) fn ctags_unavailable_warning() -> String {
    "ext-lang-ctags is enabled, but Universal Ctags (+json) was not found in PATH; install universal-ctags or run `klens ext disable ext-lang-ctags`".to_string()
}

struct BoundedProcessOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

fn run_bounded_process(
    command: &str,
    args: &[&str],
    timeout_ms: u64,
    max_stdout_bytes: usize,
) -> Result<BoundedProcessOutput, String> {
    let mut cmd = Command::new(command);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_minimal_sidecar_env(&mut cmd, CTAGS_EXTENSION_ID);
    configure_no_window(&mut cmd);

    let mut child = cmd
        .spawn()
        .map_err(|err| format!("spawn `{command}` failed: {err}"))?;
    let child_pid = child.id();
    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| "ctags stdout pipe unavailable".to_string())?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| "ctags stderr pipe unavailable".to_string())?;

    let (done_tx, done_rx) = mpsc::channel();
    let stdout_handle = thread::spawn(move || read_bounded_stream(stdout_pipe, max_stdout_bytes));
    let stderr_handle = thread::spawn(move || read_bounded_stream(stderr_pipe, MAX_STDERR_BYTES));

    let wait_handle = thread::spawn(move || {
        let status = child.wait();
        let _ = done_tx.send(status);
    });

    let status = match done_rx.recv_timeout(Duration::from_millis(timeout_ms)) {
        Ok(Ok(st)) => st,
        Ok(Err(err)) => {
            kill_process_tree(child_pid);
            let _ = wait_handle.join();
            return Err(format!("wait failed: {err}"));
        }
        Err(_) => {
            kill_process_tree(child_pid);
            let _ = wait_handle.join();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(format!("timed out after {timeout_ms}ms"));
        }
    };
    let _ = wait_handle.join();

    let (stdout_bytes, stdout_truncated) = stdout_handle
        .join()
        .map_err(|_| "ctags stdout thread panicked".to_string())?;
    let (stderr_bytes, _) = stderr_handle
        .join()
        .map_err(|_| "ctags stderr thread panicked".to_string())?;

    if stdout_truncated {
        return Err(format!(
            "output exceeded max_frame_bytes ({max_stdout_bytes} bytes)"
        ));
    }

    Ok(BoundedProcessOutput {
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        exit_code: status.code().unwrap_or(1),
    })
}

fn read_bounded_stream<R: Read>(mut reader: R, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut exceeded = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if !exceeded {
                    let remaining = max_bytes.saturating_sub(out.len());
                    if n > remaining {
                        out.extend_from_slice(&chunk[..remaining]);
                        exceeded = true;
                    } else {
                        out.extend_from_slice(&chunk[..n]);
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (out, exceeded)
}

fn parse_ctags_version(version_output: &str) -> String {
    for line in version_output.lines() {
        if let Some(rest) = line.split("Universal Ctags").nth(1) {
            let token = rest
                .trim()
                .split([',', ' ', '(', '\t'])
                .next()
                .unwrap_or("");
            let cleaned = token.trim_start_matches('v');
            if !cleaned.is_empty() && cleaned.bytes().any(|b| b.is_ascii_digit()) {
                return cleaned.to_string();
            }
        }
    }
    "unknown".to_string()
}

fn has_json_feature(features_output: &str) -> bool {
    features_output.lines().any(|line| {
        let first = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_start_matches('*');
        first.eq_ignore_ascii_case("json")
    })
}

fn normalize_ctags_language(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "c++" => "cpp".to_string(),
        "c#" => "csharp".to_string(),
        "objectivec" | "objective-c" => "objc".to_string(),
        other => other
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect(),
    }
}

fn extract_file_extension(rel: &RelPath) -> &str {
    let fname = rel.file_name().unwrap_or(rel.as_str());
    match fname.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() => ext,
        _ => "txt",
    }
}

fn map_ctags_kind(kind: &str) -> SymbolKind {
    match kind.trim().to_ascii_lowercase().as_str() {
        "function" | "func" | "subroutine" | "procedure" => SymbolKind::Function,
        "method" => SymbolKind::Method,
        "struct" => SymbolKind::Struct,
        "enum" => SymbolKind::Enum,
        "trait" => SymbolKind::Trait,
        "interface" => SymbolKind::Interface,
        "class" => SymbolKind::Class,
        "typedef" | "type" => SymbolKind::TypeAlias,
        "constant" | "enumerator" | "const" => SymbolKind::Const,
        "namespace" | "package" | "module" => SymbolKind::Module,
        "macro" => SymbolKind::Macro,
        "variable" | "field" | "member" => SymbolKind::Variable,
        _ => SymbolKind::Other,
    }
}
