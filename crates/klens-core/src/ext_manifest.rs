//! Out-of-core language parser sidecar manifest (`klens-extension.toml`) parser,
//! fail-closed validator, and deterministic project/global directory discovery.
//!
//! Strict leaf module: depends only on `paths` and standard crates (`serde`, `toml`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::ProjectRoot;

/// Canonical manifest filename inside each `<extensions_dir>/<ext-id>/` folder.
pub const EXTENSION_MANIFEST_FILE: &str = "klens-extension.toml";

/// Exact `kind` value required for offline language parser sidecar manifests.
pub const LANGUAGE_PARSER_KIND: &str = "language-parser";

/// Supported language sidecar JSON-RPC protocol version.
pub const SUPPORTED_SIDECAR_PROTOCOL_VERSION: u32 = 1;

/// Canonical catalog ID of the built-in Universal Ctags reference adapter.
pub const CTAGS_EXTENSION_ID: &str = "ext-lang-ctags";

/// Default per-file byte cap for language parser sidecars (1 MiB).
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1_048_576;

/// Hard upper bound for `max_file_bytes` (4 MiB, aligned with `MAX_INDEXABLE_BYTES`).
pub const MAX_ALLOWED_FILE_BYTES: u64 = 4_194_304;

/// Default per-file wall-clock parse timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;

/// Minimum allowed wall-clock parse timeout in milliseconds.
pub const MIN_TIMEOUT_MS: u64 = 100;

/// Maximum allowed wall-clock parse timeout in milliseconds.
pub const MAX_TIMEOUT_MS: u64 = 30_000;

/// Minimum allowed JSON-RPC frame limit (64 KiB).
pub const MIN_FRAME_BYTES: usize = 65_536;

/// Default and hard ceiling for JSON-RPC frame limit (4 MiB).
pub const MAX_FRAME_BYTES: usize = 4_194_304;

/// Maximum allowed command-line arguments in a manifest.
pub const MAX_MANIFEST_ARGS: usize = 32;

/// Maximum allowed character length of a manifest description.
pub const MAX_MANIFEST_DESCRIPTION_CHARS: usize = 200;

/// Maximum allowed length of a language extension ID (`ext-lang-*`).
pub const MAX_LANGUAGE_EXT_ID_LEN: usize = 64;

/// Maximum allowed length of a manifest SemVer version string.
pub const MAX_MANIFEST_VERSION_LEN: usize = 64;

/// Default file extensions handled by `ext-lang-ctags` (non-overlapping with core AST).
pub const DEFAULT_CTAGS_EXTENSIONS: &[&str] = &[
    "bash", "dart", "erl", "ex", "exs", "hs", "kt", "kts", "lua", "m", "mm", "pl", "pm", "r",
    "scala", "sh", "sql", "swift", "zig", "zsh",
];

/// Classification of an optional extension entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind {
    LanguageParser,
}

/// 4-state health indicator for language parser extensions in CLI / Web UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionHealthStatus {
    Disabled,
    Ready,
    Unavailable,
    Misconfigured,
}

/// Discovery root where a language parser manifest was located.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestOrigin {
    Project,
    Global,
}

impl ManifestOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Global => "global",
        }
    }
}

/// Validated `klens-extension.toml` manifest for an offline `ext-lang-*` parser sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageExtensionManifest {
    pub id: String,
    pub kind: String,
    pub version: String,
    pub protocol_version: u32,
    #[serde(default)]
    pub description: String,
    pub extensions: Vec<String>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default)]
    pub requires_network: bool,
    #[serde(default = "default_supports_read_only")]
    pub supports_read_only: bool,
}

const fn default_max_file_bytes() -> u64 {
    DEFAULT_MAX_FILE_BYTES
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

const fn default_max_frame_bytes() -> usize {
    MAX_FRAME_BYTES
}

const fn default_supports_read_only() -> bool {
    true
}

/// Valid discovered language extension manifest paired with its origin and path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredLanguageManifest {
    pub manifest: LanguageExtensionManifest,
    pub origin: ManifestOrigin,
    pub manifest_path: PathBuf,
}

/// Invalid manifest discovered on disk (surfaced honestly in `klens doctor` and UI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLanguageManifest {
    pub dir_name: String,
    pub origin: ManifestOrigin,
    pub manifest_path: PathBuf,
    pub reason: String,
}

/// Complete deterministic result of scanning the trusted user-global extension directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LanguageManifestDiscovery {
    pub manifests: BTreeMap<String, DiscoveredLanguageManifest>,
    pub invalid: Vec<InvalidLanguageManifest>,
    /// Sorted directory names found under `<project_root>/.klens/extensions/` that contain a
    /// manifest. They are NEVER loaded (a cloned repository controls them) and are surfaced
    /// only so `klens doctor` / `klens ext list` can report them honestly.
    pub ignored_project_manifests: Vec<String>,
}

/// Return `true` iff `id` matches `^ext-lang-[a-z0-9]+(-[a-z0-9]+)*$` and length `<= 64`.
pub fn is_valid_language_extension_id(id: &str) -> bool {
    if id.len() > MAX_LANGUAGE_EXT_ID_LEN {
        return false;
    }
    let Some(suffix) = id.strip_prefix("ext-lang-") else {
        return false;
    };
    if suffix.is_empty() {
        return false;
    }
    for segment in suffix.split('-') {
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return false;
        }
    }
    true
}

/// Return `true` iff `version` is a bounded SemVer string (`MAJOR.MINOR.PATCH` + optional pre/build).
pub fn is_valid_semver(version: &str) -> bool {
    if version.is_empty() || version.len() > MAX_MANIFEST_VERSION_LEN {
        return false;
    }
    if !version
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
    {
        return false;
    }
    let without_build =
        version.split_once('+').map_or(
            version,
            |(before, after)| {
                if after.is_empty() { "" } else { before }
            },
        );
    if without_build.is_empty() {
        return false;
    }
    let core = without_build
        .split_once('-')
        .map_or(
            without_build,
            |(before, after)| {
                if after.is_empty() { "" } else { before }
            },
        );
    let mut parts = core.split('.');
    let (Some(maj), Some(min), Some(pat), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    [maj, min, pat]
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Return `true` iff `ext` matches `^[a-z0-9]+(\.[a-z0-9]+)*$`.
pub fn is_valid_extension_token(ext: &str) -> bool {
    if ext.is_empty() || ext.len() > 32 {
        return false;
    }
    for seg in ext.split('.') {
        if seg.is_empty()
            || !seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return false;
        }
    }
    true
}

/// Parse and strictly validate a `klens-extension.toml` language parser manifest (fail-closed).
pub fn parse_and_validate_language_manifest(
    toml_source: &str,
    expected_dir_name: &str,
    _origin: ManifestOrigin,
) -> Result<LanguageExtensionManifest, String> {
    let mut manifest: LanguageExtensionManifest = toml::from_str(toml_source).map_err(|e| {
        format!(
            "TOML parse error: {}",
            crate::config::describe_toml_error(&e, toml_source)
        )
    })?;

    if !is_valid_language_extension_id(&manifest.id) {
        return Err(format!(
            "invalid extension id `{}` (expected ^ext-lang-[a-z0-9]+(-[a-z0-9]+)*$, <= {MAX_LANGUAGE_EXT_ID_LEN} chars)",
            manifest.id
        ));
    }
    if manifest.id != expected_dir_name {
        return Err(format!(
            "manifest id `{}` must exactly match directory name `{expected_dir_name}`",
            manifest.id
        ));
    }
    if manifest.kind != LANGUAGE_PARSER_KIND {
        return Err(format!(
            "unsupported manifest kind `{}` (expected `{LANGUAGE_PARSER_KIND}`)",
            manifest.kind
        ));
    }
    if !is_valid_semver(&manifest.version) {
        return Err(format!(
            "invalid SemVer version `{}` (expected MAJOR.MINOR.PATCH)",
            manifest.version
        ));
    }
    if manifest.protocol_version != SUPPORTED_SIDECAR_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol_version {} (expected {SUPPORTED_SIDECAR_PROTOCOL_VERSION})",
            manifest.protocol_version
        ));
    }
    if manifest.description.chars().count() > MAX_MANIFEST_DESCRIPTION_CHARS {
        return Err(format!(
            "description exceeds maximum of {MAX_MANIFEST_DESCRIPTION_CHARS} characters"
        ));
    }
    if manifest.description.chars().any(char::is_control) {
        return Err("description must not contain control characters".to_string());
    }

    if manifest.extensions.is_empty() {
        return Err("extensions list must not be empty".to_string());
    }
    let mut deduped_exts = BTreeSet::new();
    for ext in &manifest.extensions {
        if !is_valid_extension_token(ext) {
            return Err(format!(
                "invalid file extension `{ext}` (must be lowercase alphanumeric without leading dot or path characters)"
            ));
        }
        deduped_exts.insert(ext.clone());
    }
    manifest.extensions = deduped_exts.into_iter().collect();

    validate_command(&manifest.command)?;

    if manifest.args.len() > MAX_MANIFEST_ARGS {
        return Err(format!(
            "args count {} exceeds maximum of {MAX_MANIFEST_ARGS}",
            manifest.args.len()
        ));
    }
    for arg in &manifest.args {
        if arg.contains('\0') {
            return Err("args must not contain NUL bytes".to_string());
        }
    }

    if manifest.max_file_bytes == 0 || manifest.max_file_bytes > MAX_ALLOWED_FILE_BYTES {
        return Err(format!(
            "max_file_bytes {} out of allowed range 1..={MAX_ALLOWED_FILE_BYTES}",
            manifest.max_file_bytes
        ));
    }
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&manifest.timeout_ms) {
        return Err(format!(
            "timeout_ms {} out of allowed range {MIN_TIMEOUT_MS}..={MAX_TIMEOUT_MS}",
            manifest.timeout_ms
        ));
    }
    if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&manifest.max_frame_bytes) {
        return Err(format!(
            "max_frame_bytes {} out of allowed range {MIN_FRAME_BYTES}..={MAX_FRAME_BYTES}",
            manifest.max_frame_bytes
        ));
    }
    if manifest.requires_network {
        return Err(
            "requires_network must be false for language-parser sidecars (offline constitution)"
                .to_string(),
        );
    }
    if !manifest.supports_read_only {
        return Err(
            "supports_read_only must be true for language-parser sidecars (read-only constitution)"
                .to_string(),
        );
    }

    Ok(manifest)
}

fn validate_command(command: &str) -> Result<(), String> {
    if command.is_empty() || command != command.trim() {
        return Err("command must be non-empty without leading or trailing whitespace".to_string());
    }
    if command.contains(['\0', '\r', '\n']) {
        return Err("command must not contain NUL or newline characters".to_string());
    }

    let path = Path::new(command);
    let has_separator = command.contains(['/', '\\']);
    if (has_separator || command == "." || command == ".." || command.contains(':'))
        && !path.is_absolute()
    {
        return Err(format!(
            "relative command path `{command}` is forbidden; use a bare PATH binary name or an absolute executable path"
        ));
    }

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    if matches!(
        file_name.as_str(),
        "cmd"
            | "cmd.exe"
            | "sh"
            | "bash"
            | "zsh"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    ) {
        return Err(format!(
            "shell wrapper command `{command}` is forbidden; specify the parser executable directly"
        ));
    }

    Ok(())
}

/// Derive the global extensions directory (`~/.klens/extensions`) from `~/.klens/config.toml`.
pub fn global_extensions_dir_from_config(global_cfg_path: &Path) -> PathBuf {
    global_cfg_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("extensions")
}

/// Deterministically discover and validate `ext-lang-*` manifests from the trusted
/// user-global `<global_extensions_dir>/` ONLY.
///
/// Security (v0.3.2+): language-parser manifests define an executable `command`, so
/// `<project_root>/.klens/extensions/` is NEVER loaded — a cloned repository fully controls
/// that directory. Project manifests are only listed in
/// [`LanguageManifestDiscovery::ignored_project_manifests`] for honest reporting.
///
/// Strictly read-only: never writes to disk.
pub fn discover_language_manifests(
    global_extensions_dir: &Path,
    project_root: Option<&ProjectRoot>,
) -> LanguageManifestDiscovery {
    let mut result = LanguageManifestDiscovery::default();
    let mut blocked_by_project_error = BTreeSet::new();

    if let Some(root) = project_root {
        result.ignored_project_manifests =
            list_manifest_dirs(&root.root().join(".klens").join("extensions"));
    }

    scan_extensions_dir(
        global_extensions_dir,
        ManifestOrigin::Global,
        None,
        &mut result,
        &mut blocked_by_project_error,
    );

    result
}

/// Sorted names of `<dir>/<name>/klens-extension.toml` entries (metadata only, never parsed).
fn list_manifest_dirs(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().join(EXTENSION_MANIFEST_FILE).exists())
        .filter_map(|e| e.file_name().to_str().map(ToOwned::to_owned))
        .collect();
    names.sort();
    names
}

fn scan_extensions_dir(
    dir: &Path,
    origin: ManifestOrigin,
    confinement_root: Option<&Path>,
    out: &mut LanguageManifestDiscovery,
    blocked_by_project_error: &mut BTreeSet<String>,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    let mut subdirs: BTreeMap<String, PathBuf> = BTreeMap::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        subdirs.insert(name, path);
    }

    for (dir_name, subdir_path) in subdirs {
        let manifest_path = subdir_path.join(EXTENSION_MANIFEST_FILE);
        if !manifest_path.exists() {
            continue;
        }

        if origin == ManifestOrigin::Global
            && (out.manifests.contains_key(&dir_name)
                || blocked_by_project_error.contains(&dir_name))
        {
            continue;
        }

        if let Some(root) = confinement_root {
            match fs::canonicalize(&manifest_path) {
                Ok(canon) if canon.starts_with(root) => {}
                Ok(_) => {
                    blocked_by_project_error.insert(dir_name.clone());
                    out.invalid.push(InvalidLanguageManifest {
                        dir_name,
                        origin,
                        manifest_path,
                        reason: "manifest escapes project root (symlink blocked)".to_string(),
                    });
                    continue;
                }
                Err(err) => {
                    blocked_by_project_error.insert(dir_name.clone());
                    out.invalid.push(InvalidLanguageManifest {
                        dir_name,
                        origin,
                        manifest_path,
                        reason: format!("cannot inspect manifest: {err}"),
                    });
                    continue;
                }
            }
        }

        let content = match fs::read_to_string(&manifest_path) {
            Ok(c) => c,
            Err(err) => {
                if origin == ManifestOrigin::Project {
                    blocked_by_project_error.insert(dir_name.clone());
                }
                out.invalid.push(InvalidLanguageManifest {
                    dir_name,
                    origin,
                    manifest_path,
                    reason: format!("failed to read manifest: {err}"),
                });
                continue;
            }
        };

        match parse_and_validate_language_manifest(&content, &dir_name, origin) {
            Ok(manifest) => {
                out.manifests.insert(
                    manifest.id.clone(),
                    DiscoveredLanguageManifest {
                        manifest,
                        origin,
                        manifest_path,
                    },
                );
            }
            Err(reason) => {
                if origin == ManifestOrigin::Project {
                    blocked_by_project_error.insert(dir_name.clone());
                }
                out.invalid.push(InvalidLanguageManifest {
                    dir_name,
                    origin,
                    manifest_path,
                    reason,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static MANIFEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        let seq = MANIFEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-manifest-{label}-{}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const VALID_MANIFEST: &str = r#"
id = "ext-lang-java"
kind = "language-parser"
version = "0.1.0"
protocol_version = 1
description = "Offline Java parser sidecar"
extensions = ["java", "jav"]
command = "klens-ext-lang-java"
args = ["--stdio"]
"#;

    #[test]
    fn valid_manifest_parses_with_safe_defaults_and_sorted_extensions() {
        let parsed = parse_and_validate_language_manifest(
            VALID_MANIFEST,
            "ext-lang-java",
            ManifestOrigin::Project,
        )
        .unwrap();
        assert_eq!(parsed.id, "ext-lang-java");
        assert_eq!(parsed.extensions, vec!["jav", "java"]);
        assert_eq!(parsed.max_file_bytes, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(parsed.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(parsed.max_frame_bytes, MAX_FRAME_BYTES);
        assert!(!parsed.requires_network);
        assert!(parsed.supports_read_only);
    }

    #[test]
    fn manifest_validator_fails_closed_on_security_and_schema_violations() {
        // Directory mismatch
        assert!(
            parse_and_validate_language_manifest(
                VALID_MANIFEST,
                "ext-lang-other",
                ManifestOrigin::Project
            )
            .is_err()
        );

        // Network required
        let net = format!("{VALID_MANIFEST}\nrequires_network = true\n");
        assert!(
            parse_and_validate_language_manifest(&net, "ext-lang-java", ManifestOrigin::Global)
                .is_err()
        );

        // Read-only unsupported
        let no_ro = format!("{VALID_MANIFEST}\nsupports_read_only = false\n");
        assert!(
            parse_and_validate_language_manifest(&no_ro, "ext-lang-java", ManifestOrigin::Global)
                .is_err()
        );

        // Relative command path rejected
        let rel_cmd = VALID_MANIFEST.replace("klens-ext-lang-java", "./bin/parser");
        assert!(
            parse_and_validate_language_manifest(
                &rel_cmd,
                "ext-lang-java",
                ManifestOrigin::Project
            )
            .is_err()
        );

        // Shell wrapper rejected
        let sh_cmd = VALID_MANIFEST.replace("klens-ext-lang-java", "cmd.exe");
        assert!(
            parse_and_validate_language_manifest(&sh_cmd, "ext-lang-java", ManifestOrigin::Global)
                .is_err()
        );

        // Oversized frame limit rejected
        let big_frame = format!("{VALID_MANIFEST}\nmax_frame_bytes = 8388608\n");
        assert!(
            parse_and_validate_language_manifest(
                &big_frame,
                "ext-lang-java",
                ManifestOrigin::Global
            )
            .is_err()
        );

        // Bad extension with leading dot
        let dot_ext = VALID_MANIFEST.replace(r#"["java", "jav"]"#, r#"[".java"]"#);
        assert!(
            parse_and_validate_language_manifest(&dot_ext, "ext-lang-java", ManifestOrigin::Global)
                .is_err()
        );

        // Wrong protocol version
        let bad_proto = VALID_MANIFEST.replace("protocol_version = 1", "protocol_version = 2");
        assert!(
            parse_and_validate_language_manifest(
                &bad_proto,
                "ext-lang-java",
                ManifestOrigin::Global
            )
            .is_err()
        );
    }

    #[test]
    fn project_manifests_are_never_loaded_and_are_reported_as_ignored() {
        let dir = temp_dir("precedence");
        let global_ext = dir.join("home").join(".klens").join("extensions");
        let proj_dir = dir.join("proj");
        fs::create_dir_all(global_ext.join("ext-lang-java")).unwrap();
        fs::create_dir_all(global_ext.join("ext-lang-ruby")).unwrap();
        fs::create_dir_all(
            proj_dir
                .join(".klens")
                .join("extensions")
                .join("ext-lang-java"),
        )
        .unwrap();
        fs::create_dir_all(
            proj_dir
                .join(".klens")
                .join("extensions")
                .join("ext-lang-ruby"),
        )
        .unwrap();

        fs::write(
            global_ext
                .join("ext-lang-java")
                .join(EXTENSION_MANIFEST_FILE),
            VALID_MANIFEST,
        )
        .unwrap();
        fs::write(
            proj_dir
                .join(".klens")
                .join("extensions")
                .join("ext-lang-java")
                .join(EXTENSION_MANIFEST_FILE),
            VALID_MANIFEST.replace("0.1.0", "0.2.0"),
        )
        .unwrap();

        let ruby_valid = VALID_MANIFEST
            .replace("ext-lang-java", "ext-lang-ruby")
            .replace(r#"["java", "jav"]"#, r#"["rb"]"#);
        fs::write(
            global_ext
                .join("ext-lang-ruby")
                .join(EXTENSION_MANIFEST_FILE),
            &ruby_valid,
        )
        .unwrap();
        // Broken project manifest for ext-lang-ruby: ignored like every project manifest.
        fs::write(
            proj_dir
                .join(".klens")
                .join("extensions")
                .join("ext-lang-ruby")
                .join(EXTENSION_MANIFEST_FILE),
            format!("{ruby_valid}\nrequires_network = true\n"),
        )
        .unwrap();

        let project_root = ProjectRoot::new(&proj_dir).unwrap();
        let disc = discover_language_manifests(&global_ext, Some(&project_root));

        // Only trusted user-global manifests load; the repository cannot override them.
        let java = disc.manifests.get("ext-lang-java").unwrap();
        assert_eq!(java.origin, ManifestOrigin::Global);
        assert_eq!(java.manifest.version, "0.1.0");

        let ruby = disc.manifests.get("ext-lang-ruby").unwrap();
        assert_eq!(ruby.origin, ManifestOrigin::Global);
        assert!(disc.invalid.is_empty());

        assert_eq!(
            disc.ignored_project_manifests,
            vec!["ext-lang-java".to_string(), "ext-lang-ruby".to_string()]
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
