//! Single-source-of-truth out-of-core extension catalog and configuration management (`klens ext`).
//!
//! Architectural invariants (`docs/01-ARCHITECTURE.md` Section 3.4 & Section 6):
//! - Zero out-of-core extensions are enabled by default (`is_enabled_by_default() == false`).
//! - Core binary never bundles HTTP/LLM clients, LSP runtimes, or async frameworks.
//! - Extension enable/disable writes atomically to `~/.klens/config.toml` (global) or
//!   `.klens/config.toml` (project) using fail-closed extension ID validation.
//! - Both `klens ext` (CLI) and `/api/extensions*` (Web UI) delegate exclusively to this module.
//! - Security (v0.3.2+): language parsers (`ext-lang-*`, incl. `ext-lang-ctags`) spawn external
//!   processes, so they can ONLY be enabled globally. Project-scoped enablement of a language
//!   parser is rejected and never counts as effective (a cloned repository controls the
//!   project `.klens/config.toml`).

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{GlobalConfig, ProjectConfig};
use crate::envelope::SCHEMA_VERSION;
use crate::error::KlensError;
use crate::ext_manifest::{
    CTAGS_EXTENSION_ID, DEFAULT_CTAGS_EXTENSIONS, ExtensionHealthStatus, ExtensionKind,
    discover_language_manifests, global_extensions_dir_from_config, is_valid_language_extension_id,
};
use crate::paths::ProjectRoot;

/// Returns `true` for process-spawning language parser IDs (`ext-lang-*`, incl. ctags).
pub fn is_language_parser_id(id: &str) -> bool {
    id == CTAGS_EXTENSION_ID || is_valid_language_extension_id(id)
}

/// Effective enablement: language parsers honor ONLY the trusted global scope.
fn effective_enabled_for(id: &str, enabled_global: bool, enabled_project: bool) -> bool {
    enabled_global || (enabled_project && !is_language_parser_id(id))
}
use crate::traits::ExtensionSlot;

/// Isolation transport by which an out-of-core extension communicates with `klens`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionTransport {
    /// Separate subprocess communicating over newline-delimited JSON-RPC 2.0 on stdio
    /// (spawned with `CREATE_NO_WINDOW` on Windows).
    SidecarJsonRpc,
    /// Optional compile-time Cargo feature or isolated sidecar subprocess.
    SidecarOrCargoFeature,
}

impl ExtensionTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SidecarJsonRpc => "sidecar_jsonrpc",
            Self::SidecarOrCargoFeature => "sidecar_or_cargo_feature",
        }
    }
}

/// Configuration scope where an extension toggle is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionScope {
    /// Stored in project-local `.klens/config.toml`.
    Project,
    /// Stored in user-global `~/.klens/config.toml`.
    Global,
}

impl ExtensionScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Global => "global",
        }
    }
}

/// Static catalog entry describing a known out-of-core optional extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionSpec {
    pub id: &'static str,
    pub version: &'static str,
    pub transport: ExtensionTransport,
    pub description: &'static str,
}

impl ExtensionSlot for ExtensionSpec {
    fn extension_id(&self) -> &'static str {
        self.id
    }

    fn version(&self) -> &'static str {
        self.version
    }

    fn description(&self) -> &'static str {
        self.description
    }
}

/// Canonical, deterministically ordered catalog of known out-of-core extensions.
///
/// Every entry is disabled by default (`is_enabled_by_default() == false`) and requires
/// explicit user opt-in via `klens ext enable <id>`.
const KNOWN_EXTENSIONS: &[ExtensionSpec] = &[
    ExtensionSpec {
        id: "ext-ast-refactor",
        version: env!("CARGO_PKG_VERSION"),
        transport: ExtensionTransport::SidecarOrCargoFeature,
        description: "Structural AST refactoring with mandatory dry-run preview (ast-grep model).",
    },
    ExtensionSpec {
        id: "ext-karasu-browser",
        version: env!("CARGO_PKG_VERSION"),
        transport: ExtensionTransport::SidecarJsonRpc,
        description: "Local bridge forwarding Karasu Browser console errors and UI notes into project queues.",
    },
    ExtensionSpec {
        id: CTAGS_EXTENSION_ID,
        version: env!("CARGO_PKG_VERSION"),
        transport: ExtensionTransport::SidecarJsonRpc,
        description: "Offline Universal Ctags (--output-format=json) language symbol adapter (EXTERNAL_PARSER).",
    },
    ExtensionSpec {
        id: "ext-live-docs",
        version: env!("CARGO_PKG_VERSION"),
        transport: ExtensionTransport::SidecarJsonRpc,
        description: "Version-pinned local documentation cache (Context7 model) for project dependencies.",
    },
    ExtensionSpec {
        id: "ext-llm-provider",
        version: env!("CARGO_PKG_VERSION"),
        transport: ExtensionTransport::SidecarJsonRpc,
        description: "Optional direct LLM API provider (Gemini/Claude/OpenAI/Ollama) for standalone Blueprint suggestions.",
    },
    ExtensionSpec {
        id: "ext-lsp-bridge",
        version: env!("CARGO_PKG_VERSION"),
        transport: ExtensionTransport::SidecarJsonRpc,
        description: "Serena-style LSP bridge (rust-analyzer, tsserver, pyright, gopls) upgrading edges to VERIFIED_LSP.",
    },
    ExtensionSpec {
        id: "ext-worktree-orchestrator",
        version: env!("CARGO_PKG_VERSION"),
        transport: ExtensionTransport::SidecarJsonRpc,
        description: "Parallel git worktree task orchestration for independent Blueprint tasks.",
    },
];

/// Return the canonical, deterministically sorted catalog of known optional extensions.
pub const fn known_extensions() -> &'static [ExtensionSpec] {
    KNOWN_EXTENSIONS
}

/// Look up a known extension by its exact canonical ID.
pub fn find_known_extension(id: &str) -> Option<&'static ExtensionSpec> {
    let trimmed = id.trim();
    KNOWN_EXTENSIONS.iter().find(|spec| spec.id == trimmed)
}

/// Fail-closed validation of an extension ID against the known catalog.
///
/// Rejects empty strings, whitespace, path separators, uppercase variants, or unknown IDs.
pub fn validate_extension_id(id: &str) -> Result<&'static ExtensionSpec, KlensError> {
    let raw = id.trim();
    if raw.is_empty()
        || raw != id
        || !raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid_ext_error(id));
    }
    find_known_extension(raw).ok_or_else(|| invalid_ext_error(id))
}

fn invalid_ext_error(id: &str) -> KlensError {
    let known = KNOWN_EXTENSIONS
        .iter()
        .map(|s| s.id)
        .collect::<Vec<_>>()
        .join(", ");
    KlensError::InvalidExtensionId {
        id: id.to_string(),
        known,
    }
}

/// Status row for a single extension across global and project configuration scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionStatusEntry {
    pub id: String,
    pub version: String,
    pub description: String,
    pub transport: ExtensionTransport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ExtensionKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ExtensionHealthStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_detail: Option<String>,
    pub known: bool,
    pub default_enabled: bool,
    pub enabled_global: bool,
    pub enabled_project: bool,
    pub effective_enabled: bool,
}

/// Deterministic report returned by `klens ext list` and `GET /api/extensions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionListReport {
    pub schema_version: u32,
    pub global_config_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_config_path: Option<String>,
    pub has_active_project: bool,
    pub global_enabled: Vec<String>,
    pub project_enabled: Vec<String>,
    pub extensions: Vec<ExtensionStatusEntry>,
}

/// Deterministic report returned by `klens ext enable/disable` and `POST /api/extensions/toggle`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionToggleReport {
    pub schema_version: u32,
    pub id: String,
    pub scope: ExtensionScope,
    pub enabled: bool,
    pub changed: bool,
    pub config_path: String,
    pub enabled_extensions: Vec<String>,
}

/// Read-only listing of all known optional extensions plus their global and project opt-in state.
///
/// Never writes to disk (safe for `--read-only` inspection).
pub fn list_extensions(
    global_cfg_path: &Path,
    project_root: Option<&ProjectRoot>,
) -> Result<ExtensionListReport, KlensError> {
    let global_cfg = GlobalConfig::load_or_default(global_cfg_path)?;
    let global_set: BTreeSet<String> = global_cfg
        .enabled_extensions
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let (project_cfg_path, project_set) = match project_root {
        Some(root) => {
            let path = root.root().join(".klens").join("config.toml");
            let proj_cfg = ProjectConfig::load_or_default(&path)?;
            let set: BTreeSet<String> = proj_cfg
                .enabled_extensions
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            (Some(normalize_display_path(&path)), set)
        }
        None => (None, BTreeSet::new()),
    };

    let global_ext_dir = global_extensions_dir_from_config(global_cfg_path);
    let discovered = discover_language_manifests(&global_ext_dir, project_root);

    let mut entries = Vec::with_capacity(KNOWN_EXTENSIONS.len() + discovered.manifests.len());
    let mut seen_ids = BTreeSet::new();
    for spec in KNOWN_EXTENSIONS {
        seen_ids.insert(spec.id.to_string());
        let enabled_global = global_set.contains(spec.id);
        let enabled_project = project_set.contains(spec.id);
        let effective_enabled = effective_enabled_for(spec.id, enabled_global, enabled_project);

        if spec.id == CTAGS_EXTENSION_ID {
            let invalid_override = discovered.invalid.iter().find(|i| i.dir_name == spec.id);
            let valid_override = discovered.manifests.get(spec.id);
            let (version, description, extensions, command) = match valid_override {
                Some(d) => (
                    d.manifest.version.clone(),
                    if d.manifest.description.is_empty() {
                        spec.description.to_string()
                    } else {
                        d.manifest.description.clone()
                    },
                    d.manifest.extensions.clone(),
                    Some(d.manifest.command.clone()),
                ),
                None => (
                    spec.version.to_string(),
                    spec.description.to_string(),
                    DEFAULT_CTAGS_EXTENSIONS
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect(),
                    None,
                ),
            };
            let (health, health_detail) = if let Some(inv) = invalid_override {
                (
                    Some(ExtensionHealthStatus::Misconfigured),
                    Some(inv.reason.clone()),
                )
            } else if !effective_enabled {
                (Some(ExtensionHealthStatus::Disabled), None)
            } else {
                (None, None)
            };
            entries.push(ExtensionStatusEntry {
                id: spec.id.to_string(),
                version,
                description,
                transport: spec.transport,
                kind: Some(ExtensionKind::LanguageParser),
                extensions,
                command,
                health,
                health_detail,
                known: true,
                default_enabled: spec.is_enabled_by_default(),
                enabled_global,
                enabled_project,
                effective_enabled,
            });
            continue;
        }

        entries.push(ExtensionStatusEntry {
            id: spec.id.to_string(),
            version: spec.version.to_string(),
            description: spec.description.to_string(),
            transport: spec.transport,
            kind: None,
            extensions: Vec::new(),
            command: None,
            health: None,
            health_detail: None,
            known: true,
            default_enabled: spec.is_enabled_by_default(),
            enabled_global,
            enabled_project,
            effective_enabled,
        });
    }

    for (id, disc) in &discovered.manifests {
        if !seen_ids.insert(id.clone()) {
            continue;
        }
        let enabled_global = global_set.contains(id);
        let enabled_project = project_set.contains(id);
        let effective_enabled = effective_enabled_for(id, enabled_global, enabled_project);
        entries.push(ExtensionStatusEntry {
            id: id.clone(),
            version: disc.manifest.version.clone(),
            description: if disc.manifest.description.is_empty() {
                format!(
                    "Offline language parser sidecar ({}) [{}].",
                    disc.manifest.extensions.join(", "),
                    disc.origin.as_str()
                )
            } else {
                disc.manifest.description.clone()
            },
            transport: ExtensionTransport::SidecarJsonRpc,
            kind: Some(ExtensionKind::LanguageParser),
            extensions: disc.manifest.extensions.clone(),
            command: Some(disc.manifest.command.clone()),
            health: (!effective_enabled).then_some(ExtensionHealthStatus::Disabled),
            health_detail: None,
            known: true,
            default_enabled: false,
            enabled_global,
            enabled_project,
            effective_enabled,
        });
    }

    for inv in &discovered.invalid {
        if !seen_ids.insert(inv.dir_name.clone()) {
            continue;
        }
        let enabled_global = global_set.contains(&inv.dir_name);
        let enabled_project = project_set.contains(&inv.dir_name);
        entries.push(ExtensionStatusEntry {
            id: inv.dir_name.clone(),
            version: "invalid".to_string(),
            description: format!("Invalid manifest ({})", inv.origin.as_str()),
            transport: ExtensionTransport::SidecarJsonRpc,
            kind: Some(ExtensionKind::LanguageParser),
            extensions: Vec::new(),
            command: None,
            health: Some(ExtensionHealthStatus::Misconfigured),
            health_detail: Some(inv.reason.clone()),
            known: false,
            default_enabled: false,
            enabled_global,
            enabled_project,
            effective_enabled: effective_enabled_for(
                &inv.dir_name,
                enabled_global,
                enabled_project,
            ),
        });
    }

    // Surface any manually-added unknown entries honestly (zero silent hiding).
    let extra_ids: BTreeSet<&str> = global_set
        .iter()
        .chain(project_set.iter())
        .map(String::as_str)
        .filter(|id| !seen_ids.contains(*id))
        .collect();
    for extra in extra_ids {
        let enabled_global = global_set.contains(extra);
        let enabled_project = project_set.contains(extra);
        entries.push(ExtensionStatusEntry {
            id: extra.to_string(),
            version: "custom".to_string(),
            description: "Unregistered extension entry present in config.toml.".to_string(),
            transport: ExtensionTransport::SidecarJsonRpc,
            kind: None,
            extensions: Vec::new(),
            command: None,
            health: None,
            health_detail: None,
            known: false,
            default_enabled: false,
            enabled_global,
            enabled_project,
            effective_enabled: effective_enabled_for(extra, enabled_global, enabled_project),
        });
    }

    entries.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(ExtensionListReport {
        schema_version: SCHEMA_VERSION,
        global_config_path: normalize_display_path(global_cfg_path),
        project_config_path: project_cfg_path,
        has_active_project: project_root.is_some(),
        global_enabled: global_set.into_iter().collect(),
        project_enabled: project_set.into_iter().collect(),
        extensions: entries,
    })
}

/// Enable or disable an optional extension atomically in either global or project config.
///
/// Validation policy (fail-closed):
/// - When `enabled == true`, `id` MUST be a valid canonical ID from [`known_extensions`].
/// - When `enabled == false`, known IDs are disabled normally; an unknown/unregistered ID is
///   removed atomically ONLY if it is already present in the target `config.toml`'s
///   `enabled_extensions` list, otherwise [`KlensError::InvalidExtensionId`] is returned.
pub fn set_extension_enabled(
    id: &str,
    enabled: bool,
    scope: ExtensionScope,
    global_cfg_path: &Path,
    project_root: Option<&ProjectRoot>,
) -> Result<ExtensionToggleReport, KlensError> {
    if id.trim().is_empty() || id != id.trim() {
        return Err(invalid_ext_error(id));
    }

    // Fail closed: a process-spawning language parser can never be enabled per project.
    // (Disabling stays allowed so stale project entries can still be cleaned up.)
    if enabled && scope == ExtensionScope::Project && is_language_parser_id(id) {
        return Err(KlensError::ProjectScopedLanguageParser { id: id.to_string() });
    }

    let is_recognized = validate_extension_id(id).is_ok() || {
        let global_ext_dir = global_extensions_dir_from_config(global_cfg_path);
        let discovered = discover_language_manifests(&global_ext_dir, project_root);
        discovered.manifests.contains_key(id)
    };

    if enabled && !is_recognized {
        return Err(invalid_ext_error(id));
    }

    let target_id = id;

    match scope {
        ExtensionScope::Global => {
            let mut cfg = GlobalConfig::load_or_default(global_cfg_path)?;
            let (updated, changed) = apply_toggle(&cfg.enabled_extensions, target_id, enabled);
            if !is_recognized && !changed {
                return Err(invalid_ext_error(id));
            }
            if changed {
                cfg.enabled_extensions = updated.clone();
                cfg.save_atomic(global_cfg_path)?;
            }
            Ok(ExtensionToggleReport {
                schema_version: SCHEMA_VERSION,
                id: target_id.to_string(),
                scope,
                enabled,
                changed,
                config_path: normalize_display_path(global_cfg_path),
                enabled_extensions: updated,
            })
        }
        ExtensionScope::Project => {
            let root = project_root.ok_or_else(|| {
                KlensError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no project root available for project-scoped extension update",
                ))
            })?;
            let (cfg_abs, _) = root.resolve_for_write(".klens/config.toml")?;
            let mut cfg = ProjectConfig::load_or_default(&cfg_abs)?;
            let (updated, changed) = apply_toggle(&cfg.enabled_extensions, target_id, enabled);
            if !is_recognized && !changed {
                return Err(invalid_ext_error(id));
            }
            if changed {
                cfg.enabled_extensions = updated.clone();
                cfg.save_atomic(&cfg_abs)?;
            }
            Ok(ExtensionToggleReport {
                schema_version: SCHEMA_VERSION,
                id: target_id.to_string(),
                scope,
                enabled,
                changed,
                config_path: normalize_display_path(&cfg_abs),
                enabled_extensions: updated,
            })
        }
    }
}

fn apply_toggle(current: &[String], id: &str, enabled: bool) -> (Vec<String>, bool) {
    let mut set: BTreeSet<String> = current
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let changed = if enabled {
        set.insert(id.to_string())
    } else {
        set.remove(id)
    };
    (set.into_iter().collect(), changed)
}

fn normalize_display_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    #[cfg(windows)]
    let cleaned = if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        raw.into_owned()
    };
    #[cfg(not(windows))]
    let cleaned = raw.into_owned();
    cleaned.replace('\\', "/")
}

/// Format an [`ExtensionListReport`] as compact deterministic human-readable text.
pub fn format_extension_list_text(report: &ExtensionListReport) -> String {
    let mut out = String::new();
    out.push_str("Karasu Lens Optional Extensions (all disabled by default)\n");
    out.push_str(&format!("Global config:  {}\n", report.global_config_path));
    if let Some(proj) = &report.project_config_path {
        out.push_str(&format!("Project config: {proj}\n"));
    }
    out.push_str("\nID                         GLOBAL  PROJECT  EFFECTIVE  TRANSPORT\n");
    for ext in &report.extensions {
        let g = if ext.enabled_global { "on " } else { "off" };
        let p = if ext.enabled_project { "on " } else { "off" };
        let e = if ext.effective_enabled { "on " } else { "off" };
        out.push_str(&format!(
            "{:<26} {:<7} {:<8} {:<10} {}\n  {}\n",
            ext.id,
            g,
            p,
            e,
            ext.transport.as_str(),
            ext.description
        ));
        if let Some(cmd) = &ext.command {
            out.push_str(&format!("  command: {cmd}\n"));
        }
    }
    out.trim_end().to_string()
}

/// Format an [`ExtensionToggleReport`] as compact deterministic human-readable text.
pub fn format_extension_toggle_text(report: &ExtensionToggleReport) -> String {
    let verb = if report.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let note = if report.changed {
        "saved"
    } else {
        "already in requested state"
    };
    format!(
        "extension `{}` {} in {} config ({}) [{}]",
        report.id,
        verb,
        report.scope.as_str(),
        report.config_path,
        note
    )
}
