//! Out-of-core language parser sidecar orchestrator (`ext-lang-*` + `ext-lang-ctags`),
//! session lifecycle, 3-failure circuit breaker, deterministic Layer 2/3 routing,
//! `klens doctor` diagnostics, and Web UI health enrichment.

pub mod common;
pub mod ctags;
pub mod rpc;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use klens_core::{
    CTAGS_EXTENSION_ID, CheckSeverity, DoctorCheck, ExtensionHealthStatus, ExtensionKind,
    ExtensionListReport, GlobalConfig, LanguageExtensionManifest, LanguageManifestDiscovery,
    ProjectConfig, ProjectRoot, RelPath, discover_language_manifests,
    global_extensions_dir_from_config, is_valid_language_extension_id,
};

use crate::languages::AnalyzerRegistry;

pub use self::common::{
    CIRCUIT_BREAKER_THRESHOLD, CapabilitiesLanguage, CapabilitiesResult, DEFAULT_PARSE_TIMEOUT_MS,
    MAX_RPC_FRAME_BYTES, WINDOWS_CREATE_NO_WINDOW,
};
pub use self::ctags::{CtagsConfig, CtagsProbeInfo, probe_ctags};
pub use self::rpc::probe_rpc_sidecar;

use self::common::ExternalParseOutcome;
use self::ctags::{ctags_unavailable_warning, parse_file_with_ctags};
use self::rpc::RpcSidecarSession;

/// Resolved external parser slot for a non-built-in file before reading/parsing.
#[derive(Debug, Clone)]
pub(crate) enum ExternalParserSlot {
    CustomRpc {
        manifest_idx: usize,
        parser_id: String,
        parser_version: String,
        language_hint: String,
    },
    Ctags {
        parser_id: String,
        parser_version: String,
    },
    CtagsUnavailable {
        parser_id: String,
        parser_version: String,
    },
}

impl ExternalParserSlot {
    pub(crate) fn parser_id(&self) -> &str {
        match self {
            Self::CustomRpc { parser_id, .. }
            | Self::Ctags { parser_id, .. }
            | Self::CtagsUnavailable { parser_id, .. } => parser_id,
        }
    }

    pub(crate) fn parser_version(&self) -> &str {
        match self {
            Self::CustomRpc { parser_version, .. }
            | Self::Ctags { parser_version, .. }
            | Self::CtagsUnavailable { parser_version, .. } => parser_version,
        }
    }
}

/// Manages enabled `ext-lang-*` sidecars and `ext-lang-ctags` with lazy spawn,
/// graceful `ext/shutdown` on drop, and per-pass 3-failure circuit breaking.
pub(crate) struct SidecarManager {
    custom_manifests: Vec<LanguageExtensionManifest>,
    ctags_enabled: bool,
    ctags_config: CtagsConfig,
    rpc_sessions: BTreeMap<String, RpcSidecarSession>,
    failure_counts: BTreeMap<String, u32>,
    tripped_breakers: BTreeSet<String>,
    ctags_probe: Option<Result<CtagsProbeInfo, String>>,
}

impl SidecarManager {
    /// Load enabled language sidecars from the trusted user-global config and manifest directory.
    ///
    /// Security (v0.3.2+): sidecars spawn external processes, so ONLY `~/.klens/config.toml`
    /// `enabled_extensions` and `~/.klens/extensions/` manifests are honored. The project's
    /// `.klens/config.toml` and `.klens/extensions/` are ignored here because a cloned
    /// repository controls them.
    ///
    /// Strictly read-only and lazy: never spawns any subprocess during construction.
    pub(crate) fn load(global_cfg_path: Option<&Path>, project_root: &ProjectRoot) -> Self {
        let enabled = trusted_enabled_extensions(global_cfg_path);

        let global_ext_dir = global_cfg_path
            .map(global_extensions_dir_from_config)
            .unwrap_or_default();
        let discovered = discover_language_manifests(&global_ext_dir, Some(project_root));

        let mut custom_manifests = Vec::new();
        for (id, entry) in &discovered.manifests {
            if id != CTAGS_EXTENSION_ID && enabled.contains(id) {
                custom_manifests.push(entry.manifest.clone());
            }
        }
        // `discovered.manifests` is a BTreeMap keyed by `id`, so lexicographical order is guaranteed.

        let ctags_invalid = discovered
            .invalid
            .iter()
            .any(|inv| inv.dir_name == CTAGS_EXTENSION_ID);
        let ctags_enabled = enabled.contains(CTAGS_EXTENSION_ID) && !ctags_invalid;
        let ctags_config = discovered
            .manifests
            .get(CTAGS_EXTENSION_ID)
            .map(|d| CtagsConfig::from_override_manifest(&d.manifest))
            .unwrap_or_default();

        Self {
            custom_manifests,
            ctags_enabled,
            ctags_config,
            rpc_sessions: BTreeMap::new(),
            failure_counts: BTreeMap::new(),
            tripped_breakers: BTreeSet::new(),
            ctags_probe: None,
        }
    }

    /// Resolve Layer 2 (custom `ext-lang-*`) -> Layer 3 (`ext-lang-ctags`) -> Layer 4 (`None`).
    ///
    /// Caller MUST have already checked Layer 1 (built-in `AnalyzerRegistry`) so core AST
    /// grammars are never hijacked.
    pub(crate) fn resolve_slot(&mut self, rel: &RelPath) -> Option<ExternalParserSlot> {
        let lower = rel.as_str().to_ascii_lowercase();
        let file_name = lower.rsplit('/').next().unwrap_or(&lower);

        // Layer 2a: compound extensions (containing `.`) in lexicographical manifest ID order.
        for (idx, manifest) in self.custom_manifests.iter().enumerate() {
            for ext in &manifest.extensions {
                if ext.contains('.') {
                    let suffix = format!(".{ext}");
                    if file_name.ends_with(&suffix) {
                        return Some(ExternalParserSlot::CustomRpc {
                            manifest_idx: idx,
                            parser_id: manifest.id.clone(),
                            parser_version: manifest.version.clone(),
                            language_hint: ext.replace('.', "_"),
                        });
                    }
                }
            }
        }

        // Layer 2b: simple extensions in lexicographical manifest ID order.
        if let Some((_, ext)) = file_name.rsplit_once('.') {
            for (idx, manifest) in self.custom_manifests.iter().enumerate() {
                if manifest.extensions.iter().any(|candidate| candidate == ext) {
                    return Some(ExternalParserSlot::CustomRpc {
                        manifest_idx: idx,
                        parser_id: manifest.id.clone(),
                        parser_version: manifest.version.clone(),
                        language_hint: ext.to_string(),
                    });
                }
            }
        }

        // Layer 3: `ext-lang-ctags` reference adapter.
        if self.ctags_enabled && self.ctags_config.matches_path(rel) {
            let probe = self
                .ctags_probe
                .get_or_insert_with(|| probe_ctags(&self.ctags_config.command));
            return match probe {
                Ok(info) => Some(ExternalParserSlot::Ctags {
                    parser_id: CTAGS_EXTENSION_ID.to_string(),
                    parser_version: info.parser_version.clone(),
                }),
                Err(_) => Some(ExternalParserSlot::CtagsUnavailable {
                    parser_id: "ext-lang-ctags:unavailable".to_string(),
                    parser_version: "0".to_string(),
                }),
            };
        }

        None
    }

    /// Execute parsing for a cache-missed file against its resolved external parser slot.
    pub(crate) fn parse_with_slot(
        &mut self,
        slot: &ExternalParserSlot,
        rel: &RelPath,
        normalized_content: &str,
        content_blake3: &str,
        file_line_count: usize,
    ) -> ExternalParseOutcome {
        match slot {
            ExternalParserSlot::CustomRpc {
                manifest_idx,
                parser_id,
                language_hint,
                ..
            } => {
                if self.tripped_breakers.contains(parser_id) {
                    return ExternalParseOutcome::Fallback {
                        language_id: Some(language_hint.clone()),
                        reason: format!(
                            "sidecar circuit breaker opened after {CIRCUIT_BREAKER_THRESHOLD} consecutive failures (`{parser_id}`)"
                        ),
                        count_as_failure: false,
                    };
                }

                let manifest = self.custom_manifests[*manifest_idx].clone();
                if !self.rpc_sessions.contains_key(parser_id) {
                    match RpcSidecarSession::spawn(&manifest) {
                        Ok(session) => {
                            self.rpc_sessions.insert(parser_id.clone(), session);
                        }
                        Err(reason) => {
                            self.record_failure(parser_id);
                            return ExternalParseOutcome::Fallback {
                                language_id: Some(language_hint.clone()),
                                reason,
                                count_as_failure: true,
                            };
                        }
                    }
                }

                let call_result = {
                    let session = self
                        .rpc_sessions
                        .get_mut(parser_id)
                        .expect("session inserted above");
                    session.parse_file(
                        rel,
                        language_hint,
                        normalized_content,
                        content_blake3,
                        file_line_count,
                    )
                };

                match call_result {
                    Ok(ExternalParseOutcome::Parsed(ok)) => {
                        self.failure_counts.insert(parser_id.clone(), 0);
                        ExternalParseOutcome::Parsed(ok)
                    }
                    Ok(ExternalParseOutcome::Fallback {
                        language_id,
                        reason,
                        count_as_failure,
                    }) => {
                        if count_as_failure {
                            self.rpc_sessions.remove(parser_id);
                            self.record_failure(parser_id);
                        } else {
                            self.failure_counts.insert(parser_id.clone(), 0);
                        }
                        ExternalParseOutcome::Fallback {
                            language_id,
                            reason,
                            count_as_failure,
                        }
                    }
                    Err(reason) => {
                        self.rpc_sessions.remove(parser_id);
                        self.record_failure(parser_id);
                        ExternalParseOutcome::Fallback {
                            language_id: Some(language_hint.clone()),
                            reason,
                            count_as_failure: true,
                        }
                    }
                }
            }
            ExternalParserSlot::Ctags { parser_id, .. } => {
                if self.tripped_breakers.contains(parser_id) {
                    return ExternalParseOutcome::Fallback {
                        language_id: None,
                        reason: format!(
                            "sidecar circuit breaker opened after {CIRCUIT_BREAKER_THRESHOLD} consecutive failures (`{parser_id}`)"
                        ),
                        count_as_failure: false,
                    };
                }
                let Some(Ok(probe)) = self.ctags_probe.as_ref() else {
                    return ExternalParseOutcome::Fallback {
                        language_id: None,
                        reason: ctags_unavailable_warning(),
                        count_as_failure: false,
                    };
                };
                let outcome = parse_file_with_ctags(
                    &self.ctags_config,
                    probe,
                    rel,
                    normalized_content,
                    file_line_count,
                );
                match &outcome {
                    ExternalParseOutcome::Parsed(_) => {
                        self.failure_counts.insert(parser_id.clone(), 0);
                    }
                    ExternalParseOutcome::Fallback {
                        count_as_failure: true,
                        ..
                    } => {
                        self.record_failure(parser_id);
                    }
                    ExternalParseOutcome::Fallback {
                        count_as_failure: false,
                        ..
                    } => {}
                }
                outcome
            }
            ExternalParserSlot::CtagsUnavailable { .. } => ExternalParseOutcome::Fallback {
                language_id: None,
                reason: ctags_unavailable_warning(),
                count_as_failure: false,
            },
        }
    }

    /// Reset per-pass circuit breaker counters at the start of a workspace/directory sync.
    pub(crate) fn reset_circuit_breakers(&mut self) {
        self.failure_counts.clear();
        self.tripped_breakers.clear();
    }

    /// Gracefully shut down all active JSON-RPC sidecar sessions (`ext/shutdown`).
    pub(crate) fn shutdown_all(&mut self) {
        let sessions = std::mem::take(&mut self.rpc_sessions);
        for (_, session) in sessions {
            session.shutdown();
        }
    }

    fn record_failure(&mut self, parser_id: &str) {
        let count = self
            .failure_counts
            .entry(parser_id.to_string())
            .or_insert(0);
        *count = count.saturating_add(1);
        if *count >= CIRCUIT_BREAKER_THRESHOLD {
            self.tripped_breakers.insert(parser_id.to_string());
        }
    }
}

impl Drop for SidecarManager {
    fn drop(&mut self) {
        self.shutdown_all();
    }
}

/// Return the canonical set of built-in file extensions owned by core `AnalyzerRegistry`.
pub fn builtin_language_extensions() -> BTreeSet<String> {
    AnalyzerRegistry::new().all_extensions()
}

/// Trusted set of enabled extension IDs: ONLY `~/.klens/config.toml` `enabled_extensions`.
///
/// The project `.klens/config.toml` is deliberately excluded (a cloned repository controls it).
fn trusted_enabled_extensions(global_cfg_path: Option<&Path>) -> BTreeSet<String> {
    global_cfg_path
        .and_then(|path| GlobalConfig::load_or_default(path).ok())
        .map(|cfg| {
            cfg.enabled_extensions
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Honest `klens doctor` warning (Constitution Art. 2) when a project ships language-parser
/// manifests or project-level `enabled_extensions` entries that are ignored for security.
fn ignored_project_extensions_check(
    project_root: &ProjectRoot,
    discovered: &LanguageManifestDiscovery,
) -> Option<DoctorCheck> {
    let proj_cfg_path = project_root.root().join(".klens").join("config.toml");
    let mut ignored: BTreeSet<String> = ProjectConfig::load_or_default(&proj_cfg_path)
        .map(|cfg| cfg.enabled_extensions)
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| is_valid_language_extension_id(s))
        .collect();
    ignored.extend(discovered.ignored_project_manifests.iter().cloned());
    if ignored.is_empty() {
        return None;
    }
    Some(DoctorCheck {
        name: "Language sidecars (project-local)".to_string(),
        severity: CheckSeverity::Warning,
        message: format!(
            "Project-local language sidecar entries ignored for security [{}]; install trusted parsers under ~/.klens/extensions/ and enable them globally with `klens ext enable <id>`",
            ignored.into_iter().collect::<Vec<_>>().join(", ")
        ),
    })
}

/// Build read-only `klens doctor` diagnostic checks for discovered & enabled `ext-lang-*`
/// language parser sidecars (`docs/05-LANGUAGE-SIDECAR-SPEC.md` §6.4).
pub fn inspect_language_extensions_doctor(
    global_cfg_path: &Path,
    project_root: &ProjectRoot,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let builtin_exts = builtin_language_extensions();

    let mut enabled = trusted_enabled_extensions(Some(global_cfg_path));

    let global_ext_dir = global_extensions_dir_from_config(global_cfg_path);
    let discovered = discover_language_manifests(&global_ext_dir, Some(project_root));

    if let Some(check) = ignored_project_extensions_check(project_root, &discovered) {
        checks.push(check);
    }

    for inv in &discovered.invalid {
        checks.push(DoctorCheck {
            name: format!("Language sidecar ({})", inv.dir_name),
            severity: CheckSeverity::Warning,
            message: format!(
                "Invalid manifest at {}: {}; skipped (fail-closed)",
                inv.manifest_path.display(),
                inv.reason
            ),
        });
    }

    let mut enabled_lang_count = 0usize;
    let mut claimed_custom_exts: BTreeMap<String, String> = BTreeMap::new();

    for (id, entry) in &discovered.manifests {
        if id == CTAGS_EXTENSION_ID || !enabled.contains(id) {
            continue;
        }
        enabled_lang_count += 1;

        let shadowed_builtin: Vec<String> = entry
            .manifest
            .extensions
            .iter()
            .filter(|ext| builtin_exts.contains(ext.as_str()))
            .cloned()
            .collect();
        if !shadowed_builtin.is_empty() {
            checks.push(DoctorCheck {
                name: format!("Language sidecar ({id})"),
                severity: CheckSeverity::Warning,
                message: format!(
                    "Declares built-in extension(s) [{}]; built-in VERIFIED_AST takes precedence",
                    shadowed_builtin.join(", ")
                ),
            });
        }

        let mut ext_conflicts = Vec::new();
        for ext in &entry.manifest.extensions {
            if builtin_exts.contains(ext.as_str()) {
                continue;
            }
            if let Some(winner) = claimed_custom_exts.get(ext) {
                ext_conflicts.push(format!("{ext} (owned by {winner})"));
            } else {
                claimed_custom_exts.insert(ext.clone(), id.clone());
            }
        }
        if !ext_conflicts.is_empty() {
            checks.push(DoctorCheck {
                name: format!("Language sidecar ({id})"),
                severity: CheckSeverity::Warning,
                message: format!(
                    "Extension conflict(s): {}; lexicographically earlier sidecar takes precedence",
                    ext_conflicts.join(", ")
                ),
            });
        }

        match probe_rpc_sidecar(&entry.manifest) {
            Ok(caps) => {
                checks.push(DoctorCheck {
                    name: format!("Language sidecar ({id})"),
                    severity: CheckSeverity::Ok,
                    message: format!(
                        "Active ({}@{}, {} extensions, command={}, trust=EXTERNAL_PARSER)",
                        caps.parser_id,
                        caps.parser_version,
                        entry.manifest.extensions.len(),
                        entry.manifest.command
                    ),
                });
            }
            Err(reason) => {
                checks.push(DoctorCheck {
                    name: format!("Language sidecar ({id})"),
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "Enabled but handshake failed: {reason}; affected files fall back to UNPARSED_FALLBACK"
                    ),
                });
            }
        }
    }

    if enabled.remove(CTAGS_EXTENSION_ID)
        && !discovered
            .invalid
            .iter()
            .any(|i| i.dir_name == CTAGS_EXTENSION_ID)
    {
        enabled_lang_count += 1;
        let ctags_cfg = discovered
            .manifests
            .get(CTAGS_EXTENSION_ID)
            .map(|d| CtagsConfig::from_override_manifest(&d.manifest))
            .unwrap_or_default();

        let shadowed_builtin: Vec<String> = ctags_cfg
            .extensions
            .iter()
            .filter(|ext| builtin_exts.contains(ext.as_str()))
            .cloned()
            .collect();
        if !shadowed_builtin.is_empty() {
            checks.push(DoctorCheck {
                name: format!("Language sidecar ({CTAGS_EXTENSION_ID})"),
                severity: CheckSeverity::Warning,
                message: format!(
                    "Declares built-in extension(s) [{}]; built-in VERIFIED_AST takes precedence",
                    shadowed_builtin.join(", ")
                ),
            });
        }

        match probe_ctags(&ctags_cfg.command) {
            Ok(info) => {
                checks.push(DoctorCheck {
                    name: format!("Language sidecar ({CTAGS_EXTENSION_ID})"),
                    severity: CheckSeverity::Ok,
                    message: format!(
                        "Active (Universal Ctags {}, +json verified, {} extensions, trust=EXTERNAL_PARSER)",
                        info.ctags_version,
                        ctags_cfg.extensions.len()
                    ),
                });
            }
            Err(reason) => {
                checks.push(DoctorCheck {
                    name: format!("Language sidecar ({CTAGS_EXTENSION_ID})"),
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "Enabled but unavailable: {reason}; unsupported files remain UNPARSED_FALLBACK"
                    ),
                });
            }
        }
    }

    if enabled_lang_count == 0 && checks.is_empty() {
        checks.push(DoctorCheck {
            name: "Language sidecars (ext-lang-*)".to_string(),
            severity: CheckSeverity::Ok,
            message: "0 external language sidecars enabled (built-in 10 Tree-sitter languages + structured docs active)".to_string(),
        });
    }

    checks
}

/// Enrich a read-only [`ExtensionListReport`] with live sidecar health badges for all
/// `kind == Some(ExtensionKind::LanguageParser)` rows (used by `GET /api/extensions`).
pub fn enrich_extension_list_health(
    report: &mut ExtensionListReport,
    global_cfg_path: &Path,
    project_root: Option<&ProjectRoot>,
) {
    let global_ext_dir = global_extensions_dir_from_config(global_cfg_path);
    let discovered = discover_language_manifests(&global_ext_dir, project_root);

    for entry in &mut report.extensions {
        if entry.kind != Some(ExtensionKind::LanguageParser) {
            continue;
        }
        if entry.health == Some(ExtensionHealthStatus::Misconfigured) {
            continue;
        }
        if !entry.effective_enabled {
            entry.health = Some(ExtensionHealthStatus::Disabled);
            entry.health_detail = None;
            continue;
        }

        if entry.id == CTAGS_EXTENSION_ID {
            let cfg = discovered
                .manifests
                .get(CTAGS_EXTENSION_ID)
                .map(|d| CtagsConfig::from_override_manifest(&d.manifest))
                .unwrap_or_default();
            match probe_ctags(&cfg.command) {
                Ok(info) => {
                    entry.health = Some(ExtensionHealthStatus::Ready);
                    entry.health_detail = Some(format!(
                        "Universal Ctags {} (+json, EXTERNAL_PARSER)",
                        info.ctags_version
                    ));
                }
                Err(reason) => {
                    entry.health = Some(ExtensionHealthStatus::Unavailable);
                    entry.health_detail = Some(reason);
                }
            }
        } else if let Some(disc) = discovered.manifests.get(&entry.id) {
            match probe_rpc_sidecar(&disc.manifest) {
                Ok(caps) => {
                    entry.health = Some(ExtensionHealthStatus::Ready);
                    entry.health_detail = Some(format!(
                        "{}@{} (EXTERNAL_PARSER)",
                        caps.parser_id, caps.parser_version
                    ));
                }
                Err(reason) => {
                    entry.health = Some(ExtensionHealthStatus::Unavailable);
                    entry.health_detail = Some(reason);
                }
            }
        } else {
            entry.health = Some(ExtensionHealthStatus::Misconfigured);
            entry.health_detail = Some("manifest not found or invalid".to_string());
        }
    }
}
