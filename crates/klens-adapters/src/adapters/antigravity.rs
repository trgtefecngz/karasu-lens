//! Native host adapter for Google Antigravity (`--host antigravity`).
//!
//! Manages:
//! - Primary global MCP config at `~/.gemini/config/mcp_config.json`
//! - Embedded skill pack under `~/.gemini/config/skills/<skill-id>/SKILL.md`
//! - Backwards-compatible detection, doctor diagnostics, and cleanup for legacy
//!   `~/.gemini/antigravity/mcp_config.json` and `~/.gemini/antigravity/skills/`

use std::path::{Path, PathBuf};

use klens_core::{
    AdapterContext, CheckSeverity, DoctorCheck, HostAdapter, HostDetectStatus, InstallReport,
    KlensError,
};

use super::common::{
    AccessScope, ConfiguredAccessEntry, McpInspection, clean_binary_path_string,
    doctor_check_mcp_registration, inspect_json_mcp_server, paths_equivalent,
    remove_json_mcp_server, resolve_home_dir, upsert_json_mcp_server,
};
use crate::error::AdapterError;
use crate::skills::{
    SkillSelection, count_installed_skills, install_skills_into_dir, remove_klens_skills_from_dir,
};

/// Native adapter for Antigravity (`~/.gemini/config/`, with legacy `~/.gemini/antigravity/` support).
#[derive(Debug, Clone)]
pub struct AntigravityAdapter {
    home_dir: PathBuf,
    skills: SkillSelection,
    force: bool,
}

impl AntigravityAdapter {
    /// Construct an adapter targeting the current user's home directory.
    pub fn new() -> Result<Self, AdapterError> {
        Ok(Self::with_home(resolve_home_dir()?))
    }

    /// Construct an adapter rooted at an explicit home directory (ideal for isolated tests).
    pub fn with_home(home_dir: PathBuf) -> Self {
        Self {
            home_dir,
            skills: SkillSelection::default(),
            force: false,
        }
    }

    pub fn with_skills(mut self, skills: SkillSelection) -> Self {
        self.skills = skills;
        self
    }

    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Current standard Antigravity global configuration directory (`~/.gemini/config/`).
    pub fn base_dir(&self) -> PathBuf {
        self.home_dir.join(".gemini").join("config")
    }

    /// Current standard Antigravity global MCP config (`~/.gemini/config/mcp_config.json`).
    pub fn mcp_config_path(&self) -> PathBuf {
        self.base_dir().join("mcp_config.json")
    }

    /// Current standard Antigravity global skills directory (`~/.gemini/config/skills/`).
    pub fn skills_dir(&self) -> PathBuf {
        self.base_dir().join("skills")
    }

    /// Legacy Antigravity global directory (`~/.gemini/antigravity/`), inspected honestly for
    /// backwards compatibility and cleaned on `disconnect` / `uninstall --all`.
    pub fn legacy_base_dir(&self) -> PathBuf {
        self.home_dir.join(".gemini").join("antigravity")
    }

    /// Legacy Antigravity MCP config path (`~/.gemini/antigravity/mcp_config.json`).
    pub fn legacy_mcp_config_path(&self) -> PathBuf {
        self.legacy_base_dir().join("mcp_config.json")
    }

    /// Legacy Antigravity skills directory (`~/.gemini/antigravity/skills/`).
    pub fn legacy_skills_dir(&self) -> PathBuf {
        self.legacy_base_dir().join("skills")
    }

    /// Inspect configured access entries across current and legacy global MCP paths.
    pub fn configured_access(&self, current_binary: &Path) -> Vec<ConfiguredAccessEntry> {
        let mut entries = Vec::new();

        let cfg = self.mcp_config_path();
        if let McpInspection::Registered { command, .. } = inspect_json_mcp_server(&cfg) {
            entries.push(ConfiguredAccessEntry {
                host_id: self.host_id().to_string(),
                display_name: "Antigravity".to_string(),
                scope: AccessScope::Global,
                scope_label: format!("Antigravity ({})", AccessScope::Global.label_en()),
                config_path: PathBuf::from(clean_binary_path_string(&cfg)),
                binary_matches_current: Some(paths_equivalent(&command, current_binary)),
                configured_binary: Some(command),
            });
        }

        let legacy_cfg = self.legacy_mcp_config_path();
        if let McpInspection::Registered { command, .. } = inspect_json_mcp_server(&legacy_cfg) {
            entries.push(ConfiguredAccessEntry {
                host_id: self.host_id().to_string(),
                display_name: "Antigravity".to_string(),
                scope: AccessScope::Global,
                scope_label: format!("Antigravity ({}, legacy)", AccessScope::Global.label_en()),
                config_path: PathBuf::from(clean_binary_path_string(&legacy_cfg)),
                binary_matches_current: Some(paths_equivalent(&command, current_binary)),
                configured_binary: Some(command),
            });
        }

        entries
    }
}

impl HostAdapter for AntigravityAdapter {
    fn host_id(&self) -> &'static str {
        "antigravity"
    }

    fn detect(&self, _project_root: &Path) -> HostDetectStatus {
        let cfg = self.mcp_config_path();
        if matches!(
            inspect_json_mcp_server(&cfg),
            McpInspection::Registered { .. }
        ) {
            return HostDetectStatus::Installed { config_path: cfg };
        }

        let legacy_cfg = self.legacy_mcp_config_path();
        if matches!(
            inspect_json_mcp_server(&legacy_cfg),
            McpInspection::Registered { .. }
        ) {
            return HostDetectStatus::Installed {
                config_path: legacy_cfg,
            };
        }

        if self.base_dir().is_dir() || self.legacy_base_dir().is_dir() {
            return HostDetectStatus::Detected { config_path: cfg };
        }
        HostDetectStatus::NotDetected
    }

    fn install_or_update(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError> {
        let cfg_path = self.mcp_config_path();
        let mcp = upsert_json_mcp_server(&cfg_path, &ctx.binary_path, ctx.dry_run, self.force)
            .map_err(KlensError::from)?;
        let skills_rep =
            install_skills_into_dir(&self.skills_dir(), &self.skills, ctx.dry_run, self.force)
                .map_err(KlensError::from)?;

        let mut files_touched = Vec::new();
        let mut notes = Vec::new();
        let mut mutated = false;

        if mcp.file_outcome.is_planned_change() {
            files_touched.push(cfg_path.clone());
            if mcp.file_outcome.mutated_disk() {
                mutated = true;
            }
            let new_bin = clean_binary_path_string(&ctx.binary_path);
            let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };
            if mcp.updated_binary_path {
                let old = mcp.previous_binary.as_deref().unwrap_or("<unknown>");
                notes.push(format!(
                    "{prefix}Updated binary path in {}: `{old}` -> `{new_bin}`",
                    cfg_path.display()
                ));
            } else {
                notes.push(format!(
                    "{prefix}registered MCP server `klens` in {} (`{new_bin}`)",
                    cfg_path.display()
                ));
            }
        } else {
            notes.push(format!(
                "MCP server `klens` already up-to-date in {}",
                cfg_path.display()
            ));
        }

        let legacy_cfg = self.legacy_mcp_config_path();
        if matches!(
            inspect_json_mcp_server(&legacy_cfg),
            McpInspection::Registered { .. }
        ) {
            notes.push(format!(
                "note: legacy Antigravity MCP registration still exists at {} (run `klens disconnect --host antigravity` to remove both)",
                clean_binary_path_string(&legacy_cfg)
            ));
        }

        files_touched.extend(skills_rep.files_touched);
        if skills_rep.mutated_disk {
            mutated = true;
        }
        notes.extend(skills_rep.notes);

        Ok(InstallReport {
            host_id: self.host_id().to_string(),
            changed: mutated && !ctx.dry_run,
            dry_run: ctx.dry_run,
            files_touched,
            notes,
        })
    }

    fn uninstall(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError> {
        let mut files_touched = Vec::new();
        let mut notes = Vec::new();
        let mut mutated = false;
        let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };

        // Clean both current (`~/.gemini/config/`) and legacy (`~/.gemini/antigravity/`) locations.
        for (cfg_path, skills_dir, base_dir) in [
            (self.mcp_config_path(), self.skills_dir(), self.base_dir()),
            (
                self.legacy_mcp_config_path(),
                self.legacy_skills_dir(),
                self.legacy_base_dir(),
            ),
        ] {
            let mcp_out = remove_json_mcp_server(&cfg_path, ctx.dry_run, true, false)
                .map_err(KlensError::from)?;
            if mcp_out.is_planned_change() {
                files_touched.push(cfg_path.clone());
                if mcp_out.mutated_disk() {
                    mutated = true;
                }
                if let Some(bak) = mcp_out.backup_path() {
                    notes.push(format!("{prefix}backup: {}", bak.display()));
                }
                notes.push(format!(
                    "{prefix}removed MCP server `klens` from {}",
                    cfg_path.display()
                ));
            }

            let skills_rep = remove_klens_skills_from_dir(&skills_dir, &base_dir, ctx.dry_run)
                .map_err(KlensError::from)?;
            files_touched.extend(skills_rep.files_touched);
            if skills_rep.mutated_disk {
                mutated = true;
            }
            notes.extend(skills_rep.notes);
        }

        Ok(InstallReport {
            host_id: self.host_id().to_string(),
            changed: mutated && !ctx.dry_run,
            dry_run: ctx.dry_run,
            files_touched,
            notes,
        })
    }

    fn doctor(&self, ctx: &AdapterContext) -> Vec<DoctorCheck> {
        let cfg_path = self.mcp_config_path();
        let inspection = inspect_json_mcp_server(&cfg_path);
        let mut checks = vec![doctor_check_mcp_registration(
            "Antigravity",
            AccessScope::Global,
            &cfg_path,
            &inspection,
            &ctx.binary_path,
        )];

        if matches!(inspection, McpInspection::Registered { .. }) {
            let installed_count = count_installed_skills(&self.skills_dir());
            let severity = if installed_count == 0 {
                CheckSeverity::Warning
            } else {
                CheckSeverity::Ok
            };
            checks.push(DoctorCheck {
                name: "Antigravity skills".to_string(),
                severity,
                message: format!(
                    "{installed_count} embedded klens skill(s) installed in {}",
                    clean_binary_path_string(&self.skills_dir())
                ),
            });
        }

        let legacy_cfg = self.legacy_mcp_config_path();
        match inspect_json_mcp_server(&legacy_cfg) {
            McpInspection::Registered { command, .. } => {
                let clean_legacy = clean_binary_path_string(&legacy_cfg);
                let clean_current = clean_binary_path_string(&cfg_path);
                let bin_state = if paths_equivalent(&command, &ctx.binary_path) {
                    format!("`{command}`")
                } else {
                    format!(
                        "stale binary `{command}` vs `{}`",
                        clean_binary_path_string(&ctx.binary_path)
                    )
                };
                checks.push(DoctorCheck {
                    name: "Antigravity (legacy global-mcp)".to_string(),
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "legacy registration detected at {clean_legacy} ({bin_state}); current standard path is {clean_current} — run `klens disconnect --host antigravity` and `klens init --host antigravity` to migrate"
                    ),
                });
            }
            McpInspection::CorruptConfig(reason) => {
                checks.push(DoctorCheck {
                    name: "Antigravity (legacy global-mcp)".to_string(),
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "corrupt legacy config at {}: {reason}",
                        clean_binary_path_string(&legacy_cfg)
                    ),
                });
            }
            McpInspection::MissingFile | McpInspection::NotRegistered => {}
        }

        checks
    }
}
