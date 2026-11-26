//! Native host adapter for OpenAI Codex / ChatGPT Harness (`--host codex`).
//!
//! Manages:
//! - Global MCP registration `[mcp_servers.klens]` in `~/.codex/config.toml`
//! - Project-local marked block `<!-- klens:start --> ... <!-- klens:end -->` in `AGENTS.md`

use std::path::{Path, PathBuf};

use klens_core::{
    AdapterContext, CheckSeverity, DoctorCheck, HostAdapter, HostDetectStatus, InstallReport,
    KlensError,
};

use super::codex_toml::{inspect_codex_toml_mcp, remove_codex_toml_mcp, upsert_codex_toml_mcp};
use super::common::{
    AccessScope, ConfiguredAccessEntry, McpInspection, clean_binary_path_string,
    doctor_check_mcp_registration, paths_equivalent, resolve_home_dir,
};
use crate::error::AdapterError;
use crate::skills::{SkillSelection, render_inline_guide_block};
use crate::text_format::{
    MarkerStyle, has_marked_block, read_text_file, remove_marked_file, upsert_marked_file,
};

/// Native adapter for Codex (`~/.codex/config.toml` + project `AGENTS.md`).
#[derive(Debug, Clone)]
pub struct CodexAdapter {
    home_dir: PathBuf,
    skills: SkillSelection,
    force: bool,
}

impl CodexAdapter {
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

    pub fn base_dir(&self) -> PathBuf {
        self.home_dir.join(".codex")
    }

    pub fn global_config_path(&self) -> PathBuf {
        self.base_dir().join("config.toml")
    }

    pub fn project_agents_path(project_root: &Path) -> PathBuf {
        project_root.join("AGENTS.md")
    }

    fn project_has_marked_agents(project_root: &Path) -> bool {
        let p = Self::project_agents_path(project_root);
        matches!(
            read_text_file(&p),
            Ok(Some((_, lf, _))) if has_marked_block(&p, &lf, MarkerStyle::Html)
        )
    }

    /// Inspect BOTH global `~/.codex/config.toml` and project-local `AGENTS.md` registrations.
    pub fn configured_access(
        &self,
        project_root: &Path,
        current_binary: &Path,
    ) -> Vec<ConfiguredAccessEntry> {
        let mut entries = Vec::new();

        let agents_path = Self::project_agents_path(project_root);
        if Self::project_has_marked_agents(project_root) {
            entries.push(ConfiguredAccessEntry {
                host_id: self.host_id().to_string(),
                display_name: "Codex".to_string(),
                scope: AccessScope::ProjectLocal,
                scope_label: format!(
                    "Codex ({}, AGENTS.md)",
                    AccessScope::ProjectLocal.label_en()
                ),
                config_path: PathBuf::from(clean_binary_path_string(&agents_path)),
                configured_binary: None,
                binary_matches_current: None,
            });
        }

        let cfg = self.global_config_path();
        if let McpInspection::Registered { command, .. } = inspect_codex_toml_mcp(&cfg) {
            entries.push(ConfiguredAccessEntry {
                host_id: self.host_id().to_string(),
                display_name: "Codex".to_string(),
                scope: AccessScope::Global,
                scope_label: format!("Codex ({})", AccessScope::Global.label_en()),
                config_path: PathBuf::from(clean_binary_path_string(&cfg)),
                binary_matches_current: Some(paths_equivalent(&command, current_binary)),
                configured_binary: Some(command),
            });
        }

        entries
    }

    /// Remove ONLY the project-local `AGENTS.md` marked block (used by `klens detach` so
    /// `~/.codex/config.toml` keeps working for other projects).
    pub fn detach_project(
        &self,
        ctx: &AdapterContext,
        backup_existing: bool,
    ) -> Result<InstallReport, AdapterError> {
        let agents_path = Self::project_agents_path(&ctx.project_root);
        let out = remove_marked_file(
            &agents_path,
            MarkerStyle::Html,
            ctx.dry_run,
            backup_existing,
        )?;

        let mut files_touched = Vec::new();
        let mut notes = Vec::new();
        let mut mutated = false;
        if out.is_planned_change() {
            files_touched.push(agents_path.clone());
            mutated |= out.mutated_disk();
            let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };
            if let Some(bak) = out.backup_path() {
                notes.push(format!("{prefix}backup: {}", bak.display()));
            }
            notes.push(format!(
                "{prefix}removed klens marked block from {}",
                agents_path.display()
            ));
        }

        Ok(InstallReport {
            host_id: self.host_id().to_string(),
            changed: mutated && !ctx.dry_run,
            dry_run: ctx.dry_run,
            files_touched,
            notes,
        })
    }
}

impl HostAdapter for CodexAdapter {
    fn host_id(&self) -> &'static str {
        "codex"
    }

    fn detect(&self, project_root: &Path) -> HostDetectStatus {
        let cfg = self.global_config_path();
        if matches!(
            inspect_codex_toml_mcp(&cfg),
            McpInspection::Registered { .. }
        ) {
            return HostDetectStatus::Installed { config_path: cfg };
        }

        let agents_path = Self::project_agents_path(project_root);
        if Self::project_has_marked_agents(project_root) {
            return HostDetectStatus::Installed {
                config_path: agents_path,
            };
        }

        if self.base_dir().is_dir() || cfg.is_file() {
            return HostDetectStatus::Detected { config_path: cfg };
        }
        if agents_path.is_file() {
            return HostDetectStatus::Detected {
                config_path: agents_path,
            };
        }

        HostDetectStatus::NotDetected
    }

    fn install_or_update(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError> {
        let mut files_touched = Vec::new();
        let mut notes = Vec::new();
        let mut mutated = false;
        let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };

        // 1. Upsert `[mcp_servers.klens]` in `~/.codex/config.toml`
        let cfg_path = self.global_config_path();
        let mcp = upsert_codex_toml_mcp(&cfg_path, &ctx.binary_path, ctx.dry_run, self.force)
            .map_err(KlensError::from)?;
        if mcp.file_outcome.is_planned_change() {
            files_touched.push(cfg_path.clone());
            mutated |= mcp.file_outcome.mutated_disk();
            let new_bin = clean_binary_path_string(&ctx.binary_path);
            if mcp.updated_binary_path {
                let old = mcp.previous_binary.as_deref().unwrap_or("<unknown>");
                notes.push(format!(
                    "{prefix}Updated binary path in {}: `{old}` -> `{new_bin}`",
                    cfg_path.display()
                ));
            } else {
                notes.push(format!(
                    "{prefix}registered `[mcp_servers.klens]` in {}",
                    cfg_path.display()
                ));
            }
        } else {
            notes.push(format!(
                "`[mcp_servers.klens]` already up-to-date in {}",
                cfg_path.display()
            ));
        }

        // 2. Upsert marked block in project `AGENTS.md` (preserving all user lines, BOM, CRLF)
        let agents_path = Self::project_agents_path(&ctx.project_root);
        let body = render_inline_guide_block(&self.skills, None);
        let agents_out = upsert_marked_file(
            &agents_path,
            MarkerStyle::Html,
            &body,
            ctx.dry_run,
            self.force,
        )
        .map_err(KlensError::from)?;
        if agents_out.is_planned_change() {
            files_touched.push(agents_path.clone());
            mutated |= agents_out.mutated_disk();
            notes.push(format!(
                "{prefix}updated klens marked block in {}",
                agents_path.display()
            ));
        }

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

        // 1. Backup & remove `[mcp_servers.klens]` from `~/.codex/config.toml`
        let cfg_path = self.global_config_path();
        let cfg_out =
            remove_codex_toml_mcp(&cfg_path, ctx.dry_run, true).map_err(KlensError::from)?;
        if cfg_out.is_planned_change() {
            files_touched.push(cfg_path.clone());
            mutated |= cfg_out.mutated_disk();
            if let Some(bak) = cfg_out.backup_path() {
                notes.push(format!("{prefix}backup: {}", bak.display()));
            }
            notes.push(format!(
                "{prefix}removed `[mcp_servers.klens]` from {}",
                cfg_path.display()
            ));
        }

        // 2. Surgically remove marked block from project `AGENTS.md`
        let local_rep = self.detach_project(ctx, true).map_err(KlensError::from)?;
        files_touched.extend(local_rep.files_touched);
        mutated |= local_rep.changed;
        notes.extend(local_rep.notes);

        Ok(InstallReport {
            host_id: self.host_id().to_string(),
            changed: mutated && !ctx.dry_run,
            dry_run: ctx.dry_run,
            files_touched,
            notes,
        })
    }

    fn doctor(&self, ctx: &AdapterContext) -> Vec<DoctorCheck> {
        let cfg_path = self.global_config_path();
        let inspection = inspect_codex_toml_mcp(&cfg_path);
        let mut checks = vec![doctor_check_mcp_registration(
            "Codex",
            AccessScope::Global,
            &cfg_path,
            &inspection,
            &ctx.binary_path,
        )];

        let agents_path = Self::project_agents_path(&ctx.project_root);
        let clean_agents = clean_binary_path_string(&agents_path);
        let has_block = Self::project_has_marked_agents(&ctx.project_root);
        checks.push(DoctorCheck {
            name: format!("Codex AGENTS.md ({})", AccessScope::ProjectLocal.label_en()),
            severity: CheckSeverity::Ok,
            message: if has_block {
                format!(
                    "klens marked block active [{}] ({clean_agents})",
                    AccessScope::ProjectLocal.label_en()
                )
            } else {
                format!("no klens block in {clean_agents}")
            },
        });

        checks
    }
}
