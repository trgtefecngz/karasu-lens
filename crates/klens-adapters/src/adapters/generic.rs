//! Universal compatibility adapter (`--host generic`) for Cursor, Windsurf,
//! Gemini CLI, GitHub Copilot, Aider, and CLI-only workflows.
//!
//! Manages:
//! - Project-local single-page `KLENS.md` (inside `<!-- klens:start --> ... <!-- klens:end -->`)
//! - Standard `stdio` MCP JSON snippet generation (`klens init --print-mcp-json`)

use std::path::{Path, PathBuf};

use klens_core::{
    AdapterContext, CheckSeverity, DoctorCheck, HostAdapter, HostDetectStatus, InstallReport,
    KlensError,
};

use super::common::{
    AccessScope, ConfiguredAccessEntry, clean_binary_path_string, render_standard_mcp_json,
};
use crate::error::AdapterError;
use crate::skills::{SkillSelection, render_inline_guide_block};
use crate::text_format::{
    MarkerStyle, has_marked_block, read_text_file, remove_marked_file, upsert_marked_file,
};

/// Universal Tier-2 adapter writing `KLENS.md` and standard `stdio` MCP JSON snippets.
#[derive(Debug, Clone, Default)]
pub struct GenericAdapter {
    skills: SkillSelection,
    force: bool,
}

impl GenericAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_skills(mut self, skills: SkillSelection) -> Self {
        self.skills = skills;
        self
    }

    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn project_guide_path(project_root: &Path) -> PathBuf {
        project_root.join("KLENS.md")
    }

    /// Render the standard `stdio` MCP JSON snippet (`klens init --print-mcp-json`).
    pub fn mcp_json_snippet(binary_path: &Path) -> String {
        render_standard_mcp_json(binary_path)
    }

    fn has_klens_block(project_root: &Path) -> bool {
        let p = Self::project_guide_path(project_root);
        matches!(
            read_text_file(&p),
            Ok(Some((_, lf, _))) if has_marked_block(&p, &lf, MarkerStyle::Html)
        )
    }

    /// Detect universal host hint directories in `project_root` (`.cursor/`, `.windsurf/`, `.github/`).
    pub fn detected_universal_hints(project_root: &Path) -> Vec<&'static str> {
        const HINTS: &[(&str, &str)] = &[
            (".cursor", "Cursor"),
            (".windsurf", "Windsurf"),
            (".github", "GitHub Copilot"),
        ];
        HINTS
            .iter()
            .filter_map(|(dir, label)| project_root.join(dir).is_dir().then_some(*label))
            .collect()
    }

    /// Inspect project-local `KLENS.md` registration.
    pub fn configured_access(
        &self,
        project_root: &Path,
        current_binary: &Path,
    ) -> Vec<ConfiguredAccessEntry> {
        let guide = Self::project_guide_path(project_root);
        let Ok(Some((_, lf, _))) = read_text_file(&guide) else {
            return Vec::new();
        };
        if !has_marked_block(&guide, &lf, MarkerStyle::Html) {
            return Vec::new();
        }
        let expected_cmd = clean_binary_path_string(current_binary);
        let matches_bin =
            lf.contains(&expected_cmd) || lf.contains(&expected_cmd.replace('\\', "\\\\"));
        vec![ConfiguredAccessEntry {
            host_id: self.host_id().to_string(),
            display_name: "Generic (KLENS.md)".to_string(),
            scope: AccessScope::ProjectLocal,
            scope_label: format!(
                "Generic ({}, KLENS.md)",
                AccessScope::ProjectLocal.label_en()
            ),
            config_path: PathBuf::from(clean_binary_path_string(&guide)),
            configured_binary: None,
            binary_matches_current: Some(matches_bin),
        }]
    }

    /// Surgically remove `<!-- klens:start --> ... <!-- klens:end -->` from `KLENS.md`.
    pub fn detach_project(
        &self,
        ctx: &AdapterContext,
        backup_existing: bool,
    ) -> Result<InstallReport, AdapterError> {
        let guide = Self::project_guide_path(&ctx.project_root);
        let out = remove_marked_file(&guide, MarkerStyle::Html, ctx.dry_run, backup_existing)?;

        let mut files_touched = Vec::new();
        let mut notes = Vec::new();
        let mut mutated = false;
        if out.is_planned_change() {
            files_touched.push(guide.clone());
            mutated |= out.mutated_disk();
            let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };
            if let Some(bak) = out.backup_path() {
                notes.push(format!("{prefix}backup: {}", bak.display()));
            }
            notes.push(format!(
                "{prefix}removed klens marked block from {}",
                guide.display()
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

impl HostAdapter for GenericAdapter {
    fn host_id(&self) -> &'static str {
        "generic"
    }

    fn detect(&self, project_root: &Path) -> HostDetectStatus {
        let guide = Self::project_guide_path(project_root);
        if Self::has_klens_block(project_root) {
            return HostDetectStatus::Installed { config_path: guide };
        }
        if !Self::detected_universal_hints(project_root).is_empty() {
            return HostDetectStatus::Detected { config_path: guide };
        }
        HostDetectStatus::NotDetected
    }

    fn install_or_update(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError> {
        let guide = Self::project_guide_path(&ctx.project_root);
        let snippet = Self::mcp_json_snippet(&ctx.binary_path);
        let body = render_inline_guide_block(&self.skills, Some(&snippet));

        let out = upsert_marked_file(&guide, MarkerStyle::Html, &body, ctx.dry_run, self.force)
            .map_err(KlensError::from)?;

        let mut files_touched = Vec::new();
        let mut notes = Vec::new();
        let mut mutated = false;
        if out.is_planned_change() {
            files_touched.push(guide.clone());
            mutated |= out.mutated_disk();
            let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };
            notes.push(format!(
                "{prefix}updated universal guide and MCP snippet in {}",
                guide.display()
            ));
        } else {
            notes.push(format!("{} already up-to-date", guide.display()));
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
        self.detach_project(ctx, true).map_err(KlensError::from)
    }

    fn doctor(&self, ctx: &AdapterContext) -> Vec<DoctorCheck> {
        let guide = Self::project_guide_path(&ctx.project_root);
        let clean_guide = clean_binary_path_string(&guide);
        let Ok(Some((_, lf, _))) = read_text_file(&guide) else {
            return vec![DoctorCheck {
                name: format!(
                    "Generic KLENS.md ({})",
                    AccessScope::ProjectLocal.label_en()
                ),
                severity: CheckSeverity::Ok,
                message: format!("not installed at {clean_guide}"),
            }];
        };

        if !has_marked_block(&guide, &lf, MarkerStyle::Html) {
            return vec![DoctorCheck {
                name: format!(
                    "Generic KLENS.md ({})",
                    AccessScope::ProjectLocal.label_en()
                ),
                severity: CheckSeverity::Ok,
                message: format!("no klens block in {clean_guide}"),
            }];
        }

        let cmd = clean_binary_path_string(&ctx.binary_path);
        let escaped = cmd.replace('\\', "\\\\");
        let up_to_date = lf.contains(&cmd) || lf.contains(&escaped);
        vec![DoctorCheck {
            name: format!(
                "Generic KLENS.md ({})",
                AccessScope::ProjectLocal.label_en()
            ),
            severity: if up_to_date {
                CheckSeverity::Ok
            } else {
                CheckSeverity::Warning
            },
            message: if up_to_date {
                format!(
                    "guide and MCP snippet up-to-date [{}] ({clean_guide})",
                    AccessScope::ProjectLocal.label_en()
                )
            } else {
                format!(
                    "MCP snippet in {clean_guide} references a different binary path — run `klens init --host generic`"
                )
            },
        }]
    }
}
