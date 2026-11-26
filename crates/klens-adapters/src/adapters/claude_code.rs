//! Native host adapter for Claude Code (`--host claude-code`).
//!
//! Manages:
//! - Project-local `.mcp.json` (`mcpServers.klens`) and global `~/.claude.json` detection/disconnect
//! - Optional, reversible hooks in `.claude/settings.json` (`SessionStart`, opt-in `PreToolUse`)
//! - Embedded skill pack under `.claude/skills/karasu-lens/`

use std::fs;
use std::path::{Path, PathBuf};

use klens_core::{
    AdapterContext, CheckSeverity, DoctorCheck, HostAdapter, HostDetectStatus, InstallReport,
    KlensError,
};
use serde_json::{Map, Value, json};

use super::common::{
    AccessScope, ConfiguredAccessEntry, McpInspection, clean_binary_path_string,
    doctor_check_mcp_registration, inspect_json_mcp_server, paths_equivalent,
    remove_json_mcp_server, resolve_home_dir, upsert_json_mcp_server,
};
use crate::error::AdapterError;
use crate::skills::{
    SkillSelection, count_installed_skills, install_skills_into_dir, remove_klens_skills_from_dir,
};
use crate::text_format::{
    FileOpOutcome, MarkerStyle, TextFormat, apply_config_delete, apply_config_write,
    read_text_file, remove_empty_parents, remove_marked_file, retry_config_edit,
};

const KLENS_MANAGED_KEY: &str = "klens_managed";

/// Native adapter for Claude Code (`.mcp.json`, `.claude/settings.json`, `.claude/skills/karasu-lens/`).
#[derive(Debug, Clone)]
pub struct ClaudeCodeAdapter {
    home_dir: PathBuf,
    skills: SkillSelection,
    enable_session_hook: bool,
    enable_pre_tool_hook: bool,
    force: bool,
}

impl ClaudeCodeAdapter {
    /// Construct an adapter targeting the current user's home directory.
    pub fn new() -> Result<Self, AdapterError> {
        Ok(Self::with_home(resolve_home_dir()?))
    }

    /// Construct an adapter rooted at an explicit home directory (ideal for isolated tests).
    pub fn with_home(home_dir: PathBuf) -> Self {
        Self {
            home_dir,
            skills: SkillSelection::default(),
            enable_session_hook: true,
            enable_pre_tool_hook: false,
            force: false,
        }
    }

    pub fn with_skills(mut self, skills: SkillSelection) -> Self {
        self.skills = skills;
        self
    }

    pub fn with_hooks(mut self, session_hook: bool, pre_tool_hook: bool) -> Self {
        self.enable_session_hook = session_hook;
        self.enable_pre_tool_hook = pre_tool_hook;
        self
    }

    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn global_dir(&self) -> PathBuf {
        self.home_dir.join(".claude")
    }

    pub fn global_mcp_path(&self) -> PathBuf {
        self.home_dir.join(".claude.json")
    }

    pub fn project_mcp_path(project_root: &Path) -> PathBuf {
        project_root.join(".mcp.json")
    }

    pub fn project_settings_path(project_root: &Path) -> PathBuf {
        project_root.join(".claude").join("settings.json")
    }

    pub fn project_skills_dir(project_root: &Path) -> PathBuf {
        project_root
            .join(".claude")
            .join("skills")
            .join("karasu-lens")
    }

    /// Inspect BOTH project-local and global configured access entries honestly.
    pub fn configured_access(
        &self,
        project_root: &Path,
        current_binary: &Path,
    ) -> Vec<ConfiguredAccessEntry> {
        let mut entries = Vec::new();

        let local_mcp = Self::project_mcp_path(project_root);
        if let McpInspection::Registered { command, .. } = inspect_json_mcp_server(&local_mcp) {
            entries.push(ConfiguredAccessEntry {
                host_id: self.host_id().to_string(),
                display_name: "Claude Code".to_string(),
                scope: AccessScope::ProjectLocal,
                scope_label: format!("Claude Code ({})", AccessScope::ProjectLocal.label_en()),
                config_path: PathBuf::from(clean_binary_path_string(&local_mcp)),
                binary_matches_current: Some(paths_equivalent(&command, current_binary)),
                configured_binary: Some(command),
            });
        }

        let global_mcp = self.global_mcp_path();
        if let McpInspection::Registered { command, .. } = inspect_json_mcp_server(&global_mcp) {
            entries.push(ConfiguredAccessEntry {
                host_id: self.host_id().to_string(),
                display_name: "Claude Code".to_string(),
                scope: AccessScope::Global,
                scope_label: format!("Claude Code ({})", AccessScope::Global.label_en()),
                config_path: PathBuf::from(clean_binary_path_string(&global_mcp)),
                binary_matches_current: Some(paths_equivalent(&command, current_binary)),
                configured_binary: Some(command),
            });
        }

        entries
    }

    /// Clean ONLY project-local Claude Code artifacts (used by `klens detach` so global
    /// settings and other projects remain completely untouched).
    pub fn detach_project(
        &self,
        ctx: &AdapterContext,
        backup_existing: bool,
    ) -> Result<InstallReport, AdapterError> {
        let mut files_touched = Vec::new();
        let mut notes = Vec::new();
        let mut mutated = false;
        let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };

        // 1. Project-local `.mcp.json`
        let local_mcp = Self::project_mcp_path(&ctx.project_root);
        let mcp_out = remove_json_mcp_server(&local_mcp, ctx.dry_run, backup_existing, true)?;
        if mcp_out.is_planned_change() {
            files_touched.push(local_mcp.clone());
            mutated |= mcp_out.mutated_disk();
            if let Some(bak) = mcp_out.backup_path() {
                notes.push(format!("{prefix}backup: {}", bak.display()));
            }
            notes.push(format!(
                "{prefix}removed MCP server `klens` from {}",
                local_mcp.display()
            ));
        }

        // 2. Project-local `.claude/settings.json` hooks
        let settings_path = Self::project_settings_path(&ctx.project_root);
        let hook_out = remove_claude_hooks(&settings_path, ctx.dry_run, backup_existing)?;
        if hook_out.is_planned_change() {
            files_touched.push(settings_path.clone());
            mutated |= hook_out.mutated_disk();
            if let Some(bak) = hook_out.backup_path() {
                notes.push(format!("{prefix}backup: {}", bak.display()));
            }
            notes.push(format!(
                "{prefix}removed klens hooks from {}",
                settings_path.display()
            ));
            remove_empty_parents(
                settings_path.parent().unwrap_or(&ctx.project_root),
                &ctx.project_root,
                ctx.dry_run,
            );
        }

        // 3. Project-local `.claude/skills/karasu-lens/`
        let skills_dir = Self::project_skills_dir(&ctx.project_root);
        let skills_rep = remove_klens_skills_from_dir(&skills_dir, &ctx.project_root, ctx.dry_run)?;
        files_touched.extend(skills_rep.files_touched);
        mutated |= skills_rep.mutated_disk;
        notes.extend(skills_rep.notes);

        // Also remove `.claude/skills/karasu-lens/SKILL.md` index if present.
        let index_skill = skills_dir.join("SKILL.md");
        if index_skill.exists() {
            files_touched.push(index_skill.clone());
            if !ctx.dry_run {
                fs::remove_file(&index_skill).map_err(|source| AdapterError::Io {
                    path: index_skill.clone(),
                    source,
                })?;
                mutated = true;
            }
            notes.push(format!(
                "{prefix}removed Claude skill index {}",
                index_skill.display()
            ));
        }
        remove_empty_parents(&skills_dir, &ctx.project_root, ctx.dry_run);

        // 4. Optional `CLAUDE.md` marked block (surgical removal only).
        let claude_md = ctx.project_root.join("CLAUDE.md");
        let claude_md_out =
            remove_marked_file(&claude_md, MarkerStyle::Html, ctx.dry_run, backup_existing)?;
        if claude_md_out.is_planned_change() {
            files_touched.push(claude_md.clone());
            mutated |= claude_md_out.mutated_disk();
            notes.push(format!(
                "{prefix}removed klens marked block from {}",
                claude_md.display()
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

impl HostAdapter for ClaudeCodeAdapter {
    fn host_id(&self) -> &'static str {
        "claude-code"
    }

    fn detect(&self, project_root: &Path) -> HostDetectStatus {
        let local_mcp = Self::project_mcp_path(project_root);
        if matches!(
            inspect_json_mcp_server(&local_mcp),
            McpInspection::Registered { .. }
        ) {
            return HostDetectStatus::Installed {
                config_path: local_mcp,
            };
        }

        let global_mcp = self.global_mcp_path();
        if matches!(
            inspect_json_mcp_server(&global_mcp),
            McpInspection::Registered { .. }
        ) {
            return HostDetectStatus::Installed {
                config_path: global_mcp,
            };
        }

        if project_root.join(".claude").is_dir() {
            return HostDetectStatus::Detected {
                config_path: local_mcp,
            };
        }
        if self.global_dir().is_dir() || global_mcp.is_file() {
            return HostDetectStatus::Detected {
                config_path: global_mcp,
            };
        }

        HostDetectStatus::NotDetected
    }

    fn install_or_update(&self, ctx: &AdapterContext) -> Result<InstallReport, KlensError> {
        let mut files_touched = Vec::new();
        let mut notes = Vec::new();
        let mut mutated = false;
        let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };

        // 1. Upsert project-local `.mcp.json`
        let local_mcp = Self::project_mcp_path(&ctx.project_root);
        let mcp = upsert_json_mcp_server(&local_mcp, &ctx.binary_path, ctx.dry_run, self.force)
            .map_err(KlensError::from)?;
        if mcp.file_outcome.is_planned_change() {
            files_touched.push(local_mcp.clone());
            mutated |= mcp.file_outcome.mutated_disk();
            let new_bin = clean_binary_path_string(&ctx.binary_path);
            if mcp.updated_binary_path {
                let old = mcp.previous_binary.as_deref().unwrap_or("<unknown>");
                notes.push(format!(
                    "{prefix}Updated binary path in {}: `{old}` -> `{new_bin}`",
                    local_mcp.display()
                ));
            } else {
                notes.push(format!(
                    "{prefix}registered project-local MCP server `klens` in {}",
                    local_mcp.display()
                ));
            }
        } else {
            notes.push(format!(
                "MCP server `klens` already up-to-date in {}",
                local_mcp.display()
            ));
        }

        // 2. Sync optional reversible hooks in `.claude/settings.json`
        let settings_path = Self::project_settings_path(&ctx.project_root);
        let hook_out = if self.enable_session_hook || self.enable_pre_tool_hook {
            upsert_claude_hooks(
                &settings_path,
                &ctx.binary_path,
                self.enable_session_hook,
                self.enable_pre_tool_hook,
                ctx.dry_run,
                self.force,
            )
            .map_err(KlensError::from)?
        } else {
            remove_claude_hooks(&settings_path, ctx.dry_run, false).map_err(KlensError::from)?
        };
        if hook_out.is_planned_change() {
            files_touched.push(settings_path.clone());
            mutated |= hook_out.mutated_disk();
            notes.push(format!(
                "{prefix}synced reversible Claude Code hooks in {}",
                settings_path.display()
            ));
        }

        // 3. Install modular skills into `.claude/skills/karasu-lens/`
        let skills_dir = Self::project_skills_dir(&ctx.project_root);
        let skills_rep =
            install_skills_into_dir(&skills_dir, &self.skills, ctx.dry_run, self.force)
                .map_err(KlensError::from)?;
        files_touched.extend(skills_rep.files_touched);
        mutated |= skills_rep.mutated_disk;
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
        let mut report = self.detach_project(ctx, true).map_err(KlensError::from)?;

        // Also disconnect global `~/.claude.json` if `klens` is registered there.
        let global_mcp = self.global_mcp_path();
        let global_out = remove_json_mcp_server(&global_mcp, ctx.dry_run, true, false)
            .map_err(KlensError::from)?;
        if global_out.is_planned_change() {
            report.files_touched.push(global_mcp.clone());
            if global_out.mutated_disk() {
                report.changed = true;
            }
            let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };
            if let Some(bak) = global_out.backup_path() {
                report
                    .notes
                    .push(format!("{prefix}backup: {}", bak.display()));
            }
            report.notes.push(format!(
                "{prefix}removed global MCP server `klens` from {}",
                global_mcp.display()
            ));
        }

        Ok(report)
    }

    fn doctor(&self, ctx: &AdapterContext) -> Vec<DoctorCheck> {
        let local_mcp = Self::project_mcp_path(&ctx.project_root);
        let local_insp = inspect_json_mcp_server(&local_mcp);
        let global_mcp = self.global_mcp_path();
        let global_insp = inspect_json_mcp_server(&global_mcp);

        let mut checks = vec![
            doctor_check_mcp_registration(
                "Claude Code",
                AccessScope::ProjectLocal,
                &local_mcp,
                &local_insp,
                &ctx.binary_path,
            ),
            doctor_check_mcp_registration(
                "Claude Code",
                AccessScope::Global,
                &global_mcp,
                &global_insp,
                &ctx.binary_path,
            ),
        ];

        let skills_dir = Self::project_skills_dir(&ctx.project_root);
        if matches!(local_insp, McpInspection::Registered { .. }) {
            let count = count_installed_skills(&skills_dir);
            checks.push(DoctorCheck {
                name: format!(
                    "Claude Code skills ({})",
                    AccessScope::ProjectLocal.label_en()
                ),
                severity: if count == 0 {
                    CheckSeverity::Warning
                } else {
                    CheckSeverity::Ok
                },
                message: format!(
                    "{count} embedded klens skill(s) in {}",
                    clean_binary_path_string(&skills_dir)
                ),
            });
        }

        checks
    }
}

fn is_klens_hook_object(val: &Value) -> bool {
    val.as_object()
        .and_then(|obj| obj.get(KLENS_MANAGED_KEY))
        .and_then(Value::as_bool)
        == Some(true)
}

fn strip_klens_hooks_from_event_list(list: &mut Vec<Value>) -> bool {
    let mut removed_any = false;
    list.retain_mut(|group| {
        if is_klens_hook_object(group) {
            removed_any = true;
            return false;
        }
        if let Some(inner) = group.get_mut("hooks").and_then(Value::as_array_mut) {
            let before = inner.len();
            inner.retain(|item| !is_klens_hook_object(item));
            if inner.len() != before {
                removed_any = true;
                return !inner.is_empty();
            }
        }
        true
    });
    removed_any
}

pub(super) fn upsert_claude_hooks(
    settings_path: &Path,
    binary_path: &Path,
    enable_session: bool,
    enable_pre_tool: bool,
    dry_run: bool,
    force: bool,
) -> Result<FileOpOutcome, AdapterError> {
    retry_config_edit(|| {
        upsert_claude_hooks_once(
            settings_path,
            binary_path,
            enable_session,
            enable_pre_tool,
            dry_run,
            force,
        )
    })
}

fn upsert_claude_hooks_once(
    settings_path: &Path,
    binary_path: &Path,
    enable_session: bool,
    enable_pre_tool: bool,
    dry_run: bool,
    force: bool,
) -> Result<FileOpOutcome, AdapterError> {
    let existing = read_text_file(settings_path)?;
    let original = existing.as_ref().map(|(_, _, bytes)| bytes.clone());
    let (fmt, mut root_map) =
        match existing {
            Some((fmt, lf, _)) => {
                let trimmed = lf.trim();
                if trimmed.is_empty() {
                    (fmt, Map::new())
                } else {
                    let parsed: Value = serde_json::from_str(trimmed).map_err(|err| {
                        AdapterError::InvalidJsonConfig {
                            path: settings_path.to_path_buf(),
                            reason: err.to_string(),
                        }
                    })?;
                    let obj = parsed.as_object().cloned().ok_or_else(|| {
                        AdapterError::InvalidJsonConfig {
                            path: settings_path.to_path_buf(),
                            reason: "expected top-level JSON object".to_string(),
                        }
                    })?;
                    (fmt, obj)
                }
            }
            None => (TextFormat::default(), Map::new()),
        };

    let hooks_val = root_map
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks_obj = hooks_val
        .as_object_mut()
        .ok_or_else(|| AdapterError::InvalidJsonConfig {
            path: settings_path.to_path_buf(),
            reason: "`hooks` must be a JSON object".to_string(),
        })?;

    let bin = clean_binary_path_string(binary_path);

    // Sync SessionStart hook
    let session_list = hooks_obj
        .entry("SessionStart".to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| AdapterError::InvalidJsonConfig {
            path: settings_path.to_path_buf(),
            reason: "`hooks.SessionStart` must be a JSON array".to_string(),
        })?;
    strip_klens_hooks_from_event_list(session_list);
    if enable_session {
        session_list.push(json!({
            KLENS_MANAGED_KEY: true,
            "hooks": [
                {
                    "type": "command",
                    "command": format!("\"{bin}\" map --budget 600 --read-only"),
                    KLENS_MANAGED_KEY: true
                }
            ]
        }));
    }
    if session_list.is_empty() {
        hooks_obj.shift_remove("SessionStart");
    }

    // Sync optional PreToolUse hook
    if enable_pre_tool || hooks_obj.contains_key("PreToolUse") {
        let pre_list = hooks_obj
            .entry("PreToolUse".to_string())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| AdapterError::InvalidJsonConfig {
                path: settings_path.to_path_buf(),
                reason: "`hooks.PreToolUse` must be a JSON array".to_string(),
            })?;
        strip_klens_hooks_from_event_list(pre_list);
        if enable_pre_tool {
            pre_list.push(json!({
                "matcher": "Bash",
                KLENS_MANAGED_KEY: true,
                "hooks": [
                    {
                        "type": "command",
                        "command": format!("\"{bin}\" doctor --project ."),
                        KLENS_MANAGED_KEY: true
                    }
                ]
            }));
        }
        if pre_list.is_empty() {
            hooks_obj.shift_remove("PreToolUse");
        }
    }

    let mut rendered = serde_json::to_string_pretty(&Value::Object(root_map)).map_err(|err| {
        AdapterError::InvalidJsonConfig {
            path: settings_path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;
    rendered.push('\n');
    let encoded = fmt.encode(&rendered);
    apply_config_write(
        settings_path,
        original.as_deref(),
        &encoded,
        dry_run,
        false,
        force,
    )
}

pub(super) fn remove_claude_hooks(
    settings_path: &Path,
    dry_run: bool,
    backup_existing: bool,
) -> Result<FileOpOutcome, AdapterError> {
    retry_config_edit(|| remove_claude_hooks_once(settings_path, dry_run, backup_existing))
}

fn remove_claude_hooks_once(
    settings_path: &Path,
    dry_run: bool,
    backup_existing: bool,
) -> Result<FileOpOutcome, AdapterError> {
    let Some((fmt, lf, original)) = read_text_file(settings_path)? else {
        return Ok(FileOpOutcome::Unchanged);
    };
    if lf.trim().is_empty() {
        return Ok(FileOpOutcome::Unchanged);
    }

    let parsed: Value =
        serde_json::from_str(lf.trim()).map_err(|err| AdapterError::InvalidJsonConfig {
            path: settings_path.to_path_buf(),
            reason: err.to_string(),
        })?;
    let mut root_map =
        parsed
            .as_object()
            .cloned()
            .ok_or_else(|| AdapterError::InvalidJsonConfig {
                path: settings_path.to_path_buf(),
                reason: "expected top-level JSON object".to_string(),
            })?;

    let mut removed_any = false;
    if let Some(hooks_obj) = root_map.get_mut("hooks").and_then(Value::as_object_mut) {
        let mut empty_events = Vec::new();
        for (event_name, val) in hooks_obj.iter_mut() {
            if let Some(list) = val.as_array_mut() {
                if strip_klens_hooks_from_event_list(list) {
                    removed_any = true;
                }
                if list.is_empty() {
                    empty_events.push(event_name.clone());
                }
            }
        }
        for key in empty_events {
            hooks_obj.shift_remove(&key);
        }
        if hooks_obj.is_empty() {
            root_map.shift_remove("hooks");
        }
    }

    if !removed_any {
        return Ok(FileOpOutcome::Unchanged);
    }

    if root_map.is_empty() {
        return apply_config_delete(settings_path, &original, dry_run, backup_existing);
    }

    let mut rendered = serde_json::to_string_pretty(&Value::Object(root_map)).map_err(|err| {
        AdapterError::InvalidJsonConfig {
            path: settings_path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;
    rendered.push('\n');
    let encoded = fmt.encode(&rendered);
    apply_config_write(
        settings_path,
        Some(&original),
        &encoded,
        dry_run,
        backup_existing,
        false,
    )
}

/// Returns `true` iff detaching klens hooks would delete `.claude/settings.json` completely
/// (never true when user keys or user hooks remain in the file).
pub(crate) fn claude_settings_deleted_on_detach(settings_path: &Path) -> bool {
    matches!(
        remove_claude_hooks(settings_path, true, false),
        Ok(FileOpOutcome::Deleted { .. })
    )
}
