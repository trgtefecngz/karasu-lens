#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

//! Thin AI host adapters (Antigravity, Claude Code, Codex, Generic),
//! symmetric attach/detach lifecycle, and embedded modular Skill Pack for Karasu Lens (`klens`).

pub mod adapters;
pub mod doctor;
pub mod error;
pub mod format;
pub mod git_hook;
pub mod lifecycle;
mod purge;
pub mod skills;
pub mod text_format;

pub use adapters::{
    AccessScope, AdapterOptions, AdapterRegistry, AntigravityAdapter, ClaudeCodeAdapter,
    CodexAdapter, ConfiguredAccessEntry, GenericAdapter, HostKind, HostTarget, MCP_SERVER_KEY,
    McpInspection, ObservedClientAccess, clean_binary_path_string, global_config_path_in,
    load_observed_client_access, metrics_path_in, paths_equivalent, render_standard_mcp_json,
    resolve_home_dir,
};
pub use doctor::{DetectReport, DoctorReport, HostDetectionRow, detect_environment, run_doctor};
pub use error::AdapterError;
pub use format::{
    format_attach_text, format_detach_text, format_detect_text, format_disconnect_text,
    format_doctor_text, format_init_text, format_scan_text, format_uninstall_text,
};
pub use git_hook::{
    GitHookInstallReport, GitHookStatusReport, GitHookUninstallReport, format_hook_install_text,
    format_hook_status_text, format_hook_uninstall_text, install_pre_commit_hook,
    pre_commit_hook_status, uninstall_pre_commit_hook,
};
pub use lifecycle::{
    AttachReport, DetachReport, DisconnectReport, GITIGNORE_BLOCK_BODY, InitReport, ScanReport,
    ScannedProject, UninstallReport, attach_project, current_binary_path, detach_project,
    disconnect_host, init_hosts, scan_directory, uninstall_all,
};
pub use skills::{
    ConciseLevel, EMBEDDED_SKILLS, EmbeddedSkill, SkillSelection, SkillSyncReport,
    count_installed_skills, install_skills_into_dir, remove_klens_skills_from_dir,
    render_inline_guide_block, render_skill_markdown, selected_skills,
};
pub use text_format::{
    FileOpOutcome, MarkerStyle, TextFormat, UTF8_BOM, apply_file_delete, apply_file_write,
    backup_path_for, has_marked_block, read_text_file, remove_empty_parents, remove_marked_block,
    remove_marked_file, upsert_marked_block, upsert_marked_file,
};
