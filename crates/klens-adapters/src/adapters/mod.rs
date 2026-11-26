//! Thin host adapter registry (`Antigravity`, `Claude Code`, `Codex`, `Generic`).
//!
//! Dependency flow is strictly downward: `adapters/mod.rs` -> individual adapters -> `adapters/common.rs`.

pub mod antigravity;
pub mod claude_code;
pub mod codex;
pub mod codex_toml;
pub mod common;
pub mod generic;

#[cfg(test)]
mod config_write_tests;

use std::path::{Path, PathBuf};

use klens_core::HostAdapter;
use serde::{Deserialize, Serialize};

pub use antigravity::AntigravityAdapter;
pub use claude_code::ClaudeCodeAdapter;
pub use codex::CodexAdapter;
pub use common::{
    AccessScope, ConfiguredAccessEntry, MCP_SERVER_KEY, McpInspection, ObservedClientAccess,
    clean_binary_path_string, global_config_path_in, load_observed_client_access, metrics_path_in,
    paths_equivalent, render_standard_mcp_json, resolve_home_dir,
};
pub use generic::GenericAdapter;

use crate::error::AdapterError;
use crate::skills::SkillSelection;

/// Concrete host adapter identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKind {
    Antigravity,
    ClaudeCode,
    Codex,
    Generic,
}

impl HostKind {
    /// All 4 built-in hosts in deterministic canonical order.
    pub const ALL: [Self; 4] = [
        Self::Antigravity,
        Self::ClaudeCode,
        Self::Codex,
        Self::Generic,
    ];

    /// Native Tier-1 hosts checked by `--host auto`.
    pub const NATIVE: [Self; 3] = [Self::Antigravity, Self::ClaudeCode, Self::Codex];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Antigravity => "antigravity",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Generic => "generic",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Antigravity => "Antigravity",
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Generic => "Generic",
        }
    }

    pub fn parse(input: &str) -> Result<Self, AdapterError> {
        match input.trim().to_ascii_lowercase().as_str() {
            "antigravity" => Ok(Self::Antigravity),
            "claude-code" | "claude_code" | "claude" => Ok(Self::ClaudeCode),
            "codex" => Ok(Self::Codex),
            "generic" => Ok(Self::Generic),
            other => Err(AdapterError::UnknownHost(other.to_string())),
        }
    }
}

/// Host selector accepted by `klens init --host` and `klens disconnect --host`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostTarget {
    Auto,
    All,
    Single(HostKind),
}

impl HostTarget {
    pub fn parse(input: &str) -> Result<Self, AdapterError> {
        match input.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "all" => Ok(Self::All),
            other => Ok(Self::Single(HostKind::parse(other)?)),
        }
    }
}

/// Options configuring adapter behavior during `init` / `disconnect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterOptions {
    pub skills: SkillSelection,
    pub claude_session_hook: bool,
    pub claude_pre_tool_hook: bool,
    pub force: bool,
}

impl Default for AdapterOptions {
    fn default() -> Self {
        Self {
            skills: SkillSelection::default(),
            claude_session_hook: true,
            claude_pre_tool_hook: false,
            force: false,
        }
    }
}

/// Registry holding all 4 concrete adapters configured for a specific `home_dir`.
#[derive(Debug, Clone)]
pub struct AdapterRegistry {
    pub home_dir: PathBuf,
    pub antigravity: AntigravityAdapter,
    pub claude_code: ClaudeCodeAdapter,
    pub codex: CodexAdapter,
    pub generic: GenericAdapter,
}

impl AdapterRegistry {
    /// Build a registry using the current user's home directory (`USERPROFILE` / `HOME`).
    pub fn with_defaults(options: &AdapterOptions) -> Result<Self, AdapterError> {
        Ok(Self::with_home(resolve_home_dir()?, options))
    }

    /// Build a registry rooted at an explicit `home_dir` (zero env mutation; safe for tests).
    pub fn with_home(home_dir: PathBuf, options: &AdapterOptions) -> Self {
        let antigravity = AntigravityAdapter::with_home(home_dir.clone())
            .with_skills(options.skills.clone())
            .with_force(options.force);
        let claude_code = ClaudeCodeAdapter::with_home(home_dir.clone())
            .with_skills(options.skills.clone())
            .with_hooks(options.claude_session_hook, options.claude_pre_tool_hook)
            .with_force(options.force);
        let codex = CodexAdapter::with_home(home_dir.clone())
            .with_skills(options.skills.clone())
            .with_force(options.force);
        let generic = GenericAdapter::new()
            .with_skills(options.skills.clone())
            .with_force(options.force);

        Self {
            home_dir,
            antigravity,
            claude_code,
            codex,
            generic,
        }
    }

    /// Borrow a specific adapter as a `klens_core::HostAdapter` trait object.
    pub fn adapter(&self, kind: HostKind) -> &dyn HostAdapter {
        match kind {
            HostKind::Antigravity => &self.antigravity,
            HostKind::ClaudeCode => &self.claude_code,
            HostKind::Codex => &self.codex,
            HostKind::Generic => &self.generic,
        }
    }

    /// Collect all configured access entries (project-local AND global, distinctly labeled)
    /// across all 4 adapters in deterministic order.
    pub fn all_configured_access(
        &self,
        project_root: &Path,
        current_binary: &Path,
    ) -> Vec<ConfiguredAccessEntry> {
        let mut out = Vec::new();
        out.extend(self.antigravity.configured_access(current_binary));
        out.extend(
            self.claude_code
                .configured_access(project_root, current_binary),
        );
        out.extend(self.codex.configured_access(project_root, current_binary));
        out.extend(self.generic.configured_access(project_root, current_binary));
        out
    }
}
