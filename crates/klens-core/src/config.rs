use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::envelope::SCHEMA_VERSION;
use crate::error::KlensError;
use crate::paths::{
    DEFAULT_SENSITIVE_PATTERNS, RelPath, is_sensitive_path_with_extra, matches_any_pattern,
    write_atomic,
};

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

const fn default_ui_port() -> u16 {
    4729
}

/// Supported human-facing Web UI language codes (AI/MCP outputs always stay English).
pub const SUPPORTED_UI_LANGS: &[&str] = &["en", "tr", "de", "es", "fr", "pt"];

fn default_ui_lang() -> String {
    "en".to_string()
}

/// Check whether `lang` is a supported Web UI language code.
pub fn is_supported_ui_lang(lang: &str) -> bool {
    SUPPORTED_UI_LANGS.contains(&lang)
}

/// Operating mode of a project tracked by `klens` (`.klens/config.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectMode {
    /// Normal active mode: index cache and `.klens/` metadata enabled.
    #[default]
    Active,
    /// Zero-footprint inspection: never writes into the project directory.
    ReadOnly,
    /// Temporarily paused: hooks/indexing stay idle until resumed.
    Paused,
}

/// Per-project configuration stored at `.klens/config.toml`.
///
/// Separates two distinct security concepts:
/// - [`Self::extra_sensitive_patterns`]: Additional secret files blocked from **both read and write**
///   (the built-in `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*` patterns are always locked).
/// - [`Self::protected_paths`]: Locked code/contract files that remain **readable**,
///   but are flagged against unintended edits during `diff-check` (empty by default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub mode: ProjectMode,
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    /// Additional sensitive-file glob patterns forbidden for both reading and writing.
    #[serde(default)]
    pub extra_sensitive_patterns: Vec<String>,
    /// Locked code paths that stay readable, but are guarded against edits in `diff-check`.
    #[serde(default)]
    pub protected_paths: Vec<String>,
    #[serde(default)]
    pub enabled_extensions: Vec<String>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            mode: ProjectMode::Active,
            allowed_clients: Vec::new(),
            extra_sensitive_patterns: Vec::new(),
            protected_paths: Vec::new(),
            enabled_extensions: Vec::new(),
        }
    }
}

impl ProjectConfig {
    /// Load and validate a `.klens/config.toml` file.
    pub fn load(path: &Path) -> Result<Self, KlensError> {
        let raw = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load a `.klens/config.toml` file, returning [`ProjectConfig::default`] if missing.
    pub fn load_or_default(path: &Path) -> Result<Self, KlensError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load(path)
    }

    /// Atomically serialize and save this configuration as TOML.
    pub fn save_atomic(&self, path: &Path) -> Result<(), KlensError> {
        self.validate()?;
        let encoded = toml::to_string_pretty(self)?;
        write_atomic(path, encoded.as_bytes())?;
        Ok(())
    }

    /// Validate schema invariants.
    pub fn validate(&self) -> Result<(), KlensError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(KlensError::InvalidSchemaVersion {
                expected: SCHEMA_VERSION,
                found: self.schema_version,
            });
        }
        Ok(())
    }

    /// Return the locked union of built-in sensitive patterns and `extra_sensitive_patterns`.
    ///
    /// Built-in sensitive defaults (see [`crate::sensitive::BUILTIN_SENSITIVE_PATTERNS`]:
    /// `.env*`, private keys, SSH/cloud credential dirs, token files, …) can never be removed
    /// via project configuration.
    pub fn effective_sensitive_patterns(&self) -> Vec<String> {
        let mut set: BTreeSet<String> = DEFAULT_SENSITIVE_PATTERNS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for pattern in &self.extra_sensitive_patterns {
            let trimmed = pattern.trim();
            if !trimmed.is_empty() {
                set.insert(trimmed.to_string());
            }
        }
        set.into_iter().collect()
    }

    /// Check whether `rel` is blocked for reading and writing as a sensitive secret file.
    pub fn is_sensitive_file(&self, rel: &RelPath) -> bool {
        is_sensitive_path_with_extra(rel, &self.extra_sensitive_patterns)
    }

    /// Check whether `rel` is a locked code path (readable, protected from edits in `diff-check`).
    pub fn is_protected_code_path(&self, rel: &RelPath) -> bool {
        matches_any_pattern(rel, &self.protected_paths)
    }
}

/// Entry representing a project registered in the user's global `~/.klens/config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredProject {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub mode: ProjectMode,
}

/// User-wide configuration stored at `~/.klens/config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_ui_port")]
    pub ui_port: u16,
    #[serde(default = "default_ui_lang")]
    pub ui_lang: String,
    #[serde(default)]
    pub registered_projects: Vec<RegisteredProject>,
    #[serde(default)]
    pub enabled_extensions: Vec<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ui_port: default_ui_port(),
            ui_lang: default_ui_lang(),
            registered_projects: Vec::new(),
            enabled_extensions: Vec::new(),
        }
    }
}

impl GlobalConfig {
    /// Resolve the default path `~/.klens/config.toml` from environment variables.
    pub fn default_path() -> Option<PathBuf> {
        let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
        Some(PathBuf::from(home).join(".klens").join("config.toml"))
    }

    /// Load and validate a `~/.klens/config.toml` file.
    pub fn load(path: &Path) -> Result<Self, KlensError> {
        let raw = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load a `~/.klens/config.toml` file, returning [`GlobalConfig::default`] if missing.
    pub fn load_or_default(path: &Path) -> Result<Self, KlensError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load(path)
    }

    /// Atomically serialize and save this configuration as TOML.
    pub fn save_atomic(&self, path: &Path) -> Result<(), KlensError> {
        self.validate()?;
        let encoded = toml::to_string_pretty(self)?;
        write_atomic(path, encoded.as_bytes())?;
        Ok(())
    }

    /// Validate schema invariants.
    pub fn validate(&self) -> Result<(), KlensError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(KlensError::InvalidSchemaVersion {
                expected: SCHEMA_VERSION,
                found: self.schema_version,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_config_separates_sensitive_patterns_from_protected_code_paths() {
        let default_cfg = ProjectConfig::default();
        assert!(default_cfg.extra_sensitive_patterns.is_empty());
        assert!(default_cfg.protected_paths.is_empty());

        let locked_defaults = default_cfg.effective_sensitive_patterns();
        for builtin in [".env", ".env.*", "*.pem", "*.key", "id_rsa*"] {
            assert!(locked_defaults.iter().any(|p| p == builtin));
        }

        let cfg = ProjectConfig {
            mode: ProjectMode::ReadOnly,
            allowed_clients: vec!["antigravity".into(), "claude-code".into()],
            extra_sensitive_patterns: vec!["secrets/*.json".into()],
            protected_paths: vec![
                "crates/klens-core/src/paths.rs".into(),
                "migrations/*".into(),
            ],
            ..ProjectConfig::default()
        };

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let decoded: ProjectConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(decoded, cfg);
        assert_eq!(decoded.schema_version, 1);

        // Built-in sensitive defaults remain locked alongside extra_sensitive_patterns.
        let effective = decoded.effective_sensitive_patterns();
        assert!(effective.iter().any(|p| p == ".env"));
        assert!(effective.iter().any(|p| p == ".env.*"));
        assert!(effective.iter().any(|p| p == "secrets/*.json"));
        // Protected code paths do NOT leak into sensitive (read-forbidden) patterns.
        assert!(!effective.iter().any(|p| p == "migrations/*"));

        let protected_code = RelPath::normalize("crates/klens-core/src/paths.rs").unwrap();
        assert!(!decoded.is_sensitive_file(&protected_code));
        assert!(decoded.is_protected_code_path(&protected_code));

        let extra_secret = RelPath::normalize("secrets/prod.json").unwrap();
        assert!(decoded.is_sensitive_file(&extra_secret));
        assert!(!decoded.is_protected_code_path(&extra_secret));

        let builtin_secret = RelPath::normalize(".env.production").unwrap();
        assert!(decoded.is_sensitive_file(&builtin_secret));
        assert!(!decoded.is_protected_code_path(&builtin_secret));
    }

    #[test]
    fn global_config_defaults_and_rejects_unknown_schema_version() {
        let cfg = GlobalConfig::default();
        assert_eq!(cfg.schema_version, 1);
        assert_eq!(cfg.ui_port, 4729);
        assert_eq!(cfg.ui_lang, "en");
        assert!(cfg.validate().is_ok());

        // Backward compatibility: older config.toml without `ui_lang` defaults to `"en"`.
        let legacy_toml = "schema_version = 1\nui_port = 4729\n";
        let legacy_cfg: GlobalConfig = toml::from_str(legacy_toml).unwrap();
        assert_eq!(legacy_cfg.ui_lang, "en");
        assert_eq!(legacy_cfg.ui_port, 4729);

        let tr_toml = "schema_version = 1\nui_port = 4729\nui_lang = \"tr\"\n";
        let tr_cfg: GlobalConfig = toml::from_str(tr_toml).unwrap();
        assert_eq!(tr_cfg.ui_lang, "tr");

        let bad = GlobalConfig {
            schema_version: 2,
            ..GlobalConfig::default()
        };
        assert!(matches!(
            bad.validate(),
            Err(KlensError::InvalidSchemaVersion {
                expected: 1,
                found: 2
            })
        ));
    }
}
