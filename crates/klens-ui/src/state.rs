//! Shared server configuration and runtime state for `klens-ui`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use klens_adapters::{global_config_path_in, resolve_home_dir};
use klens_core::telemetry::{default_claude_projects_dir, default_metrics_path};
use klens_core::{GlobalConfig, ProjectRoot, is_supported_ui_lang};

use crate::error::UiError;
use crate::security::generate_session_token;

/// Launch configuration for the local `klens-ui` HTTP server.
#[derive(Debug, Clone, Default)]
pub struct UiConfig {
    /// Requested port (`Some(p)` binds strictly to `127.0.0.1:<p>`; `None` tries
    /// `GlobalConfig::ui_port` (default 4729) and falls back to an OS-assigned free port).
    pub port: Option<u16>,
    /// Optional initial project root to open immediately.
    pub initial_root: Option<PathBuf>,
    /// Server-level read-only lock (`--read-only`). When `true`, write operations to any
    /// target project directory are strictly forbidden and cannot be disabled via HTTP.
    pub read_only: bool,
    /// Suppress automatic browser opening when `true`.
    pub no_open: bool,
    /// Optional explicit home directory override (used in isolated tests; defaults to OS home).
    pub home_dir: Option<PathBuf>,
    /// Optional explicit Layer 1 `metrics.jsonl` path override (for tests).
    pub metrics_path: Option<PathBuf>,
    /// Optional explicit Layer 2 `~/.claude/projects` path override (for tests).
    pub claude_projects_dir: Option<PathBuf>,
    /// Optional explicit read-only SQLite cache directory override (for tests).
    pub readonly_cache_dir: Option<PathBuf>,
    /// Optional explicit binary path override (defaults to `current_exe()`).
    pub binary_path: Option<PathBuf>,
}

/// Mutable runtime state guarded by a `Mutex` inside [`UiState`].
#[derive(Debug)]
pub struct UiMutableState {
    pub active_project: Option<ProjectRoot>,
    /// Active session read-only mode (always `true` when `cli_read_only_locked == true`).
    pub read_only: bool,
    /// Active human-facing UI language (`en`, `tr`, `de`, `es`, `fr`, `pt`).
    pub ui_lang: String,
}

/// Shared runtime state passed across route handlers.
#[derive(Debug)]
pub struct UiState {
    pub bound_port: u16,
    pub session_token: String,
    pub cli_read_only_locked: bool,
    pub home_dir: PathBuf,
    pub metrics_path: Option<PathBuf>,
    pub claude_projects_dir: Option<PathBuf>,
    pub readonly_cache_dir: Option<PathBuf>,
    pub binary_path: PathBuf,
    pub shutdown_requested: Arc<AtomicBool>,
    pub inner: Mutex<UiMutableState>,
}

impl UiState {
    /// Construct initial [`UiState`] from [`UiConfig`] and the bound loopback port.
    pub fn new(config: &UiConfig, bound_port: u16) -> Result<Self, UiError> {
        let home_dir = match &config.home_dir {
            Some(h) => h.clone(),
            None => resolve_home_dir()?,
        };

        let global_cfg = GlobalConfig::load_or_default(&global_config_path_in(&home_dir))
            .unwrap_or_else(|_| GlobalConfig::default());
        let ui_lang = if is_supported_ui_lang(&global_cfg.ui_lang) {
            global_cfg.ui_lang
        } else {
            "en".to_string()
        };

        let active_project = match &config.initial_root {
            Some(path) => Some(ProjectRoot::new(path)?),
            None => None,
        };

        let metrics_path = config.metrics_path.clone().or_else(|| {
            if config.home_dir.is_some() {
                Some(home_dir.join(".klens").join("metrics.jsonl"))
            } else {
                default_metrics_path()
            }
        });

        let claude_projects_dir = config.claude_projects_dir.clone().or_else(|| {
            if config.home_dir.is_some() {
                Some(home_dir.join(".claude").join("projects"))
            } else {
                default_claude_projects_dir()
            }
        });

        let readonly_cache_dir = config.readonly_cache_dir.clone().or_else(|| {
            if config.home_dir.is_some() {
                Some(home_dir.join(".klens").join("readonly-cache"))
            } else {
                None
            }
        });

        let binary_path = config.binary_path.clone().unwrap_or_else(|| {
            klens_adapters::current_binary_path().unwrap_or_else(|_| PathBuf::from("klens"))
        });

        Ok(Self {
            bound_port,
            session_token: generate_session_token(),
            cli_read_only_locked: config.read_only,
            home_dir,
            metrics_path,
            claude_projects_dir,
            readonly_cache_dir,
            binary_path,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            inner: Mutex::new(UiMutableState {
                active_project,
                read_only: config.read_only,
                ui_lang,
            }),
        })
    }

    /// Return `(Option<ProjectRoot>, effective_read_only, ui_lang)` snapshot.
    pub fn snapshot(&self) -> (Option<ProjectRoot>, bool, String) {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (
            guard.active_project.clone(),
            self.cli_read_only_locked || guard.read_only,
            guard.ui_lang.clone(),
        )
    }

    /// Return the active [`ProjectRoot`] and effective `read_only` flag, or [`UiError::NoActiveProject`].
    pub fn require_project(&self) -> Result<(ProjectRoot, bool), UiError> {
        let (proj_opt, read_only, _) = self.snapshot();
        let project = proj_opt.ok_or(UiError::NoActiveProject)?;
        Ok((project, read_only))
    }

    /// Switch the active project directory and optional session read-only mode.
    ///
    /// Fails closed with `403` if the server was launched with `--read-only` and the
    /// caller attempts to request `read_only: false`.
    pub fn select_project(
        &self,
        path: &Path,
        requested_read_only: Option<bool>,
    ) -> Result<(ProjectRoot, bool), UiError> {
        if self.cli_read_only_locked && requested_read_only == Some(false) {
            return Err(UiError::ReadOnlyForbidden(
                "disable server-level --read-only lock".to_string(),
            ));
        }
        let project = ProjectRoot::new(path)?;
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ro) = requested_read_only {
            guard.read_only = self.cli_read_only_locked || ro;
        }
        guard.active_project = Some(project.clone());
        let effective_ro = self.cli_read_only_locked || guard.read_only;
        Ok((project, effective_ro))
    }

    /// Update the active UI language in memory and persist atomically to `~/.klens/config.toml`.
    pub fn set_ui_lang(&self, lang: &str) -> Result<String, UiError> {
        if !is_supported_ui_lang(lang) {
            return Err(UiError::BadRequest(format!(
                "unsupported ui_lang `{lang}` (expected one of: en, tr, de, es, fr, pt)"
            )));
        }

        let cfg_path = global_config_path_in(&self.home_dir);
        let mut cfg = GlobalConfig::load_or_default(&cfg_path)?;
        cfg.ui_lang = lang.to_string();
        cfg.save_atomic(&cfg_path)?;

        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.ui_lang = lang.to_string();
        Ok(lang.to_string())
    }

    /// Request graceful shutdown of the HTTP server loop.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }

    /// Check whether graceful shutdown has been triggered.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Tokenized loopback URL printed on startup and passed to the local browser.
    pub fn launch_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/?token={}",
            self.bound_port, self.session_token
        )
    }
}

/// Heuristic check for whether a directory looks like a real software project
/// (used on double-click / no-arg launch to avoid opening a random Downloads/exe folder).
///
/// The user home directory, its parents, and drive roots are never projects (v0.3.2+):
/// the user-global `~/.klens/` folder would otherwise match the `.klens` marker and make a
/// no-arg launch from `~` index the entire home directory.
pub fn directory_looks_like_project(dir: &Path) -> bool {
    if klens_core::is_unsafe_project_root(dir) {
        return false;
    }
    const MARKERS: &[&str] = &[
        ".klens",
        ".git",
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
        "Makefile",
        "pom.xml",
        "build.gradle",
    ];
    MARKERS.iter().any(|m| dir.join(m).exists())
}
