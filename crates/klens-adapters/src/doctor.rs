//! Read-only environment detection (`klens detect`) and diagnostic health checks (`klens doctor`).
//!
//! Zero-deception invariant (`docs/03-HOST-ADAPTERS-AND-SKILLS.md` Section 3.5):
//! Always separates **Configured Access** (project-local vs global MCP) from
//! **Observed Access** (real `clientInfo` records streamed from `~/.klens/metrics.jsonl`).

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use klens_core::{
    AdapterContext, CheckSeverity, DoctorCheck, GlobalConfig, HostDetectStatus, ProjectConfig,
    ProjectMode, ProjectRoot, blake3_file,
};
use serde::{Deserialize, Serialize};

use crate::adapters::{
    AdapterRegistry, ConfiguredAccessEntry, GenericAdapter, HostKind, ObservedClientAccess,
    clean_binary_path_string, global_config_path_in, load_observed_client_access, metrics_path_in,
    paths_equivalent,
};
use crate::text_format::{MarkerStyle, has_marked_block, read_text_file};

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Single host detection row returned by `klens detect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostDetectionRow {
    pub host_id: String,
    pub display_name: String,
    pub status: HostDetectStatus,
}

/// Complete read-only detection report (`klens detect`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectReport {
    pub project_root: PathBuf,
    pub project_id: String,
    pub project_registered: bool,
    pub project_mode: Option<ProjectMode>,
    pub allowed_clients: Vec<String>,
    pub hosts: Vec<HostDetectionRow>,
    pub universal_hints: Vec<String>,
    pub configured_access: Vec<ConfiguredAccessEntry>,
    pub observed_access: Vec<ObservedClientAccess>,
}

/// Complete read-only diagnostic report (`klens doctor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub project_root: PathBuf,
    pub project_id: String,
    pub binary_path: PathBuf,
    pub overall: CheckSeverity,
    pub checks: Vec<DoctorCheck>,
    pub configured_access: Vec<ConfiguredAccessEntry>,
    pub observed_access: Vec<ObservedClientAccess>,
}

/// Read-only scan of standard AI host paths, configured scopes, and observed client audit.
pub fn detect_environment(
    registry: &AdapterRegistry,
    project_root: &ProjectRoot,
    current_binary: &Path,
) -> DetectReport {
    let hosts = HostKind::ALL
        .iter()
        .map(|&kind| {
            let status = match registry.adapter(kind).detect(project_root.root()) {
                HostDetectStatus::NotDetected => HostDetectStatus::NotDetected,
                HostDetectStatus::Detected { config_path } => HostDetectStatus::Detected {
                    config_path: PathBuf::from(clean_binary_path_string(&config_path)),
                },
                HostDetectStatus::Installed { config_path } => HostDetectStatus::Installed {
                    config_path: PathBuf::from(clean_binary_path_string(&config_path)),
                },
            };
            HostDetectionRow {
                host_id: kind.as_str().to_string(),
                display_name: kind.display_name().to_string(),
                status,
            }
        })
        .collect();

    let universal_hints = GenericAdapter::detected_universal_hints(project_root.root())
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();

    let configured_access = registry.all_configured_access(project_root.root(), current_binary);
    let observed_access = load_observed_client_access(
        &metrics_path_in(&registry.home_dir),
        project_root.project_id(),
    );

    let global_cfg_path = global_config_path_in(&registry.home_dir);
    let project_registered = GlobalConfig::load(&global_cfg_path)
        .map(|cfg| {
            cfg.registered_projects
                .iter()
                .any(|p| paths_equivalent(&p.path, project_root.root()))
        })
        .unwrap_or(false);

    let proj_cfg_path = project_root.root().join(".klens").join("config.toml");
    let (project_mode, allowed_clients) = match ProjectConfig::load(&proj_cfg_path) {
        Ok(cfg) => (Some(cfg.mode), cfg.allowed_clients),
        Err(_) => (None, Vec::new()),
    };

    DetectReport {
        project_root: PathBuf::from(clean_binary_path_string(project_root.root())),
        project_id: project_root.project_id().to_string(),
        project_registered,
        project_mode,
        allowed_clients,
        hosts,
        universal_hints,
        configured_access,
        observed_access,
    }
}

/// Run read-only diagnostics covering adapters, binary freshness, global/project configs,
/// SQLite cache health, stale memory count, `.gitignore`, and observed client audit.
pub fn run_doctor(
    registry: &AdapterRegistry,
    project_root: &ProjectRoot,
    current_binary: &Path,
) -> DoctorReport {
    let ctx = AdapterContext {
        project_root: project_root.root().to_path_buf(),
        binary_path: current_binary.to_path_buf(),
        dry_run: true,
    };

    let mut checks = Vec::new();
    for kind in HostKind::ALL {
        checks.extend(registry.adapter(kind).doctor(&ctx));
    }

    checks.push(check_global_registration(
        &registry.home_dir,
        project_root.root(),
    ));
    checks.push(check_project_config(project_root.root()));
    checks.push(check_sqlite_cache(project_root.root()));
    checks.push(check_memory_staleness(project_root));
    checks.push(check_gitignore_status(project_root.root()));

    let overall = checks
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(CheckSeverity::Ok);

    let configured_access = registry.all_configured_access(project_root.root(), current_binary);
    let observed_access = load_observed_client_access(
        &metrics_path_in(&registry.home_dir),
        project_root.project_id(),
    );

    DoctorReport {
        project_root: PathBuf::from(clean_binary_path_string(project_root.root())),
        project_id: project_root.project_id().to_string(),
        binary_path: PathBuf::from(clean_binary_path_string(current_binary)),
        overall,
        checks,
        configured_access,
        observed_access,
    }
}

fn check_global_registration(home_dir: &Path, project_root: &Path) -> DoctorCheck {
    let global_path = global_config_path_in(home_dir);
    if !global_path.exists() {
        return DoctorCheck {
            name: "Global registry (~/.klens/config.toml)".to_string(),
            severity: CheckSeverity::Ok,
            message: "not created yet (run `klens attach` to register this project)".to_string(),
        };
    }

    match GlobalConfig::load(&global_path) {
        Ok(cfg) => {
            let registered = cfg
                .registered_projects
                .iter()
                .any(|p| paths_equivalent(&p.path, project_root));
            DoctorCheck {
                name: "Global registry (~/.klens/config.toml)".to_string(),
                severity: CheckSeverity::Ok,
                message: if registered {
                    format!(
                        "project registered ({} total project(s))",
                        cfg.registered_projects.len()
                    )
                } else {
                    format!(
                        "project not attached yet ({} other project(s) registered)",
                        cfg.registered_projects.len()
                    )
                },
            }
        }
        Err(err) => DoctorCheck {
            name: "Global registry (~/.klens/config.toml)".to_string(),
            severity: CheckSeverity::Error,
            message: format!("corrupt global config: {err}"),
        },
    }
}

fn check_project_config(project_root: &Path) -> DoctorCheck {
    let cfg_path = project_root.join(".klens").join("config.toml");
    if !cfg_path.exists() {
        return DoctorCheck {
            name: "Project config (.klens/config.toml)".to_string(),
            severity: CheckSeverity::Ok,
            message: "not attached (defaults to active mode when run directly)".to_string(),
        };
    }

    match ProjectConfig::load(&cfg_path) {
        Ok(cfg) => {
            let clients = if cfg.allowed_clients.is_empty() {
                "all connected clients".to_string()
            } else {
                format!("restricted to {:?}", cfg.allowed_clients)
            };
            DoctorCheck {
                name: "Project config (.klens/config.toml)".to_string(),
                severity: CheckSeverity::Ok,
                message: format!("mode={:?}, access={clients}", cfg.mode),
            }
        }
        Err(err) => DoctorCheck {
            name: "Project config (.klens/config.toml)".to_string(),
            severity: CheckSeverity::Error,
            message: format!("invalid `.klens/config.toml`: {err}"),
        },
    }
}

fn check_sqlite_cache(project_root: &Path) -> DoctorCheck {
    let db_path = project_root.join(".klens").join("cache").join("index.db");
    if !db_path.exists() {
        return DoctorCheck {
            name: "SQLite cache (.klens/cache/index.db)".to_string(),
            severity: CheckSeverity::Ok,
            message: "not built yet (disposable cache; created on first index)".to_string(),
        };
    }

    let meta = match fs::metadata(&db_path) {
        Ok(m) => m,
        Err(err) => {
            return DoctorCheck {
                name: "SQLite cache (.klens/cache/index.db)".to_string(),
                severity: CheckSeverity::Error,
                message: format!("cannot stat index.db: {err}"),
            };
        }
    };

    if meta.len() < SQLITE_MAGIC.len() as u64 {
        return DoctorCheck {
            name: "SQLite cache (.klens/cache/index.db)".to_string(),
            severity: CheckSeverity::Error,
            message: format!(
                "index.db is truncated ({} bytes); delete `.klens/cache/index.db` to rebuild",
                meta.len()
            ),
        };
    }

    let mut header = [0u8; 16];
    let read_ok = File::open(&db_path)
        .and_then(|mut f| f.read_exact(&mut header))
        .is_ok();
    if !read_ok || &header != SQLITE_MAGIC {
        return DoctorCheck {
            name: "SQLite cache (.klens/cache/index.db)".to_string(),
            severity: CheckSeverity::Error,
            message: "invalid SQLite header; safe to delete `.klens/cache/index.db` and rebuild"
                .to_string(),
        };
    }

    let wal_present = project_root
        .join(".klens")
        .join("cache")
        .join("index.db-wal")
        .exists();
    DoctorCheck {
        name: "SQLite cache (.klens/cache/index.db)".to_string(),
        severity: CheckSeverity::Ok,
        message: format!(
            "healthy SQLite 3 database ({} bytes, wal_active={wal_present})",
            meta.len()
        ),
    }
}

fn check_memory_staleness(project_root: &ProjectRoot) -> DoctorCheck {
    let memory_dir = project_root.root().join(".klens").join("memory");
    if !memory_dir.is_dir() {
        return DoctorCheck {
            name: "Memory staleness (.klens/memory/)".to_string(),
            severity: CheckSeverity::Ok,
            message: "0 memory notes (directory not created yet)".to_string(),
        };
    }

    let mut total_notes = 0usize;
    let mut stale_notes = Vec::new();
    let mut malformed_notes = Vec::new();

    if let Ok(entries) = fs::read_dir(&memory_dir) {
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("md"))
            })
            .collect();
        paths.sort();

        for md_path in paths {
            total_notes += 1;
            let name = md_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("note.md")
                .to_string();
            match inspect_memory_note_state(project_root, &md_path) {
                FallbackNoteState::Fresh => {}
                FallbackNoteState::Stale => stale_notes.push(name),
                FallbackNoteState::Malformed => malformed_notes.push(name),
            }
        }
    }

    if stale_notes.is_empty() && malformed_notes.is_empty() {
        DoctorCheck {
            name: "Memory staleness (.klens/memory/)".to_string(),
            severity: CheckSeverity::Ok,
            message: format!("{total_notes} memory note(s) checked, 0 stale"),
        }
    } else if stale_notes.is_empty() {
        DoctorCheck {
            name: "Memory staleness (.klens/memory/)".to_string(),
            severity: CheckSeverity::Warning,
            message: format!(
                "{} malformed/unreadable memory note(s) out of {total_notes}: {}",
                malformed_notes.len(),
                malformed_notes.join(", ")
            ),
        }
    } else if malformed_notes.is_empty() {
        DoctorCheck {
            name: "Memory staleness (.klens/memory/)".to_string(),
            severity: CheckSeverity::Warning,
            message: format!(
                "{} stale memory note(s) out of {total_notes}: {}",
                stale_notes.len(),
                stale_notes.join(", ")
            ),
        }
    } else {
        DoctorCheck {
            name: "Memory staleness (.klens/memory/)".to_string(),
            severity: CheckSeverity::Warning,
            message: format!(
                "{} stale and {} malformed memory note(s) out of {total_notes}: stale=[{}], malformed=[{}]",
                stale_notes.len(),
                malformed_notes.len(),
                stale_notes.join(", "),
                malformed_notes.join(", ")
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallbackNoteState {
    Fresh,
    Stale,
    Malformed,
}

#[derive(Debug, Default)]
struct FallbackAnchor {
    path: Option<String>,
    has_symbol: bool,
    blake3: Option<String>,
}

/// Inspect YAML frontmatter `anchors:` (`path:` + optional `symbol:` + `blake3:`) or explicit
/// `status: stale` inside a `.klens/memory/*.md` file without pulling in a YAML crate.
///
/// For symbol-scoped anchors (`symbol:` present), avoids false STALE comparisons against
/// whole-file `blake3_file` hashes (only checks that the anchored file still exists).
/// Files missing or lacking a valid closed `---` frontmatter block are flagged `Malformed`.
fn inspect_memory_note_state(project_root: &ProjectRoot, md_path: &Path) -> FallbackNoteState {
    let Ok(Some((_, lf, _))) = read_text_file(md_path) else {
        return FallbackNoteState::Malformed;
    };

    let mut lines = lf.lines();
    if lines.next().map(str::trim) != Some("---") {
        return FallbackNoteState::Malformed;
    }

    let mut closed = false;
    let mut explicitly_stale = false;
    let mut in_anchors = false;
    let mut anchors: Vec<FallbackAnchor> = Vec::new();
    let mut current: Option<FallbackAnchor> = None;

    for raw in lines {
        let trimmed = raw.trim();
        if trimmed == "---" {
            closed = true;
            if let Some(a) = current.take() {
                anchors.push(a);
            }
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("status:")
            && rest.trim().eq_ignore_ascii_case("stale")
        {
            explicitly_stale = true;
        }
        if trimmed == "anchors:" {
            in_anchors = true;
            if let Some(a) = current.take() {
                anchors.push(a);
            }
            continue;
        }
        if in_anchors {
            if trimmed.is_empty() {
                continue;
            }
            if !raw.starts_with(' ') && !raw.starts_with('\t') && !trimmed.starts_with('-') {
                in_anchors = false;
                if let Some(a) = current.take() {
                    anchors.push(a);
                }
                continue;
            }
            if trimmed.starts_with('-') {
                if let Some(a) = current.take() {
                    anchors.push(a);
                }
                current = Some(FallbackAnchor::default());
            }
            let entry = current.get_or_insert_with(FallbackAnchor::default);
            let cleaned = trimmed.trim_start_matches('-').trim();
            if let Some(path_val) = cleaned.strip_prefix("path:") {
                entry.path = Some(unquote_yaml_scalar(path_val));
            } else if let Some(sym_val) = cleaned.strip_prefix("symbol:") {
                if !unquote_yaml_scalar(sym_val).is_empty() {
                    entry.has_symbol = true;
                }
            } else if let Some(hash_val) = cleaned.strip_prefix("blake3:") {
                entry.blake3 = Some(unquote_yaml_scalar(hash_val));
            }
        }
    }

    if !closed {
        return FallbackNoteState::Malformed;
    }
    if explicitly_stale {
        return FallbackNoteState::Stale;
    }

    for anchor in &anchors {
        let Some(ref rel_str) = anchor.path else {
            continue;
        };
        if anchor.has_symbol {
            // Symbol hashes cannot be verified by whole-file `blake3_file`; only verify file existence here.
            if project_root.resolve_existing(rel_str).is_err() {
                return FallbackNoteState::Stale;
            }
            continue;
        }
        if let Some(ref expected) = anchor.blake3 {
            let is_fresh = project_root
                .resolve_existing(rel_str)
                .ok()
                .and_then(|(abs, _)| blake3_file(&abs).ok())
                .is_some_and(|actual| {
                    let clean_expected = expected.strip_prefix("blake3:").unwrap_or(expected);
                    actual.eq_ignore_ascii_case(clean_expected)
                });
            if !is_fresh {
                return FallbackNoteState::Stale;
            }
        }
    }

    FallbackNoteState::Fresh
}

fn unquote_yaml_scalar(raw: &str) -> String {
    let s = raw.split('#').next().unwrap_or(raw).trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn check_gitignore_status(project_root: &Path) -> DoctorCheck {
    let gitignore_path = project_root.join(".gitignore");
    let Ok(Some((_, lf, _))) = read_text_file(&gitignore_path) else {
        return DoctorCheck {
            name: ".gitignore status".to_string(),
            severity: CheckSeverity::Warning,
            message: ".gitignore not found; run `klens attach` to ignore `.klens/cache/` and `.klens/runs/`"
                .to_string(),
        };
    };

    let has_block = has_marked_block(&gitignore_path, &lf, MarkerStyle::Hash);
    let ignores_cache = lf.lines().any(|l| {
        let norm = l.trim().trim_start_matches('/');
        matches!(
            norm,
            ".klens/cache/" | ".klens/cache" | ".klens/" | ".klens"
        )
    });
    let ignores_runs = lf.lines().any(|l| {
        let norm = l.trim().trim_start_matches('/');
        matches!(norm, ".klens/runs/" | ".klens/runs" | ".klens/" | ".klens")
    });

    if ignores_cache && ignores_runs {
        DoctorCheck {
            name: ".gitignore status".to_string(),
            severity: CheckSeverity::Ok,
            message: if has_block {
                "`.klens/cache/` and `.klens/runs/` ignored via managed `# klens:start` block"
                    .to_string()
            } else {
                "`.klens/cache/` and `.klens/runs/` are ignored".to_string()
            },
        }
    } else {
        DoctorCheck {
            name: ".gitignore status".to_string(),
            severity: CheckSeverity::Warning,
            message:
                "missing ignore entries for `.klens/cache/` or `.klens/runs/` — run `klens attach`"
                    .to_string(),
        }
    }
}
