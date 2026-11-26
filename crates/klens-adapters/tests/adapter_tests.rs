use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_adapters::{
    AccessScope, AdapterError, AdapterOptions, AdapterRegistry, ConciseLevel, HostKind, HostTarget,
    SkillSelection, UTF8_BOM, attach_project, detach_project, detect_environment, disconnect_host,
    global_config_path_in, init_hosts, metrics_path_in, run_doctor, scan_directory, uninstall_all,
};
use klens_core::telemetry::{MetricEvent, append_metric_event};
use klens_core::{
    AdapterContext, CheckSeverity, GlobalConfig, ProjectMode, ProjectRoot, blake3_file,
};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let seq = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("klens-p3b-{label}-{}-{seq}", std::process::id()));
        let home = root.join("home");
        let project = root.join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        Self {
            root,
            home,
            project,
        }
    }

    fn project_root(&self) -> ProjectRoot {
        ProjectRoot::new(&self.project).unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Recursively snapshot every file's relative path and exact raw bytes for byte-level assertions.
fn snapshot_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    if !root.exists() {
        return map;
    }
    collect_tree(root, root, &mut map);
    map
}

fn collect_tree(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            collect_tree(base, &path, out);
        } else if path.is_file() {
            out.insert(rel, fs::read(&path).unwrap());
        }
    }
}

/// Mandatory Test 1:
/// Moving the `klens` binary from `path_a` to `path_b` updates all 4 adapters idempotently
/// without throwing errors and without disturbing user lines, JSON/TOML keys, BOM, or CRLF.
#[test]
fn moved_binary_idempotent_update_preserves_user_lines_and_keys() {
    let sb = Sandbox::new("moved-binary");

    // Pre-populate user files with UTF-8 BOM, CRLF, Turkish characters, and custom user keys.
    let ag_cfg = sb.home.join(".gemini/config/mcp_config.json");
    fs::create_dir_all(ag_cfg.parent().unwrap()).unwrap();
    let ag_seed = "\u{FEFF}{\r\n  \"customTop\": \"türkçe-ğüşiöç\",\r\n  \"mcpServers\": {\r\n    \"github\": { \"command\": \"gh-mcp\", \"args\": [] }\r\n  }\r\n}\r\n";
    fs::write(&ag_cfg, ag_seed.as_bytes()).unwrap();

    let codex_cfg = sb.home.join(".codex/config.toml");
    fs::create_dir_all(codex_cfg.parent().unwrap()).unwrap();
    let codex_seed = "\u{FEFF}# Kullanıcı Codex ayarları (ğüşiöç 🚀)\r\nmodel = \"gpt-5\"\r\n\r\n[mcp_servers.other]\r\ncommand = \"other-mcp\"\r\nargs = [\"serve\"]\r\n";
    fs::write(&codex_cfg, codex_seed.as_bytes()).unwrap();

    let agents_md = sb.project.join("AGENTS.md");
    let agents_seed = "\u{FEFF}# Benim Proje Kurallarım (ğüşiöç)\r\nAsla bu satıra dokunma.\r\n";
    fs::write(&agents_md, agents_seed.as_bytes()).unwrap();

    let claude_settings = sb.project.join(".claude/settings.json");
    fs::create_dir_all(claude_settings.parent().unwrap()).unwrap();
    let settings_seed = "\u{FEFF}{\r\n  \"theme\": \"dark\",\r\n  \"hooks\": {\r\n    \"SessionStart\": [\r\n      { \"hooks\": [{ \"type\": \"command\", \"command\": \"echo user-hook\" }] }\r\n    ]\r\n  }\r\n}\r\n";
    fs::write(&claude_settings, settings_seed.as_bytes()).unwrap();

    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let path_a = PathBuf::from(r"C:\old-location\bin\klens.exe");
    let path_b = PathBuf::from(r"C:\moved-location\tools\klens.exe");

    // 1. Initial install with `path_a`
    let ctx_a = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: path_a.clone(),
        dry_run: false,
    };
    let rep_a = init_hosts(&registry, HostTarget::All, &ctx_a).unwrap();
    assert_eq!(rep_a.reports.len(), 4);
    assert!(rep_a.reports.iter().all(|r| r.changed));

    // 2. Re-running with identical `path_a` is a clean no-op
    let rep_a_again = init_hosts(&registry, HostTarget::All, &ctx_a).unwrap();
    assert!(rep_a_again.reports.iter().all(|r| !r.changed));

    // 3. Re-running after binary moved to `path_b` succeeds and updates all registrations
    let ctx_b = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: path_b.clone(),
        dry_run: false,
    };
    let rep_b = init_hosts(&registry, HostTarget::All, &ctx_b).unwrap();
    assert!(rep_b.reports.iter().all(|r| r.changed));

    for host_id in ["antigravity", "claude-code", "codex"] {
        let host_rep = rep_b.reports.iter().find(|r| r.host_id == host_id).unwrap();
        assert!(
            host_rep
                .notes
                .iter()
                .any(|n| n.contains("Updated binary path")),
            "expected Updated binary path note for {host_id}, got {:?}",
            host_rep.notes
        );
    }

    // Verify Antigravity config preserved BOM, CRLF, user top-level key, and `github` server
    let ag_bytes = fs::read(&ag_cfg).unwrap();
    assert!(ag_bytes.starts_with(UTF8_BOM));
    let ag_str = std::str::from_utf8(&ag_bytes[3..]).unwrap();
    assert!(ag_str.contains("\r\n"));
    let ag_json: serde_json::Value = serde_json::from_str(ag_str).unwrap();
    assert_eq!(ag_json["customTop"], "türkçe-ğüşiöç");
    assert_eq!(ag_json["mcpServers"]["github"]["command"], "gh-mcp");
    assert_eq!(
        ag_json["mcpServers"]["klens"]["command"],
        r"C:\moved-location\tools\klens.exe"
    );

    // Verify Codex TOML preserved BOM, CRLF, comments, `model`, `[mcp_servers.other]`, and updated `klens`
    let codex_bytes = fs::read(&codex_cfg).unwrap();
    assert!(codex_bytes.starts_with(UTF8_BOM));
    let codex_str = std::str::from_utf8(&codex_bytes[3..]).unwrap();
    assert!(codex_str.contains("\r\n"));
    assert!(codex_str.contains("# Kullanıcı Codex ayarları (ğüşiöç 🚀)"));
    let codex_tbl: toml::Table = toml::from_str(codex_str).unwrap();
    assert_eq!(codex_tbl["model"].as_str(), Some("gpt-5"));
    assert_eq!(
        codex_tbl["mcp_servers"]["other"]["command"].as_str(),
        Some("other-mcp")
    );
    assert_eq!(
        codex_tbl["mcp_servers"]["klens"]["command"].as_str(),
        Some(r"C:\moved-location\tools\klens.exe")
    );

    // Verify AGENTS.md preserved BOM, CRLF, and user lines
    let agents_bytes = fs::read(&agents_md).unwrap();
    assert!(agents_bytes.starts_with(UTF8_BOM));
    let agents_str = std::str::from_utf8(&agents_bytes[3..]).unwrap();
    assert!(agents_str.contains("Asla bu satıra dokunma.\r\n"));
    assert!(agents_str.contains("<!-- klens:start -->\r\n"));

    // Verify Claude `.claude/settings.json` preserved user hook, `theme`, BOM, and CRLF
    let settings_bytes = fs::read(&claude_settings).unwrap();
    assert!(settings_bytes.starts_with(UTF8_BOM));
    let settings_str = std::str::from_utf8(&settings_bytes[3..]).unwrap();
    assert!(settings_str.contains("\r\n"));
    let settings_json: serde_json::Value = serde_json::from_str(settings_str).unwrap();
    assert_eq!(settings_json["theme"], "dark");
    let session_hooks = settings_json["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(session_hooks.len(), 2);
    assert_eq!(session_hooks[0]["hooks"][0]["command"], "echo user-hook");
    assert!(
        session_hooks[1]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains(r"C:\moved-location\tools\klens.exe")
    );
}

/// Mandatory Test 2:
/// Symmetric `attach` + `init` -> `detach` (preserves user blueprint/memory & global configs)
/// -> `detach --purge` leaves the project directory **byte-for-byte identical** to its initial state.
#[test]
fn symmetric_attach_and_detach_purge_leaves_byte_for_byte_identical_project() {
    let sb = Sandbox::new("symmetric-zero-trace");

    // Seed original project files with tricky encodings and line endings:
    // 1. `.gitignore`: UTF-8 BOM + CRLF + Turkish comment
    fs::write(
        sb.project.join(".gitignore"),
        "\u{FEFF}# Özel kurallar (ğüşiöç)\r\ntarget/\r\n*.log\r\n".as_bytes(),
    )
    .unwrap();
    // 2. `AGENTS.md`: pure LF with trailing newline
    fs::write(
        sb.project.join("AGENTS.md"),
        "# User Agents\nKeep every line intact.\n",
    )
    .unwrap();
    // 3. `KLENS.md`: pure LF WITHOUT trailing newline
    fs::write(sb.project.join("KLENS.md"), "# Existing KLENS notes").unwrap();
    // 4. `src/main.rs`: regular source file
    fs::create_dir_all(sb.project.join("src")).unwrap();
    fs::write(sb.project.join("src/main.rs"), "fn main() {}\n").unwrap();

    let before_snapshot = snapshot_tree(&sb.project);

    let proj_root = sb.project_root();
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());

    // Attach + init all 4 hosts
    let attach_rep =
        attach_project(&sb.home, &proj_root, Some(ProjectMode::Active), false).unwrap();
    assert!(attach_rep.changed);

    // Verify single source of truth (`~/.klens/config.toml`) and NO `projects.json`!
    assert!(global_config_path_in(&sb.home).is_file());
    assert!(!sb.home.join(".klens/projects.json").exists());
    let global_cfg = GlobalConfig::load(&global_config_path_in(&sb.home)).unwrap();
    assert_eq!(global_cfg.registered_projects.len(), 1);

    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };
    init_hosts(&registry, HostTarget::All, &ctx).unwrap();

    // Simulate runtime caches + user-authored blueprint & memory notes
    fs::create_dir_all(sb.project.join(".klens/cache")).unwrap();
    fs::write(
        sb.project.join(".klens/cache/index.db"),
        b"SQLite format 3\0dummy",
    )
    .unwrap();
    fs::create_dir_all(sb.project.join(".klens/runs")).unwrap();
    fs::write(sb.project.join(".klens/runs/r1.raw.log"), b"log").unwrap();
    fs::create_dir_all(sb.project.join(".klens/blueprint")).unwrap();
    fs::write(
        sb.project.join(".klens/blueprint/PROJECT_CONTRACT.md"),
        "# Locked Contract\n",
    )
    .unwrap();
    fs::create_dir_all(sb.project.join(".klens/memory")).unwrap();
    fs::write(
        sb.project.join(".klens/memory/adr-001.md"),
        "# Decision 1\n",
    )
    .unwrap();

    // 1. Non-purge `detach`: clears caches, runs, project-local MCP/hooks/skills/markers,
    //    unregisters from `~/.klens/config.toml`, keeps `blueprint/` & `memory/`, and NEVER
    //    touches global host configs (`~/.codex/config.toml`, `~/.gemini/config/mcp_config.json`).
    let detach_soft = detach_project(&registry, &proj_root, false, false).unwrap();
    assert!(detach_soft.changed);
    assert!(!sb.project.join(".klens/cache").exists());
    assert!(!sb.project.join(".klens/runs").exists());
    assert!(!sb.project.join(".mcp.json").exists());
    assert!(!sb.project.join(".claude").exists());
    assert!(
        sb.project
            .join(".klens/blueprint/PROJECT_CONTRACT.md")
            .is_file()
    );
    assert!(sb.project.join(".klens/memory/adr-001.md").is_file());
    assert!(sb.home.join(".codex/config.toml").is_file());
    assert!(sb.home.join(".gemini/config/mcp_config.json").is_file());

    let global_after = GlobalConfig::load(&global_config_path_in(&sb.home)).unwrap();
    assert!(global_after.registered_projects.is_empty());

    // 2. Purge `detach --purge`: removes `.klens/` completely -> byte-for-byte original tree!
    let detach_purge = detach_project(&registry, &proj_root, true, false).unwrap();
    assert!(detach_purge.changed);
    assert!(!sb.project.join(".klens").exists());

    let after_snapshot = snapshot_tree(&sb.project);
    assert_eq!(
        before_snapshot, after_snapshot,
        "project directory must be byte-for-byte identical after attach -> detach --purge"
    );
}

/// Mandatory Test 3:
/// `--dry-run` on `attach`, `init`, `detach`, `disconnect`, and `uninstall` must NEVER
/// mutate or create even a single byte anywhere on disk (including backups!).
#[test]
fn dry_run_never_mutates_a_single_byte_on_disk() {
    let sb = Sandbox::new("dry-run-guarantee");
    fs::write(sb.project.join(".gitignore"), "target/\n").unwrap();
    let proj_root = sb.project_root();
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());

    let initial_snapshot = snapshot_tree(&sb.root);

    // Dry-run attach
    let attach_dry = attach_project(&sb.home, &proj_root, None, true).unwrap();
    assert!(attach_dry.dry_run);
    assert!(!attach_dry.changed);
    assert!(!attach_dry.files_touched.is_empty());
    assert_eq!(snapshot_tree(&sb.root), initial_snapshot);

    // Dry-run init
    let dry_ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: true,
    };
    let init_dry = init_hosts(&registry, HostTarget::All, &dry_ctx).unwrap();
    assert!(init_dry.dry_run);
    assert!(init_dry.reports.iter().all(|r| !r.changed));
    assert!(init_dry.reports.iter().all(|r| !r.files_touched.is_empty()));
    assert_eq!(snapshot_tree(&sb.root), initial_snapshot);

    // Now actually attach & init, then snapshot again before dry-run removals
    attach_project(&sb.home, &proj_root, None, false).unwrap();
    let real_ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };
    init_hosts(&registry, HostTarget::All, &real_ctx).unwrap();

    let installed_snapshot = snapshot_tree(&sb.root);

    // Dry-run detach --purge
    let detach_dry = detach_project(&registry, &proj_root, true, true).unwrap();
    assert!(detach_dry.dry_run);
    assert!(!detach_dry.changed);
    assert!(!detach_dry.files_touched.is_empty());
    assert_eq!(snapshot_tree(&sb.root), installed_snapshot);

    // Dry-run disconnect --host all (must NOT create .bak files!)
    let disc_dry = disconnect_host(&registry, HostTarget::All, &dry_ctx).unwrap();
    assert!(disc_dry.dry_run);
    assert!(disc_dry.reports.iter().all(|r| !r.changed));
    assert_eq!(snapshot_tree(&sb.root), installed_snapshot);

    // Dry-run uninstall --all
    let uninst_dry = uninstall_all(&registry, &dry_ctx, true).unwrap();
    assert!(uninst_dry.dry_run);
    assert!(!uninst_dry.changed);
    assert!(!uninst_dry.global_dir_removed);
    assert_eq!(snapshot_tree(&sb.root), installed_snapshot);
}

/// Mandatory Test 4:
/// `detect` and `doctor` honestly separate Project-Local vs Global configured registrations
/// AND Layer 2 observed client audit records from `~/.klens/metrics.jsonl`.
#[test]
fn detect_and_doctor_separate_project_local_vs_global_and_observed_access() {
    let sb = Sandbox::new("visibility-layers");
    let proj_root = sb.project_root();
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());

    let bin_v1 = PathBuf::from(r"C:\v1\klens.exe");
    let bin_v2 = PathBuf::from(r"C:\v2\klens.exe");

    // Register Antigravity (global), Claude Code (project-local), Codex (global + project-local AGENTS.md)
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: bin_v1.clone(),
        dry_run: false,
    };
    init_hosts(&registry, HostTarget::Single(HostKind::Antigravity), &ctx).unwrap();
    init_hosts(&registry, HostTarget::Single(HostKind::ClaudeCode), &ctx).unwrap();
    init_hosts(&registry, HostTarget::Single(HostKind::Codex), &ctx).unwrap();

    // Also add a global `~/.claude.json` registration to verify BOTH scopes appear for Claude Code
    fs::write(
        sb.home.join(".claude.json"),
        serde_json::json!({
            "mcpServers": {
                "klens": {
                    "command": r"C:\v1\klens.exe",
                    "args": ["mcp"]
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    // Record real observed MCP events in `~/.klens/metrics.jsonl` (including an unrelated project)
    let metrics_path = metrics_path_in(&sb.home);
    append_metric_event(
        &metrics_path,
        &MetricEvent::new(
            "2026-11-23T01:00:00Z",
            proj_root.project_id(),
            Some("project".to_string()),
            "antigravity",
            "2.0",
            "klens_map",
            1200,
            200,
            false,
        ),
    )
    .unwrap();
    append_metric_event(
        &metrics_path,
        &MetricEvent::new(
            "2026-11-23T01:05:00Z",
            proj_root.project_id(),
            Some("project".to_string()),
            "claude-code",
            "1.4",
            "klens_read",
            800,
            120,
            false,
        ),
    )
    .unwrap();
    append_metric_event(
        &metrics_path,
        &MetricEvent::new(
            "2026-11-23T01:10:00Z",
            "other-project-id",
            Some("other".to_string()),
            "codex",
            "0.9",
            "klens_find",
            500,
            50,
            false,
        ),
    )
    .unwrap();

    // Check `detect` with current binary `bin_v1`
    let detect = detect_environment(&registry, &proj_root, &bin_v1);

    let has_local_claude = detect.configured_access.iter().any(|e| {
        e.host_id == "claude-code"
            && e.scope == AccessScope::ProjectLocal
            && e.scope_label.contains("project-local")
    });
    let has_global_claude = detect.configured_access.iter().any(|e| {
        e.host_id == "claude-code"
            && e.scope == AccessScope::Global
            && e.scope_label.contains("global-mcp")
    });
    let has_global_ag = detect.configured_access.iter().any(|e| {
        e.host_id == "antigravity"
            && e.scope == AccessScope::Global
            && e.scope_label.contains("global-mcp")
    });
    let has_local_codex = detect
        .configured_access
        .iter()
        .any(|e| e.host_id == "codex" && e.scope == AccessScope::ProjectLocal);
    let has_global_codex = detect
        .configured_access
        .iter()
        .any(|e| e.host_id == "codex" && e.scope == AccessScope::Global);

    assert!(has_local_claude, "missing project-local Claude Code entry");
    assert!(has_global_claude, "missing global Claude Code entry");
    assert!(has_global_ag, "missing global Antigravity entry");
    assert!(
        has_local_codex,
        "missing project-local Codex AGENTS.md entry"
    );
    assert!(has_global_codex, "missing global Codex config.toml entry");

    // Observed access must include only this project's 2 clients (not `other-project-id`)
    assert_eq!(detect.observed_access.len(), 2);
    assert_eq!(detect.observed_access[0].client_name, "antigravity");
    assert_eq!(detect.observed_access[1].client_name, "claude-code");

    // Check `doctor` against moved binary `bin_v2`: must warn about stale binary paths
    // AND clearly label project-local vs global checks.
    let doctor = run_doctor(&registry, &proj_root, &bin_v2);
    assert_eq!(doctor.overall, CheckSeverity::Warning);
    assert!(
        doctor
            .checks
            .iter()
            .any(|c| c.name.contains("project-local")
                && c.severity == CheckSeverity::Warning
                && c.message.contains("stale binary path"))
    );
    assert!(doctor.checks.iter().any(|c| c.name.contains("global-mcp")
        && c.severity == CheckSeverity::Warning
        && c.message.contains("stale binary path")));
}

#[test]
fn disconnect_creates_backup_and_preserves_bom_crlf_and_user_entries() {
    let sb = Sandbox::new("disconnect-backup");

    let ag_cfg = sb.home.join(".gemini/config/mcp_config.json");
    fs::create_dir_all(ag_cfg.parent().unwrap()).unwrap();
    let ag_orig = "\u{FEFF}{\r\n  \"mcpServers\": {\r\n    \"keepMe\": {\r\n      \"command\": \"keep-bin\",\r\n      \"args\": [\"serve\"]\r\n    }\r\n  }\r\n}\r\n";
    fs::write(&ag_cfg, ag_orig.as_bytes()).unwrap();

    let codex_cfg = sb.home.join(".codex/config.toml");
    fs::create_dir_all(codex_cfg.parent().unwrap()).unwrap();
    let codex_orig = "\u{FEFF}# Özel yorum ğüşiöç\r\nmodel = \"o3\"\r\n\r\n[mcp_servers.keep]\r\ncommand = \"keep-codex\"\r\nargs = []\r\n";
    fs::write(&codex_cfg, codex_orig.as_bytes()).unwrap();

    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };

    init_hosts(&registry, HostTarget::Single(HostKind::Antigravity), &ctx).unwrap();
    init_hosts(&registry, HostTarget::Single(HostKind::Codex), &ctx).unwrap();

    let pre_disconnect_ag = fs::read(&ag_cfg).unwrap();
    let pre_disconnect_codex = fs::read(&codex_cfg).unwrap();

    let disc = disconnect_host(&registry, HostTarget::All, &ctx).unwrap();
    assert!(disc.reports.iter().any(|r| r.changed));

    // Verify backups were created with exact pre-disconnect bytes
    let ag_backups: Vec<PathBuf> = fs::read_dir(ag_cfg.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".bak"))
        .collect();
    assert_eq!(ag_backups.len(), 1);
    assert_eq!(fs::read(&ag_backups[0]).unwrap(), pre_disconnect_ag);

    let codex_backups: Vec<PathBuf> = fs::read_dir(codex_cfg.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".bak"))
        .collect();
    assert_eq!(codex_backups.len(), 1);
    assert_eq!(fs::read(&codex_backups[0]).unwrap(), pre_disconnect_codex);

    // Verify `klens` removed, user entries + BOM + CRLF preserved
    let ag_after = fs::read(&ag_cfg).unwrap();
    assert!(ag_after.starts_with(UTF8_BOM));
    let ag_text = std::str::from_utf8(&ag_after[3..]).unwrap();
    assert!(ag_text.contains("\r\n"));
    let ag_val: serde_json::Value = serde_json::from_str(ag_text).unwrap();
    assert!(ag_val["mcpServers"].get("klens").is_none());
    assert_eq!(ag_val["mcpServers"]["keepMe"]["command"], "keep-bin");

    let codex_after = fs::read(&codex_cfg).unwrap();
    assert_eq!(
        codex_after,
        codex_orig.as_bytes(),
        "Codex config.toml must return byte-for-byte to original including BOM, CRLF, and Turkish comment"
    );
}

#[test]
fn scan_is_read_only_and_discovers_depth_1_and_2_projects() {
    let sb = Sandbox::new("scan-readonly");
    let workspace = sb.root.join("workspaces");
    fs::create_dir_all(workspace.join("alpha/.git")).unwrap();
    fs::create_dir_all(workspace.join("group/beta")).unwrap();
    fs::write(
        workspace.join("group/beta/Cargo.toml"),
        "[package]\nname = \"beta\"\n",
    )
    .unwrap();
    // Depth 3 should not be scanned (spec: 1-2 levels deep)
    fs::create_dir_all(workspace.join("a/b/too-deep")).unwrap();
    fs::write(workspace.join("a/b/too-deep/package.json"), "{}").unwrap();
    // Noisy dir should be skipped
    fs::create_dir_all(workspace.join("node_modules/pkg")).unwrap();
    fs::write(workspace.join("node_modules/pkg/package.json"), "{}").unwrap();

    let before = snapshot_tree(&sb.root);
    let report = scan_directory(&workspace, &sb.home, 2).unwrap();
    assert_eq!(
        snapshot_tree(&sb.root),
        before,
        "scan must write zero bytes"
    );

    let names: Vec<&str> = report.projects.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta"]);
}

#[test]
fn uninstall_requires_all_flag_and_cleans_global_klens_dir() {
    let sb = Sandbox::new("uninstall-all");
    let proj_root = sb.project_root();
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());

    attach_project(&sb.home, &proj_root, None, false).unwrap();
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };
    init_hosts(&registry, HostTarget::All, &ctx).unwrap();
    assert!(sb.home.join(".klens").is_dir());

    // Refuses without `--all`
    let err = uninstall_all(&registry, &ctx, false).unwrap_err();
    assert!(matches!(err, AdapterError::UninstallRequiresAllFlag));
    assert!(sb.home.join(".klens").is_dir());

    // Succeeds with `--all`
    let rep = uninstall_all(&registry, &ctx, true).unwrap();
    assert!(rep.changed);
    assert!(rep.global_dir_removed);
    assert!(!sb.home.join(".klens").exists());
}

#[test]
fn doctor_flags_corrupt_sqlite_and_stale_memory_notes() {
    let sb = Sandbox::new("doctor-diagnostics");
    fs::create_dir_all(sb.project.join("src")).unwrap();
    let src_file = sb.project.join("src/lib.rs");
    fs::write(&src_file, "pub fn answer() -> u32 { 42 }\n").unwrap();
    let fresh_hash = blake3_file(&src_file).unwrap();

    // Write 1 fresh memory note + 1 stale memory note
    let mem_dir = sb.project.join(".klens/memory");
    fs::create_dir_all(&mem_dir).unwrap();
    fs::write(
        mem_dir.join("fresh.md"),
        format!(
            "---\nschema_version: 1\nstatus: active\nanchors:\n  - path: src/lib.rs\n    blake3: \"{fresh_hash}\"\n---\nFresh note\n"
        ),
    )
    .unwrap();
    fs::write(
        mem_dir.join("stale.md"),
        "---\nschema_version: 1\nstatus: active\nanchors:\n  - path: src/lib.rs\n    blake3: \"0000deadbeef\"\n---\nStale note\n",
    )
    .unwrap();

    // Write corrupt SQLite header
    let cache_dir = sb.project.join(".klens/cache");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(
        cache_dir.join("index.db"),
        b"not-a-valid-sqlite-header-bytes",
    )
    .unwrap();

    let proj_root = sb.project_root();
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let doc = run_doctor(&registry, &proj_root, Path::new(r"C:\bin\klens.exe"));

    assert_eq!(doc.overall, CheckSeverity::Error);
    assert!(
        doc.checks
            .iter()
            .any(|c| { c.name.contains("SQLite cache") && c.severity == CheckSeverity::Error })
    );
    assert!(doc.checks.iter().any(|c| {
        c.name.contains("Memory staleness")
            && c.severity == CheckSeverity::Warning
            && c.message.contains("1 stale memory note(s)")
    }));
}

#[test]
fn skill_pack_concise_modes_and_optional_skill_forge_toggle_cleanly() {
    let sb = Sandbox::new("skills-toggle");
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };

    // Default: surgical + blueprint + concise(balanced), no skill-forge
    let reg_default = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    init_hosts(
        &reg_default,
        HostTarget::Single(HostKind::Antigravity),
        &ctx,
    )
    .unwrap();
    let skills_root = sb.home.join(".gemini/config/skills");
    assert!(skills_root.join("klens-surgical-coding/SKILL.md").is_file());
    assert!(
        skills_root
            .join("klens-blueprint-architect/SKILL.md")
            .is_file()
    );
    let concise_md = fs::read_to_string(skills_root.join("klens-concise/SKILL.md")).unwrap();
    assert!(concise_md.contains("Current level: `balanced`"));
    assert!(!skills_root.join("klens-skill-forge/SKILL.md").exists());

    // Switch concise=off and enable skill-forge
    let opts_custom = AdapterOptions {
        skills: SkillSelection {
            concise: ConciseLevel::Off,
            skill_forge: true,
            ..SkillSelection::default()
        },
        ..AdapterOptions::default()
    };
    let reg_custom = AdapterRegistry::with_home(sb.home.clone(), &opts_custom);
    init_hosts(&reg_custom, HostTarget::Single(HostKind::Antigravity), &ctx).unwrap();
    assert!(!skills_root.join("klens-concise/SKILL.md").exists());
    assert!(skills_root.join("klens-skill-forge/SKILL.md").is_file());
}

#[test]
fn antigravity_legacy_path_detected_reported_by_doctor_and_cleaned_on_disconnect_and_uninstall() {
    let sb = Sandbox::new("antigravity-legacy");
    let proj_root = sb.project_root();
    let bin = PathBuf::from(r"C:\bin\klens.exe");

    // Seed ONLY the legacy `~/.gemini/antigravity/mcp_config.json` + legacy skill file.
    let legacy_cfg = sb.home.join(".gemini/antigravity/mcp_config.json");
    fs::create_dir_all(legacy_cfg.parent().unwrap()).unwrap();
    fs::write(
        &legacy_cfg,
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "keepLegacy": { "command": "other-mcp", "args": [] },
                "klens": { "command": r"C:\bin\klens.exe", "args": ["mcp"] }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let legacy_skill = sb
        .home
        .join(".gemini/antigravity/skills/klens-surgical-coding/SKILL.md");
    fs::create_dir_all(legacy_skill.parent().unwrap()).unwrap();
    fs::write(&legacy_skill, "# legacy skill\n").unwrap();

    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());

    // 1. `detect()` and `configured_access()` honestly report the legacy registration.
    let det = detect_environment(&registry, &proj_root, &bin);
    let ag_row = det
        .hosts
        .iter()
        .find(|h| h.host_id == "antigravity")
        .unwrap();
    assert!(
        matches!(
            &ag_row.status,
            klens_core::HostDetectStatus::Installed { config_path }
                if config_path.to_string_lossy().replace('\\', "/").ends_with(".gemini/antigravity/mcp_config.json")
        ),
        "expected legacy path Installed status, got {:?}",
        ag_row.status
    );
    assert!(det.configured_access.iter().any(|e| {
        e.host_id == "antigravity"
            && e.scope == AccessScope::Global
            && e.scope_label.contains("legacy")
            && e.config_path
                .to_string_lossy()
                .replace('\\', "/")
                .ends_with(".gemini/antigravity/mcp_config.json")
    }));

    // 2. `doctor()` emits an honest Warning for the legacy path.
    let doc = run_doctor(&registry, &proj_root, &bin);
    assert!(doc.checks.iter().any(|c| {
        c.name.contains("legacy")
            && c.severity == CheckSeverity::Warning
            && c.message.contains("mcp_config.json")
    }));

    // 3. `init --host antigravity` installs into the current standard `~/.gemini/config/` path.
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: bin.clone(),
        dry_run: false,
    };
    init_hosts(&registry, HostTarget::Single(HostKind::Antigravity), &ctx).unwrap();
    let current_cfg = sb.home.join(".gemini/config/mcp_config.json");
    assert!(current_cfg.is_file());
    assert!(
        sb.home
            .join(".gemini/config/skills/klens-surgical-coding/SKILL.md")
            .is_file()
    );

    // Now BOTH current and legacy entries appear honestly in `configured_access`.
    let det_both = detect_environment(&registry, &proj_root, &bin);
    let ag_entries: Vec<_> = det_both
        .configured_access
        .iter()
        .filter(|e| e.host_id == "antigravity")
        .collect();
    assert_eq!(ag_entries.len(), 2);

    // 4. `disconnect --host antigravity` cleans BOTH current and legacy paths while preserving `keepLegacy`.
    let disc = disconnect_host(&registry, HostTarget::Single(HostKind::Antigravity), &ctx).unwrap();
    assert!(disc.reports[0].changed);

    let current_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&current_cfg).unwrap()).unwrap();
    assert!(current_json["mcpServers"].get("klens").is_none());
    assert!(
        !sb.home
            .join(".gemini/config/skills/klens-surgical-coding/SKILL.md")
            .exists()
    );

    let legacy_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&legacy_cfg).unwrap()).unwrap();
    assert!(legacy_json["mcpServers"].get("klens").is_none());
    assert_eq!(
        legacy_json["mcpServers"]["keepLegacy"]["command"],
        "other-mcp"
    );
    assert!(!legacy_skill.exists());

    // 5. Re-seed legacy + current and verify `uninstall --all` also cleans both locations.
    fs::write(
        &legacy_cfg,
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "klens": { "command": r"C:\bin\klens.exe", "args": ["mcp"] }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    init_hosts(&registry, HostTarget::Single(HostKind::Antigravity), &ctx).unwrap();
    attach_project(&sb.home, &proj_root, None, false).unwrap();

    let uninst = uninstall_all(&registry, &ctx, true).unwrap();
    assert!(uninst.changed);
    assert!(!sb.home.join(".klens").exists());
    let legacy_after_uninst: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&legacy_cfg).unwrap()).unwrap();
    assert!(legacy_after_uninst["mcpServers"].get("klens").is_none());
    let current_after_uninst: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&current_cfg).unwrap()).unwrap();
    assert!(current_after_uninst["mcpServers"].get("klens").is_none());
}
