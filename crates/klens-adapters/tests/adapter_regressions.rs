use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_adapters::{
    AdapterOptions, AdapterRegistry, HostKind, HostTarget, clean_binary_path_string,
    detach_project, detect_environment, disconnect_host, format_detect_text, format_doctor_text,
    init_hosts, paths_equivalent, run_doctor,
};
use klens_core::{AdapterContext, CheckSeverity, ProjectRoot, blake3_file};

static REG_COUNTER: AtomicU64 = AtomicU64::new(0);

struct RegSandbox {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl RegSandbox {
    fn new(label: &str) -> Self {
        let seq = REG_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "klens-p3b-reg-{label}-{}-{seq}",
            std::process::id()
        ));
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

impl Drop for RegSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Regression 1:
/// Updating Codex `config.toml` when the binary moves MUST preserve `[mcp_servers.klens.env]`
/// (user subtables), while `disconnect --host codex` MUST cleanly remove both `[mcp_servers.klens]`
/// and its `[mcp_servers.klens.env]` subtable without touching sibling `[mcp_servers.other]`.
#[test]
fn regression_codex_binary_update_preserves_klens_env_subtable_and_disconnect_cleans_it() {
    let sb = RegSandbox::new("codex-subtable");
    let codex_cfg = sb.home.join(".codex/config.toml");
    fs::create_dir_all(codex_cfg.parent().unwrap()).unwrap();

    let seed = "\
# User Codex config
model = \"gpt-5\"

[mcp_servers.klens]
command = \"C:\\\\old\\\\klens.exe\"
args = [\"mcp\"]

[mcp_servers.klens.env]
KLENS_LOG = \"debug\"
CUSTOM_VAR = \"keep-me\"

[mcp_servers.other]
command = \"other-mcp\"
args = [\"serve\"]
";
    fs::write(&codex_cfg, seed).unwrap();

    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let ctx_moved = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\new\klens.exe"),
        dry_run: false,
    };

    // 1. Moved binary update must preserve `[mcp_servers.klens.env]`
    let rep = init_hosts(&registry, HostTarget::Single(HostKind::Codex), &ctx_moved).unwrap();
    assert!(rep.reports[0].changed);

    let after_update = fs::read_to_string(&codex_cfg).unwrap();
    let parsed: toml::Table = toml::from_str(&after_update).unwrap();
    assert_eq!(
        parsed["mcp_servers"]["klens"]["command"].as_str(),
        Some(r"C:\new\klens.exe")
    );
    assert_eq!(
        parsed["mcp_servers"]["klens"]["env"]["KLENS_LOG"].as_str(),
        Some("debug")
    );
    assert_eq!(
        parsed["mcp_servers"]["klens"]["env"]["CUSTOM_VAR"].as_str(),
        Some("keep-me")
    );
    assert_eq!(
        parsed["mcp_servers"]["other"]["command"].as_str(),
        Some("other-mcp")
    );

    // 2. Disconnect must remove BOTH `[mcp_servers.klens]` and `[mcp_servers.klens.env]`,
    //    while keeping `model` and `[mcp_servers.other]`.
    let disc = disconnect_host(&registry, HostTarget::Single(HostKind::Codex), &ctx_moved).unwrap();
    assert!(disc.reports[0].changed);

    let after_disc = fs::read_to_string(&codex_cfg).unwrap();
    let parsed_after: toml::Table = toml::from_str(&after_disc).unwrap();
    assert_eq!(parsed_after["model"].as_str(), Some("gpt-5"));
    assert!(
        parsed_after["mcp_servers"]
            .as_table()
            .unwrap()
            .get("klens")
            .is_none()
    );
    assert_eq!(
        parsed_after["mcp_servers"]["other"]["command"].as_str(),
        Some("other-mcp")
    );
    assert!(!after_disc.contains("[mcp_servers.klens.env]"));
}

/// Regression 2:
/// - `doctor` accepts leading-slash `.gitignore` rules (`/.klens/cache/`, `/.klens/runs/`, `/.klens/`).
/// - Blank lines inside YAML frontmatter `anchors:` never stop staleness detection.
#[test]
fn regression_doctor_handles_leading_slash_gitignore_and_blank_lines_in_memory_anchors() {
    let sb = RegSandbox::new("doctor-gitignore-memory");
    fs::write(
        sb.project.join(".gitignore"),
        "/target\n/.klens/cache/\n/.klens/runs/\n",
    )
    .unwrap();
    fs::create_dir_all(sb.project.join("src")).unwrap();
    let src_file = sb.project.join("src/lib.rs");
    fs::write(&src_file, "pub fn ok() {}\n").unwrap();
    let fresh_hash = blake3_file(&src_file).unwrap();

    let mem_dir = sb.project.join(".klens/memory");
    fs::create_dir_all(&mem_dir).unwrap();
    fs::write(
        mem_dir.join("spaced-stale.md"),
        format!(
            "---\nschema_version: 1\nstatus: active\nanchors:\n  - path: src/lib.rs\n    blake3: \"{fresh_hash}\"\n\n  - path: src/lib.rs\n    blake3: \"deadbeef0000\"\n---\nBody\n"
        ),
    )
    .unwrap();

    let proj_root = sb.project_root();
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let doc = run_doctor(&registry, &proj_root, Path::new(r"C:\bin\klens.exe"));

    let gitignore_check = doc
        .checks
        .iter()
        .find(|c| c.name == ".gitignore status")
        .unwrap();
    assert_eq!(
        gitignore_check.severity,
        CheckSeverity::Ok,
        "expected leading-slash `/.klens/cache/` + `/.klens/runs/` to be OK, got: {}",
        gitignore_check.message
    );

    let mem_check = doc
        .checks
        .iter()
        .find(|c| c.name.contains("Memory staleness"))
        .unwrap();
    assert_eq!(mem_check.severity, CheckSeverity::Warning);
    assert!(
        mem_check.message.contains("1 stale memory note(s)"),
        "blank line inside frontmatter anchors must not stop staleness scan: {}",
        mem_check.message
    );
}

/// Regression 3:
/// Windows `\\?\UNC\...` -> `\\...` and `\\?\C:\...` -> `C:\...` are normalized cleanly,
/// and formatted `detect` / `doctor` outputs never leak `\\?\` verbatim prefixes.
#[test]
fn regression_windows_unc_and_verbatim_paths_clean_in_helpers_and_formatters() {
    assert_eq!(
        clean_binary_path_string(Path::new(r"\\?\UNC\server\share\tools\klens.exe")),
        r"\\server\share\tools\klens.exe"
    );
    assert_eq!(
        clean_binary_path_string(Path::new(r"\\?\C:\Users\dev\klens.exe")),
        r"C:\Users\dev\klens.exe"
    );
    assert!(paths_equivalent(
        r"\\?\UNC\server\share\klens.exe",
        Path::new(r"\\server\share\klens.exe")
    ));
    assert!(paths_equivalent(
        r"\\?\C:\Tools\klens.exe",
        Path::new(r"C:\Tools\klens.exe")
    ));

    let sb = RegSandbox::new("verbatim-display");
    let proj_root = sb.project_root();
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let bin = Path::new(r"\\?\C:\bin\klens.exe");

    let detect_txt = format_detect_text(&detect_environment(&registry, &proj_root, bin));
    let doctor_txt = format_doctor_text(&run_doctor(&registry, &proj_root, bin));
    assert!(
        !detect_txt.contains(r"\\?\"),
        "detect output leaked Windows verbatim prefix:\n{detect_txt}"
    );
    assert!(
        !doctor_txt.contains(r"\\?\"),
        "doctor output leaked Windows verbatim prefix:\n{doctor_txt}"
    );
}

/// Regression 4:
/// A user's own empty hook group inside `.claude/settings.json` (containing zero klens hooks)
/// must NEVER be deleted by `klens init` or `klens detach`/`disconnect`.
#[test]
fn regression_claude_preserves_user_empty_hook_group_untouched() {
    let sb = RegSandbox::new("claude-empty-hook-group");
    let settings_path = sb.project.join(".claude/settings.json");
    fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
    fs::write(
        &settings_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "hooks": {
                "SessionStart": [
                    { "matcher": "user-placeholder", "hooks": [] }
                ]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };

    init_hosts(&registry, HostTarget::Single(HostKind::ClaudeCode), &ctx).unwrap();
    let after_init: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
    let groups_after_init = after_init["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(groups_after_init.len(), 2);
    assert_eq!(groups_after_init[0]["matcher"], "user-placeholder");

    disconnect_host(&registry, HostTarget::Single(HostKind::ClaudeCode), &ctx).unwrap();
    let after_disc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
    let groups_after_disc = after_disc["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(
        groups_after_disc.len(),
        1,
        "user's own empty hook group must remain untouched"
    );
    assert_eq!(groups_after_disc[0]["matcher"], "user-placeholder");
}

/// Regression 5:
/// Fallback memory check in `klens-adapters::doctor` must NOT false-positive STALE on
/// symbol-anchored notes (whose `blake3` is the symbol hash, not the full file hash),
/// and MUST warn on malformed/unclosed frontmatter `.md` files.
#[test]
fn regression_doctor_fallback_handles_symbol_anchor_and_malformed_frontmatter() {
    let sb = RegSandbox::new("doctor-sym-malformed");
    fs::create_dir_all(sb.project.join("src")).unwrap();
    fs::write(sb.project.join("src/world.rs"), "pub fn save_chunk() {}\n").unwrap();
    fs::create_dir_all(sb.project.join(".klens/memory")).unwrap();

    // Symbol-anchored note with a symbol-only hash (different from whole-file blake3):
    // fallback doctor must keep it Ok (no false STALE).
    fs::write(
        sb.project.join(".klens/memory/sym-note.md"),
        concat!(
            "---\n",
            "schema_version: 1\n",
            "id: sym-note\n",
            "title: Symbol anchored\n",
            "status: active\n",
            "anchors:\n",
            "  - path: src/world.rs\n",
            "    symbol: fn save_chunk\n",
            "    blake3: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "---\n",
            "Body.\n",
        ),
    )
    .unwrap();

    let proj_root = sb.project_root();
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let bin = Path::new(r"C:\bin\klens.exe");
    let doc_ok = run_doctor(&registry, &proj_root, bin);
    let mem_ok = doc_ok
        .checks
        .iter()
        .find(|c| c.name.contains("Memory staleness"))
        .unwrap();
    assert_eq!(
        mem_ok.severity,
        CheckSeverity::Ok,
        "symbol-anchored note must not trigger false STALE in fallback doctor: {}",
        mem_ok.message
    );

    // Add a malformed note with unclosed frontmatter -> MUST emit Warning!
    fs::write(
        sb.project.join(".klens/memory/broken.md"),
        "---\nid: broken\nno closing delimiter\n",
    )
    .unwrap();
    let doc_warn = run_doctor(&registry, &proj_root, bin);
    let mem_warn = doc_warn
        .checks
        .iter()
        .find(|c| c.name.contains("Memory staleness"))
        .unwrap();
    assert_eq!(
        mem_warn.severity,
        CheckSeverity::Warning,
        "malformed frontmatter note must trigger Warning in doctor: {}",
        mem_warn.message
    );
    assert!(mem_warn.message.contains("broken.md"));
}

fn find_backups_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".klens-backup-") && n.ends_with(".bak"))
        })
        .collect();
    out.sort();
    out
}

/// Regression 6:
/// `detach --purge` cleans project-local managed `disconnect` backups (`.mcp.json`, `CLAUDE.md`,
/// `AGENTS.md`, `KLENS.md`, `.claude/settings.json`) and prunes empty `.claude/` directories,
/// while honoring `dry_run == true` (zero mutations), preserving normal `detach` backups,
/// preserving non-managed backups, and NEVER touching global backups (`~/.gemini/`, `~/.claude.json`, `~/.codex/`).
#[test]
fn regression_detach_purge_cleans_project_backups_and_empty_claude_preserving_global_backups() {
    let sb = RegSandbox::new("detach-purge-backups");
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let bin = PathBuf::from(r"C:\bin\klens.exe");
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: bin.clone(),
        dry_run: false,
    };

    // Seed global `~/.claude.json` with `klens` + project `CLAUDE.md` marked block + unrelated backup.
    fs::write(
        sb.home.join(".claude.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "klens": { "command": r"C:\bin\klens.exe", "args": ["mcp"] }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        sb.project.join("CLAUDE.md"),
        "<!-- klens:start -->\nmanaged\n<!-- klens:end -->\n",
    )
    .unwrap();
    let unrelated_bak = sb
        .project
        .join("README.md.klens-backup-20261124-000000.bak");
    fs::write(&unrelated_bak, "keep unrelated backup").unwrap();

    // Install claude-code, codex, generic, and antigravity.
    init_hosts(&registry, HostTarget::Single(HostKind::ClaudeCode), &ctx).unwrap();
    init_hosts(&registry, HostTarget::Single(HostKind::Codex), &ctx).unwrap();
    init_hosts(&registry, HostTarget::Single(HostKind::Generic), &ctx).unwrap();
    init_hosts(&registry, HostTarget::Single(HostKind::Antigravity), &ctx).unwrap();

    // Disconnect all hosts so timestamped backups are created in both project and global dirs.
    disconnect_host(&registry, HostTarget::All, &ctx).unwrap();

    let proj_root_baks = find_backups_in(&sb.project);
    let claude_baks = find_backups_in(&sb.project.join(".claude"));
    let global_gemini_baks = find_backups_in(&sb.home.join(".gemini/config"));
    let global_claude_baks = find_backups_in(&sb.home);
    let global_codex_baks = find_backups_in(&sb.home.join(".codex"));

    // 4 managed root backups + 1 unrelated backup = 5 in project root; 1 in `.claude/`.
    assert_eq!(proj_root_baks.len(), 5, "root backups: {proj_root_baks:?}");
    assert_eq!(claude_baks.len(), 1, "claude backups: {claude_baks:?}");
    assert_eq!(global_gemini_baks.len(), 1);
    assert_eq!(global_claude_baks.len(), 1);
    assert_eq!(global_codex_baks.len(), 1);

    let proj_root = sb.project_root();

    // 1. Normal `detach` (purge == false) MUST preserve all project backups.
    let normal_rep = detach_project(&registry, &proj_root, false, false).unwrap();
    assert!(!normal_rep.purge);
    assert_eq!(find_backups_in(&sb.project).len(), 5);
    assert_eq!(find_backups_in(&sb.project.join(".claude")).len(), 1);

    // 2. `detach --purge --dry-run` MUST delete 0 files/dirs and report planned removals cleanly.
    let dry_rep = detach_project(&registry, &proj_root, true, true).unwrap();
    assert!(dry_rep.purge);
    assert!(dry_rep.dry_run);
    assert!(!dry_rep.changed);
    assert_eq!(find_backups_in(&sb.project).len(), 5);
    assert_eq!(find_backups_in(&sb.project.join(".claude")).len(), 1);
    assert!(sb.project.join(".claude").is_dir());
    assert!(
        dry_rep
            .notes
            .iter()
            .any(|n| n.starts_with("[dry-run] would remove managed backup"))
    );
    assert!(
        dry_rep
            .notes
            .iter()
            .any(|n| n.starts_with("[dry-run] would remove empty directory")
                && n.ends_with(".claude"))
    );
    assert!(dry_rep.files_touched.iter().any(|p| p.ends_with(".claude")));

    // Verify deterministic sorted order for planned managed backups in `files_touched`.
    let planned_baks: Vec<&PathBuf> = dry_rep
        .files_touched
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".klens-backup-"))
        })
        .collect();
    assert_eq!(planned_baks.len(), 5, "planned backups: {planned_baks:?}");
    let mut sorted_planned = planned_baks.clone();
    sorted_planned.sort();
    assert_eq!(planned_baks, sorted_planned);

    // 3. Real `detach --purge` removes all 5 managed project backups and empty `.claude/`,
    //    while preserving unrelated project backup and ALL global backups!
    let purge_rep = detach_project(&registry, &proj_root, true, false).unwrap();
    assert!(purge_rep.purge);
    assert!(purge_rep.changed);

    // Only the unrelated README backup remains in project root; `.claude/` is completely gone.
    assert_eq!(find_backups_in(&sb.project), vec![unrelated_bak.clone()]);
    assert!(unrelated_bak.is_file());
    assert!(!sb.project.join(".claude").exists());

    // Global backups MUST remain 100% intact.
    assert_eq!(
        find_backups_in(&sb.home.join(".gemini/config")),
        global_gemini_baks
    );
    assert_eq!(find_backups_in(&sb.home), global_claude_baks);
    assert_eq!(find_backups_in(&sb.home.join(".codex")), global_codex_baks);
}

/// Regression 7:
/// When the user has their own file under `.claude/` (e.g. `.claude/custom-user-note.txt`),
/// `detach --purge` removes only `settings.json.klens-backup-*.bak` and empty `.claude/skills`,
/// preserving `.claude/` and the user's file 100%. Also verifies `remove_empty_parents` cleans
/// empty `.claude/skills` even when `.claude/skills/karasu-lens` was already deleted earlier.
#[test]
fn regression_detach_purge_preserves_user_claude_files_and_cleans_empty_skills_parent() {
    let sb = RegSandbox::new("detach-purge-user-claude");
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };

    init_hosts(&registry, HostTarget::Single(HostKind::ClaudeCode), &ctx).unwrap();

    // User adds their own file inside `.claude/`.
    let user_note = sb.project.join(".claude/custom-user-note.txt");
    fs::write(&user_note, "user custom note — never delete").unwrap();

    disconnect_host(&registry, HostTarget::Single(HostKind::ClaudeCode), &ctx).unwrap();
    assert_eq!(find_backups_in(&sb.project.join(".claude")).len(), 1);

    // Simulate leftover empty `.claude/skills` where `.claude/skills/karasu-lens` is already gone.
    let empty_skills = sb.project.join(".claude/skills");
    fs::create_dir_all(&empty_skills).unwrap();
    assert!(!empty_skills.join("karasu-lens").exists());

    let proj_root = sb.project_root();
    let rep = detach_project(&registry, &proj_root, true, false).unwrap();
    assert!(rep.changed);

    // Backup and empty `.claude/skills` are removed, while `.claude/` and user note remain intact.
    assert!(find_backups_in(&sb.project.join(".claude")).is_empty());
    assert!(!empty_skills.exists());
    assert!(sb.project.join(".claude").is_dir());
    assert_eq!(
        fs::read_to_string(&user_note).unwrap(),
        "user custom note — never delete"
    );
}

/// Regression 8a:
/// `init --host claude-code` (WITHOUT prior `disconnect`) -> `detach --purge --dry-run`:
/// deletes 0 files on disk while accurately predicting that `.claude` (and its skill dirs)
/// will be removed; subsequent real `detach --purge` removes `.claude` completely.
#[test]
fn regression_init_then_detach_purge_dry_run_predicts_empty_claude_removal() {
    let sb = RegSandbox::new("init-detach-dry-empty-claude");
    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };

    init_hosts(&registry, HostTarget::Single(HostKind::ClaudeCode), &ctx).unwrap();
    let claude_dir = sb.project.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    assert!(settings_path.is_file());
    assert!(claude_dir.join("skills/karasu-lens").is_dir());

    let proj_root = sb.project_root();
    let canonical_claude_dir = proj_root.root().join(".claude");
    let dry_rep = detach_project(&registry, &proj_root, true, true).unwrap();
    assert!(dry_rep.purge);
    assert!(dry_rep.dry_run);
    assert!(!dry_rep.changed);

    // Zero mutations on disk during `--dry-run`.
    assert!(settings_path.is_file());
    assert!(claude_dir.join("skills/karasu-lens").is_dir());
    assert!(sb.project.join(".mcp.json").is_file());

    // Report must accurately predict `.claude` directory removal.
    assert!(
        dry_rep
            .files_touched
            .iter()
            .any(|p| p == &canonical_claude_dir),
        "expected `.claude` in dry-run files_touched: {:?}",
        dry_rep.files_touched
    );
    assert!(
        dry_rep.notes.iter().any(|n| {
            n.starts_with("[dry-run] would remove empty directory") && n.ends_with(".claude")
        }),
        "expected dry-run note for `.claude` removal: {:?}",
        dry_rep.notes
    );

    // Real `detach --purge` deletes `.claude` completely.
    let real_rep = detach_project(&registry, &proj_root, true, false).unwrap();
    assert!(real_rep.changed);
    assert!(!claude_dir.exists());
    assert!(!sb.project.join(".mcp.json").exists());
}

/// Regression 8b:
/// When `.claude/settings.json` contains user keys (e.g. `"theme": "dark"`),
/// `init --host claude-code` -> `detach --purge --dry-run` MUST NOT claim that `.claude`
/// will be deleted, and real `detach --purge` preserves `.claude/settings.json` with user keys.
#[test]
fn regression_init_then_detach_purge_dry_run_never_claims_claude_removal_with_user_settings() {
    let sb = RegSandbox::new("init-detach-dry-user-settings");
    let claude_dir = sb.project.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(&settings_path, "{\n  \"theme\": \"dark\"\n}\n").unwrap();

    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let ctx = AdapterContext {
        project_root: sb.project.clone(),
        binary_path: PathBuf::from(r"C:\bin\klens.exe"),
        dry_run: false,
    };

    init_hosts(&registry, HostTarget::Single(HostKind::ClaudeCode), &ctx).unwrap();

    let proj_root = sb.project_root();
    let canonical_claude_dir = proj_root.root().join(".claude");
    let dry_rep = detach_project(&registry, &proj_root, true, true).unwrap();
    assert!(dry_rep.purge);
    assert!(dry_rep.dry_run);
    assert!(!dry_rep.changed);

    // Fail-closed: `.claude` MUST NOT be reported for deletion because `settings.json` has `"theme": "dark"`.
    assert!(
        !dry_rep.files_touched.iter().any(|p| {
            p == &canonical_claude_dir
                || p == &claude_dir
                || paths_equivalent(&p.to_string_lossy(), &claude_dir)
        }),
        "dry-run must NOT claim `.claude` will be removed when user keys exist in settings.json: {:?}",
        dry_rep.files_touched
    );
    assert!(
        !dry_rep.notes.iter().any(|n| {
            n.starts_with("[dry-run] would remove empty directory") && n.ends_with(".claude")
        }),
        "dry-run notes must NOT claim `.claude` will be removed: {:?}",
        dry_rep.notes
    );

    // Real `detach --purge` strips only klens hooks and preserves `.claude/settings.json` with `"theme": "dark"`.
    let real_rep = detach_project(&registry, &proj_root, true, false).unwrap();
    assert!(real_rep.changed);
    assert!(claude_dir.is_dir());
    assert!(settings_path.is_file());
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
    assert_eq!(parsed["theme"], "dark");
    assert!(parsed.get("hooks").is_none());
}
