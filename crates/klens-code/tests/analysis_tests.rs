use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_code::{
    BoundaryDirection, CodeError, CodeIndex, DependencyEcosystem, DiffAlertKind, FindMatchKind,
    ImpactStatus, MAX_INDEXABLE_BYTES, TrafficLight, analyze_impact, build_code_graph,
    build_project_map, build_project_map_focused, collect_dependencies, find_in_workspace,
    format_diff_check_text, format_map_text, run_diff_check, run_health_check,
};
use klens_core::{
    CheckSeverity, EdgeConfidence, EdgeRelation, OmissionKind, ProjectConfig, ProjectRoot, RelPath,
    TrustLevel,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "klens-p1b-test-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.path.join(rel);
        if let Some(p) = full.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(full, content).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_git_checked(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().expect("git command failed to spawn");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn deps_collects_cargo_npm_python_and_go_manifests_deterministically() {
    let proj = TempDir::new("deps");
    let cache = TempDir::new("deps-cache");

    proj.write(
        "Cargo.toml",
        concat!(
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n",
            "[dependencies]\nserde = \"1.0.215\"\n",
            "local-lib = { path = \"./local\" }\n",
        ),
    );
    proj.write(
        "web/package.json",
        r#"{"dependencies":{"react":"^19.1.0"},"devDependencies":{"vitest":"2.1.4"}}"#,
    );
    proj.write(
        "py/pyproject.toml",
        "[project]\nname = \"pydemo\"\ndependencies = [\"httpx>=0.27.0\"]\n",
    );
    proj.write(
        "go/go.mod",
        "module example.com/demo\n\ngo 1.23\n\nrequire github.com/pkg/errors v0.9.1\n",
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let inv = collect_dependencies(&index).unwrap();

    assert_eq!(inv.manifests_scanned.len(), 4);
    assert!(inv.dependencies.iter().any(|d| {
        d.ecosystem == DependencyEcosystem::Cargo
            && d.name == "serde"
            && d.version == "1.0.215"
            && d.is_external
    }));
    assert!(inv.dependencies.iter().any(|d| {
        d.ecosystem == DependencyEcosystem::Cargo && d.name == "local-lib" && !d.is_external
    }));
    assert!(inv.dependencies.iter().any(|d| {
        d.ecosystem == DependencyEcosystem::Npm && d.name == "react" && d.version == "^19.1.0"
    }));
    assert!(inv.dependencies.iter().any(|d| {
        d.ecosystem == DependencyEcosystem::Python && d.name == "httpx" && d.version == ">=0.27.0"
    }));
    assert!(inv.dependencies.iter().any(|d| {
        d.ecosystem == DependencyEcosystem::Go
            && d.name == "github.com/pkg/errors"
            && d.version == "v0.9.1"
    }));
}

#[test]
fn pagerank_map_ranks_hub_highest_marks_protected_and_reports_budget_omissions() {
    let proj = TempDir::new("map-pagerank");
    let cache = TempDir::new("map-pagerank-cache");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\n",
    );
    proj.write(
        "src/core_hub.rs",
        "pub struct CoreState;\npub fn compute_core_value() -> usize { 42 }\n",
    );
    proj.write(
        "src/a.rs",
        "use crate::core_hub::compute_core_value;\npub fn run_a() -> usize { compute_core_value() }\n",
    );
    proj.write(
        "src/b.rs",
        "use crate::core_hub::compute_core_value;\npub fn run_b() -> usize { compute_core_value() }\n",
    );
    proj.write(
        "src/c.rs",
        "use crate::core_hub::compute_core_value;\npub fn run_c() -> usize { compute_core_value() }\n",
    );

    let cfg = ProjectConfig {
        protected_paths: vec!["src/core_hub.rs".into()],
        ..ProjectConfig::default()
    };
    cfg.save_atomic(&proj.path().join(".klens").join("config.toml"))
        .unwrap();

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    let full_map = build_project_map(&mut index, 4000).unwrap();
    assert_eq!(full_map.trust, TrustLevel::VerifiedAst);
    assert_eq!(full_map.data.protected_files, vec!["src/core_hub.rs"]);
    assert_eq!(
        full_map.data.files[0].path, "src/core_hub.rs",
        "hub imported by 3 files must rank #1 via PageRank"
    );
    assert!(full_map.data.files[0].is_protected);
    assert!(full_map.data.dependencies.iter().any(|d| d.name == "serde"));

    // Tight budget must explicitly report omissions (Constitution Article 2).
    let tight_map = build_project_map(&mut index, 45).unwrap();
    assert!(tight_map.data.included_files < tight_map.data.total_files);
    assert!(
        tight_map
            .omissions
            .iter()
            .any(|o| o.kind == OmissionKind::Items),
        "expected explicit omitted files omission, got {:?}",
        tight_map.omissions
    );
}

#[test]
fn graph_detects_cycles_in_rust_ts_python_and_god_nodes_over_800_lines() {
    let proj = TempDir::new("cycles-god");
    let cache = TempDir::new("cycles-god-cache");

    // Rust cycle: src/a.rs <-> src/b.rs
    proj.write("src/a.rs", "use crate::b;\npub fn fn_a() {}\n");
    proj.write("src/b.rs", "use crate::a;\npub fn fn_b() {}\n");

    // TypeScript cycle: web/x.ts <-> web/y.ts
    proj.write(
        "web/x.ts",
        "import { fnY } from './y';\nexport function fnX() { return fnY(); }\n",
    );
    proj.write(
        "web/y.ts",
        "import { fnX } from './x';\nexport function fnY() { return fnX(); }\n",
    );

    // >800 line God Node file
    let mut huge = String::new();
    for i in 1..=820 {
        huge.push_str(&format!("pub const LINE_{i:04}: usize = {i};\n"));
    }
    proj.write("src/giant_god.rs", &huge);

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    let graph_env = build_code_graph(&mut index).unwrap();
    let g = &graph_env.data;

    assert!(
        g.cycles.contains(&vec![
            "file:src/a.rs".to_string(),
            "file:src/b.rs".to_string(),
            "file:src/a.rs".to_string(),
        ]),
        "expected Rust cycle a.rs -> b.rs -> a.rs, got: {:?}",
        g.cycles
    );
    assert!(
        g.cycles.contains(&vec![
            "file:web/x.ts".to_string(),
            "file:web/y.ts".to_string(),
            "file:web/x.ts".to_string(),
        ]),
        "expected TS cycle x.ts -> y.ts -> x.ts, got: {:?}",
        g.cycles
    );
    assert!(
        g.god_nodes.contains(&"src/giant_god.rs".to_string()),
        "expected >800 line file in god_nodes, got: {:?}",
        g.god_nodes
    );
    let god_node = g
        .nodes
        .iter()
        .find(|n| n.path == "src/giant_god.rs")
        .unwrap();
    assert!(god_node.is_god_node);
    assert_eq!(god_node.lines, 820);

    // Health check must report BOTH god_nodes and cycles as RED.
    let health_env = run_health_check(&mut index).unwrap();
    assert_eq!(health_env.data.checks.len(), 5);
    assert_eq!(health_env.data.overall, TrafficLight::Red);
    let god_chk = health_env
        .data
        .checks
        .iter()
        .find(|c| c.id == "god_nodes")
        .unwrap();
    assert_eq!(god_chk.light, TrafficLight::Red);
    let cyc_chk = health_env
        .data
        .checks
        .iter()
        .find(|c| c.id == "cycles")
        .unwrap();
    assert_eq!(cyc_chk.light, TrafficLight::Red);
}

#[test]
fn impact_tracks_direct_transitive_and_fails_closed_on_ambiguous_symbol() {
    let proj = TempDir::new("impact");
    let cache = TempDir::new("impact-cache");

    proj.write(
        "src/core.rs",
        "pub fn calculate_gravity(mass: f64) -> f64 {\n    mass * 9.81\n}\n",
    );
    proj.write(
        "src/physics.rs",
        "use crate::core::calculate_gravity;\npub fn step_body() -> f64 {\n    calculate_gravity(2.0)\n}\n",
    );
    proj.write(
        "src/game.rs",
        "use crate::physics::step_body;\npub fn tick() -> f64 {\n    step_body()\n}\n",
    );
    proj.write(
        "src/models.rs",
        concat!(
            "pub struct Alpha;\n",
            "impl Alpha {\n    pub fn duplicate_ctor() -> Self { Self }\n}\n",
            "pub struct Beta;\n",
            "impl Beta {\n    pub fn duplicate_ctor() -> Self { Self }\n}\n",
        ),
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    // Symbol impact on `calculate_gravity` must find direct import/call in physics.rs AND transitive game.rs.
    let sym_imp = analyze_impact(&mut index, "calculate_gravity").unwrap();
    assert_eq!(sym_imp.data.status, ImpactStatus::Ok);
    assert_eq!(sym_imp.data.target_path.as_deref(), Some("src/core.rs"));
    assert!(sym_imp.data.hits.iter().any(|h| {
        h.path == "src/physics.rs" && h.distance == 1 && h.confidence == EdgeConfidence::Extracted
    }));
    assert!(sym_imp.data.hits.iter().any(|h| {
        h.path == "src/physics.rs"
            && h.distance == 1
            && h.confidence == EdgeConfidence::Inferred
            && h.line == Some(3)
    }));
    assert!(sym_imp.data.hits.iter().any(|h| {
        h.path == "src/game.rs" && h.distance == 2 && h.confidence == EdgeConfidence::Extracted
    }));

    // Ambiguous symbol `duplicate_ctor` MUST fail closed with `AMBIGUOUS_TARGET` (Constitution Article 3).
    let amb = analyze_impact(&mut index, "duplicate_ctor").unwrap();
    assert_eq!(amb.data.status, ImpactStatus::AmbiguousTarget);
    assert_eq!(amb.data.candidates.len(), 2);
}

#[test]
fn find_respects_gitignore_dedups_lines_and_handles_special_error_queries() {
    let proj = TempDir::new("find");
    let cache = TempDir::new("find-cache");

    proj.write(".gitignore", "custom_ignored/\n*.generated.rs\n");
    proj.write(
        "src/parser.rs",
        "pub fn parse_special_token() -> &'static str {\n    \"error[E0308]: mismatched types in parse_special_token\"\n}\n",
    );
    proj.write("target/debug/out.rs", "pub fn parse_special_token() {}\n");
    proj.write(
        "node_modules/lib/index.js",
        "function parse_special_token() {}\n",
    );
    proj.write(
        "custom_ignored/skip.rs",
        "pub fn parse_special_token() {}\n",
    );
    proj.write(
        "src/noise.generated.rs",
        "pub fn parse_special_token() {}\n",
    );
    proj.write(".env", "SECRET=parse_special_token\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    let res = find_in_workspace(&mut index, "parse_special_token", 50).unwrap();
    assert!(!res.data.matches.is_empty());
    for hit in &res.data.matches {
        assert_eq!(
            hit.path, "src/parser.rs",
            "ignored or sensitive path leaked into find results: {}",
            hit.path
        );
    }
    // Line 1 is deduplicated into a single Symbol hit (not duplicated as Symbol + Text).
    let line1_hits: Vec<_> = res.data.matches.iter().filter(|m| m.line == 1).collect();
    assert_eq!(line1_hits.len(), 1);
    assert_eq!(line1_hits[0].match_kind, FindMatchKind::Symbol);

    // Special punctuation error message query must work without FTS5 syntax error.
    let err_search = find_in_workspace(&mut index, "error[E0308]: mismatched types", 10).unwrap();
    assert_eq!(err_search.data.matches.len(), 1);
    assert_eq!(err_search.data.matches[0].path, "src/parser.rs");
    assert_eq!(err_search.data.matches[0].line, 2);
}

#[test]
fn diff_check_raises_red_alerts_for_protected_paths_new_deps_and_secret_leaks() {
    let proj = TempDir::new("diff-check");
    let cache = TempDir::new("diff-check-cache");

    proj.write(".gitignore", ".env\ntarget/\n");
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
    );
    proj.write(
        "src/locked.rs",
        "pub fn critical_guard(x: i32) -> i32 {\n    x + 1\n}\n",
    );
    proj.write(
        "src/caller.rs",
        "use crate::locked::critical_guard;\npub fn invoke() -> i32 {\n    critical_guard(5)\n}\n",
    );
    let cfg = ProjectConfig {
        protected_paths: vec!["src/locked.rs".into()],
        ..ProjectConfig::default()
    };
    cfg.save_atomic(&proj.path().join(".klens").join("config.toml"))
        .unwrap();

    run_git_checked(proj.path(), &["init"]);
    run_git_checked(proj.path(), &["config", "user.email", "test@klens.local"]);
    run_git_checked(proj.path(), &["config", "user.name", "Klens Test"]);
    run_git_checked(proj.path(), &["add", "."]);
    run_git_checked(proj.path(), &["commit", "-m", "initial"]);

    // Clean state: diff-check is OK, health protected_paths is GREEN.
    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let clean_diff = run_diff_check(&mut index).unwrap();
    assert_eq!(clean_diff.data.overall_severity, CheckSeverity::Ok);
    assert!(clean_diff.data.alerts.is_empty());

    // Now introduce 3 violations:
    // 1. Edit locked `src/locked.rs`
    proj.write(
        "src/locked.rs",
        "pub fn critical_guard(x: i32) -> i32 {\n    x + 99\n}\n",
    );
    // 2. Add new external dependency to `Cargo.toml`
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\nreqwest = \"0.12.9\"\n",
    );
    // 3. Leak a synthetic GitHub token in `src/caller.rs`
    let synthetic_gh = format!("ghp_{}", "abcdef1234567890abcdef1234567890abcd");
    proj.write(
        "src/caller.rs",
        &format!(
            "use crate::locked::critical_guard;\npub fn invoke() -> i32 {{\n    let _t = \"{synthetic_gh}\";\n    critical_guard(5)\n}}\n"
        ),
    );

    let dirty = run_diff_check(&mut index).unwrap();
    assert_eq!(dirty.data.overall_severity, CheckSeverity::Error);
    assert_eq!(dirty.data.protected_violations, vec!["src/locked.rs"]);
    assert!(dirty.data.alerts.iter().any(|a| {
        a.kind == DiffAlertKind::ProtectedPathViolation
            && a.severity == CheckSeverity::Error
            && a.path == "src/locked.rs"
    }));
    assert!(
        dirty
            .data
            .added_dependencies
            .iter()
            .any(|d| { d.name == "reqwest" && d.version == "0.12.9" })
    );
    assert!(dirty.data.alerts.iter().any(|a| {
        a.kind == DiffAlertKind::NewExternalDependency
            && a.severity == CheckSeverity::Error
            && a.path == "Cargo.toml"
    }));
    assert_eq!(dirty.data.secret_leaks.len(), 1);
    assert!(dirty.redactions_count >= 1);

    // Ensure raw secret NEVER appears in serialized JSON.
    let serialized = dirty.to_deterministic_json().unwrap();
    assert!(!serialized.contains(&synthetic_gh));

    // Verify AST symbol mapping for `src/locked.rs`.
    let locked_summary = dirty
        .data
        .changed_files
        .iter()
        .find(|f| f.path == "src/locked.rs")
        .unwrap();
    assert!(locked_summary.is_protected);
    assert!(
        locked_summary
            .changed_symbols
            .iter()
            .any(|s| s.qualified_name == "fn critical_guard")
    );

    // Verify health also flags `protected_paths` RED and `.env` `.gitignore` GREEN.
    let health = run_health_check(&mut index).unwrap();
    let prot_chk = health
        .data
        .checks
        .iter()
        .find(|c| c.id == "protected_paths")
        .unwrap();
    assert_eq!(prot_chk.light, TrafficLight::Red);
    let env_chk = health
        .data
        .checks
        .iter()
        .find(|c| c.id == "env_gitignore")
        .unwrap();
    assert_eq!(env_chk.light, TrafficLight::Green);
}

#[test]
fn health_checks_env_exposure_and_last_test_run_metadata() {
    let proj = TempDir::new("health-env");
    let cache = TempDir::new("health-env-cache");

    proj.write("src/lib.rs", "pub fn ok() {}\n");
    // `.env` exists without `.gitignore` -> MUST be RED!
    proj.write(".env", "DB_PASS=secret\n");
    // Recorded passing test run in `.klens/runs/` -> MUST be GREEN!
    proj.write(
        ".klens/runs/20261122-213000-a1b2.meta.json",
        r#"{"schema_version":1,"run_id":"20261122-213000-a1b2","command":"cargo test --workspace","exit_code":0}"#,
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    let health1 = run_health_check(&mut index).unwrap();
    assert_eq!(health1.data.checks.len(), 5);
    assert_eq!(
        health1
            .data
            .checks
            .iter()
            .find(|c| c.id == "env_gitignore")
            .unwrap()
            .light,
        TrafficLight::Red
    );
    assert_eq!(
        health1
            .data
            .checks
            .iter()
            .find(|c| c.id == "last_test_status")
            .unwrap()
            .light,
        TrafficLight::Green
    );

    // Add `.env` to `.gitignore` and add a newer failing test run.
    proj.write(".gitignore", ".env\n");
    proj.write(
        ".klens/runs/20261122-220000-b3c4.meta.json",
        r#"{"schema_version":1,"run_id":"20261122-220000-b3c4","command":"cargo test --workspace","exit_code":101}"#,
    );

    let health2 = run_health_check(&mut index).unwrap();
    assert_eq!(
        health2
            .data
            .checks
            .iter()
            .find(|c| c.id == "env_gitignore")
            .unwrap()
            .light,
        TrafficLight::Green
    );
    assert_eq!(
        health2
            .data
            .checks
            .iter()
            .find(|c| c.id == "last_test_status")
            .unwrap()
            .light,
        TrafficLight::Red
    );
}

#[test]
fn find_catches_camelcase_midword_and_prefix_even_when_exact_token_exists_elsewhere() {
    let proj = TempDir::new("find-camelcase");
    let cache = TempDir::new("find-camelcase-cache");

    // File 1 has exact token `Timeout` (previously short-circuited prefix/substring lookup!).
    proj.write("src/exact.rs", "// Timeout error definition\n");
    // File 2 has camelCase mid-word `handleTimeout` (not a token prefix in FTS5 unicode61).
    proj.write(
        "web/timer.ts",
        "export function handleTimeout(ms: number) {\n  return handleTimeout(ms);\n}\n",
    );
    // File 3 has prefix match `timeoutDuration`.
    proj.write("src/prefix.rs", "pub const timeoutDuration: u64 = 5000;\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    let res = find_in_workspace(&mut index, "Timeout", 50).unwrap();
    let matched_paths: Vec<&str> = res.data.matches.iter().map(|m| m.path.as_str()).collect();
    assert!(
        matched_paths.contains(&"src/exact.rs"),
        "expected exact match in src/exact.rs, got: {matched_paths:?}"
    );
    assert!(
        matched_paths.contains(&"web/timer.ts"),
        "expected camelCase mid-word match `handleTimeout` in web/timer.ts, got: {matched_paths:?}"
    );
    assert!(
        matched_paths.contains(&"src/prefix.rs"),
        "expected prefix match `timeoutDuration` in src/prefix.rs, got: {matched_paths:?}"
    );
}

#[test]
fn graph_and_impact_detect_call_after_rust_raw_string_with_hash() {
    let proj = TempDir::new("rust-raw-str");
    let cache = TempDir::new("rust-raw-str-cache");

    proj.write(
        "src/target.rs",
        "pub fn after_raw_target() -> usize {\n    99\n}\n",
    );
    proj.write(
        "src/caller.rs",
        concat!(
            "use crate::target::after_raw_target;\n",
            "pub fn invoke_after_raw() -> usize {\n",
            "    let _s = r#\"hello # not a comment\"#; after_raw_target()\n",
            "}\n",
        ),
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    let graph_env = build_code_graph(&mut index).unwrap();
    assert!(
        graph_env.data.edges.iter().any(|e| {
            e.from == "sym:src/caller.rs#fn invoke_after_raw"
                && e.to == "sym:src/target.rs#fn after_raw_target"
                && e.relation == EdgeRelation::Calls
                && e.confidence == EdgeConfidence::Inferred
        }),
        "expected INFERRED Calls edge after Rust r#\"...\"# raw string, got: {:?}",
        graph_env.data.edges
    );

    let impact_env = analyze_impact(&mut index, "after_raw_target").unwrap();
    assert!(
        impact_env.data.hits.iter().any(|h| {
            h.path == "src/caller.rs"
                && h.line == Some(3)
                && h.relation == EdgeRelation::Calls
                && h.confidence == EdgeConfidence::Inferred
        }),
        "expected impact hit on L3 after Rust r#\"...\"#, got: {:?}",
        impact_env.data.hits
    );
}

#[test]
fn diff_check_skips_oversized_untracked_file_and_formats_actual_envelope_trust() {
    let proj = TempDir::new("diff-oversized");
    let cache = TempDir::new("diff-oversized-cache");

    proj.write("src/lib.rs", "pub fn ok() {}\n");

    // Non-git repo returns TrustLevel::VerifiedRaw -> formatter MUST print `[VERIFIED_RAW]`.
    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let non_git = run_diff_check(&mut index).unwrap();
    assert_eq!(non_git.trust, TrustLevel::VerifiedRaw);
    let formatted = format_diff_check_text(&non_git);
    assert!(
        formatted.starts_with("[VERIFIED_RAW] "),
        "formatter must reflect actual envelope.trust, got:\n{formatted}"
    );

    // Initialize git repo and create an untracked file strictly larger than MAX_INDEXABLE_BYTES.
    run_git_checked(proj.path(), &["init"]);
    run_git_checked(proj.path(), &["config", "user.email", "t@klens.local"]);
    run_git_checked(proj.path(), &["config", "user.name", "Test"]);
    run_git_checked(proj.path(), &["add", "src/lib.rs"]);
    run_git_checked(proj.path(), &["commit", "-m", "init"]);

    let huge = vec![b'a'; (MAX_INDEXABLE_BYTES as usize) + 128];
    fs::write(proj.path().join("huge_untracked.txt"), huge).unwrap();

    let dirty = run_diff_check(&mut index).unwrap();
    assert!(
        dirty
            .warnings
            .iter()
            .any(|w| w.contains("huge_untracked.txt") && w.contains("maximum indexable size")),
        "expected oversized untracked warning, got: {:?}",
        dirty.warnings
    );
}

#[test]
fn health_god_nodes_distinguishes_oversize_test_files_yellow_from_production_files_red() {
    let proj = TempDir::new("health-god-prod-vs-test");
    let cache = TempDir::new("health-god-prod-vs-test-cache");

    proj.write("src/lib.rs", "pub fn small_fn() -> usize { 1 }\n");

    let mut big_lines = String::new();
    for i in 1..=820 {
        big_lines.push_str(&format!("pub const ROW_{i:04}: usize = {i};\n"));
    }
    proj.write("tests/big_integration_tests.rs", &big_lines);

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    // Only a test file exceeds 800 lines -> YELLOW with honest production vs test summary.
    let health_test_only = run_health_check(&mut index).unwrap();
    let god_test_only = health_test_only
        .data
        .checks
        .iter()
        .find(|c| c.id == "god_nodes")
        .unwrap();
    assert_eq!(
        god_test_only.light,
        TrafficLight::Yellow,
        "expected YELLOW when only test files exceed 800 lines, got: {god_test_only:?}"
    );
    assert!(
        god_test_only
            .summary
            .contains("0 production files > 800 lines"),
        "expected honest 0 production files summary, got: {}",
        god_test_only.summary
    );
    assert!(
        god_test_only.summary.contains("1 test file(s) > 800 lines"),
        "expected 1 test file(s) count in summary, got: {}",
        god_test_only.summary
    );
    assert!(
        god_test_only
            .details
            .iter()
            .any(|d| d.contains("tests/big_integration_tests.rs")),
        "expected test file listed in details, got: {:?}",
        god_test_only.details
    );

    // Adding a production file > 800 lines must flip `god_nodes` to RED.
    proj.write("src/big_prod.rs", &big_lines);
    let health_with_prod = run_health_check(&mut index).unwrap();
    let god_with_prod = health_with_prod
        .data
        .checks
        .iter()
        .find(|c| c.id == "god_nodes")
        .unwrap();
    assert_eq!(
        god_with_prod.light,
        TrafficLight::Red,
        "expected RED once a production file exceeds 800 lines, got: {god_with_prod:?}"
    );
    assert!(
        god_with_prod
            .details
            .iter()
            .any(|d| d.contains("src/big_prod.rs")),
        "expected production file listed in details, got: {:?}",
        god_with_prod.details
    );
}

#[test]
fn focused_project_map_scopes_budget_tracks_boundary_links_and_fails_closed() {
    let proj = TempDir::new("map-focused");
    let cache = TempDir::new("map-focused-cache");

    proj.write(
        "shared/ext.ts",
        "export function extHelper(v: number): number { return v * 2; }\n",
    );
    proj.write(
        "subpkg/core.ts",
        "export function subCore(v: number): number { return v + 10; }\n",
    );
    proj.write(
        "subpkg/bridge.ts",
        "import { extHelper } from '../shared/ext';\nexport function bridge(v: number): number { return extHelper(v); }\n",
    );
    proj.write(
        "app/consumer.ts",
        "import { subCore } from '../subpkg/core';\nexport function consume(): number { return subCore(1); }\n",
    );
    // Add many unrelated files outside `subpkg` so a focused budget proves isolation.
    for i in 0..12 {
        proj.write(
            &format!("other/mod_{i:02}.ts"),
            &format!(
                "export function otherFnA_{i:02}(x: number): number {{ return x + {i}; }}\nexport function otherFnB_{i:02}(x: number): number {{ return x * 2; }}\n"
            ),
        );
    }

    let cfg = ProjectConfig {
        protected_paths: vec!["subpkg/core.ts".into(), "shared/ext.ts".into()],
        ..ProjectConfig::default()
    };
    cfg.save_atomic(&proj.path().join(".klens").join("config.toml"))
        .unwrap();

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let focus = RelPath::normalize("subpkg").unwrap();

    // 1. Focused map fits the entire `subpkg` subtree even at modest budget and is byte-for-byte deterministic.
    let m1 = build_project_map_focused(&mut index, 400, Some(&focus)).unwrap();
    let m2 = build_project_map_focused(&mut index, 400, Some(&focus)).unwrap();
    assert_eq!(
        m1.to_deterministic_json().unwrap(),
        m2.to_deterministic_json().unwrap(),
        "focused map JSON must be byte-for-byte deterministic"
    );
    assert_eq!(
        format_map_text(&m1),
        format_map_text(&m2),
        "focused map text must be byte-for-byte deterministic"
    );

    assert_eq!(m1.data.focus_path.as_deref(), Some("subpkg"));
    assert_eq!(m1.data.total_files, 2);
    assert_eq!(m1.data.included_files, 2);
    assert_eq!(m1.data.protected_files, vec!["subpkg/core.ts"]);
    assert!(m1.data.files.iter().all(|f| f.path.starts_with("subpkg/")));

    // Verify both Incoming and Outgoing boundary links with EXTRACTED confidence.
    assert!(m1.data.boundary_links.iter().any(|l| {
        l.direction == BoundaryDirection::Incoming
            && l.internal_path == "subpkg/core.ts"
            && l.external_path == "app/consumer.ts"
            && l.confidence == EdgeConfidence::Extracted
    }));
    assert!(m1.data.boundary_links.iter().any(|l| {
        l.direction == BoundaryDirection::Outgoing
            && l.internal_path == "subpkg/bridge.ts"
            && l.external_path == "shared/ext.ts"
            && l.confidence == EdgeConfidence::Extracted
    }));

    let rendered = format_map_text(&m1);
    assert!(rendered.contains("focus=subpkg"));
    assert!(rendered.contains("## Boundary Links"));
    assert!(rendered.contains("<- app/consumer.ts -> subpkg/core.ts [EXTRACTED]"));
    assert!(rendered.contains("-> subpkg/bridge.ts -> shared/ext.ts [EXTRACTED]"));

    // 2. Narrow budget must explicitly emit `boundary_links_budget_exceeded` omission (never silent truncation).
    let tight = build_project_map_focused(&mut index, 40, Some(&focus)).unwrap();
    assert!(
        tight
            .omissions
            .iter()
            .any(|o| o.reason == "boundary_links_budget_exceeded"),
        "expected boundary_links_budget_exceeded omission under tight budget, got: {:?}",
        tight.omissions
    );

    // 3. Nonexistent focus path must fail closed with `CodeError::PathNotFound`.
    let missing = RelPath::normalize("missing/subdir").unwrap();
    let err = build_project_map_focused(&mut index, 400, Some(&missing)).unwrap_err();
    assert!(
        matches!(err, CodeError::PathNotFound(ref p) if p == "missing/subdir"),
        "expected CodeError::PathNotFound, got: {err:?}"
    );
}
