use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_code::{CodeIndex, DiffAlertKind, DiffCheckOptions, run_diff_check_with_options};
use klens_core::{CheckSeverity, ProjectConfig, ProjectRoot};

static STAGED_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let id = STAGED_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "klens-diff-staged-{label}-{}-{id}",
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

fn init_git_repo(dir: &Path) {
    run_git_checked(dir, &["init"]);
    run_git_checked(dir, &["config", "user.email", "test@klens.local"]);
    run_git_checked(dir, &["config", "user.name", "Klens Test"]);
}

fn synthetic_github_token() -> String {
    format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
}

#[test]
fn staged_diff_check_ignores_unstaged_and_untracked_secrets_and_manifests() {
    let proj = TempDir::new("ignore-unstaged");
    let cache = TempDir::new("ignore-unstaged-cache");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"staged-demo\"\nversion = \"0.1.0\"\n\n[dependencies]\n",
    );
    proj.write("src/lib.rs", "pub fn greet() -> &'static str { \"hi\" }\n");
    proj.write("src/other.rs", "pub fn helper() -> i32 { 1 }\n");

    init_git_repo(proj.path());
    run_git_checked(proj.path(), &["add", "."]);
    run_git_checked(proj.path(), &["commit", "-m", "initial"]);

    // Clean staged change in src/lib.rs.
    proj.write(
        "src/lib.rs",
        "pub fn greet() -> &'static str { \"hello staged\" }\n",
    );
    run_git_checked(proj.path(), &["add", "src/lib.rs"]);

    // Unstaged secret leak in tracked file + untracked file with secret + unstaged manifest dep.
    let token = synthetic_github_token();
    proj.write(
        "src/other.rs",
        &format!("pub fn helper() -> &'static str {{ \"{token}\" }}\n"),
    );
    proj.write(
        "untracked_secret.rs",
        &format!("const LEAK: &str = \"{token}\";\n"),
    );
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"staged-demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.215\"\n",
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let env =
        run_diff_check_with_options(&mut index, DiffCheckOptions { staged_only: true }).unwrap();

    assert!(env.data.is_git_repo);
    assert_eq!(env.data.overall_severity, CheckSeverity::Ok);
    assert!(env.data.secret_leaks.is_empty());
    assert!(env.data.added_dependencies.is_empty());
    assert!(env.data.alerts.is_empty());
    assert_eq!(env.data.changed_files.len(), 1);
    assert_eq!(env.data.changed_files[0].path, "src/lib.rs");
}

#[test]
fn staged_diff_check_catches_staged_secret_protected_path_and_staged_manifest_dep() {
    let proj = TempDir::new("catch-staged");
    let cache = TempDir::new("catch-staged-cache");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"staged-catch\"\nversion = \"0.1.0\"\n\n[dependencies]\n",
    );
    proj.write("src/auth.rs", "pub fn verify() -> bool { true }\n");
    proj.write("src/app.rs", "pub fn run() {}\n");

    let cfg = ProjectConfig {
        protected_paths: vec!["src/auth.rs".to_string()],
        ..ProjectConfig::default()
    };
    cfg.save_atomic(&proj.path().join(".klens").join("config.toml"))
        .unwrap();

    init_git_repo(proj.path());
    run_git_checked(
        proj.path(),
        &["add", "Cargo.toml", "src/auth.rs", "src/app.rs"],
    );
    run_git_checked(proj.path(), &["commit", "-m", "initial"]);

    // Stage: (1) synthetic secret in src/app.rs, (2) edit to protected src/auth.rs,
    // (3) staged new external dependency in Cargo.toml (plus an unstaged second dep that must NOT appear).
    let token = synthetic_github_token();
    proj.write(
        "src/app.rs",
        &format!("pub fn run() -> &'static str {{ \"{token}\" }}\n"),
    );
    proj.write("src/auth.rs", "pub fn verify() -> bool { false }\n");
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"staged-catch\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.215\"\n",
    );
    run_git_checked(
        proj.path(),
        &["add", "src/app.rs", "src/auth.rs", "Cargo.toml"],
    );

    // Modify Cargo.toml in working tree AFTER staging so only `serde` is staged, not `anyhow`.
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"staged-catch\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.215\"\nanyhow = \"1.0.95\"\n",
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let env =
        run_diff_check_with_options(&mut index, DiffCheckOptions { staged_only: true }).unwrap();

    assert_eq!(env.data.overall_severity, CheckSeverity::Error);
    assert!(
        env.data
            .alerts
            .iter()
            .any(|a| a.kind == DiffAlertKind::SecretLeak && a.path == "src/app.rs")
    );
    assert!(
        env.data
            .alerts
            .iter()
            .any(|a| a.kind == DiffAlertKind::ProtectedPathViolation && a.path == "src/auth.rs")
    );
    assert_eq!(env.data.added_dependencies.len(), 1);
    assert_eq!(env.data.added_dependencies[0].name, "serde");
}
