use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_adapters::{
    AdapterError, AdapterOptions, AdapterRegistry, detach_project, install_pre_commit_hook,
    pre_commit_hook_status, uninstall_pre_commit_hook,
};
use klens_core::ProjectRoot;

static HOOK_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct HookSandbox {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl HookSandbox {
    fn new(label: &str) -> Self {
        let seq = HOOK_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "klens-hook-test-{label}-{}-{seq}",
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
}

impl Drop for HookSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn init_git_repo(dir: &Path) {
    let mut cmd = Command::new("git");
    cmd.args(["init"]).current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().expect("failed to spawn git init");
    assert!(
        out.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn preserves_existing_user_hook_is_idempotent_updates_binary_and_uninstalls_surgically() {
    let sb = HookSandbox::new("user-hook");
    init_git_repo(&sb.project);

    let hook_path = sb.project.join(".git").join("hooks").join("pre-commit");
    fs::create_dir_all(hook_path.parent().unwrap()).unwrap();
    let user_hook_bytes = b"#!/bin/sh\r\necho \"custom user hook\"\r\n";
    fs::write(&hook_path, user_hook_bytes).unwrap();

    let bin_a = PathBuf::from(r"C:\tools\v1\klens.exe");
    let bin_b = PathBuf::from(r"C:\tools\v2\klens.exe");

    // 1. Install preserves user lines and CRLF.
    let rep1 = install_pre_commit_hook(&sb.project, &bin_a, false, false).unwrap();
    assert!(rep1.changed);
    assert!(!rep1.created_new_file);
    assert!(rep1.preserved_existing_hook);
    let content1 = fs::read_to_string(&hook_path).unwrap();
    assert!(content1.contains("echo \"custom user hook\"\r\n"));
    assert!(content1.contains("# klens:start\r\n"));
    assert!(content1.contains(
        "'C:/tools/v1/klens.exe' diff-check --staged --read-only --fail-on error || exit $?"
    ));
    assert!(content1.contains("# klens:end\r\n"));

    // 2. Second install is strictly idempotent (`changed == false`).
    let rep2 = install_pre_commit_hook(&sb.project, &bin_a, false, false).unwrap();
    assert!(!rep2.changed);

    // 3. Moved binary path updates cleanly while keeping user hook lines.
    let rep3 = install_pre_commit_hook(&sb.project, &bin_b, true, false).unwrap();
    assert!(rep3.changed);
    let content3 = fs::read_to_string(&hook_path).unwrap();
    assert!(content3.contains("echo \"custom user hook\"\r\n"));
    assert!(content3.contains(
        "'C:/tools/v2/klens.exe' diff-check --staged --read-only --fail-on warning || exit $?"
    ));
    assert!(!content3.contains("v1/klens.exe"));

    // 4. Status reflects installed + other user hooks + binary freshness.
    let status_fresh = pre_commit_hook_status(&sb.project, &bin_b);
    assert!(status_fresh.is_git_repo);
    assert!(status_fresh.installed);
    assert!(status_fresh.has_other_user_hooks);
    assert_eq!(status_fresh.binary_matches_current, Some(true));

    let status_stale = pre_commit_hook_status(&sb.project, &bin_a);
    assert_eq!(status_stale.binary_matches_current, Some(false));

    // 5. Uninstall with `--dry-run` writes zero bytes.
    let dry_un = uninstall_pre_commit_hook(&sb.project, true, false).unwrap();
    assert!(!dry_un.changed);
    assert!(dry_un.preserved_user_hook);
    assert_eq!(fs::read_to_string(&hook_path).unwrap(), content3);

    // 6. Real uninstall strips only the klens block, restoring exact original user bytes.
    let real_un = uninstall_pre_commit_hook(&sb.project, false, false).unwrap();
    assert!(real_un.changed);
    assert!(!real_un.removed_file);
    assert!(real_un.preserved_user_hook);
    assert_eq!(fs::read(&hook_path).unwrap(), user_hook_bytes);
}

#[test]
fn empty_git_repo_install_and_detach_leaves_zero_pre_commit_residue() {
    let sb = HookSandbox::new("empty-detach");
    init_git_repo(&sb.project);

    let hook_path = sb.project.join(".git").join("hooks").join("pre-commit");
    assert!(!hook_path.exists());

    let bin = PathBuf::from("/usr/local/bin/klens");
    let inst = install_pre_commit_hook(&sb.project, &bin, false, false).unwrap();
    assert!(inst.changed);
    assert!(inst.created_new_file);
    assert!(!inst.preserved_existing_hook);
    assert!(hook_path.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&hook_path).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "expected pre-commit hook to be executable");
    }

    let registry = AdapterRegistry::with_home(sb.home.clone(), &AdapterOptions::default());
    let project_root = ProjectRoot::new(&sb.project).unwrap();

    // Dry-run detach must not delete the hook file.
    let dry_det = detach_project(&registry, &project_root, false, true).unwrap();
    assert!(!dry_det.changed);
    assert!(hook_path.is_file());

    // Real detach removes the klens-only pre-commit file completely.
    let real_det = detach_project(&registry, &project_root, false, false).unwrap();
    assert!(real_det.changed);
    assert!(!hook_path.exists());
}

#[test]
fn non_git_directory_fails_closed_and_writes_zero_files() {
    let sb = HookSandbox::new("non-git");
    let bin = PathBuf::from("/usr/local/bin/klens");

    let status = pre_commit_hook_status(&sb.project, &bin);
    assert!(!status.is_git_repo);
    assert!(status.hook_path.is_none());
    assert!(!status.installed);

    let inst_err = install_pre_commit_hook(&sb.project, &bin, false, false).unwrap_err();
    assert!(matches!(inst_err, AdapterError::NotAGitRepo(_)));

    let un_err = uninstall_pre_commit_hook(&sb.project, false, false).unwrap_err();
    assert!(matches!(un_err, AdapterError::NotAGitRepo(_)));

    assert!(fs::read_dir(&sb.project).unwrap().next().is_none());
}
