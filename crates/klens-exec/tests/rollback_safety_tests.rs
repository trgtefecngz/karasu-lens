//! B2 regression tests (v0.3.3+): `klens rollback` must never lose work irreversibly.
//!
//! 1. Applying a rollback first saves an automatic safety checkpoint of the current working
//!    tree, so uncommitted edits and brand-new files can always be brought back.
//! 2. A dry run never creates checkpoints.
//! 3. (Unix) Paths that Git would quote (`"`, `\`) are handled exactly via `-z` parsing.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::ProjectRoot;
use klens_exec::{create_checkpoint, format_rollback_text, list_checkpoints, rollback_checkpoint};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Repo(PathBuf);

impl Repo {
    fn new(label: &str) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-rollback-safety-{label}-{}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let repo = Self(dir);
        repo.git(&["init"]);
        repo.git(&["config", "user.email", "t@klens.local"]);
        repo.git(&["config", "user.name", "T"]);
        repo
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.0.join(rel);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.0.join(rel)).unwrap()
    }

    fn git(&self, args: &[&str]) {
        let mut cmd = Command::new("git");
        cmd.args(args).current_dir(&self.0);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn applied_rollback_saves_a_safety_checkpoint_that_restores_unsaved_work() {
    let repo = Repo::new("safety");
    repo.write("src/app.txt", "v1\n");
    repo.git(&["add", "."]);
    repo.git(&["commit", "-m", "init"]);

    let root = ProjectRoot::new(repo.path()).unwrap();
    let baseline = create_checkpoint(&root, Some("baseline")).unwrap();

    // Unsaved work done after the checkpoint: an edit and a brand-new, never-committed file.
    repo.write("src/app.txt", "v2 unsaved edit\n");
    repo.write("notes/new_work.txt", "precious, never committed\n");

    let applied = rollback_checkpoint(&root, &baseline.data.id, false).unwrap();
    assert_eq!(repo.read("src/app.txt"), "v1\n");
    assert!(!repo.path().join("notes/new_work.txt").exists());

    // A safety checkpoint of the pre-rollback state must exist...
    let safety = list_checkpoints(&root)
        .unwrap()
        .data
        .into_iter()
        .find(|cp| cp.note.starts_with("auto-backup before rollback"))
        .expect("rollback must save an automatic safety checkpoint before changing files");

    // ...and must be announced to the user.
    let text = format_rollback_text(&applied);
    assert!(
        text.contains(&safety.id),
        "rollback output must name the safety checkpoint:\n{text}"
    );

    // Undoing the rollback brings every byte of the unsaved work back.
    rollback_checkpoint(&root, &safety.id, false).unwrap();
    assert_eq!(repo.read("src/app.txt"), "v2 unsaved edit\n");
    assert_eq!(
        repo.read("notes/new_work.txt"),
        "precious, never committed\n"
    );
}

#[test]
fn dry_run_and_noop_rollbacks_never_create_checkpoints() {
    let repo = Repo::new("dryrun");
    repo.write("a.txt", "1\n");
    repo.git(&["add", "."]);
    repo.git(&["commit", "-m", "init"]);

    let root = ProjectRoot::new(repo.path()).unwrap();
    let cp = create_checkpoint(&root, Some("baseline")).unwrap();

    // No changes: applying is a no-op and must not add a checkpoint.
    rollback_checkpoint(&root, &cp.data.id, false).unwrap();
    assert_eq!(list_checkpoints(&root).unwrap().data.len(), 1);

    // Dry run with changes: preview only, no checkpoint, no file changes.
    repo.write("a.txt", "2\n");
    let preview = rollback_checkpoint(&root, &cp.data.id, true).unwrap();
    assert_eq!(preview.data.files_to_modify, vec!["a.txt"]);
    assert_eq!(list_checkpoints(&root).unwrap().data.len(), 1);
    assert_eq!(repo.read("a.txt"), "2\n");
}

#[test]
fn rollback_handles_a_file_replaced_by_a_directory_and_back() {
    let repo = Repo::new("dirswap");
    repo.write("docs", "docs used to be a single file\n");
    repo.write("keep/folder.txt", "folder content\n");
    repo.git(&["add", "."]);
    repo.git(&["commit", "-m", "init"]);

    let root = ProjectRoot::new(repo.path()).unwrap();
    let cp = create_checkpoint(&root, Some("baseline")).unwrap();

    // File -> directory, and directory -> file, after the checkpoint.
    fs::remove_file(repo.path().join("docs")).unwrap();
    repo.write("docs/readme.md", "now a folder\n");
    fs::remove_dir_all(repo.path().join("keep")).unwrap();
    repo.write("keep", "now a single file\n");

    rollback_checkpoint(&root, &cp.data.id, false).unwrap();
    assert_eq!(repo.read("docs"), "docs used to be a single file\n");
    assert_eq!(repo.read("keep/folder.txt"), "folder content\n");
}

#[cfg(unix)]
#[test]
fn paths_that_git_would_quote_are_rolled_back_exactly() {
    let repo = Repo::new("quoted");
    repo.write("keep\"quote.txt", "original\n");
    repo.git(&["add", "."]);
    repo.git(&["commit", "-m", "init"]);

    let root = ProjectRoot::new(repo.path()).unwrap();
    let cp = create_checkpoint(&root, Some("baseline")).unwrap();

    repo.write("keep\"quote.txt", "changed\n");
    repo.write("added\\back\"slash.txt", "should be removed\n");

    let applied = rollback_checkpoint(&root, &cp.data.id, false).unwrap();
    assert_eq!(applied.data.files_to_modify, vec!["keep\"quote.txt"]);
    assert_eq!(applied.data.files_to_delete, vec!["added\\back\"slash.txt"]);
    assert_eq!(repo.read("keep\"quote.txt"), "original\n");
    assert!(!repo.path().join("added\\back\"slash.txt").exists());
}

/// A project can be a sub-folder of a larger git repository (monorepo). Rollback must work
/// there and must never touch files outside the project folder.
#[test]
fn rollback_in_a_repository_subfolder_restores_only_that_folder() {
    let repo = Repo::new("subdir");
    repo.write("app/src/f.txt", "v1\n");
    repo.write("other/g.txt", "sibling v1\n");
    repo.git(&["add", "."]);
    repo.git(&["commit", "-m", "init"]);

    let root = ProjectRoot::new(repo.path().join("app")).unwrap();
    let baseline = create_checkpoint(&root, Some("baseline")).unwrap();

    repo.write("app/src/f.txt", "v2\n");
    repo.write("app/new.txt", "added later\n");
    repo.write("other/g.txt", "sibling v2 (outside the project)\n");

    let applied = rollback_checkpoint(&root, &baseline.data.id, false).unwrap();

    assert_eq!(applied.data.files_to_modify, vec!["src/f.txt".to_string()]);
    assert_eq!(applied.data.files_to_delete, vec!["new.txt".to_string()]);
    assert_eq!(repo.read("app/src/f.txt"), "v1\n");
    assert!(!repo.path().join("app/new.txt").exists());
    assert_eq!(
        repo.read("other/g.txt"),
        "sibling v2 (outside the project)\n",
        "rollback changed a file outside the project folder"
    );
}

/// Checkpoints are git objects that travel with `git bundle --all`, mirrors and backups:
/// credential files must never be stored in them, and rollback must never rewrite them.
#[test]
fn checkpoints_never_store_or_restore_credential_files() {
    let repo = Repo::new("sensitive");
    repo.write("src/app.txt", "v1\n");
    repo.write(".env", "API_KEY=first\n");
    repo.write(".ssh/id_ed25519", "PRIVATE KEY v1\n");
    repo.git(&["add", "src/app.txt"]);
    repo.git(&["commit", "-m", "init"]);

    let root = ProjectRoot::new(repo.path()).unwrap();
    let baseline = create_checkpoint(&root, Some("baseline")).unwrap();

    let out = Command::new("git")
        .args([
            "ls-tree",
            "-r",
            "--name-only",
            &format!("refs/klens/checkpoints/{}", baseline.data.id),
        ])
        .current_dir(repo.path())
        .output()
        .unwrap();
    let stored = String::from_utf8_lossy(&out.stdout);
    assert!(stored.contains("src/app.txt"), "{stored}");
    assert!(!stored.contains(".env"), "credential file stored: {stored}");
    assert!(
        !stored.contains("id_ed25519"),
        "credential file stored: {stored}"
    );

    repo.write("src/app.txt", "v2\n");
    repo.write(".env", "API_KEY=second\n");
    rollback_checkpoint(&root, &baseline.data.id, false).unwrap();
    assert_eq!(repo.read("src/app.txt"), "v1\n");
    assert_eq!(repo.read(".env"), "API_KEY=second\n");
}
