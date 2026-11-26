//! A folder can arrive with its own `.git/config` (zip/archive, shared folder). Git settings in
//! there can name programs (`core.fsmonitor`, hooks via `core.hooksPath`, filter/textconv
//! drivers, `diff.external`). klens's own git calls must never run them: indexing, diff checks,
//! checkpoints and rollbacks are supposed to be safe on untrusted folders.
//!
//! Runs the real `klens` binary with a sandboxed `USERPROFILE`/`HOME`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Repo {
    base: PathBuf,
    home: PathBuf,
    project: PathBuf,
    marker: PathBuf,
}

impl Repo {
    fn new(label: &str) -> Self {
        let base =
            std::env::temp_dir().join(format!("klens-gitcfg-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let home = base.join("home");
        let project = base.join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        let marker = base.join("marker.txt");
        let repo = Self {
            base,
            home,
            project,
            marker,
        };
        repo.git(&["init", "-q"]);
        repo.git(&["config", "user.email", "t@t"]);
        repo.git(&["config", "user.name", "t"]);
        fs::write(repo.project.join("a.txt"), "one\n").unwrap();
        fs::write(repo.project.join("lib.rs"), "pub fn a() {}\n").unwrap();
        repo.git(&["add", "-A"]);
        repo.git(&["commit", "-q", "-m", "init"]);
        repo.plant_programs();
        repo
    }

    /// Writes scripts that append their name to `marker.txt`, then wires every git setting
    /// that can launch a program to them.
    fn plant_programs(&self) {
        let scripts = self.base.join("scripts");
        let hooks = self.base.join("hooks");
        fs::create_dir_all(&scripts).unwrap();
        fs::create_dir_all(&hooks).unwrap();
        let marker = slash(&self.marker);
        let script = |name: &str, passthrough: bool| -> String {
            let path = scripts.join(format!("{name}.sh"));
            let tail = if passthrough { "cat\n" } else { "" };
            fs::write(
                &path,
                format!("#!/bin/sh\necho {name} >> \"{marker}\"\n{tail}"),
            )
            .unwrap();
            format!("sh \"{}\"", slash(&path))
        };
        for hook in [
            "reference-transaction",
            "pre-commit",
            "post-checkout",
            "post-index-change",
            "pre-auto-gc",
        ] {
            let path = hooks.join(hook);
            fs::write(
                &path,
                format!("#!/bin/sh\necho hook-{hook} >> \"{marker}\"\n"),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        self.git(&["config", "core.hooksPath", &slash(&hooks)]);
        self.git(&["config", "core.fsmonitor", &script("fsmonitor", false)]);
        self.git(&["config", "filter.evil.clean", &script("filter-clean", true)]);
        self.git(&[
            "config",
            "filter.evil.smudge",
            &script("filter-smudge", true),
        ]);
        self.git(&["config", "diff.evil.textconv", &script("textconv", true)]);
        self.git(&["config", "diff.external", &script("external-diff", false)]);
        fs::write(
            self.project.join(".git").join("info").join("attributes"),
            "*.txt filter=evil diff=evil\n",
        )
        .unwrap();
    }

    fn git(&self, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(&self.project)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git must be installed");
        assert!(status.success(), "git {args:?} failed");
    }

    fn klens(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_klens"));
        cmd.args(args)
            .current_dir(&self.project)
            .env("USERPROFILE", &self.home)
            .env("HOME", &self.home)
            .stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        cmd.output().expect("failed to run klens binary")
    }

    fn programs_that_ran(&self) -> String {
        fs::read_to_string(&self.marker).unwrap_or_default()
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn slash(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

/// Sanity check: plain `git` really does run the planted programs in this setup.
#[test]
fn planted_git_settings_do_run_programs_under_plain_git() {
    let repo = Repo::new("control");
    fs::write(repo.project.join("a.txt"), "two\n").unwrap();
    let _ = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&repo.project)
        .output();
    let _ = Command::new("git")
        .args(["diff"])
        .current_dir(&repo.project)
        .output();
    let ran = repo.programs_that_ran();
    assert!(
        ran.contains("fsmonitor"),
        "control did not trigger: {ran:?}"
    );
}

#[test]
fn diff_check_and_handoff_never_run_repository_git_programs() {
    let repo = Repo::new("read");
    fs::write(repo.project.join("a.txt"), "two\n").unwrap();
    fs::write(repo.project.join("lib.rs"), "pub fn a() { let _ = 1; }\n").unwrap();

    let diff = repo.klens(&["diff-check"]);
    let handoff = repo.klens(&["handoff"]);

    let ran = repo.programs_that_ran();
    assert!(ran.is_empty(), "klens ran repository programs:\n{ran}");
    assert!(
        diff.status.success(),
        "diff-check failed: {}",
        String::from_utf8_lossy(&diff.stderr)
    );
    assert!(handoff.status.success());
}

#[test]
fn checkpoint_and_rollback_never_run_repository_git_programs() {
    let repo = Repo::new("write");
    fs::write(repo.project.join("a.txt"), "two\n").unwrap();

    let cp = repo.klens(&["checkpoint", "--json", "before"]);
    assert!(
        cp.status.success(),
        "checkpoint failed: {}",
        String::from_utf8_lossy(&cp.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&cp.stdout).unwrap();
    let id = json["data"]["id"]
        .as_str()
        .or_else(|| json["data"]["checkpoint_id"].as_str())
        .unwrap_or_else(|| panic!("no checkpoint id in {json}"))
        .to_string();

    fs::write(repo.project.join("a.txt"), "three\n").unwrap();
    let rb = repo.klens(&["rollback", &id]);
    assert!(
        rb.status.success(),
        "rollback failed: {}",
        String::from_utf8_lossy(&rb.stderr)
    );
    assert_eq!(
        fs::read_to_string(repo.project.join("a.txt")).unwrap(),
        "two\n"
    );

    let ran = repo.programs_that_ran();
    assert!(ran.is_empty(), "klens ran repository programs:\n{ran}");
}

/// Filters from the user's own (global/system) git config — Git LFS above all — are trusted
/// and must keep working; only filters defined by the repository's own config are disabled.
/// Otherwise an LFS checkpoint would store raw binaries and a rollback would write pointer
/// text over real files.
#[test]
fn filters_from_the_users_own_git_config_keep_working() {
    let repo = Repo::new("trusted-filter");
    let script = repo.base.join("scripts").join("trusted.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\necho trusted-filter >> \"{}\"\ncat\n",
            slash(&repo.marker)
        ),
    )
    .unwrap();
    fs::write(
        repo.home.join(".gitconfig"),
        format!(
            "[filter \"trusted\"]\n\tclean = sh \"{}\"\n",
            slash(&script)
        ),
    )
    .unwrap();
    fs::write(
        repo.project.join(".gitattributes"),
        "*.dat filter=trusted\n",
    )
    .unwrap();
    fs::write(repo.project.join("blob.dat"), "data\n").unwrap();

    let cp = repo.klens(&["checkpoint", "trusted"]);
    assert!(
        cp.status.success(),
        "checkpoint failed: {}",
        String::from_utf8_lossy(&cp.stderr)
    );

    let ran = repo.programs_that_ran();
    assert!(
        ran.contains("trusted-filter"),
        "the user's own filter was disabled: {ran:?}"
    );
    assert!(
        !ran.contains("filter-clean"),
        "repository filter ran:\n{ran}"
    );
}
