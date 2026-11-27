//! `klens read <absolute path>` must use the real project root (the repository), not the
//! nearest sub-package manifest, and must never create a nested `.klens/` inside a sub-crate.
//!
//! Runs the real `klens` binary with a sandboxed `USERPROFILE`/`HOME`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Workspace {
    base: PathBuf,
    home: PathBuf,
    repo: PathBuf,
}

impl Workspace {
    fn new(label: &str) -> Self {
        let base =
            std::env::temp_dir().join(format!("klens-read-path-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let ws = Self {
            home: base.join("home"),
            repo: base.join("repo"),
            base,
        };
        fs::create_dir_all(&ws.home).unwrap();
        let krate = ws.repo.join("crates").join("sub");
        fs::create_dir_all(krate.join("src")).unwrap();
        fs::write(
            ws.repo.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/sub\"]\n",
        )
        .unwrap();
        fs::write(krate.join("Cargo.toml"), "[package]\nname = \"sub\"\n").unwrap();
        fs::write(krate.join("src").join("lib.rs"), "pub fn sub() {}\n").unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&ws.repo)
            .status()
            .unwrap();
        assert!(status.success());
        ws
    }

    fn klens(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_klens"));
        cmd.args(args)
            .current_dir(cwd)
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
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn absolute_read_uses_the_repository_root_from_inside_and_outside() {
    let ws = Workspace::new("abs");
    let file = ws
        .repo
        .join("crates")
        .join("sub")
        .join("src")
        .join("lib.rs");
    let file_arg = file.display().to_string();
    let elsewhere = ws.base.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();

    // The repo itself, a sibling folder, and a plain parent folder (no markers) that contains it.
    for cwd in [&ws.repo, &elsewhere, &ws.base] {
        let out = ws.klens(cwd, &["read", &file_arg, "--lines", "1:1"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "read failed from {}: {}",
            cwd.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("crates/sub/src/lib.rs"),
            "path not relative to the repository root: {stdout}"
        );
    }
    assert!(
        !ws.repo.join("crates").join("sub").join(".klens").exists(),
        "a nested .klens was created inside the sub-crate"
    );
    assert!(
        !ws.base.join(".klens").exists(),
        "a .klens was created in the plain parent folder"
    );
}

#[test]
fn a_plain_parent_folder_is_never_chosen_as_the_root() {
    let ws = Workspace::new("parent");
    let dev = ws.base.join("dev");
    let proj = dev.join("proj");
    fs::create_dir_all(proj.join("src")).unwrap();
    fs::create_dir_all(proj.join(".git")).unwrap();
    fs::write(proj.join("src").join("lib.rs"), "pub fn p() {}\n").unwrap();
    let file_arg = proj.join("src").join("lib.rs").display().to_string();

    let out = ws.klens(&dev, &["read", &file_arg, "--lines", "1:1"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("] src/lib.rs"),
        "root is not the project: {stdout}"
    );
    assert!(
        !dev.join(".klens").exists(),
        "a .klens was created in the plain parent"
    );
}
