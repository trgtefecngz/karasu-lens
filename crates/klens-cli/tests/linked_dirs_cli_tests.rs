//! A project's `.klens` (or `.claude`) folder may be a symbolic link / junction pointing
//! somewhere else (a Linux/macOS clone can carry symlinks; on Windows a tool or user can make a
//! junction). klens must never read, write or delete through such a link.
//!
//! Runs the real `klens` binary with a sandboxed `USERPROFILE`/`HOME`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Sandbox {
    base: PathBuf,
    home: PathBuf,
    project: PathBuf,
    outside: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let base =
            std::env::temp_dir().join(format!("klens-linked-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let sb = Self {
            home: base.join("home"),
            project: base.join("project"),
            outside: base.join("outside"),
            base,
        };
        fs::create_dir_all(&sb.home).unwrap();
        fs::create_dir_all(sb.project.join("src")).unwrap();
        fs::create_dir_all(&sb.outside).unwrap();
        fs::write(sb.project.join("src").join("lib.rs"), "pub fn a() {}\n").unwrap();
        sb
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

    fn outside_entries(&self) -> Vec<String> {
        let mut names = Vec::new();
        collect(&self.outside, &self.outside, &mut names);
        names.sort();
        names
    }
}

fn collect(base: &Path, dir: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        out.push(path.strip_prefix(base).unwrap().display().to_string());
        if path.is_dir() {
            collect(base, &path, out);
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // Remove links first so cleanup never follows them.
        for link in [".klens", ".claude"] {
            let p = self.project.join(link);
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
                let _ = fs::remove_dir(&p).or_else(|_| fs::remove_file(&p));
            }
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// Directory link: a junction on Windows (no privileges needed), a symlink elsewhere.
fn link_dir(link: &Path, target: &Path) {
    #[cfg(windows)]
    {
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[test]
fn linked_klens_folder_is_refused_and_nothing_is_written_outside() {
    let sb = Sandbox::new("klens");
    link_dir(&sb.project.join(".klens"), &sb.outside);

    let map = sb.klens(&["map"]);
    assert!(!map.status.success(), "map should refuse a linked .klens");
    let stderr = String::from_utf8_lossy(&map.stderr);
    assert!(stderr.contains("link"), "unclear error: {stderr}");
    assert!(
        sb.outside_entries().is_empty(),
        "{:?}",
        sb.outside_entries()
    );
}

#[test]
fn linked_entry_inside_klens_is_refused_and_detach_deletes_nothing_outside() {
    let sb = Sandbox::new("klens-cache");
    fs::create_dir_all(sb.project.join(".klens")).unwrap();
    fs::create_dir_all(sb.outside.join("keep")).unwrap();
    fs::write(sb.outside.join("keep").join("precious.txt"), "keep me\n").unwrap();
    link_dir(
        &sb.project.join(".klens").join("runs"),
        &sb.outside.join("keep"),
    );

    let detach = sb.klens(&["detach"]);
    assert!(
        !detach.status.success(),
        "detach should refuse a linked .klens entry"
    );
    assert!(sb.outside.join("keep").join("precious.txt").is_file());
}

#[test]
fn linked_claude_folder_is_never_written_through() {
    let sb = Sandbox::new("claude");
    link_dir(&sb.project.join(".claude"), &sb.outside);

    let init = sb.klens(&["init", "--host", "claude-code"]);
    assert!(
        !init.status.success(),
        "init should refuse a linked .claude"
    );
    assert!(
        sb.outside_entries().is_empty(),
        "{:?}",
        sb.outside_entries()
    );
}
