//! A2 regression tests (v0.3.2+): `klens` must refuse to treat the user home directory,
//! a parent of it, or a filesystem/drive root as a project root.
//!
//! Background: the global `~/.klens/` directory looks like a project marker, so launching
//! `klens` from the home directory (UI double-click, MCP host started in `~`) silently indexed
//! the entire home directory into a multi-GB `~/.klens/cache/index.db`.
//!
//! Every test runs the real `klens` binary with a sandboxed `USERPROFILE`/`HOME`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    base: PathBuf,
    home: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "klens-root-guard-{label}-{}-{seq}",
            std::process::id()
        ));
        let home = base.join("home");
        // A realistic home: the global `~/.klens/` dir plus some personal files.
        fs::create_dir_all(home.join(".klens")).unwrap();
        fs::write(home.join("notes.md"), "# personal notes\n").unwrap();
        Self { base, home }
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

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_refused(out: &Output, what: &str) {
    assert!(
        !out.status.success(),
        "{what}: expected refusal, got success\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        stderr(out)
    );
    let err = stderr(out);
    assert!(
        err.contains("refusing to use") && err.contains("project root"),
        "{what}: expected an explicit unsafe-root error, got:\n{err}"
    );
}

#[test]
fn map_refuses_user_home_directory_and_writes_no_index() {
    let sb = Sandbox::new("home");
    let out = sb.klens(&sb.base, &["map", "--root", sb.home.to_str().unwrap()]);
    assert_refused(&out, "klens map --root <home>");
    assert!(
        !sb.home
            .join(".klens")
            .join("cache")
            .join("index.db")
            .exists(),
        "home directory must never be indexed"
    );
}

#[test]
fn map_refuses_parent_of_user_home_directory() {
    let sb = Sandbox::new("parent");
    let out = sb.klens(&sb.home, &["map", "--root", sb.base.to_str().unwrap()]);
    assert_refused(&out, "klens map --root <parent of home>");
    assert!(
        !sb.base.join(".klens").exists(),
        "parent of home must never be indexed"
    );
}

#[test]
fn mcp_started_from_home_without_project_is_refused() {
    let sb = Sandbox::new("mcp");
    // Hosts often start MCP servers with cwd = home and no `--project`.
    let out = sb.klens(&sb.home, &["mcp"]);
    assert_refused(&out, "klens mcp (cwd = home)");
    assert!(!sb.home.join(".klens").join("cache").exists());
}

#[test]
fn project_inside_home_directory_still_works() {
    let sb = Sandbox::new("child");
    let project = sb.home.join("Projects").join("app");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(project.join("src").join("lib.rs"), "pub fn ok() {}\n").unwrap();

    let out = sb.klens(&sb.home, &["map", "--root", project.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "a normal project inside home must keep working\nstderr:\n{}",
        stderr(&out)
    );
    assert!(
        project
            .join(".klens")
            .join("cache")
            .join("index.db")
            .exists()
    );
}
