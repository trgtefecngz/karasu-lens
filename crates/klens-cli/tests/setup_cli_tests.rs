//! `klens setup` registers klens once, at user scope, for every installed AI host, so it works
//! in any project without per-project files.
//!
//! Runs the real `klens` binary with a sandboxed `USERPROFILE`/`HOME`.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

struct Home {
    base: PathBuf,
    home: PathBuf,
}

impl Home {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!("klens-setup-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let home = base.join("home");
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::create_dir_all(home.join(".gemini")).unwrap();
        fs::write(
            home.join(".claude.json"),
            "{\n  \"numStartups\": 3,\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"other-mcp\"\n    }\n  }\n}\n",
        )
        .unwrap();
        fs::write(home.join(".codex").join("config.toml"), "model = \"x\"\n").unwrap();
        Self { base, home }
    }

    fn klens(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_klens"));
        cmd.args(args)
            // Run from the home folder itself: setup must not need (or create) a project.
            .current_dir(&self.home)
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

    fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut files = Vec::new();
        collect(&self.home, &self.home, &mut files);
        files.sort();
        files
    }
}

fn collect(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(base, &path, out);
        } else {
            let rel = path.strip_prefix(base).unwrap().display().to_string();
            out.push((rel, fs::read(&path).unwrap()));
        }
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn setup_registers_every_installed_host_at_user_scope_and_is_idempotent() {
    let h = Home::new("all");

    let dry = h.klens(&["setup", "--dry-run"]);
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let before = h.snapshot();

    let out = h.klens(&["setup"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let claude: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(h.home.join(".claude.json")).unwrap()).unwrap();
    assert_eq!(claude["numStartups"], 3, "user keys must be kept");
    assert_eq!(claude["mcpServers"]["other"]["command"], "other-mcp");
    assert_eq!(claude["mcpServers"]["klens"]["args"][0], "mcp");

    let codex = fs::read_to_string(h.home.join(".codex").join("config.toml")).unwrap();
    assert!(codex.contains("model = \"x\""), "{codex}");
    assert!(codex.contains("[mcp_servers.klens]"), "{codex}");

    let gemini = fs::read_to_string(
        h.home
            .join(".gemini")
            .join("config")
            .join("mcp_config.json"),
    )
    .unwrap();
    assert!(gemini.contains("\"klens\""), "{gemini}");

    // Dry run wrote nothing; no project files appeared in the home folder.
    assert!(!before.iter().any(|(p, _)| p.contains("mcp_config.json")));
    assert!(!h.home.join(".klens").join("cache").exists());
    assert!(!h.home.join(".mcp.json").exists());

    // Second run changes nothing.
    let after_first = h.snapshot();
    let again = h.klens(&["setup"]);
    assert!(again.status.success());
    assert_eq!(after_first, h.snapshot(), "setup is not idempotent");
}

#[test]
fn setup_skips_hosts_that_are_not_installed() {
    let h = Home::new("only-claude");
    fs::remove_dir_all(h.home.join(".codex")).unwrap();
    fs::remove_dir_all(h.home.join(".gemini")).unwrap();

    let out = h.klens(&["setup"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!h.home.join(".codex").exists());
    assert!(!h.home.join(".gemini").exists());
    let claude = fs::read_to_string(h.home.join(".claude.json")).unwrap();
    assert!(claude.contains("\"klens\""), "{claude}");
}

#[test]
fn setup_adds_a_removable_guide_to_claudes_user_instructions() {
    let h = Home::new("guide");
    let user_md = h.home.join(".claude").join("CLAUDE.md");
    fs::create_dir_all(user_md.parent().unwrap()).unwrap();
    fs::write(&user_md, "# My own rules\n\nAlways answer in Turkish.\n").unwrap();

    let out = h.klens(&["setup"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let with_guide = fs::read_to_string(&user_md).unwrap();
    assert!(with_guide.starts_with("# My own rules"), "{with_guide}");
    assert!(with_guide.contains("Always answer in Turkish."));
    assert!(with_guide.contains("klens_outline"), "{with_guide}");
    assert!(with_guide.contains("klens:start"), "{with_guide}");
    let settings = h.home.join(".claude").join("settings.json");
    let hooks = fs::read_to_string(&settings).unwrap();
    assert!(hooks.contains("hook pre-tool"), "{hooks}");
    assert!(hooks.contains("\"PreToolUse\""), "{hooks}");
    assert!(
        !hooks.contains("SessionStart"),
        "no session hook globally: {hooks}"
    );

    // Undo from any project folder: the guide and the MCP entry go, the user's rules stay.
    let project = h.base.join("project");
    fs::create_dir_all(&project).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_klens"));
    cmd.args(["disconnect", "--host", "claude-code"])
        .current_dir(&project)
        .env("USERPROFILE", &h.home)
        .env("HOME", &h.home)
        .stdin(Stdio::null());
    let undo = cmd.output().unwrap();
    assert!(
        undo.status.success(),
        "{}",
        String::from_utf8_lossy(&undo.stderr)
    );

    assert_eq!(
        fs::read_to_string(&user_md).unwrap(),
        "# My own rules\n\nAlways answer in Turkish.\n"
    );
    let claude = fs::read_to_string(h.home.join(".claude.json")).unwrap();
    assert!(!claude.contains("\"klens\""), "{claude}");
    assert!(
        !settings.exists() || !fs::read_to_string(&settings).unwrap().contains("klens"),
        "hook left behind"
    );
}

/// A broken user settings file (comment, trailing comma) must not stop `disconnect`
/// halfway: the guide and the other hosts' registrations are still removed.
#[test]
fn disconnect_continues_past_a_broken_user_settings_file() {
    let h = Home::new("broken-settings");
    let out = h.klens(&["setup"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let settings = h.home.join(".claude").join("settings.json");
    fs::write(&settings, "// my comment\n{\"a\": 1,}\n").unwrap();

    let project = h.base.join("project");
    fs::create_dir_all(&project).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_klens"));
    cmd.args(["disconnect", "--host", "all"])
        .current_dir(&project)
        .env("USERPROFILE", &h.home)
        .env("HOME", &h.home)
        .stdin(Stdio::null());
    let undo = cmd.output().unwrap();
    assert!(
        undo.status.success(),
        "{}",
        String::from_utf8_lossy(&undo.stderr)
    );

    let guide = fs::read_to_string(h.home.join(".claude").join("CLAUDE.md")).unwrap_or_default();
    assert!(
        !guide.contains("klens_outline"),
        "guide left behind: {guide}"
    );
    let codex = fs::read_to_string(h.home.join(".codex").join("config.toml")).unwrap();
    assert!(!codex.contains("mcp_servers.klens"), "{codex}");
    assert_eq!(
        fs::read_to_string(&settings).unwrap(),
        "// my comment\n{\"a\": 1,}\n",
        "the broken file must be left exactly as it was"
    );
}

#[test]
fn setup_without_the_hook_leaves_claude_settings_untouched() {
    let h = Home::new("no-hook");
    let settings = h.home.join(".claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{\n  \"autoMode\": true\n}\n").unwrap();

    let out = h.klens(&["setup", "--no-hook"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(
        fs::read_to_string(&settings).unwrap(),
        "{\n  \"autoMode\": true\n}\n"
    );
    let claude = fs::read_to_string(h.home.join(".claude.json")).unwrap();
    assert!(
        claude.contains("\"klens\""),
        "MCP registration still happens: {claude}"
    );
    let guide = fs::read_to_string(h.home.join(".claude").join("CLAUDE.md")).unwrap();
    assert!(
        guide.contains("klens_outline"),
        "guide still written: {guide}"
    );
}
