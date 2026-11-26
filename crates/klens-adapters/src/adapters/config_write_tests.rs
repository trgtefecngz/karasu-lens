//! Host applications (Claude Code, Codex) rewrite their own config files at any time. When
//! klens edits the same file, a host write that lands between klens's read and klens's write
//! must never be lost, and the user's key order must be kept.

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use super::claude_code::{remove_claude_hooks, upsert_claude_hooks};
use super::codex_toml::remove_codex_toml_mcp;
use super::common::{remove_json_mcp_server, upsert_json_mcp_server};
use crate::error::AdapterError;
use crate::text_format::{BEFORE_CONFIG_COMMIT, CONFIG_EDIT_ATTEMPTS, FileOpOutcome};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-config-write-{label}-{}-{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Installs a "host writes the file right now" hook for the current test thread and returns
/// how many times klens reached the commit point.
struct HostWriter {
    commits: Rc<Cell<usize>>,
}

impl HostWriter {
    /// The host rewrites the file with `content` the first time klens is about to commit.
    fn once(content: &'static str) -> Self {
        Self::install(move |path, call| {
            if call == 0 {
                fs::write(path, content).unwrap();
            }
        })
    }

    /// The host rewrites the file on every attempt (a host that never stops writing).
    fn always() -> Self {
        Self::install(|path, call| {
            fs::write(path, format!("{{\n  \"hostWrite\": {call}\n}}\n")).unwrap();
        })
    }

    fn install(mut write: impl FnMut(&Path, usize) + 'static) -> Self {
        let commits = Rc::new(Cell::new(0));
        let counter = Rc::clone(&commits);
        BEFORE_CONFIG_COMMIT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |path: &Path| {
                let call = counter.get();
                counter.set(call + 1);
                write(path, call);
            }));
        });
        Self { commits }
    }
}

impl Drop for HostWriter {
    fn drop(&mut self) {
        BEFORE_CONFIG_COMMIT.with(|hook| *hook.borrow_mut() = None);
    }
}

fn json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

const CLAUDE_JSON: &str = "{\n  \"theme\": \"dark\"\n}\n";
const CLAUDE_JSON_HOST_UPDATED: &str = "{\n  \"theme\": \"dark\",\n  \"numStartups\": 13\n}\n";

#[test]
fn host_write_during_mcp_upsert_is_kept() {
    let dir = TempDir::new("upsert");
    let cfg = dir.file(".claude.json", CLAUDE_JSON);
    let host = HostWriter::once(CLAUDE_JSON_HOST_UPDATED);

    upsert_json_mcp_server(&cfg, Path::new("/opt/klens"), false, false).unwrap();

    let after = json(&cfg);
    assert_eq!(after["numStartups"], 13, "host change was overwritten");
    assert_eq!(after["mcpServers"]["klens"]["command"], "/opt/klens");
    assert_eq!(host.commits.get(), 2, "edit should be redone once");
}

#[test]
fn host_write_during_forced_mcp_upsert_is_kept() {
    let dir = TempDir::new("force");
    let cfg = dir.file(".claude.json", CLAUDE_JSON);
    let _host = HostWriter::once(CLAUDE_JSON_HOST_UPDATED);

    upsert_json_mcp_server(&cfg, Path::new("/opt/klens"), false, true).unwrap();

    let after = json(&cfg);
    assert_eq!(after["numStartups"], 13, "host change was overwritten");
    assert_eq!(after["mcpServers"]["klens"]["command"], "/opt/klens");
}

#[test]
fn host_write_during_mcp_remove_is_kept() {
    let dir = TempDir::new("remove");
    let cfg = dir.file(
        ".claude.json",
        r#"{"mcpServers": {"klens": {"command": "k"}, "other": {"command": "o"}}}"#,
    );
    let _host = HostWriter::once(
        r#"{"numStartups": 13, "mcpServers": {"klens": {"command": "k"}, "other": {"command": "o"}}}"#,
    );

    remove_json_mcp_server(&cfg, false, false, false).unwrap();

    let after = json(&cfg);
    assert_eq!(after["numStartups"], 13, "host change was overwritten");
    assert!(after["mcpServers"].get("klens").is_none());
    assert_eq!(after["mcpServers"]["other"]["command"], "o");
}

#[test]
fn host_write_during_project_mcp_delete_keeps_the_file() {
    let dir = TempDir::new("delete");
    let cfg = dir.file(
        ".mcp.json",
        r#"{"mcpServers": {"klens": {"command": "k"}}}"#,
    );
    let _host = HostWriter::once(
        r#"{"mcpServers": {"klens": {"command": "k"}, "added": {"command": "a"}}}"#,
    );

    let outcome = remove_json_mcp_server(&cfg, false, false, true).unwrap();

    assert!(
        matches!(outcome, FileOpOutcome::Written { .. }),
        "{outcome:?}"
    );
    let after = json(&cfg);
    assert_eq!(after["mcpServers"]["added"]["command"], "a");
    assert!(after["mcpServers"].get("klens").is_none());
}

#[test]
fn host_that_keeps_writing_gets_a_clear_error_and_its_content_wins() {
    let dir = TempDir::new("busy");
    let cfg = dir.file(".claude.json", CLAUDE_JSON);
    let host = HostWriter::always();

    let err = upsert_json_mcp_server(&cfg, Path::new("/opt/klens"), false, false).unwrap_err();

    assert!(
        matches!(err, AdapterError::ConfigChangedDuringUpdate { .. }),
        "{err:?}"
    );
    assert_eq!(host.commits.get(), CONFIG_EDIT_ATTEMPTS);
    let after = json(&cfg);
    assert_eq!(after["hostWrite"], CONFIG_EDIT_ATTEMPTS - 1);
    assert!(
        after.get("mcpServers").is_none(),
        "klens overwrote the host"
    );
}

#[test]
fn host_write_during_codex_remove_is_kept() {
    let dir = TempDir::new("codex");
    let seed = "model = \"x\"\n\n[mcp_servers.klens]\ncommand = \"k\"\nargs = [\"mcp\"]\n";
    let cfg = dir.file("config.toml", seed);
    let _host = HostWriter::once(
        "model = \"x\"\n# trusted by host\n[projects.\"/work\"]\ntrust_level = \"trusted\"\n\n[mcp_servers.klens]\ncommand = \"k\"\nargs = [\"mcp\"]\n",
    );

    remove_codex_toml_mcp(&cfg, false, false).unwrap();

    let after = fs::read_to_string(&cfg).unwrap();
    assert!(after.contains("trust_level = \"trusted\""), "{after}");
    assert!(after.contains("# trusted by host"), "{after}");
    assert!(!after.contains("mcp_servers.klens"), "{after}");
}

const SETTINGS: &str = r#"{
  "permissions": {
    "allow": []
  },
  "hooks": {
    "Stop": [
      {
        "hooks": []
      }
    ],
    "SessionStart": [
      {
        "klens_managed": true,
        "hooks": []
      }
    ],
    "PostToolUse": [
      {
        "hooks": []
      }
    ],
    "Notification": [
      {
        "hooks": []
      }
    ]
  },
  "model": "opus"
}
"#;

const SETTINGS_WITHOUT_KLENS: &str = r#"{
  "permissions": {
    "allow": []
  },
  "hooks": {
    "Stop": [
      {
        "hooks": []
      }
    ],
    "PostToolUse": [
      {
        "hooks": []
      }
    ],
    "Notification": [
      {
        "hooks": []
      }
    ]
  },
  "model": "opus"
}
"#;

#[test]
fn removing_klens_hooks_keeps_user_hook_and_key_order() {
    let dir = TempDir::new("hooks-remove");
    let path = dir.file("settings.json", SETTINGS);
    remove_claude_hooks(&path, false, false).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), SETTINGS_WITHOUT_KLENS);
}

#[test]
fn disabling_session_hook_keeps_user_hook_and_key_order() {
    let dir = TempDir::new("hooks-upsert");
    let path = dir.file("settings.json", SETTINGS);
    upsert_claude_hooks(&path, Path::new("/opt/klens"), false, false, false, false).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), SETTINGS_WITHOUT_KLENS);
}

#[test]
fn host_write_during_claude_hook_update_is_kept() {
    let dir = TempDir::new("hooks-race");
    let path = dir.file("settings.json", SETTINGS);
    let host = HostWriter::once(
        r#"{"hooks": {"SessionStart": [{"klens_managed": true, "hooks": []}]}, "effortLevel": "high"}"#,
    );

    upsert_claude_hooks(&path, Path::new("/opt/klens"), false, false, false, false).unwrap();

    let after = json(&path);
    assert_eq!(after["effortLevel"], "high", "host change was overwritten");
    assert!(after["hooks"].get("SessionStart").is_none());
    assert_eq!(host.commits.get(), 2);
}
