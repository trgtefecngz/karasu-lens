//! Host config files such as `~/.claude.json` are owned by the host application. When klens
//! registers or removes its MCP entry it must leave everything else exactly where it was:
//! top-level key order, the order of other MCP servers, and user fields inside the klens entry.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_adapters::adapters::common::{remove_json_mcp_server, upsert_json_mcp_server};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("klens-order-{label}-{}-{seq}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const NEW_BINARY: &str = "/opt/klens/bin/klens";

/// Keys are deliberately NOT alphabetical, and `klens` sits in the middle of `mcpServers`
/// with two servers after it, so both sorting and swap-removal would be visible.
const SEED: &str = r#"{
  "numStartups": 12,
  "theme": "dark",
  "mcpServers": {
    "zeta": {
      "command": "zeta-mcp"
    },
    "klens": {
      "env": {
        "KLENS_LOG": "debug"
      },
      "command": "/old/klens",
      "args": [
        "mcp"
      ]
    },
    "alpha": {
      "command": "alpha-mcp"
    },
    "beta": {
      "command": "beta-mcp"
    }
  },
  "autoUpdates": false,
  "projects": {
    "/work/b": {},
    "/work/a": {}
  }
}
"#;

const AFTER_UPDATE: &str = r#"{
  "numStartups": 12,
  "theme": "dark",
  "mcpServers": {
    "zeta": {
      "command": "zeta-mcp"
    },
    "klens": {
      "env": {
        "KLENS_LOG": "debug"
      },
      "command": "/opt/klens/bin/klens",
      "args": [
        "mcp"
      ]
    },
    "alpha": {
      "command": "alpha-mcp"
    },
    "beta": {
      "command": "beta-mcp"
    }
  },
  "autoUpdates": false,
  "projects": {
    "/work/b": {},
    "/work/a": {}
  }
}
"#;

const AFTER_REMOVE: &str = r#"{
  "numStartups": 12,
  "theme": "dark",
  "mcpServers": {
    "zeta": {
      "command": "zeta-mcp"
    },
    "alpha": {
      "command": "alpha-mcp"
    },
    "beta": {
      "command": "beta-mcp"
    }
  },
  "autoUpdates": false,
  "projects": {
    "/work/b": {},
    "/work/a": {}
  }
}
"#;

/// A fresh registration is appended after the user's existing servers.
const AFTER_FRESH_ADD: &str = r#"{
  "numStartups": 12,
  "theme": "dark",
  "mcpServers": {
    "zeta": {
      "command": "zeta-mcp"
    },
    "alpha": {
      "command": "alpha-mcp"
    },
    "beta": {
      "command": "beta-mcp"
    },
    "klens": {
      "command": "/opt/klens/bin/klens",
      "args": [
        "mcp"
      ]
    }
  },
  "autoUpdates": false,
  "projects": {
    "/work/b": {},
    "/work/a": {}
  }
}
"#;

fn seeded(sb: &Sandbox, name: &str) -> PathBuf {
    let path = sb.root.join(name);
    fs::write(&path, SEED).unwrap();
    path
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn updating_klens_entry_keeps_user_key_order() {
    let sb = Sandbox::new("update");
    let cfg = seeded(&sb, ".claude.json");
    upsert_json_mcp_server(&cfg, Path::new(NEW_BINARY), false, false).unwrap();
    assert_eq!(read(&cfg), AFTER_UPDATE);
}

#[test]
fn forced_upsert_keeps_user_key_order() {
    let sb = Sandbox::new("force");
    let cfg = seeded(&sb, ".claude.json");
    upsert_json_mcp_server(&cfg, Path::new(NEW_BINARY), false, true).unwrap();
    assert_eq!(read(&cfg), AFTER_UPDATE);
}

#[test]
fn removing_klens_entry_keeps_user_key_order() {
    let sb = Sandbox::new("remove");
    let cfg = seeded(&sb, ".claude.json");
    remove_json_mcp_server(&cfg, false, false, false).unwrap();
    assert_eq!(read(&cfg), AFTER_REMOVE);
}

#[test]
fn fresh_registration_is_appended_without_reordering() {
    let sb = Sandbox::new("fresh");
    let cfg = sb.root.join(".claude.json");
    fs::write(&cfg, AFTER_REMOVE).unwrap();
    upsert_json_mcp_server(&cfg, Path::new(NEW_BINARY), false, false).unwrap();
    assert_eq!(read(&cfg), AFTER_FRESH_ADD);
}
