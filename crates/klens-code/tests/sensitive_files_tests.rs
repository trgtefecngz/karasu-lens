//! A3 regression tests (v0.3.2+): well-known credential files and directories must never be
//! read, indexed, or searchable — while ordinary source files with similar names stay usable.
//!
//! Every file below contains the same canary token. Sensitive files must be blocked by
//! `ProjectRoot` path resolution, `klens_read` (`read_lines`), and the FTS index
//! (`klens_find`), while every "safe" lookalike remains readable and searchable.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_code::{CodeIndex, LineRange, find_in_workspace, read_lines};
use klens_core::{PathError, ProjectRoot, RelPath};

const CANARY: &str = "klenscanary7f3a";

/// Credential files/directories that MUST be blocked everywhere.
const SENSITIVE: &[&str] = &[
    // Built-in since v0.1 (regression guard).
    ".env",
    "config/.env.production",
    "certs/server.pem",
    "certs/server.key",
    "deploy/id_rsa",
    // SSH keys beyond RSA and whole SSH / cloud / GPG / Kubernetes credential directories.
    "deploy/id_ed25519",
    "deploy/id_ecdsa",
    "deploy/id_dsa",
    ".ssh/config",
    ".ssh/known_hosts",
    "home/.ssh/id_custom",
    ".aws/credentials",
    ".aws/config",
    ".gnupg/pubring.kbx",
    ".kube/config",
    // Package-manager / network credential files.
    ".npmrc",
    "web/.npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".pgpass",
    // Certificate stores and PuTTY keys.
    "certs/client.pfx",
    "certs/client.p12",
    "android/release.jks",
    "android/debug.keystore",
    "putty/server.ppk",
    // Tool-specific token files.
    ".docker/config.json",
    ".codex/auth.json",
    ".claude/.credentials.json",
    ".config/gh/hosts.yml",
    // direnv, signing keys, password databases and more tool token / history files.
    ".envrc",
    "keys/AuthKey_ABC123.p8",
    "android/platform.pk8",
    "vault/passwords.kdbx",
    ".vault-token",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".dockercfg",
    ".yarnrc.yml",
    ".bash_history",
    ".azure/accessTokens.json",
    ".config/gcloud/application_default_credentials.json",
    ".terraform.d/credentials.tfrc.json",
];

/// Ordinary project files with lookalike names that MUST stay readable and searchable.
const SAFE: &[&str] = &[
    "src/keys.rs",
    "src/ssh_client.rs",
    "src/credentials.rs",
    "src/auth.json",
    "docs/aws-setup.md",
    "docs/ssh.md",
    "config/settings.json",
    "hosts.yml",
    "npmrc.md",
    ".claude/settings.json",
    ".github/workflows/ci.yml",
    "kube/deployment.yaml",
    "src/azure.rs",
    "terraform/main.tf",
    ".cargo/config.toml",
];

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempProject(PathBuf);

impl TempProject {
    fn new() -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-sensitive-files-{}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        for rel in SENSITIVE.iter().chain(SAFE) {
            write(&dir, rel);
        }
        Self(dir)
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write(root: &Path, rel: &str) {
    let full = root.join(rel);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, format!("token = \"{CANARY}\"\n")).unwrap();
}

#[test]
fn credential_files_are_blocked_by_path_resolution_and_reads() {
    let tmp = TempProject::new();
    let root = ProjectRoot::new(&tmp.0).unwrap();
    let index = CodeIndex::open(root.clone(), false).unwrap();

    let mut leaked = Vec::new();
    for rel in SENSITIVE {
        match root.resolve_existing(rel) {
            Err(PathError::SensitiveFileBlocked(_)) => {}
            other => leaked.push(format!("{rel}: resolve_existing -> {other:?}")),
        }
        let rel_path = RelPath::normalize(rel).unwrap();
        if read_lines(&index, &rel_path, LineRange::parse("1:5").unwrap()).is_ok() {
            leaked.push(format!("{rel}: read_lines succeeded"));
        }
    }
    assert!(
        leaked.is_empty(),
        "sensitive files were readable:\n{}",
        leaked.join("\n")
    );

    for rel in SAFE {
        assert!(
            root.resolve_existing(rel).is_ok(),
            "ordinary file `{rel}` must stay readable"
        );
    }
}

#[test]
fn credential_files_are_never_indexed_or_searchable() {
    let tmp = TempProject::new();
    let root = ProjectRoot::new(&tmp.0).unwrap();
    let mut index = CodeIndex::open(root, false).unwrap();

    let found: BTreeSet<String> = find_in_workspace(&mut index, CANARY, 500)
        .unwrap()
        .data
        .matches
        .into_iter()
        .map(|m| m.path)
        .collect();

    let leaked: Vec<&str> = SENSITIVE
        .iter()
        .copied()
        .filter(|rel| found.contains(*rel))
        .collect();
    assert!(
        leaked.is_empty(),
        "sensitive files leaked into the search index: {leaked:?}"
    );

    let missing: Vec<&str> = SAFE
        .iter()
        .copied()
        .filter(|rel| !found.contains(*rel))
        .collect();
    assert!(
        missing.is_empty(),
        "ordinary files must stay searchable, missing: {missing:?}"
    );
}

/// A private key embedded in an ordinary (readable) file, e.g. a test fixture.
const KEY_FIXTURE: &str = "// fixture\n\
const KEY: &str = r#\"\n\
-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpAIBAAKCAQEAkeybodyline1klenspemcanary\n\
MIIEpAIBAAKCAQEAkeybodyline2klenspemcanary\n\
-----END RSA PRIVATE KEY-----\n\
\"#;\n\
fn after_key() { let marker = \"klensafterkey\"; }\n";

fn key_fixture_project() -> (TempProject, CodeIndex) {
    let tmp = TempProject::new();
    fs::create_dir_all(tmp.0.join("tests")).unwrap();
    fs::write(tmp.0.join("tests/fixture.rs"), KEY_FIXTURE).unwrap();
    let root = ProjectRoot::new(&tmp.0).unwrap();
    let index = CodeIndex::open(root, false).unwrap();
    (tmp, index)
}

#[test]
fn line_range_inside_a_private_key_body_is_masked() {
    let (_tmp, index) = key_fixture_project();
    let rel = RelPath::normalize("tests/fixture.rs").unwrap();
    // Lines 4-5 are the key body; the BEGIN line (3) is outside the requested range.
    for spec in ["4:5", "4:4", "5:8", "1:8"] {
        let env = read_lines(&index, &rel, LineRange::parse(spec).unwrap()).unwrap();
        let content = env.data.content.unwrap_or_default();
        assert!(
            !content.contains("klenspemcanary"),
            "{spec}: key body leaked:\n{content}"
        );
        assert!(
            content.contains("[REDACTED:PRIVATE_KEY]"),
            "{spec}: {content}"
        );
        assert!(env.redactions_count >= 1, "{spec}: redaction not counted");
    }
    // Line numbers stay true: line 8 is still the line after the key.
    let env = read_lines(&index, &rel, LineRange::parse("8:8").unwrap()).unwrap();
    assert!(env.data.content.unwrap().starts_with("L8| fn after_key"));
}

#[test]
fn search_hits_never_show_a_private_key_body_and_keep_true_line_numbers() {
    let (_tmp, mut index) = key_fixture_project();
    let body_hits = find_in_workspace(&mut index, "klenspemcanary", 50).unwrap();
    for hit in &body_hits.data.matches {
        assert!(
            !hit.snippet.contains("klenspemcanary"),
            "key body leaked through find: {hit:?}"
        );
    }
    let after = find_in_workspace(&mut index, "klensafterkey", 50).unwrap();
    let hit = after
        .data
        .matches
        .iter()
        .find(|m| m.path == "tests/fixture.rs")
        .expect("line after the key must stay searchable");
    assert_eq!(hit.line, 8, "line numbers after a key block must not shift");
}
