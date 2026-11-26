//! Built-in sensitive (credential) file rules — locked, case-insensitive, and never removable
//! via project configuration.
//!
//! Enforced by [`crate::paths::is_sensitive_path_with_extra`], which gates `ProjectRoot` reads
//! and writes, `klens_read`, the FTS index (`klens_find`), and project maps.
//!
//! The list covers `.env` files, private keys, SSH keys, cloud/GPG/Kubernetes credential
//! directories, package-manager tokens, certificate stores, and AI/dev-tool token files. Rules
//! are deliberately name-exact so ordinary source files (`src/keys.rs`, `src/credentials.rs`,
//! `docs/aws-setup.md`) stay readable.

/// Directory names whose entire contents are treated as credential material.
/// `.git` holds remote URLs with embedded credentials, hooks and repository config.
pub const SENSITIVE_DIR_NAMES: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".git"];

/// Exact file names (case-insensitive).
pub const SENSITIVE_FILE_NAMES: &[&str] = &[
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".pgpass",
    ".credentials.json",
];

/// File-name prefixes (case-insensitive).
pub const SENSITIVE_FILE_PREFIXES: &[&str] =
    &[".env.", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];

/// File-name suffixes (case-insensitive).
pub const SENSITIVE_FILE_SUFFIXES: &[&str] =
    &[".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".ppk"];

/// Trailing path segments identifying tool-specific token files (case-insensitive).
pub const SENSITIVE_PATH_SUFFIXES: &[&str] =
    &[".docker/config.json", ".codex/auth.json", "gh/hosts.yml"];

/// Human-readable glob summary of every built-in rule (for `effective_sensitive_patterns`
/// and documentation). Matching itself uses [`is_builtin_sensitive`].
pub const BUILTIN_SENSITIVE_PATTERNS: &[&str] = &[
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.pfx",
    "*.p12",
    "*.jks",
    "*.keystore",
    "*.ppk",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".pgpass",
    ".credentials.json",
    ".ssh/**",
    ".aws/**",
    ".gnupg/**",
    ".kube/**",
    ".git/**",
    ".docker/config.json",
    ".codex/auth.json",
    "gh/hosts.yml",
];

/// Return `true` if a normalized forward-slash relative path matches a built-in rule.
pub fn is_builtin_sensitive(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    let mut segments = lower.split('/');
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);

    if segments.any(|seg| SENSITIVE_DIR_NAMES.contains(&seg)) {
        return true;
    }
    if SENSITIVE_FILE_NAMES.contains(&file_name)
        || SENSITIVE_FILE_PREFIXES
            .iter()
            .any(|p| file_name.starts_with(p))
        || SENSITIVE_FILE_SUFFIXES
            .iter()
            .any(|s| file_name.ends_with(s))
    {
        return true;
    }
    SENSITIVE_PATH_SUFFIXES
        .iter()
        .any(|suffix| lower == *suffix || lower.ends_with(&format!("/{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_credentials_case_insensitively() {
        for rel in [
            ".env",
            "a/.ENV.local",
            "deploy/ID_ED25519",
            "deploy/id_ecdsa.pub",
            "x/.ssh/anything",
            ".AWS/credentials",
            ".kube/config",
            ".npmrc",
            "certs/c.PFX",
            "android/debug.keystore",
            "home/.docker/config.json",
            ".codex/auth.json",
            ".claude/.credentials.json",
            ".config/gh/hosts.yml",
        ] {
            assert!(is_builtin_sensitive(rel), "`{rel}` must be sensitive");
        }
    }

    #[test]
    fn keeps_ordinary_lookalike_source_files_readable() {
        for rel in [
            "src/keys.rs",
            "src/ssh_client.rs",
            "src/credentials.rs",
            "src/auth.json",
            "docs/aws-setup.md",
            "config/settings.json",
            "hosts.yml",
            "npmrc.md",
            ".claude/settings.json",
            "kube/deployment.yaml",
            "docker/config.json",
            "my-gh/hosts.yml",
        ] {
            assert!(!is_builtin_sensitive(rel), "`{rel}` must stay readable");
        }
    }

    #[test]
    fn git_internals_are_sensitive_but_git_dotfiles_are_not() {
        for rel in [
            ".git/config",
            ".git/hooks/pre-commit",
            "sub/.git/config",
            ".GIT/config",
        ] {
            assert!(is_builtin_sensitive(rel), "`{rel}` must be blocked");
        }
        for rel in [
            ".gitignore",
            ".gitattributes",
            ".github/workflows/ci.yml",
            "git/config",
        ] {
            assert!(!is_builtin_sensitive(rel), "`{rel}` must stay readable");
        }
    }
}
