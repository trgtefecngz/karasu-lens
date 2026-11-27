use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::PathError;
use crate::hash::project_id_from_canonical_root;

static ATOMIC_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Default sensitive patterns blocked from both read and write access (summary of the
/// locked built-in rules in [`crate::sensitive`]).
pub const DEFAULT_SENSITIVE_PATTERNS: &[&str] = crate::sensitive::BUILTIN_SENSITIVE_PATTERNS;

/// A validated, normalized relative path inside a project root.
///
/// Guarantees:
/// - Always uses `/` as separator (even on Windows).
/// - Never empty, never absolute, never starts with `/`.
/// - Never contains `..` or `.` segments.
/// - Never contains NUL (`\0`), NTFS alternate data stream colons (`:`),
///   or Windows trailing-dot / trailing-space bypass segments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelPath(String);

impl RelPath {
    /// Validate and normalize a relative path string into forward-slash canonical form.
    pub fn normalize(input: &str) -> Result<Self, PathError> {
        if input.is_empty() {
            return Err(PathError::EmptyPath);
        }

        if input.contains('\0') {
            return Err(PathError::InvalidSegment {
                path: input.to_string(),
                reason: "NUL byte is forbidden",
            });
        }

        if input.starts_with('/') || input.starts_with('\\') || has_windows_drive_prefix(input) {
            return Err(PathError::AbsolutePathNotAllowed(input.to_string()));
        }

        let mut segments: Vec<&str> = Vec::new();
        for seg in input.split(['/', '\\']) {
            match seg {
                "" | "." => continue,
                ".." => return Err(PathError::TraversalAttempt(input.to_string())),
                other => {
                    if other.contains(':') {
                        return Err(PathError::InvalidSegment {
                            path: input.to_string(),
                            reason: "colon (`:`) / NTFS ADS stream is forbidden",
                        });
                    }
                    if other.ends_with('.') || other.ends_with(' ') {
                        return Err(PathError::InvalidSegment {
                            path: input.to_string(),
                            reason: "trailing dot or space in path segment is forbidden",
                        });
                    }
                    segments.push(other);
                }
            }
        }

        if segments.is_empty() {
            return Err(PathError::EmptyPath);
        }

        Ok(Self(segments.join("/")))
    }

    /// Convert a `std::path::Path` that is known to be relative into a [`RelPath`].
    pub fn from_relative_path(path: &Path) -> Result<Self, PathError> {
        let raw = path
            .to_str()
            .ok_or_else(|| PathError::NonUtf8Path(path.to_path_buf()))?;
        Self::normalize(raw)
    }

    /// Borrow the normalized forward-slash relative path string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the final file name component, if present.
    pub fn file_name(&self) -> Option<&str> {
        self.0.rsplit('/').next()
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RelPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Canonicalized project root enforcing strict path confinement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRoot {
    canonical_root: PathBuf,
    project_id: String,
}

impl ProjectRoot {
    /// Open and canonicalize an existing directory as a confined project root.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, PathError> {
        let root_ref = root.as_ref();
        if !root_ref.is_dir() {
            return Err(PathError::InvalidRoot(root_ref.to_path_buf()));
        }
        let canonical_root = fs::canonicalize(root_ref).map_err(|source| PathError::Io {
            path: root_ref.to_path_buf(),
            source,
        })?;
        if !canonical_root.is_dir() {
            return Err(PathError::InvalidRoot(canonical_root));
        }
        // Never index the user home directory, a parent of it, or a drive root (v0.3.2+).
        if let Some(reason) = crate::root_guard::unsafe_project_root_reason(&canonical_root) {
            return Err(PathError::UnsafeProjectRoot {
                path: root_ref.to_path_buf(),
                reason,
            });
        }
        // klens state must live in a real folder inside the project: a linked `.klens` (or a
        // link inside it) would redirect cache/config reads, writes and `detach` deletions.
        if let Some(path) = crate::links::linked_entry_in_state_dir(&canonical_root) {
            return Err(PathError::LinkedStateEntry { path });
        }
        let project_id = project_id_from_canonical_root(&canonical_root);
        Ok(Self {
            canonical_root,
            project_id,
        })
    }

    /// Canonical filesystem path of the project root.
    pub fn root(&self) -> &Path {
        &self.canonical_root
    }

    /// Deterministic BLAKE3-prefix identifier of this project root.
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Resolve an existing relative path inside the project root, enforcing:
    /// - no `..` traversal or absolute paths,
    /// - canonicalization containment (blocks symlink escapes),
    /// - default sensitive-file blacklist.
    pub fn resolve_existing(&self, rel: impl AsRef<Path>) -> Result<(PathBuf, RelPath), PathError> {
        self.resolve_existing_with_extra(rel, &[])
    }

    /// Like [`ProjectRoot::resolve_existing`], plus additional sensitive glob patterns.
    pub fn resolve_existing_with_extra(
        &self,
        rel: impl AsRef<Path>,
        extra_sensitive: &[String],
    ) -> Result<(PathBuf, RelPath), PathError> {
        let requested_rel = validate_input_relative_path(rel.as_ref())?;
        if is_sensitive_path_with_extra(&requested_rel, extra_sensitive) {
            return Err(PathError::SensitiveFileBlocked(requested_rel.0));
        }

        let candidate = self.canonical_root.join(requested_rel.as_str());
        let canonical_target = fs::canonicalize(&candidate).map_err(|source| PathError::Io {
            path: candidate,
            source,
        })?;

        if !canonical_target.starts_with(&self.canonical_root) {
            return Err(PathError::EscapesRoot(requested_rel.0));
        }

        let canonical_rel =
            ensure_within_root(&self.canonical_root, &canonical_target, &requested_rel)?;

        if is_sensitive_path_with_extra(&canonical_rel, extra_sensitive) {
            return Err(PathError::SensitiveFileBlocked(canonical_rel.0));
        }

        Ok((canonical_target, canonical_rel))
    }

    /// Resolve a target path for creating or overwriting a file inside the project root.
    ///
    /// Canonicalizes the deepest existing ancestor (and the target itself if it already
    /// exists) to prevent symlink escapes even for not-yet-created files.
    pub fn resolve_for_write(
        &self,
        rel: impl AsRef<Path>,
    ) -> Result<(PathBuf, RelPath), PathError> {
        self.resolve_for_write_with_extra(rel, &[])
    }

    /// Like [`ProjectRoot::resolve_for_write`], plus additional sensitive glob patterns.
    pub fn resolve_for_write_with_extra(
        &self,
        rel: impl AsRef<Path>,
        extra_sensitive: &[String],
    ) -> Result<(PathBuf, RelPath), PathError> {
        let requested_rel = validate_input_relative_path(rel.as_ref())?;
        if is_sensitive_path_with_extra(&requested_rel, extra_sensitive) {
            return Err(PathError::SensitiveFileBlocked(requested_rel.0));
        }

        let candidate = self.canonical_root.join(requested_rel.as_str());

        // If the target path (or a symlink at that path) already exists, verify where it points.
        if fs::symlink_metadata(&candidate).is_ok() {
            let canonical_target =
                fs::canonicalize(&candidate).map_err(|source| PathError::Io {
                    path: candidate.clone(),
                    source,
                })?;
            if !canonical_target.starts_with(&self.canonical_root) {
                return Err(PathError::EscapesRoot(requested_rel.0));
            }
            let stripped = canonical_target
                .strip_prefix(&self.canonical_root)
                .map_err(|_| PathError::EscapesRoot(requested_rel.0.clone()))?;
            let canonical_rel = RelPath::from_relative_path(stripped)?;
            if is_sensitive_path_with_extra(&canonical_rel, extra_sensitive) {
                return Err(PathError::SensitiveFileBlocked(canonical_rel.0));
            }
            return Ok((canonical_target, canonical_rel));
        }

        // Walk up to the deepest existing ancestor and verify it stays inside canonical_root.
        let mut remaining: Vec<std::ffi::OsString> = Vec::new();
        let mut cursor = candidate.as_path();
        while fs::symlink_metadata(cursor).is_err() {
            if let Some(name) = cursor.file_name() {
                remaining.push(name.to_os_string());
            } else {
                return Err(PathError::EscapesRoot(requested_rel.0));
            }
            cursor = cursor
                .parent()
                .ok_or_else(|| PathError::EscapesRoot(requested_rel.0.clone()))?;
        }

        let canonical_ancestor = fs::canonicalize(cursor).map_err(|source| PathError::Io {
            path: cursor.to_path_buf(),
            source,
        })?;
        if !canonical_ancestor.starts_with(&self.canonical_root) {
            return Err(PathError::EscapesRoot(requested_rel.0));
        }

        let mut resolved = canonical_ancestor;
        for part in remaining.into_iter().rev() {
            resolved.push(part);
        }

        let stripped = resolved
            .strip_prefix(&self.canonical_root)
            .map_err(|_| PathError::EscapesRoot(requested_rel.0.clone()))?;
        let canonical_rel = RelPath::from_relative_path(stripped)?;
        if is_sensitive_path_with_extra(&canonical_rel, extra_sensitive) {
            return Err(PathError::SensitiveFileBlocked(canonical_rel.0));
        }

        Ok((resolved, canonical_rel))
    }
}

/// Check whether a normalized relative path matches the default sensitive file blacklist.
pub fn is_sensitive_path(rel: &RelPath) -> bool {
    is_sensitive_path_with_extra(rel, &[])
}

/// Check whether a normalized relative path matches either the built-in sensitive blacklist
/// or any user-configured extra sensitive glob patterns (read + write forbidden).
pub fn is_sensitive_path_with_extra(rel: &RelPath, extra_patterns: &[String]) -> bool {
    crate::sensitive::is_builtin_sensitive(rel.as_str()) || matches_any_pattern(rel, extra_patterns)
}

/// Check whether a normalized relative path matches any glob pattern in `patterns`.
///
/// Patterns containing `/` match against the full normalized relative path;
/// patterns without `/` match against the file name component (case-insensitive).
pub fn matches_any_pattern(rel: &RelPath, patterns: &[String]) -> bool {
    let file_name = rel.file_name().unwrap_or(rel.as_str());
    let lower_name = file_name.to_ascii_lowercase();
    let lower_full = rel.as_str().to_ascii_lowercase();

    for pattern in patterns {
        let lower_pat = pattern.trim().replace('\\', "/").to_ascii_lowercase();
        if lower_pat.is_empty() {
            continue;
        }
        if lower_pat.contains('/') {
            if glob_match(&lower_pat, &lower_full) {
                return true;
            }
        } else if glob_match(&lower_pat, &lower_name) {
            return true;
        }
    }

    false
}

/// Atomically write bytes to `target` using a sibling temporary file and rename.
/// Atomically replace `target` with `content` (temp file + rename). On Unix the new file keeps
/// the permission bits of the file it replaces, so a private `0600` config stays private.
pub fn write_atomic(target: &Path, content: &[u8]) -> Result<(), PathError> {
    write_atomic_with_mode_of(target, content, target)
}

/// Like [`write_atomic`], but the new file takes its Unix permission bits from `mode_source`
/// when that file exists (used for backups, which must be as private as the original).
pub fn write_atomic_with_mode_of(
    target: &Path,
    content: &[u8],
    mode_source: &Path,
) -> Result<(), PathError> {
    #[cfg(unix)]
    {
        let source_permissions = fs::metadata(mode_source).ok().map(|m| m.permissions());
        // When the bits are copied, the temp file starts private (0600) and gets them before any
        // byte is written, so the content is never readable more widely than the original.
        let tmp_mode = source_permissions.as_ref().map(|_| PRIVATE_FILE_MODE);
        write_atomic_inner(target, content, tmp_mode, |tmp_path: &Path| {
            if let Some(permissions) = &source_permissions {
                fs::set_permissions(tmp_path, permissions.clone())?;
            }
            Ok(())
        })
    }
    #[cfg(not(unix))]
    {
        let _ = mode_source;
        write_atomic_inner(target, content, None, |_| Ok(()))
    }
}

/// Like [`write_atomic`], but on Unix the file is always owner-only (`0600`), from the moment
/// the temporary file is created. Used for files that may hold unredacted secrets, such as raw
/// command logs. On other platforms it is the same as [`write_atomic`].
pub fn write_atomic_private(target: &Path, content: &[u8]) -> Result<(), PathError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        write_atomic_inner(
            target,
            content,
            Some(PRIVATE_FILE_MODE),
            |tmp_path: &Path| {
                fs::set_permissions(tmp_path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            },
        )
    }
    #[cfg(not(unix))]
    {
        write_atomic_inner(target, content, None, |_| Ok(()))
    }
}

#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// `tmp_mode` (Unix only) is the mode the temporary file is created with; `prepare_tmp` runs
/// on the empty temporary file, before the content is written.
fn write_atomic_inner(
    target: &Path,
    content: &[u8],
    tmp_mode: Option<u32>,
    prepare_tmp: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), PathError> {
    #[cfg(not(unix))]
    let _ = tmp_mode;
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent).map_err(|source| PathError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("klens");
    let pid = std::process::id();

    let mut tmp_path = PathBuf::new();
    let mut tmp_file = None;
    for _ in 0..32 {
        let seq = ATOMIC_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{file_name}.klens-tmp-{pid}-{seq}"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if let Some(mode) = tmp_mode {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        match options.open(&candidate) {
            Ok(file) => {
                tmp_path = candidate;
                tmp_file = Some(file);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(PathError::Io {
                    path: candidate,
                    source,
                });
            }
        }
    }

    let mut file = tmp_file.ok_or_else(|| PathError::Io {
        path: target.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate unique temporary file for atomic write",
        ),
    })?;

    let write_res = prepare_tmp(&tmp_path)
        .and_then(|()| file.write_all(content))
        .and_then(|()| file.sync_all());
    drop(file);

    if let Err(source) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(PathError::Io {
            path: tmp_path,
            source,
        });
    }

    if let Err(source) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(PathError::Io {
            path: target.to_path_buf(),
            source,
        });
    }

    Ok(())
}

fn ensure_within_root(
    canonical_root: &Path,
    canonical_target: &Path,
    requested: &RelPath,
) -> Result<RelPath, PathError> {
    if !canonical_target.starts_with(canonical_root) {
        return Err(PathError::EscapesRoot(requested.0.clone()));
    }
    let stripped = canonical_target
        .strip_prefix(canonical_root)
        .map_err(|_| PathError::EscapesRoot(requested.0.clone()))?;
    RelPath::from_relative_path(stripped)
}

fn validate_input_relative_path(path: &Path) -> Result<RelPath, PathError> {
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(PathError::TraversalAttempt(path.display().to_string()));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(PathError::AbsolutePathNotAllowed(
                    path.display().to_string(),
                ));
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    RelPath::from_relative_path(path)
}

fn has_windows_drive_prefix(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// `true` for a plain local absolute path: `C:\x`, `C:/x`, `\\?\C:\x`, `//?/C:/x`, or (outside
/// Windows) `/x`. Never a network share (`\\host\share`, `//host/share`, `\\?\UNC\...`) or a
/// device path (`\\.\...`).
///
/// Call this before handing an untrusted absolute path (from an AI agent, command output or the
/// Web UI) to the filesystem: on Windows, merely canonicalizing or stat-ing a network path opens
/// an SMB connection, which leaks the user's NTLM credential hash and stalls for ~20 s.
pub fn is_plain_local_absolute(path: &str) -> bool {
    let unverbatim = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix("//?/"))
        .unwrap_or(path);
    if has_windows_drive_prefix(unverbatim) {
        return true;
    }
    !cfg!(windows) && unverbatim.starts_with('/') && !starts_with_two_separators(unverbatim)
}

/// `true` when `path` names (or may name) a network share or a Windows device namespace:
/// anything starting with two path separators (`\\host\share`, `//host/share`, `\\?\UNC\...`,
/// `\\.\pipe\...`), except the local verbatim drive form `\\?\C:\...`.
///
/// Relative paths and ordinary absolute paths return `false`. Use it to refuse a path before any
/// filesystem call when relative input is also allowed.
pub fn is_network_or_device_path(path: &str) -> bool {
    let trimmed = path.trim();
    if !starts_with_two_separators(trimmed) {
        return false;
    }
    let unverbatim = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix("//?/"));
    !unverbatim.is_some_and(has_windows_drive_prefix)
}

fn starts_with_two_separators(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && matches!(bytes[0], b'/' | b'\\') && matches!(bytes[1], b'/' | b'\\')
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_idx: Option<usize> = None;
    let mut match_idx: usize = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }

    pi == p.len()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let seq = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "klens-paths-test-{label}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn relpath_normalizes_backslashes_and_rejects_traversal() {
        let p = RelPath::normalize(r"src\world\save.rs").unwrap();
        assert_eq!(p.as_str(), "src/world/save.rs");

        assert!(matches!(
            RelPath::normalize("../disari.txt"),
            Err(PathError::TraversalAttempt(_))
        ));
        assert!(matches!(
            RelPath::normalize("src/../../disari.txt"),
            Err(PathError::TraversalAttempt(_))
        ));
        assert!(matches!(
            RelPath::normalize("C:/Windows/System32"),
            Err(PathError::AbsolutePathNotAllowed(_))
        ));
        assert!(matches!(
            RelPath::normalize("/etc/passwd"),
            Err(PathError::AbsolutePathNotAllowed(_))
        ));
    }

    #[test]
    fn relpath_and_project_root_block_windows_ads_nul_and_trailing_dot_or_space_bypasses() {
        let bypass_inputs = [
            ".env::$DATA",
            "config/.env::$DATA",
            "cert.pem.",
            "certs/cert.pem.",
            ".env ",
            "src/.env ",
            "dir./main.rs",
            "dir /main.rs",
            "src/main.rs\0.txt",
            "file:stream",
        ];

        for bad in bypass_inputs {
            assert!(
                matches!(
                    RelPath::normalize(bad),
                    Err(PathError::InvalidSegment { .. })
                ),
                "expected `{bad}` to be rejected as InvalidSegment"
            );
        }

        let sandbox = TestDir::new("windows-bypass");
        let project_dir = sandbox.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();
        fs::write(project_dir.join(".env"), "SECRET=1").unwrap();
        fs::write(project_dir.join("cert.pem"), "pem").unwrap();

        let root = ProjectRoot::new(&project_dir).unwrap();
        for bad in [".env::$DATA", "cert.pem.", ".env ", "cert.pem\0"] {
            assert!(
                matches!(
                    root.resolve_existing(bad),
                    Err(PathError::InvalidSegment { .. })
                ),
                "expected resolve_existing(`{bad}`) to reject bypass"
            );
            assert!(
                matches!(
                    root.resolve_for_write(bad),
                    Err(PathError::InvalidSegment { .. })
                ),
                "expected resolve_for_write(`{bad}`) to reject bypass"
            );
        }
    }

    #[test]
    fn project_root_blocks_parent_traversal_and_sensitive_files() {
        let sandbox = TestDir::new("confinement");
        let project_dir = sandbox.path().join("project");
        fs::create_dir_all(project_dir.join("src")).unwrap();
        fs::write(sandbox.path().join("disari.txt"), "outside").unwrap();
        fs::write(project_dir.join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(project_dir.join(".env"), "SECRET=1").unwrap();
        fs::write(project_dir.join(".env.production"), "SECRET=2").unwrap();
        fs::write(project_dir.join("cert.pem"), "pem").unwrap();
        fs::write(project_dir.join("private.key"), "key").unwrap();
        fs::write(project_dir.join("id_rsa"), "ssh").unwrap();

        let root = ProjectRoot::new(&project_dir).unwrap();

        // Normal file resolves with `/` normalized RelPath.
        let (_, rel) = root.resolve_existing(r"src\main.rs").unwrap();
        assert_eq!(rel.as_str(), "src/main.rs");

        // `../disari.txt` is rejected.
        assert!(matches!(
            root.resolve_existing("../disari.txt"),
            Err(PathError::TraversalAttempt(_))
        ));

        // Default sensitive files are rejected.
        for blocked in [
            ".env",
            ".env.production",
            "cert.pem",
            "private.key",
            "id_rsa",
        ] {
            assert!(
                matches!(
                    root.resolve_existing(blocked),
                    Err(PathError::SensitiveFileBlocked(_))
                ),
                "expected `{blocked}` to be blocked"
            );
        }
    }

    #[test]
    fn project_root_blocks_symlink_escaping_outside() {
        let sandbox = TestDir::new("symlink");
        let outside_dir = sandbox.path().join("outside");
        let project_dir = sandbox.path().join("project");
        fs::create_dir_all(&outside_dir).unwrap();
        fs::create_dir_all(&project_dir).unwrap();

        let outside_file = outside_dir.join("secret.txt");
        fs::write(&outside_file, "outside secret").unwrap();

        let root = ProjectRoot::new(&project_dir).unwrap();

        #[cfg(unix)]
        {
            let link_path = project_dir.join("escape.txt");
            std::os::unix::fs::symlink(&outside_file, &link_path).unwrap();
            let err = root.resolve_existing("escape.txt").unwrap_err();
            assert!(matches!(err, PathError::EscapesRoot(_)));
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;

            let link_file = project_dir.join("escape.txt");
            match std::os::windows::fs::symlink_file(&outside_file, &link_file) {
                Ok(()) => {
                    let err = root.resolve_existing("escape.txt").unwrap_err();
                    assert!(matches!(err, PathError::EscapesRoot(_)));
                }
                Err(err) if err.raw_os_error() == Some(1314) => {
                    // Without Developer Mode / Admin on Windows, file symlinks return
                    // ERROR_PRIVILEGE_NOT_HELD (1314), whereas NTFS directory junctions
                    // work for standard users and exercise the exact same canonicalize guard.
                    let junction_dir = project_dir.join("escape_dir");
                    let output = std::process::Command::new("cmd")
                        .args(["/C", "mklink", "/J"])
                        .arg(&junction_dir)
                        .arg(&outside_dir)
                        .creation_flags(CREATE_NO_WINDOW)
                        .output()
                        .expect("failed to create NTFS junction for symlink escape test");
                    assert!(
                        output.status.success(),
                        "mklink /J failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );

                    let err = root.resolve_existing("escape_dir/secret.txt").unwrap_err();
                    assert!(matches!(err, PathError::EscapesRoot(_)));

                    // Clean up junction before TestDir::drop runs.
                    let _ = fs::remove_dir(&junction_dir);
                }
                Err(err) => panic!("unexpected symlink_file error: {err}"),
            }
        }
    }

    #[test]
    fn ensure_within_root_rejects_sibling_prefix_collision() {
        let root = Path::new(r"C:\work\proj");
        let sibling = Path::new(r"C:\work\proj-evil\secret.txt");
        let req = RelPath::normalize("secret.txt").unwrap();
        assert!(matches!(
            ensure_within_root(root, sibling, &req),
            Err(PathError::EscapesRoot(_))
        ));
    }

    #[test]
    fn resolve_for_write_allows_new_nested_file_and_blocks_sensitive_and_traversal() {
        let sandbox = TestDir::new("write");
        let project_dir = sandbox.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();
        let root = ProjectRoot::new(&project_dir).unwrap();

        let (abs, rel) = root.resolve_for_write(".klens/config.toml").unwrap();
        assert_eq!(rel.as_str(), ".klens/config.toml");
        assert!(abs.starts_with(root.root()));

        assert!(matches!(
            root.resolve_for_write("../escape.toml"),
            Err(PathError::TraversalAttempt(_))
        ));
        assert!(matches!(
            root.resolve_for_write(".env.local"),
            Err(PathError::SensitiveFileBlocked(_))
        ));
    }

    #[test]
    fn write_atomic_creates_and_overwrites_without_leaving_temp_files() {
        let dir = TestDir::new("atomic");
        let target = dir.path().join("nested/config.toml");

        write_atomic(&target, b"mode = \"active\"\n").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "mode = \"active\"\n");

        write_atomic(&target, b"mode = \"read_only\"\n").unwrap();
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "mode = \"read_only\"\n"
        );

        let entries: Vec<_> = fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "config.toml");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_keeps_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("klens-mode-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.json");
        fs::write(&target, "{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

        write_atomic(&target, b"{\"a\":1}").unwrap();
        let backup = dir.join("config.json.bak");
        write_atomic_with_mode_of(&backup, b"{}", &target).unwrap();

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let (target_mode, backup_mode) = (mode(&target), mode(&backup));
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(target_mode, 0o600);
        assert_eq!(backup_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_private_creates_owner_only_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("private-mode");
        let target = dir.path().join("runs/run.log");

        write_atomic_private(&target, b"ghp_secret raw output").unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // Replacing a world-readable file still yields an owner-only file.
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic_private(&target, b"again").unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&target).unwrap(), "again");
    }

    #[test]
    fn write_atomic_private_writes_content_without_temp_leftovers() {
        let dir = TestDir::new("private-content");
        let target = dir.path().join("run.log");
        write_atomic_private(&target, b"one").unwrap();
        write_atomic_private(&target, b"two").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "two");
        let count = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 1);
    }

    #[test]
    fn network_and_device_paths_are_never_plain_local() {
        for p in [
            r"\\192.0.2.1\share\x.rs",
            "//192.0.2.1/share/x.rs",
            r"\\?\UNC\192.0.2.1\share\x.rs",
            "//?/UNC/192.0.2.1/share/x.rs",
            r"\\.\pipe\x",
            r"\/192.0.2.1/share",
            r"/\192.0.2.1\share",
        ] {
            assert!(!is_plain_local_absolute(p), "{p} must not be local");
            assert!(is_network_or_device_path(p), "{p} must be a network path");
        }
    }

    #[test]
    fn local_drive_and_relative_paths_are_not_network_paths() {
        for p in [r"C:\x\y.rs", "C:/x/y.rs", r"\\?\C:\x\y.rs", "//?/C:/x/y.rs"] {
            assert!(is_plain_local_absolute(p), "{p} must be local");
            assert!(!is_network_or_device_path(p), "{p} is not a network path");
        }
        for p in ["src/lib.rs", ".", "/home/u/p", r"\x"] {
            assert!(!is_network_or_device_path(p), "{p} is not a network path");
        }
        assert_eq!(is_plain_local_absolute("/home/u/p"), !cfg!(windows));
        assert!(!is_plain_local_absolute("src/lib.rs"));
    }
}
