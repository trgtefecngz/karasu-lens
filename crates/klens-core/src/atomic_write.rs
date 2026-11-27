//! Atomic file replacement (temporary sibling file + rename) with Unix permission handling.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::PathError;

static ATOMIC_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let seq = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "klens-atomic-test-{label}-{}-{seq}",
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
}
