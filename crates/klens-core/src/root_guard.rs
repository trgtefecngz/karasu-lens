//! Unsafe project-root guard (v0.3.2+).
//!
//! `klens` must never treat the user home directory, any parent of it, or a filesystem/drive
//! root (`C:\`, `/`) as a project root. Doing so indexes every personal file into a multi-GB
//! SQLite cache and widens what AI agents can read. It also collides with the user-global
//! `~/.klens/` directory, which otherwise looks like a project marker.
//!
//! [`crate::ProjectRoot::new`] enforces this guard, so the CLI, `klens mcp`, and the Web UI all
//! share the same rule.

use std::fs;
use std::path::{Path, PathBuf};

/// Return why a canonical directory is unsafe as a project root, or `None` if it is fine.
///
/// Uses the current user's home directory from `USERPROFILE` / `HOME`.
pub fn unsafe_project_root_reason(canonical_dir: &Path) -> Option<&'static str> {
    unsafe_project_root_reason_with_home(canonical_dir, canonical_home_dir().as_deref())
}

/// Pure variant of [`unsafe_project_root_reason`] with an explicit canonical home directory.
pub fn unsafe_project_root_reason_with_home(
    canonical_dir: &Path,
    canonical_home: Option<&Path>,
) -> Option<&'static str> {
    if canonical_dir.parent().is_none() {
        return Some("it is a filesystem or drive root");
    }
    if let Some(home) = canonical_home {
        if canonical_dir == home {
            return Some("it is the user home directory");
        }
        if home.starts_with(canonical_dir) {
            return Some("it contains the user home directory");
        }
    }
    None
}

/// Canonicalize `dir` and report whether it is unsafe as a project root.
///
/// Returns `false` when `dir` cannot be canonicalized (the caller reports that error).
pub fn is_unsafe_project_root(dir: &Path) -> bool {
    fs::canonicalize(dir)
        .map(|canonical| unsafe_project_root_reason(&canonical).is_some())
        .unwrap_or(false)
}

fn canonical_home_dir() -> Option<PathBuf> {
    let raw = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    if raw.is_empty() {
        return None;
    }
    fs::canonicalize(PathBuf::from(raw)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_layout(label: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "klens-root-guard-unit-{label}-{}",
            std::process::id()
        ));
        let home = base.join("home");
        fs::create_dir_all(home.join("Projects").join("app")).unwrap();
        (
            fs::canonicalize(&base).unwrap(),
            fs::canonicalize(&home).unwrap(),
        )
    }

    #[test]
    fn filesystem_root_is_always_unsafe() {
        let (base, home) = temp_layout("fsroot");
        let mut root = base.clone();
        while let Some(parent) = root.parent() {
            root = parent.to_path_buf();
        }
        assert!(unsafe_project_root_reason_with_home(&root, Some(&home)).is_some());
        assert!(unsafe_project_root_reason_with_home(&root, None).is_some());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn home_and_its_parents_are_unsafe_but_children_and_siblings_are_fine() {
        let (base, home) = temp_layout("home");
        assert!(unsafe_project_root_reason_with_home(&home, Some(&home)).is_some());
        assert!(unsafe_project_root_reason_with_home(&base, Some(&home)).is_some());

        let child = home.join("Projects").join("app");
        assert_eq!(
            unsafe_project_root_reason_with_home(&child, Some(&home)),
            None
        );

        let sibling = base.join("work");
        fs::create_dir_all(&sibling).unwrap();
        let sibling = fs::canonicalize(&sibling).unwrap();
        assert_eq!(
            unsafe_project_root_reason_with_home(&sibling, Some(&home)),
            None
        );

        // A name that merely shares a prefix with home is NOT a parent of it.
        let lookalike = fs::canonicalize(base.join("home"))
            .unwrap()
            .with_extension("bak");
        fs::create_dir_all(&lookalike).unwrap();
        let lookalike = fs::canonicalize(&lookalike).unwrap();
        assert_eq!(
            unsafe_project_root_reason_with_home(&lookalike, Some(&home)),
            None
        );
        let _ = fs::remove_dir_all(&base);
    }
}
