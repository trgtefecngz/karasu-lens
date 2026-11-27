//! Turning a path typed by a user or an AI agent into a project-relative [`RelPath`].
//!
//! Agents (Claude Code, Codex) usually pass absolute paths. Rejecting them made the first call
//! of a session fail; instead, an absolute path inside the project is converted, and one
//! outside it is refused with a message that names the project root.

use std::fs;
use std::path::Path;

use crate::error::PathError;
use crate::paths::{ProjectRoot, RelPath};

impl ProjectRoot {
    /// Accept a relative path, or an absolute path inside this project, as a [`RelPath`].
    ///
    /// Absolute paths are matched against the project root first lexically (`/` or `\`,
    /// `\\?\` prefix, case-insensitive on Windows), then — for existing files reached through
    /// a differently spelled path such as an 8.3 short name — by canonicalizing. Anything that
    /// does not end up inside the root is refused; the usual confinement checks still apply to
    /// the returned path.
    pub fn relative_input(&self, raw: &str) -> Result<RelPath, PathError> {
        let trimmed = raw.trim();
        if !looks_absolute(trimmed) {
            return RelPath::normalize(trimmed);
        }

        let root = normalize_separators(&self.root().to_string_lossy());
        let candidate = normalize_separators(trimmed);
        if let Some(rest) = strip_root(&candidate, &root) {
            return RelPath::normalize(if rest.is_empty() { "." } else { rest });
        }

        if let Ok(canonical) = fs::canonicalize(Path::new(trimmed))
            && let Ok(rest) = canonical.strip_prefix(self.root())
        {
            return RelPath::from_relative_path(rest);
        }

        Err(PathError::OutsideProject {
            path: trimmed.to_string(),
            root: root.clone(),
        })
    }
}

impl ProjectRoot {
    /// Like [`ProjectRoot::relative_input`], but the project root itself (`.`, empty, or its
    /// absolute path, with or without a trailing separator) is `None`: "the whole project",
    /// for tools that accept a folder (`klens_outline`, `klens_map` focus).
    pub fn relative_input_or_root(&self, raw: &str) -> Result<Option<RelPath>, PathError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "." {
            return Ok(None);
        }
        if looks_absolute(trimmed) {
            let root = normalize_separators(&self.root().to_string_lossy());
            if strip_root(&normalize_separators(trimmed), &root) == Some("") {
                return Ok(None);
            }
        }
        self.relative_input(trimmed).map(Some)
    }
}

fn looks_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with('/')
        || path.starts_with('\\')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

/// Forward slashes, no `\\?\` / `//?/` prefix, no trailing slash.
fn normalize_separators(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let unprefixed = slashed.strip_prefix("//?/").unwrap_or(&slashed);
    unprefixed.trim_end_matches('/').to_string()
}

fn strip_root<'a>(candidate: &'a str, root: &str) -> Option<&'a str> {
    let head = candidate.get(..root.len())?;
    let same = if cfg!(windows) {
        head.eq_ignore_ascii_case(root)
    } else {
        head == root
    };
    if !same {
        return None;
    }
    let rest = &candidate[root.len()..];
    if rest.is_empty() {
        Some("")
    } else {
        rest.strip_prefix('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> (std::path::PathBuf, ProjectRoot) {
        let dir = std::env::temp_dir().join(format!(
            "klens-input-path-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src").join("lib.rs"), "pub fn a() {}\n").unwrap();
        let root = ProjectRoot::new(&dir).unwrap();
        (dir, root)
    }

    #[test]
    fn absolute_paths_inside_the_project_become_relative() {
        let (dir, root) = project();
        let canonical = root.root().to_string_lossy().into_owned();
        let plain = canonical.trim_start_matches(r"\\?\").to_string();
        let inputs = [
            format!("{plain}/src/lib.rs"),
            format!("{}/src/lib.rs", plain.replace('\\', "/")),
            format!(r"{plain}\src\lib.rs"),
            format!(r"\\?\{plain}\src\lib.rs"),
            "src/lib.rs".to_string(),
        ];
        let results: Vec<String> = inputs
            .iter()
            .map(|input| {
                root.relative_input(input)
                    .unwrap_or_else(|e| panic!("{input}: {e}"))
                    .as_str()
                    .to_string()
            })
            .collect();
        let _ = fs::remove_dir_all(&dir);
        for (input, got) in inputs.iter().zip(&results) {
            assert_eq!(got, "src/lib.rs", "input {input}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_match_case_insensitively() {
        let (dir, root) = project();
        let upper = format!(
            "{}\\SRC\\lib.rs",
            root.root()
                .to_string_lossy()
                .trim_start_matches(r"\\?\")
                .to_uppercase()
        );
        let got = root.relative_input(&upper).map(|r| r.as_str().to_string());
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(got.unwrap(), "SRC/lib.rs");
    }

    #[test]
    fn absolute_paths_outside_the_project_are_refused_with_the_root_named() {
        let (dir, root) = project();
        let outside = std::env::temp_dir().join("somewhere-else").join("x.rs");
        let err = root
            .relative_input(&outside.to_string_lossy())
            .unwrap_err()
            .to_string();
        let root_shown = normalize_separators(&root.root().to_string_lossy());
        let _ = fs::remove_dir_all(&dir);
        assert!(err.contains(&root_shown), "{err}");
    }

    #[test]
    fn sibling_folder_with_the_same_prefix_is_outside() {
        let (dir, root) = project();
        let sibling = format!(
            "{}-other/src/lib.rs",
            normalize_separators(&root.root().to_string_lossy())
        );
        let res = root.relative_input(&sibling);
        let _ = fs::remove_dir_all(&dir);
        assert!(res.is_err(), "{res:?}");
    }
}
