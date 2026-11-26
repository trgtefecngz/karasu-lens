//! Symbolic link / junction checks for klens state and project-local host folders.

use std::fs;
use std::path::{Path, PathBuf};

/// First existing component of `rel` (below `root`) that is a symbolic link or junction.
///
/// Used before writing project-local files whose parent folders could be links (a
/// Linux/macOS clone can carry symlinks; on Windows a junction can be made without privileges).
pub fn first_linked_component(root: &Path, rel: &str) -> Option<PathBuf> {
    let mut current = root.to_path_buf();
    for part in rel
        .split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != ".")
    {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Some(current),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

/// Any link at `.klens` or inside it (bounded walk: depth 4, 20 000 entries).
pub(crate) fn linked_entry_in_state_dir(root: &Path) -> Option<PathBuf> {
    if let Some(link) = first_linked_component(root, ".klens") {
        return Some(link);
    }
    let state_dir = root.join(".klens");
    if !state_dir.is_dir() {
        return None;
    }
    let mut stack = vec![(state_dir, 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > 20_000 {
                return None;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                return Some(entry.path());
            }
            if file_type.is_dir() && depth < 4 {
                stack.push((entry.path(), depth + 1));
            }
        }
    }
    None
}
