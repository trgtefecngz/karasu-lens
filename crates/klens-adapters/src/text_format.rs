//! UTF-8 BOM, CRLF/LF preservation, surgical marker blocks, backups, and dry-run file planning.
//!
//! Leaf module with zero upward crate dependencies so the module graph stays strictly acyclic.

use std::fs;
use std::path::{Path, PathBuf};

use klens_core::time::UtcParts;
use klens_core::{KlensError, write_atomic};

use crate::error::AdapterError;

/// Standard UTF-8 Byte Order Mark (`U+FEFF`).
pub const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Detected encoding & line-ending metadata of a text file so edits preserve
/// original Windows CRLF/LF style and UTF-8 BOM byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TextFormat {
    pub has_bom: bool,
    pub uses_crlf: bool,
}

impl TextFormat {
    /// Detect BOM and CRLF/LF format and return normalized LF text.
    pub fn decode(path: &Path, bytes: &[u8]) -> Result<(Self, String), AdapterError> {
        let (has_bom, body_bytes) = if let Some(rest) = bytes.strip_prefix(UTF8_BOM) {
            (true, rest)
        } else {
            (false, bytes)
        };

        let raw_text =
            std::str::from_utf8(body_bytes).map_err(|err| AdapterError::InvalidUtf8 {
                path: path.to_path_buf(),
                reason: err.to_string(),
            })?;

        let uses_crlf = raw_text.contains("\r\n");
        let normalized = raw_text.replace("\r\n", "\n");
        Ok((Self { has_bom, uses_crlf }, normalized))
    }

    /// Encode normalized LF text back into raw bytes preserving BOM and CRLF/LF.
    pub fn encode(self, normalized_lf: &str) -> Vec<u8> {
        let clean = normalized_lf.replace("\r\n", "\n");
        let rendered = if self.uses_crlf {
            clean.replace('\n', "\r\n")
        } else {
            clean
        };

        let mut out = Vec::with_capacity(rendered.len() + if self.has_bom { 3 } else { 0 });
        if self.has_bom {
            out.extend_from_slice(UTF8_BOM);
        }
        out.extend_from_slice(rendered.as_bytes());
        out
    }
}

/// Comment marker delimiters used to isolate `klens`-managed sections inside user files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerStyle {
    /// Markdown / HTML comment markers (`<!-- klens:start -->` ... `<!-- klens:end -->`).
    Html,
    /// Line-comment markers for `.gitignore` (`# klens:start` ... `# klens:end`).
    Hash,
}

impl MarkerStyle {
    pub const fn start_marker(self) -> &'static str {
        match self {
            Self::Html => "<!-- klens:start -->",
            Self::Hash => "# klens:start",
        }
    }

    pub const fn end_marker(self) -> &'static str {
        match self {
            Self::Html => "<!-- klens:end -->",
            Self::Hash => "# klens:end",
        }
    }
}

/// Byte range `[start, end)` of a marked block in normalized LF text.
///
/// Both offsets are guaranteed to fall on valid UTF-8 character boundaries because they
/// are computed strictly from `str` line boundaries.
fn find_marker_span(
    path: &Path,
    normalized_lf: &str,
    style: MarkerStyle,
) -> Result<Option<(usize, usize)>, AdapterError> {
    let start_tok = style.start_marker();
    let end_tok = style.end_marker();

    let mut offset = 0usize;
    let mut start_pos: Option<usize> = None;

    for segment in normalized_lf.split_inclusive('\n') {
        let line_trimmed = segment.trim_end_matches('\n').trim();
        let next_offset = offset + segment.len();

        if line_trimmed == start_tok {
            if start_pos.is_some() {
                return Err(AdapterError::MalformedMarkerBlock {
                    path: path.to_path_buf(),
                    reason: format!("duplicate `{start_tok}` before closing `{end_tok}`"),
                });
            }
            start_pos = Some(offset);
        } else if line_trimmed == end_tok {
            let Some(begin) = start_pos else {
                return Err(AdapterError::MalformedMarkerBlock {
                    path: path.to_path_buf(),
                    reason: format!("found `{end_tok}` without matching `{start_tok}`"),
                });
            };
            return Ok(Some((begin, next_offset)));
        }

        offset = next_offset;
    }

    if start_pos.is_some() {
        return Err(AdapterError::MalformedMarkerBlock {
            path: path.to_path_buf(),
            reason: format!("unclosed `{start_tok}` without matching `{end_tok}`"),
        });
    }

    Ok(None)
}

/// Returns `true` if `normalized_lf` contains a valid `klens` marked block of `style`.
pub fn has_marked_block(path: &Path, normalized_lf: &str, style: MarkerStyle) -> bool {
    matches!(find_marker_span(path, normalized_lf, style), Ok(Some(_)))
}

/// Insert or idempotently replace a marked block inside normalized LF text.
///
/// Preserves all user lines outside the markers without touching trailing newline conventions.
pub fn upsert_marked_block(
    path: &Path,
    existing_lf: Option<&str>,
    style: MarkerStyle,
    body: &str,
) -> Result<String, AdapterError> {
    let clean_body = body.replace("\r\n", "\n");
    let trimmed_body = clean_body.trim_matches('\n');
    let block = format!(
        "{}\n{}\n{}\n",
        style.start_marker(),
        trimmed_body,
        style.end_marker()
    );

    let Some(existing) = existing_lf else {
        return Ok(block);
    };
    if existing.is_empty() {
        return Ok(block);
    }

    if let Some((start, end)) = find_marker_span(path, existing, style)? {
        let mut updated = String::with_capacity(existing.len() + block.len());
        updated.push_str(&existing[..start]);
        updated.push_str(&block);
        updated.push_str(&existing[end..]);
        return Ok(updated);
    }

    // Append with a single `\n` separator so `remove_marked_block` restores both
    // trailing-newline and no-trailing-newline originals byte-for-byte.
    let mut updated = String::with_capacity(existing.len() + block.len() + 1);
    updated.push_str(existing);
    updated.push('\n');
    updated.push_str(&block);
    Ok(updated)
}

/// Surgically remove a marked block from normalized LF text.
///
/// Returns:
/// - `Ok(None)` if no marked block exists (file does not need changes).
/// - `Ok(Some(remaining))` with the exact remaining user content (`""` when nothing remains).
pub fn remove_marked_block(
    path: &Path,
    existing_lf: &str,
    style: MarkerStyle,
) -> Result<Option<String>, AdapterError> {
    let Some((start, end)) = find_marker_span(path, existing_lf, style)? else {
        return Ok(None);
    };

    let mut before = &existing_lf[..start];
    let mut after = &existing_lf[end..];

    if !before.is_empty() {
        if let Some(stripped) = before.strip_suffix('\n') {
            before = stripped;
        }
    } else if let Some(stripped) = after.strip_prefix('\n') {
        after = stripped;
    }

    let mut out = String::with_capacity(before.len() + after.len());
    out.push_str(before);
    out.push_str(after);
    Ok(Some(out))
}

/// Result of planning or applying a file write/delete operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOpOutcome {
    /// Content on disk was already identical; no write occurred.
    Unchanged,
    /// File was created or updated (or would be under `dry_run`).
    Written {
        dry_run: bool,
        backup_path: Option<PathBuf>,
    },
    /// File was deleted (or would be under `dry_run`).
    Deleted {
        dry_run: bool,
        backup_path: Option<PathBuf>,
    },
}

impl FileOpOutcome {
    /// Whether this operation changed (or would change under `dry_run`) the filesystem.
    pub fn is_planned_change(&self) -> bool {
        !matches!(self, Self::Unchanged)
    }

    /// Whether bytes were actually mutated on disk.
    pub fn mutated_disk(&self) -> bool {
        matches!(
            self,
            Self::Written { dry_run: false, .. } | Self::Deleted { dry_run: false, .. }
        )
    }

    /// Optional backup file path created (or planned under `dry_run`).
    pub fn backup_path(&self) -> Option<&Path> {
        match self {
            Self::Unchanged => None,
            Self::Written { backup_path, .. } | Self::Deleted { backup_path, .. } => {
                backup_path.as_deref()
            }
        }
    }
}

/// Compute a deterministic timestamped backup path beside `target`.
pub fn backup_path_for(target: &Path) -> PathBuf {
    let stamp = UtcParts::now().to_compact_stamp();
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    let backup_name = format!("{name}.klens-backup-{stamp}.bak");
    target
        .parent()
        .map_or_else(|| PathBuf::from(&backup_name), |p| p.join(&backup_name))
}

/// Read an existing text file and decode its [`TextFormat`] + normalized LF body.
/// Returns `Ok(None)` if the file does not exist.
pub fn read_text_file(path: &Path) -> Result<Option<(TextFormat, String, Vec<u8>)>, AdapterError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|source| AdapterError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let (fmt, normalized) = TextFormat::decode(path, &bytes)?;
    Ok(Some((fmt, normalized, bytes)))
}

/// Refuse to replace a file that is a symbolic link: the atomic rename would turn the link into
/// a plain copy (dotfile managers link `~/.claude/settings.json`, `CLAUDE.md`, ...), and in a
/// project a link could point outside it. The user edits such a file by hand instead.
fn refuse_file_link(target: &Path) -> Result<(), AdapterError> {
    if fs::symlink_metadata(target).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(AdapterError::LinkedProjectPath {
            path: target.to_path_buf(),
        });
    }
    Ok(())
}

/// Atomically write `new_bytes` to `target` if different from existing contents.
///
/// Guarantees:
/// - Under `dry_run == true`, writes ZERO bytes (neither target nor backup).
/// - When `backup_existing == true` and `target` already exists with different bytes,
///   atomically saves an exact byte-for-byte backup first.
pub fn apply_file_write(
    target: &Path,
    new_bytes: &[u8],
    dry_run: bool,
    backup_existing: bool,
) -> Result<FileOpOutcome, AdapterError> {
    refuse_file_link(target)?;
    let existing_bytes = if target.exists() {
        Some(fs::read(target).map_err(|source| AdapterError::Io {
            path: target.to_path_buf(),
            source,
        })?)
    } else {
        None
    };

    if existing_bytes.as_deref() == Some(new_bytes) {
        return Ok(FileOpOutcome::Unchanged);
    }

    let backup_path = if backup_existing && existing_bytes.is_some() {
        Some(backup_path_for(target))
    } else {
        None
    };

    if dry_run {
        return Ok(FileOpOutcome::Written {
            dry_run: true,
            backup_path,
        });
    }

    if let (Some(orig), Some(bak)) = (&existing_bytes, &backup_path) {
        klens_core::write_atomic_with_mode_of(bak, orig, target).map_err(KlensError::from)?;
    }

    write_atomic(target, new_bytes).map_err(KlensError::from)?;
    Ok(FileOpOutcome::Written {
        dry_run: false,
        backup_path,
    })
}

/// Delete `target` if it exists (strictly no-op under `dry_run == true`).
pub fn apply_file_delete(
    target: &Path,
    dry_run: bool,
    backup_existing: bool,
) -> Result<FileOpOutcome, AdapterError> {
    if !target.exists() {
        return Ok(FileOpOutcome::Unchanged);
    }

    let backup_path = if backup_existing {
        Some(backup_path_for(target))
    } else {
        None
    };

    if dry_run {
        return Ok(FileOpOutcome::Deleted {
            dry_run: true,
            backup_path,
        });
    }

    if let Some(bak) = &backup_path {
        let orig = fs::read(target).map_err(|source| AdapterError::Io {
            path: target.to_path_buf(),
            source,
        })?;
        klens_core::write_atomic_with_mode_of(bak, &orig, target).map_err(KlensError::from)?;
    }

    fs::remove_file(target).map_err(|source| AdapterError::Io {
        path: target.to_path_buf(),
        source,
    })?;
    Ok(FileOpOutcome::Deleted {
        dry_run: false,
        backup_path,
    })
}

/// How many times a host config edit is recomputed when the host rewrites the file mid-edit.
pub const CONFIG_EDIT_ATTEMPTS: usize = 3;

/// Run a read-modify-write `edit` again (from a fresh read) when another program changed
/// the file in between, up to [`CONFIG_EDIT_ATTEMPTS`] times.
pub fn retry_config_edit<T>(
    mut edit: impl FnMut() -> Result<T, AdapterError>,
) -> Result<T, AdapterError> {
    for _ in 1..CONFIG_EDIT_ATTEMPTS {
        match edit() {
            Err(AdapterError::ConfigChangedDuringUpdate { .. }) => continue,
            other => return other,
        }
    }
    edit()
}

/// Write a host-owned config file (e.g. `~/.claude.json`) that klens edited in memory.
///
/// `expected_original` is the exact content the edit was computed from (`None` = the file did
/// not exist). Host applications rewrite these files at any time; if the file no longer
/// matches, nothing is written and [`AdapterError::ConfigChangedDuringUpdate`] is returned so
/// the caller can redo the edit on top of the newer content instead of overwriting it.
/// `always_write` writes even when the bytes are identical (`--force`).
pub fn apply_config_write(
    target: &Path,
    expected_original: Option<&[u8]>,
    new_bytes: &[u8],
    dry_run: bool,
    backup_existing: bool,
    always_write: bool,
) -> Result<FileOpOutcome, AdapterError> {
    refuse_file_link(target)?;
    let current = read_optional_bytes(target)?;
    ensure_unchanged(target, expected_original, current.as_deref())?;

    if !always_write && current.as_deref() == Some(new_bytes) {
        return Ok(FileOpOutcome::Unchanged);
    }
    let backup_path = (backup_existing && current.is_some()).then(|| backup_path_for(target));
    if dry_run {
        return Ok(FileOpOutcome::Written {
            dry_run: true,
            backup_path,
        });
    }
    if let (Some(orig), Some(bak)) = (&current, &backup_path) {
        klens_core::write_atomic_with_mode_of(bak, orig, target).map_err(KlensError::from)?;
    }

    before_config_commit(target);
    let latest = read_optional_bytes(target)?;
    ensure_unchanged(target, expected_original, latest.as_deref())?;
    write_atomic(target, new_bytes).map_err(KlensError::from)?;
    Ok(FileOpOutcome::Written {
        dry_run: false,
        backup_path,
    })
}

/// Delete a host-owned config file, with the same "unchanged since read" guarantee as
/// [`apply_config_write`].
pub fn apply_config_delete(
    target: &Path,
    expected_original: &[u8],
    dry_run: bool,
    backup_existing: bool,
) -> Result<FileOpOutcome, AdapterError> {
    let current = read_optional_bytes(target)?;
    ensure_unchanged(target, Some(expected_original), current.as_deref())?;
    if !dry_run {
        before_config_commit(target);
        let latest = read_optional_bytes(target)?;
        ensure_unchanged(target, Some(expected_original), latest.as_deref())?;
    }
    apply_file_delete(target, dry_run, backup_existing)
}

fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>, AdapterError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(AdapterError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn ensure_unchanged(
    target: &Path,
    expected: Option<&[u8]>,
    actual: Option<&[u8]>,
) -> Result<(), AdapterError> {
    if expected == actual {
        Ok(())
    } else {
        Err(AdapterError::ConfigChangedDuringUpdate {
            path: target.to_path_buf(),
        })
    }
}

#[cfg(test)]
pub(crate) type ConfigCommitHook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    /// Test seam: runs right before a config file is committed, to simulate a host
    /// application writing the same file at that moment.
    pub(crate) static BEFORE_CONFIG_COMMIT: std::cell::RefCell<Option<ConfigCommitHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn before_config_commit(target: &Path) {
    BEFORE_CONFIG_COMMIT.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(target);
        }
    });
}

#[cfg(not(test))]
fn before_config_commit(_target: &Path) {}

/// Upsert a marked block into `target` preserving UTF-8 BOM, CRLF/LF, and user lines.
pub fn upsert_marked_file(
    target: &Path,
    style: MarkerStyle,
    body: &str,
    dry_run: bool,
    force: bool,
) -> Result<FileOpOutcome, AdapterError> {
    let existing = read_text_file(target)?;
    let (fmt, existing_lf, existing_bytes) = match existing {
        Some((fmt, lf, bytes)) => (fmt, Some(lf), Some(bytes)),
        None => (TextFormat::default(), None, None),
    };

    let updated_lf = upsert_marked_block(target, existing_lf.as_deref(), style, body)?;
    let encoded = fmt.encode(&updated_lf);

    if !force && existing_bytes.as_deref() == Some(encoded.as_slice()) {
        return Ok(FileOpOutcome::Unchanged);
    }

    if dry_run {
        return Ok(FileOpOutcome::Written {
            dry_run: true,
            backup_path: None,
        });
    }

    write_atomic(target, &encoded).map_err(KlensError::from)?;
    Ok(FileOpOutcome::Written {
        dry_run: false,
        backup_path: None,
    })
}

/// Surgically remove a marked block from `target`, deleting the file if nothing remains.
/// Preserves UTF-8 BOM, CRLF/LF, and all user lines outside the block.
pub fn remove_marked_file(
    target: &Path,
    style: MarkerStyle,
    dry_run: bool,
    backup_existing: bool,
) -> Result<FileOpOutcome, AdapterError> {
    let Some((fmt, existing_lf, _bytes)) = read_text_file(target)? else {
        return Ok(FileOpOutcome::Unchanged);
    };

    let Some(remaining_lf) = remove_marked_block(target, &existing_lf, style)? else {
        return Ok(FileOpOutcome::Unchanged);
    };

    if remaining_lf.is_empty() {
        return apply_file_delete(target, dry_run, backup_existing);
    }

    let encoded = fmt.encode(&remaining_lf);
    apply_file_write(target, &encoded, dry_run, backup_existing)
}

/// Remove an empty directory tree bottom-up up to (but never deleting) `stop_at`.
///
/// If `start_dir` no longer exists, walks upward to the deepest existing ancestor strictly
/// beneath `stop_at` so empty parent directories (such as `.claude/skills` and `.claude`)
/// are still pruned safely. Never follows or removes symlinks.
pub fn remove_empty_parents(start_dir: &Path, stop_at: &Path, dry_run: bool) {
    if dry_run {
        return;
    }
    let mut cur = start_dir;
    while cur != stop_at && cur.starts_with(stop_at) {
        match fs::symlink_metadata(cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                    return;
                }
                break;
            }
            Err(_) => {
                let Some(parent) = cur.parent() else {
                    return;
                };
                cur = parent;
            }
        }
    }
    while cur != stop_at && cur.starts_with(stop_at) {
        let Ok(meta) = fs::symlink_metadata(cur) else {
            break;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            break;
        }
        match fs::read_dir(cur) {
            Ok(mut entries) => {
                if entries.next().is_some() || fs::remove_dir(cur).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
        let Some(parent) = cur.parent() else {
            break;
        };
        cur = parent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_utf8_bom_crlf_and_turkish_user_lines_roundtrip() {
        let p = Path::new("AGENTS.md");
        let original = "\u{FEFF}# Proje Kuralları (ğüşiöç 🚀)\r\nSatır iki.\r\n";
        let (fmt, lf) = TextFormat::decode(p, original.as_bytes()).unwrap();
        assert!(fmt.has_bom);
        assert!(fmt.uses_crlf);

        let with_block =
            upsert_marked_block(p, Some(&lf), MarkerStyle::Html, "klens body").unwrap();
        let encoded_with = fmt.encode(&with_block);
        assert!(encoded_with.starts_with(UTF8_BOM));
        let text_with = std::str::from_utf8(&encoded_with[3..]).unwrap();
        assert!(
            text_with.contains("\r\n<!-- klens:start -->\r\nklens body\r\n<!-- klens:end -->\r\n")
        );

        // Second upsert is byte-for-byte idempotent.
        let (fmt2, lf2) = TextFormat::decode(p, &encoded_with).unwrap();
        let with_block_again =
            upsert_marked_block(p, Some(&lf2), MarkerStyle::Html, "klens body").unwrap();
        assert_eq!(fmt2.encode(&with_block_again), encoded_with);

        // Removal restores exact original bytes!
        let removed = remove_marked_block(p, &lf2, MarkerStyle::Html)
            .unwrap()
            .unwrap();
        assert_eq!(fmt2.encode(&removed), original.as_bytes());
    }

    #[test]
    fn preserves_no_trailing_newline_file_byte_for_byte() {
        let p = Path::new(".gitignore");
        let original = "target/\n*.log";
        let with_block = upsert_marked_block(
            p,
            Some(original),
            MarkerStyle::Hash,
            ".klens/cache/\n.klens/runs/",
        )
        .unwrap();
        let removed = remove_marked_block(p, &with_block, MarkerStyle::Hash)
            .unwrap()
            .unwrap();
        assert_eq!(removed, original);
    }

    #[test]
    fn rejects_unclosed_marker_block() {
        let p = Path::new("AGENTS.md");
        let broken = "user\n<!-- klens:start -->\norphan\n";
        let err = upsert_marked_block(p, Some(broken), MarkerStyle::Html, "new").unwrap_err();
        assert!(matches!(err, AdapterError::MalformedMarkerBlock { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn linked_config_files_are_never_replaced() {
        let dir = std::env::temp_dir().join(format!("klens-link-write-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real-settings.json");
        let link = dir.join("settings.json");
        fs::write(&real, "{}\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let config = apply_config_write(&link, Some(b"{}\n"), b"{\"a\":1}\n", false, false, false);
        let plain = apply_file_write(&link, b"x\n", false, false);
        let still_link = fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink();
        let real_text = fs::read_to_string(&real).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert!(
            matches!(config, Err(AdapterError::LinkedProjectPath { .. })),
            "{config:?}"
        );
        assert!(
            matches!(plain, Err(AdapterError::LinkedProjectPath { .. })),
            "{plain:?}"
        );
        assert!(still_link);
        assert_eq!(real_text, "{}\n");
    }
}
