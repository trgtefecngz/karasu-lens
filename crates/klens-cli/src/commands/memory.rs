//! CLI subcommands for `.klens/memory/` (`klens memory list|get|search|add|update|delete|verify|refresh|export`).

use std::fs;
use std::path::{Component, Path, PathBuf};

use clap::{Args, Subcommand};
use klens_adapters::clean_binary_path_string;
use klens_core::{ProvenanceEnvelope, RelPath, is_sensitive_path, write_atomic};
use klens_mcp::LazyCodeSymbolResolver;
use klens_memory::{
    AddMemoryRequest, AnchorSpec, MemoryError, MemoryExportFormat, MemoryExportRequest, MemoryKind,
    MemoryStatus, UpdateMemoryRequest, add_memory, delete_memory, export_memory,
    format_memory_batch_refresh_text, format_memory_delete_text, format_memory_export_text,
    format_memory_get_text, format_memory_index_text, format_memory_search_text,
    format_memory_verify_text, format_memory_write_text, get_memory, list_memory_index,
    refresh_memories, refresh_memory, search_memory, trust_label, update_memory, verify_all_notes,
};
use serde_json::json;

use super::common::{CliError, resolve_project_root};

#[derive(Debug, Args)]
pub(crate) struct MemoryArgs {
    #[command(subcommand)]
    pub action: MemoryAction,
}

#[derive(Debug, Subcommand)]
pub(crate) enum MemoryAction {
    /// Progressive-disclosure index of memory notes (metadata + live BLAKE3 trust, never leaks bodies).
    #[command(visible_alias = "index")]
    List(MemoryListArgs),
    /// Read a single memory note by ID with live BLAKE3 anchor verification.
    Get(MemoryGetArgs),
    /// Search memory notes deterministically via SQLite FTS5 (`unicode61`) across titles, tags, wikilinks, and bodies.
    Search(MemorySearchArgs),
    /// Create a new Obsidian-compatible Markdown memory note with BLAKE3 code anchors.
    Add(MemoryAddArgs),
    /// Update fields of an existing memory note (title, kind, status, tags, anchors, body).
    Update(MemoryUpdateArgs),
    /// Delete a memory note by ID from `.klens/memory/`.
    Delete(MemoryDeleteArgs),
    /// Verify BLAKE3 anchors of all notes in `.klens/memory/` and report any stale notes.
    Verify(MemoryVerifyArgs),
    /// Refresh BLAKE3 anchor hashes of one or all reviewed notes while preserving Markdown bodies verbatim.
    Refresh(MemoryRefreshArgs),
    /// Export verified & secret-redacted memory notes as unified Markdown or deterministic JSON.
    Export(MemoryExportArgs),
}

#[derive(Debug, Args)]
pub(crate) struct MemoryListArgs {
    /// Filter by note kind (`decision|bugfix|architecture|feedback|constraint`).
    #[arg(long)]
    pub kind: Option<String>,

    /// Filter by exact tag name (case-insensitive).
    #[arg(long)]
    pub tag: Option<String>,

    /// Show only stale notes whose BLAKE3 anchors changed or disappeared.
    #[arg(long)]
    pub stale_only: bool,

    /// Zero-footprint mode: never writes `.klens/cache/` into the target project.
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryGetArgs {
    /// Memory note identifier (e.g. `adr-001-chunk-save`).
    pub id: String,

    /// Zero-footprint mode: never writes `.klens/cache/` into the target project.
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MemorySearchArgs {
    /// Search query (keywords, error codes, tags, wikilinks, or paths).
    pub query: String,

    /// Optional kind filter (`decision|bugfix|architecture|feedback|constraint`).
    #[arg(long)]
    pub kind: Option<String>,

    /// Maximum hits to return (default 20).
    #[arg(long)]
    pub limit: Option<usize>,

    /// Zero-footprint mode: never writes `.klens/cache/` into the target project.
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryAddArgs {
    /// Human-readable title of the memory note.
    #[arg(long)]
    pub title: String,

    /// Optional explicit note ID (auto-slugified from kind + title when omitted).
    #[arg(long)]
    pub id: Option<String>,

    /// Note category (`decision|bugfix|architecture|feedback|constraint`).
    #[arg(long, default_value = "decision")]
    pub kind: String,

    /// Markdown body text.
    #[arg(long, conflicts_with = "body_file")]
    pub body: Option<String>,

    /// Read Markdown body text from a UTF-8 file.
    #[arg(long, conflicts_with = "body")]
    pub body_file: Option<PathBuf>,

    /// Code anchor (`<path>` or `<path>#<symbol>`), repeatable.
    #[arg(long = "anchor", value_name = "SPEC")]
    pub anchors: Vec<String>,

    /// Tag name (repeatable or comma-separated).
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryUpdateArgs {
    /// Existing memory note ID to update.
    pub id: String,

    /// Updated title.
    #[arg(long)]
    pub title: Option<String>,

    /// Updated kind (`decision|bugfix|architecture|feedback|constraint`).
    #[arg(long)]
    pub kind: Option<String>,

    /// Updated lifecycle status (`active|stale|archived`).
    #[arg(long)]
    pub status: Option<String>,

    /// Replacement Markdown body text.
    #[arg(long, conflicts_with = "body_file")]
    pub body: Option<String>,

    /// Read replacement Markdown body text from a UTF-8 file.
    #[arg(long, conflicts_with = "body")]
    pub body_file: Option<PathBuf>,

    /// Replace anchors with these `<path>` / `<path>#<symbol>` specs (repeatable).
    #[arg(long = "anchor", value_name = "SPEC", conflicts_with = "clear_anchors")]
    pub anchors: Vec<String>,

    /// Remove all anchors from this note.
    #[arg(long, conflicts_with = "anchors")]
    pub clear_anchors: bool,

    /// Replace tags with these values (repeatable or comma-separated).
    #[arg(long = "tag", value_name = "TAG", conflicts_with = "clear_tags")]
    pub tags: Vec<String>,

    /// Remove all tags from this note.
    #[arg(long, conflicts_with = "tags")]
    pub clear_tags: bool,

    /// Recompute current BLAKE3 hashes for existing anchors.
    #[arg(long)]
    pub refresh_anchors: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryDeleteArgs {
    /// Memory note ID to delete.
    pub id: String,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryVerifyArgs {
    /// Zero-footprint mode: never writes `.klens/cache/` into the target project.
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryRefreshArgs {
    /// Memory note ID whose BLAKE3 anchors should be refreshed.
    pub id: Option<String>,

    /// Refresh all notes in `.klens/memory/`.
    #[arg(long, conflicts_with = "id")]
    pub all: bool,

    /// With `--all`, refresh only currently STALE notes.
    #[arg(long, requires = "all")]
    pub stale_only: bool,

    /// Preview planned refreshes and broken anchors without writing a single byte to disk.
    #[arg(long)]
    pub dry_run: bool,

    /// Zero-footprint flag (fail-closed rejected for mutating refresh operations).
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryExportArgs {
    /// Export format (`md` or `json`).
    #[arg(long, default_value = "md")]
    pub format: String,

    /// Filter by note kind (`decision|bugfix|architecture|feedback|constraint`).
    #[arg(long)]
    pub kind: Option<String>,

    /// Filter by exact tag name (case-insensitive).
    #[arg(long)]
    pub tag: Option<String>,

    /// Export only stale notes whose BLAKE3 anchors changed or disappeared.
    #[arg(long)]
    pub stale_only: bool,

    /// Write exported output atomically to a file (forbidden inside project root when `--read-only`).
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Zero-footprint mode: never writes `.klens/cache/` or `--out` inside the target project.
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

pub(crate) fn run_memory_cmd(args: MemoryArgs) -> Result<String, CliError> {
    match args.action {
        MemoryAction::List(list_args) => {
            let project_root = resolve_project_root(None, list_args.root.as_deref())?;
            let kind = match list_args.kind {
                Some(ref k) => Some(MemoryKind::parse(k)?),
                None => None,
            };
            let mut resolver =
                LazyCodeSymbolResolver::new(&project_root, list_args.read_only, None);
            let env = list_memory_index(
                &project_root,
                kind,
                list_args.tag.as_deref(),
                list_args.stale_only,
                &mut resolver,
            )?;
            if list_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_memory_index_text(&env).trim_end().to_string())
            }
        }
        MemoryAction::Get(get_args) => {
            let project_root = resolve_project_root(None, get_args.root.as_deref())?;
            let mut resolver = LazyCodeSymbolResolver::new(&project_root, get_args.read_only, None);
            let env = get_memory(&project_root, &get_args.id, &mut resolver)?;
            if get_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_memory_get_text(&env).trim_end().to_string())
            }
        }
        MemoryAction::Search(search_args) => {
            let project_root = resolve_project_root(None, search_args.root.as_deref())?;
            let kind = match search_args.kind {
                Some(ref k) => Some(MemoryKind::parse(k)?),
                None => None,
            };
            let mut resolver =
                LazyCodeSymbolResolver::new(&project_root, search_args.read_only, None);
            let env = search_memory(
                &project_root,
                &search_args.query,
                kind,
                search_args.limit,
                &mut resolver,
            )?;
            if search_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_memory_search_text(&env).trim_end().to_string())
            }
        }
        MemoryAction::Add(add_args) => {
            let project_root = resolve_project_root(None, add_args.root.as_deref())?;
            let kind = MemoryKind::parse(&add_args.kind)?;
            let body = read_body_arg(add_args.body, add_args.body_file)?.unwrap_or_default();
            let mut anchors = Vec::with_capacity(add_args.anchors.len());
            for spec in &add_args.anchors {
                anchors.push(AnchorSpec::parse(spec)?);
            }
            let mut resolver = LazyCodeSymbolResolver::new(&project_root, false, None);
            let env = add_memory(
                &project_root,
                AddMemoryRequest {
                    id: add_args.id,
                    title: add_args.title,
                    kind,
                    body,
                    anchors,
                    tags: add_args.tags,
                },
                &mut resolver,
            )?;
            if add_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_memory_write_text(&env).trim_end().to_string())
            }
        }
        MemoryAction::Update(upd_args) => {
            let project_root = resolve_project_root(None, upd_args.root.as_deref())?;
            let kind = match upd_args.kind {
                Some(ref k) => Some(MemoryKind::parse(k)?),
                None => None,
            };
            let status = match upd_args.status {
                Some(ref s) => Some(MemoryStatus::parse(s)?),
                None => None,
            };
            let body = read_body_arg(upd_args.body, upd_args.body_file)?;
            let anchors = if upd_args.clear_anchors {
                Some(Vec::new())
            } else if !upd_args.anchors.is_empty() {
                let mut parsed = Vec::with_capacity(upd_args.anchors.len());
                for spec in &upd_args.anchors {
                    parsed.push(AnchorSpec::parse(spec)?);
                }
                Some(parsed)
            } else {
                None
            };
            let tags = if upd_args.clear_tags {
                Some(Vec::new())
            } else if !upd_args.tags.is_empty() {
                Some(upd_args.tags)
            } else {
                None
            };

            let mut resolver = LazyCodeSymbolResolver::new(&project_root, false, None);
            let env = update_memory(
                &project_root,
                UpdateMemoryRequest {
                    id: upd_args.id,
                    title: upd_args.title,
                    kind,
                    status,
                    body,
                    anchors,
                    tags,
                    refresh_anchors: upd_args.refresh_anchors,
                },
                &mut resolver,
            )?;
            if upd_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_memory_write_text(&env).trim_end().to_string())
            }
        }
        MemoryAction::Delete(del_args) => {
            let project_root = resolve_project_root(None, del_args.root.as_deref())?;
            let env = delete_memory(&project_root, &del_args.id)?;
            if del_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_memory_delete_text(&env).trim_end().to_string())
            }
        }
        MemoryAction::Verify(ver_args) => {
            let project_root = resolve_project_root(None, ver_args.root.as_deref())?;
            let mut resolver = LazyCodeSymbolResolver::new(&project_root, ver_args.read_only, None);
            let env = verify_all_notes(&project_root, &mut resolver)?;
            if ver_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_memory_verify_text(&env).trim_end().to_string())
            }
        }
        MemoryAction::Refresh(ref_args) => {
            if ref_args.read_only {
                return Err(CliError::ReadOnly(
                    "read-only mode forbids running `klens memory refresh`".to_string(),
                ));
            }
            if ref_args.id.is_none() && !ref_args.all {
                return Err(CliError::InvalidArgument(
                    "specify a note <ID> or pass --all".to_string(),
                ));
            }
            if ref_args.stale_only && !ref_args.all {
                return Err(CliError::InvalidArgument(
                    "`--stale-only` requires `--all`".to_string(),
                ));
            }
            let project_root = resolve_project_root(None, ref_args.root.as_deref())?;
            if let Some(ref id) = ref_args.id
                && !ref_args.dry_run
            {
                let mut resolver = LazyCodeSymbolResolver::new(&project_root, false, None);
                let env = refresh_memory(&project_root, id, &mut resolver)?;
                return if ref_args.json {
                    Ok(env.to_deterministic_json_pretty()?)
                } else {
                    Ok(format_memory_write_text(&env).trim_end().to_string())
                };
            }

            let target_ids: Option<Vec<String>> = ref_args.id.map(|id| vec![id]);
            let mut resolver = LazyCodeSymbolResolver::new(&project_root, ref_args.dry_run, None);
            let env = refresh_memories(
                &project_root,
                target_ids.as_deref(),
                ref_args.stale_only,
                ref_args.dry_run,
                &mut resolver,
            )?;
            if ref_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_memory_batch_refresh_text(&env)
                    .trim_end()
                    .to_string())
            }
        }
        MemoryAction::Export(exp_args) => {
            let format = MemoryExportFormat::parse(&exp_args.format)?;
            let kind = match exp_args.kind {
                Some(ref k) => Some(MemoryKind::parse(k)?),
                None => None,
            };
            let project_root = resolve_project_root(None, exp_args.root.as_deref())?;
            let mut resolver = LazyCodeSymbolResolver::new(&project_root, exp_args.read_only, None);
            let env = export_memory(
                &project_root,
                MemoryExportRequest {
                    kind,
                    tag: exp_args.tag,
                    stale_only: exp_args.stale_only,
                    format,
                },
                &mut resolver,
            )?;

            let Some(out_path) = exp_args.out else {
                return if exp_args.json || format == MemoryExportFormat::Json {
                    Ok(env.to_deterministic_json_pretty()?)
                } else {
                    Ok(format_memory_export_text(&env).trim_end().to_string())
                };
            };

            let resolved_out = resolve_export_out_path(&out_path)?;
            let inside_project = resolved_out.starts_with(project_root.root());
            if exp_args.read_only && inside_project {
                return Err(CliError::ReadOnly(
                    "read-only mode forbids writing inside the project root".to_string(),
                ));
            }
            if inside_project
                && let Ok(stripped) = resolved_out.strip_prefix(project_root.root())
                && let Ok(rel) = RelPath::from_relative_path(stripped)
                && is_sensitive_path(&rel)
            {
                return Err(CliError::Core(klens_core::KlensError::Path(
                    klens_core::PathError::SensitiveFileBlocked(rel.as_str().to_string()),
                )));
            }

            let file_content = match format {
                MemoryExportFormat::Markdown => {
                    env.data.rendered_markdown.clone().unwrap_or_default()
                }
                MemoryExportFormat::Json => {
                    let mut json_text = env.to_deterministic_json_pretty()?;
                    if !json_text.ends_with('\n') {
                        json_text.push('\n');
                    }
                    json_text
                }
            };
            let bytes_written = file_content.len();
            write_atomic(&resolved_out, file_content.as_bytes())
                .map_err(|e| CliError::Core(klens_core::KlensError::Path(e)))?;

            let display_path = clean_binary_path_string(&resolved_out);
            if exp_args.json {
                let mut summary_env = ProvenanceEnvelope::new(
                    env.trust,
                    project_root.project_id(),
                    json!({
                        "format": format.as_str(),
                        "out_path": display_path,
                        "bytes_written": bytes_written,
                        "total_notes": env.data.total_notes,
                        "stale_count": env.data.stale_count,
                    }),
                )
                .with_redactions_count(env.redactions_count);
                for w in &env.warnings {
                    summary_env = summary_env.with_warning(w.clone());
                }
                Ok(summary_env.to_deterministic_json_pretty()?)
            } else {
                let mut summary = format!(
                    "[{}] memory export wrote {} bytes ({}) notes={} stale={} redactions={} -> {}",
                    trust_label(env.trust),
                    bytes_written,
                    format.as_str(),
                    env.data.total_notes,
                    env.data.stale_count,
                    env.redactions_count,
                    display_path
                );
                for w in &env.warnings {
                    summary.push_str(&format!("\nWARNING: {w}"));
                }
                Ok(summary)
            }
        }
    }
}

fn resolve_export_out_path(raw_out: &Path) -> Result<PathBuf, CliError> {
    let abs_raw = if raw_out.is_absolute() {
        raw_out.to_path_buf()
    } else {
        let cwd = std::env::current_dir().map_err(|source| MemoryError::Io {
            path: PathBuf::from("."),
            source,
        })?;
        cwd.join(raw_out)
    };
    let normalized = normalize_lexical(&abs_raw);

    if fs::symlink_metadata(&normalized).is_ok() {
        let canonical = fs::canonicalize(&normalized).map_err(|source| MemoryError::Io {
            path: normalized.clone(),
            source,
        })?;
        return Ok(canonical);
    }

    let mut remaining = Vec::new();
    let mut cursor = normalized.as_path();
    while fs::symlink_metadata(cursor).is_err() {
        if let Some(name) = cursor.file_name() {
            remaining.push(name.to_os_string());
        } else {
            break;
        }
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => break,
        }
    }

    let mut resolved = fs::canonicalize(cursor).unwrap_or_else(|_| cursor.to_path_buf());
    for part in remaining.into_iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn read_body_arg(
    inline: Option<String>,
    body_file: Option<PathBuf>,
) -> Result<Option<String>, MemoryError> {
    if let Some(text) = inline {
        return Ok(Some(text));
    }
    if let Some(path) = body_file {
        let content =
            fs::read_to_string(&path).map_err(|source| MemoryError::Io { path, source })?;
        return Ok(Some(content));
    }
    Ok(None)
}
