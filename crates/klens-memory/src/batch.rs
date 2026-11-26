//! Batch memory vault operations: read-only Markdown/JSON export (`export_memory`)
//! and safe single/batch BLAKE3 anchor refresh (`refresh_memories`).
//!
//! Guarantees:
//! - Mandatory output-gate secret redaction (`klens_core::redact_secrets`, Constitution Article 8).
//! - Deterministic ID-ascending output ordering.
//! - `export_memory` and `refresh_memories(..., dry_run = true, ...)` write **0 bytes** to disk.
//! - Notes with deleted/broken anchors are never corrupted during batch refresh; they are
//!   reported in `failed` with explicit reasons while healthy notes are safely refreshed.
//! - Hand-edited Obsidian Markdown bodies are preserved verbatim.

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::fs;

use klens_core::time::now_iso8601_utc;
use klens_core::{
    ProjectRoot, ProvenanceEnvelope, TrustLevel, normalize_line_endings, redact_secrets,
    write_atomic,
};
use serde::{Deserialize, Serialize};

use crate::error::MemoryError;
use crate::markdown::{extract_wikilinks, parse_markdown_note, serialize_markdown_note};
use crate::types::{
    AnchorSpec, MemoryAnchor, MemoryKind, MemoryNote, MemoryStatus, NoteVerification, StaleReason,
    SymbolResolver, note_rel_path, trust_label, validate_note_id,
};
use crate::verify::{compute_anchor, load_vault_notes, verify_note};

/// Output format for [`export_memory`] (`md` / `markdown` or `json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryExportFormat {
    Markdown,
    Json,
}

impl MemoryExportFormat {
    /// Fail-closed parser accepting `md`, `markdown`, or `json` (case-insensitive).
    pub fn parse(input: &str) -> Result<Self, MemoryError> {
        match input.trim().to_ascii_lowercase().as_str() {
            "md" | "markdown" => Ok(Self::Markdown),
            "json" => Ok(Self::Json),
            other => Err(MemoryError::InvalidExportFormat(other.to_string())),
        }
    }

    /// Canonical lowercase format identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Json => "json",
        }
    }

    /// File extension associated with this format (`"md"` or `"json"`).
    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Json => "json",
        }
    }
}

impl fmt::Display for MemoryExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Filter and format parameters for [`export_memory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryExportRequest {
    pub kind: Option<MemoryKind>,
    pub tag: Option<String>,
    pub stale_only: bool,
    pub format: MemoryExportFormat,
}

impl Default for MemoryExportRequest {
    fn default() -> Self {
        Self {
            kind: None,
            tag: None,
            stale_only: false,
            format: MemoryExportFormat::Markdown,
        }
    }
}

/// Single verified & secret-redacted note included in [`MemoryExportPayload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedMemoryItem {
    pub note: MemoryNote,
    pub verification: NoteVerification,
    pub markdown: String,
}

/// Payload for `klens memory export` and `GET /api/memory/export`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryExportPayload {
    pub format: MemoryExportFormat,
    pub total_notes: usize,
    pub stale_count: usize,
    pub notes: Vec<ExportedMemoryItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_markdown: Option<String>,
}

/// Per-note outcome classification during batch refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchRefreshItemOutcome {
    Refreshed,
    Unchanged,
    Failed,
}

/// Detailed record of a note refreshed (or planned for refresh in `dry_run` mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRefreshEntry {
    pub id: String,
    pub changed: bool,
    pub previous_trust: TrustLevel,
    pub new_trust: TrustLevel,
    pub updated_anchors: usize,
    pub outcome: BatchRefreshItemOutcome,
}

/// Record of a note that could not be refreshed (left untouched on disk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRefreshFailure {
    pub id: String,
    pub reason: String,
}

/// Payload for `klens memory refresh --all [--stale-only] [--dry-run]` and `POST /api/memory/refresh-all`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryBatchRefreshPayload {
    pub dry_run: bool,
    pub stale_only: bool,
    pub total_scanned: usize,
    pub refreshed: Vec<BatchRefreshEntry>,
    pub unchanged: Vec<String>,
    pub failed: Vec<BatchRefreshFailure>,
}

/// Read-only export of `.klens/memory/` notes with live BLAKE3 verification and output-gate secret redaction.
///
/// Writes **0 bytes** to disk. Malformed `.md` files in `.klens/memory/` are surfaced in
/// `envelope.warnings` rather than silently dropped.
pub fn export_memory(
    project_root: &ProjectRoot,
    req: MemoryExportRequest,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryExportPayload>, MemoryError> {
    let (vault_notes, vault_warnings) = load_vault_notes(project_root)?;
    let tag_filter = req
        .tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);

    let mut exported_items: Vec<ExportedMemoryItem> = Vec::new();
    let mut stale_count = 0usize;
    let mut total_redactions = 0usize;

    for mut note in vault_notes {
        if let Some(kind) = req.kind
            && note.frontmatter.kind != kind
        {
            continue;
        }
        if let Some(ref wanted_tag) = tag_filter
            && !note
                .frontmatter
                .tags
                .iter()
                .any(|t| t.to_lowercase() == *wanted_tag)
        {
            continue;
        }

        let verification = verify_note(project_root, &note, resolver);
        let is_stale = !verification.fresh;
        if req.stale_only && !is_stale {
            continue;
        }
        if is_stale {
            stale_count += 1;
        }

        total_redactions += redact_note_fields(&mut note);

        let raw_item_md = serialize_markdown_note(&note.frontmatter, &note.body);
        let red_item_md = redact_secrets(&raw_item_md);
        total_redactions += red_item_md.redactions_count;

        exported_items.push(ExportedMemoryItem {
            note,
            verification,
            markdown: red_item_md.text,
        });
    }

    // Deterministic order: id ASC, then rel_path ASC.
    exported_items.sort_by(|a, b| {
        a.note
            .frontmatter
            .id
            .cmp(&b.note.frontmatter.id)
            .then_with(|| a.note.rel_path.cmp(&b.note.rel_path))
    });

    let total_notes = exported_items.len();
    let rendered_markdown = if req.format == MemoryExportFormat::Markdown {
        let raw_doc = render_unified_markdown(&exported_items, &req, &vault_warnings);
        let red_doc = redact_secrets(&raw_doc);
        total_redactions += red_doc.redactions_count;
        Some(red_doc.text)
    } else {
        None
    };

    let trust = if stale_count > 0 {
        TrustLevel::Stale
    } else {
        TrustLevel::VerifiedRaw
    };

    let payload = MemoryExportPayload {
        format: req.format,
        total_notes,
        stale_count,
        notes: exported_items,
        rendered_markdown,
    };

    let mut env = ProvenanceEnvelope::new(trust, project_root.project_id(), payload)
        .with_redactions_count(total_redactions);
    for w in vault_warnings {
        env = env.with_warning(w);
    }
    if stale_count > 0 {
        env = env.with_warning(format!(
            "{stale_count} of {total_notes} exported memory note(s) have STALE BLAKE3 anchors"
        ));
    }

    Ok(env)
}

/// Batch (or targeted) BLAKE3 anchor refresh preserving hand-edited Markdown bodies verbatim.
///
/// - When `target_ids` is `None`, scans all notes in `.klens/memory/` in deterministic ID order.
/// - When `target_ids` is `Some(ids)`, validates and targets those specific note IDs.
/// - When `dry_run == true`, writes **0 bytes** to disk while reporting exact planned updates & failures.
/// - Notes whose anchored file/symbol was deleted or became ambiguous are never modified;
///   they are recorded under `failed` with explicit reasons and surfaced in `envelope.warnings`.
pub fn refresh_memories(
    project_root: &ProjectRoot,
    target_ids: Option<&[String]>,
    stale_only: bool,
    dry_run: bool,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryBatchRefreshPayload>, MemoryError> {
    let (notes, vault_warnings) = match target_ids {
        Some(ids) => (load_targeted_notes(project_root, ids)?, Vec::new()),
        None => load_vault_notes(project_root)?,
    };

    let mut total_scanned = 0usize;
    let mut refreshed: Vec<BatchRefreshEntry> = Vec::new();
    let mut unchanged: Vec<String> = Vec::new();
    let mut failed: Vec<BatchRefreshFailure> = Vec::new();

    for note in notes {
        total_scanned += 1;
        let note_id = note.frontmatter.id.clone();
        let before_ver = verify_note(project_root, &note, resolver);
        let previous_trust = before_ver.trust;

        if stale_only && before_ver.fresh {
            unchanged.push(note_id);
            continue;
        }

        let mut recomputed: Vec<MemoryAnchor> = Vec::with_capacity(note.frontmatter.anchors.len());
        let mut resolve_err: Option<String> = None;
        for anchor in &note.frontmatter.anchors {
            let spec = AnchorSpec {
                path: anchor.path.clone(),
                symbol: anchor.symbol.clone(),
            };
            match compute_anchor(project_root, &spec, resolver) {
                Ok(fresh_anchor) => recomputed.push(fresh_anchor),
                Err(err) => {
                    resolve_err = Some(err.to_string());
                    break;
                }
            }
        }

        if let Some(reason) = resolve_err {
            failed.push(BatchRefreshFailure {
                id: note_id,
                reason,
            });
            continue;
        }

        recomputed.sort();
        recomputed.dedup();

        let anchors_changed = recomputed != note.frontmatter.anchors;
        let status_changed = note.frontmatter.status != MemoryStatus::Active;
        if !anchors_changed && !status_changed {
            unchanged.push(note_id);
            continue;
        }

        let updated_anchors = count_updated_anchors(&note.frontmatter.anchors, &recomputed);

        let mut updated_fm = note.frontmatter.clone();
        updated_fm.anchors = recomputed;
        updated_fm.status = MemoryStatus::Active;
        updated_fm.updated_at = now_iso8601_utc();
        updated_fm.validate()?;

        // Preserve hand-edited Obsidian Markdown body verbatim.
        let preserved_body = normalize_line_endings(&note.body).into_owned();

        let new_trust = if dry_run {
            let preview_note = MemoryNote {
                frontmatter: updated_fm,
                body: preserved_body,
                wikilinks: note.wikilinks.clone(),
                rel_path: note.rel_path.clone(),
            };
            verify_note(project_root, &preview_note, resolver).trust
        } else {
            let rendered = serialize_markdown_note(&updated_fm, &preserved_body);
            let (write_abs, _) = project_root.resolve_for_write(&note.rel_path)?;
            write_atomic(&write_abs, rendered.as_bytes())?;
            let reparsed = parse_markdown_note(&note.rel_path, &rendered)?;
            verify_note(project_root, &reparsed, resolver).trust
        };

        refreshed.push(BatchRefreshEntry {
            id: note_id,
            changed: true,
            previous_trust,
            new_trust,
            updated_anchors,
            outcome: BatchRefreshItemOutcome::Refreshed,
        });
    }

    let trust = if !failed.is_empty() {
        TrustLevel::Stale
    } else {
        TrustLevel::VerifiedRaw
    };

    let mut env = ProvenanceEnvelope::new(
        trust,
        project_root.project_id(),
        MemoryBatchRefreshPayload {
            dry_run,
            stale_only,
            total_scanned,
            refreshed,
            unchanged,
            failed,
        },
    );

    for w in vault_warnings {
        env = env.with_warning(w);
    }
    if !env.data.failed.is_empty() {
        let failed_count = env.data.failed.len();
        let summary = env
            .data
            .failed
            .iter()
            .map(|f| format!("{} ({})", f.id, f.reason))
            .collect::<Vec<_>>()
            .join("; ");
        env = env.with_warning(format!(
            "{failed_count} memory note(s) failed to refresh and were left untouched: {summary}"
        ));
    }

    Ok(env)
}

/// Format an [`export_memory`] envelope as human-readable text (returns the unified Markdown
/// document directly when `format == Markdown`).
pub fn format_memory_export_text(envelope: &ProvenanceEnvelope<MemoryExportPayload>) -> String {
    if let Some(ref md) = envelope.data.rendered_markdown {
        return md.clone();
    }

    let data = &envelope.data;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] memory export format={} notes={} stale={} redactions={}",
        trust_label(envelope.trust),
        data.format.as_str(),
        data.total_notes,
        data.stale_count,
        envelope.redactions_count
    );
    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }
    for item in &data.notes {
        let _ = writeln!(
            out,
            "- [{}] {} ({}) \"{}\"",
            trust_label(item.verification.trust),
            item.note.frontmatter.id,
            item.note.frontmatter.kind.as_str(),
            item.note.frontmatter.title
        );
    }
    out
}

/// Format a [`refresh_memories`] envelope into a deterministic, human-readable summary.
pub fn format_memory_batch_refresh_text(
    envelope: &ProvenanceEnvelope<MemoryBatchRefreshPayload>,
) -> String {
    let data = &envelope.data;
    let mode = if data.dry_run { "dry-run" } else { "apply" };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] memory refresh mode={} stale_only={} scanned={} refreshed={} unchanged={} failed={}",
        trust_label(envelope.trust),
        mode,
        data.stale_only,
        data.total_scanned,
        data.refreshed.len(),
        data.unchanged.len(),
        data.failed.len()
    );

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    for entry in &data.refreshed {
        let tag = if data.dry_run {
            "WOULD_REFRESH"
        } else {
            "REFRESHED"
        };
        let _ = writeln!(
            out,
            "  [{tag}] {} ({} -> {}, updated_anchors={})",
            entry.id,
            trust_label(entry.previous_trust),
            trust_label(entry.new_trust),
            entry.updated_anchors
        );
    }

    for id in &data.unchanged {
        let _ = writeln!(out, "  [UNCHANGED] {id}");
    }

    for fail in &data.failed {
        let _ = writeln!(out, "  [FAILED] {} — {}", fail.id, fail.reason);
    }

    out
}

fn load_targeted_notes(
    project_root: &ProjectRoot,
    ids: &[String],
) -> Result<Vec<MemoryNote>, MemoryError> {
    let mut seen = BTreeSet::new();
    let mut notes = Vec::with_capacity(ids.len());

    for raw_id in ids {
        let clean_id = validate_note_id(raw_id)?;
        if !seen.insert(clean_id.clone()) {
            continue;
        }
        let rel = note_rel_path(&clean_id)?;
        let (abs, canonical_rel) = match project_root.resolve_existing(rel.as_str()) {
            Ok(pair) => pair,
            Err(klens_core::PathError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Err(MemoryError::NotFound(clean_id));
            }
            Err(err) => return Err(MemoryError::Path(err)),
        };
        let raw =
            fs::read_to_string(&abs).map_err(|source| MemoryError::Io { path: abs, source })?;
        notes.push(parse_markdown_note(canonical_rel.as_str(), &raw)?);
    }

    notes.sort_by(|a, b| {
        a.frontmatter
            .id
            .cmp(&b.frontmatter.id)
            .then_with(|| a.rel_path.cmp(&b.rel_path))
    });
    Ok(notes)
}

fn redact_note_fields(note: &mut MemoryNote) -> usize {
    let mut total = 0usize;

    let red_title = redact_secrets(&note.frontmatter.title);
    if red_title.redactions_count > 0 {
        total += red_title.redactions_count;
        note.frontmatter.title = red_title.text;
    }

    let red_body = redact_secrets(&note.body);
    if red_body.redactions_count > 0 {
        total += red_body.redactions_count;
        note.body = red_body.text;
        note.wikilinks = extract_wikilinks(&note.body);
    }

    for tag in &mut note.frontmatter.tags {
        let red_tag = redact_secrets(tag);
        if red_tag.redactions_count > 0 {
            total += red_tag.redactions_count;
            *tag = red_tag.text;
        }
    }

    total
}

fn count_updated_anchors(old: &[MemoryAnchor], new: &[MemoryAnchor]) -> usize {
    let mut changed = 0usize;
    for anchor in new {
        let already_exact = old.iter().any(|o| {
            o.path == anchor.path
                && o.symbol == anchor.symbol
                && o.blake3.eq_ignore_ascii_case(&anchor.blake3)
        });
        if !already_exact {
            changed += 1;
        }
    }
    changed
}

fn render_unified_markdown(
    items: &[ExportedMemoryItem],
    req: &MemoryExportRequest,
    vault_warnings: &[String],
) -> String {
    let stale_count = items.iter().filter(|i| !i.verification.fresh).count();
    let mut out = String::new();
    let _ = writeln!(out, "# Karasu Lens Memory Export");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **Notes:** {} | **Stale:** {}",
        items.len(),
        stale_count
    );

    let mut filters = Vec::new();
    if let Some(kind) = req.kind {
        filters.push(format!("kind={}", kind.as_str()));
    }
    if let Some(ref tag) = req.tag
        && !tag.trim().is_empty()
    {
        filters.push(format!("tag={}", tag.trim()));
    }
    if req.stale_only {
        filters.push("stale_only=true".to_string());
    }
    if !filters.is_empty() {
        let _ = writeln!(out, "- **Filters:** {}", filters.join(", "));
    }

    if !vault_warnings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Warnings");
        let _ = writeln!(out);
        for w in vault_warnings {
            let _ = writeln!(out, "- {w}");
        }
    }

    if items.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "_No memory notes matched the export filters._");
        return out;
    }

    for item in items {
        let fm = &item.note.frontmatter;
        let ver = &item.verification;
        let _ = writeln!(out);
        let _ = writeln!(out, "---");
        let _ = writeln!(out);
        let _ = writeln!(out, "## {} (`{}`)", fm.title, fm.id);
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "- **Trust:** `[{}]` | **Kind:** `{}` | **Status:** `{}` | **Path:** `{}`",
            trust_label(ver.trust),
            fm.kind.as_str(),
            fm.status.as_str(),
            item.note.rel_path
        );
        if !fm.tags.is_empty() {
            let _ = writeln!(out, "- **Tags:** {}", fm.tags.join(", "));
        }
        if !item.note.wikilinks.is_empty() {
            let _ = writeln!(out, "- **Wikilinks:** {}", item.note.wikilinks.join(", "));
        }
        if !ver.anchor_checks.is_empty() {
            let _ = writeln!(out, "- **Anchors:**");
            for chk in &ver.anchor_checks {
                let target = match &chk.symbol {
                    Some(sym) => format!("{}#{sym}", chk.path),
                    None => chk.path.clone(),
                };
                if chk.fresh {
                    let _ = writeln!(out, "  - `[FRESH]` `{target}`");
                } else {
                    let reason = chk.stale_reason.map_or("stale", StaleReason::as_str);
                    let _ = writeln!(out, "  - `[STALE:{reason}]` `{target}`");
                }
            }
        }
        if !item.note.body.trim().is_empty() {
            let _ = writeln!(out);
            out.push_str(item.note.body.trim_end());
            out.push('\n');
        }
    }

    out
}
