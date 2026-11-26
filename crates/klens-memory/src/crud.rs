//! Full CRUD operations (`get`, `add`, `update`, `refresh`, `delete`) for `.klens/memory/`.
//!
//! Guarantees:
//! - Strict path confinement via `ProjectRoot` (`resolve_existing` / `resolve_for_write`).
//! - Atomic Markdown writes via `klens_core::write_atomic`.
//! - UTC ISO-8601 timestamps via `klens_core::time::now_iso8601_utc` (zero `chrono`).
//! - Secret redaction at the output gate (`klens_core::redact_secrets`, Constitution Article 8).
//! - `refresh` preserves user-edited Markdown bodies verbatim while updating anchor hashes.

use std::fs;

use klens_core::time::now_iso8601_utc;
use klens_core::{
    ProjectRoot, ProvenanceEnvelope, SCHEMA_VERSION, TrustLevel, normalize_line_endings,
    redact_secrets, write_atomic,
};

use crate::error::MemoryError;
use crate::markdown::{extract_wikilinks, parse_markdown_note, serialize_markdown_note};
use crate::types::{
    AnchorSpec, MemoryAnchor, MemoryDeletePayload, MemoryFrontmatter, MemoryGetPayload, MemoryKind,
    MemoryNote, MemoryStatus, MemoryWritePayload, SymbolResolver, normalize_tags, note_rel_path,
    slugify_note_id, validate_note_id,
};
use crate::verify::{compute_anchor, verify_note};

/// Request payload for creating a new memory note.
#[derive(Debug, Clone)]
pub struct AddMemoryRequest {
    pub id: Option<String>,
    pub title: String,
    pub kind: MemoryKind,
    pub body: String,
    pub anchors: Vec<AnchorSpec>,
    pub tags: Vec<String>,
}

/// Request payload for partially updating an existing memory note.
#[derive(Debug, Clone)]
pub struct UpdateMemoryRequest {
    pub id: String,
    pub title: Option<String>,
    pub kind: Option<MemoryKind>,
    pub status: Option<MemoryStatus>,
    pub body: Option<String>,
    pub anchors: Option<Vec<AnchorSpec>>,
    pub tags: Option<Vec<String>>,
    pub refresh_anchors: bool,
}

/// Read a single note by ID with live BLAKE3 anchor verification and output secret redaction.
pub fn get_memory(
    project_root: &ProjectRoot,
    id: &str,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryGetPayload>, MemoryError> {
    let rel = note_rel_path(id)?;
    let (abs, canonical_rel) = match project_root.resolve_existing(rel.as_str()) {
        Ok(pair) => pair,
        Err(klens_core::PathError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Err(MemoryError::NotFound(id.trim().to_string()));
        }
        Err(err) => return Err(MemoryError::Path(err)),
    };

    let raw = fs::read_to_string(&abs).map_err(|source| MemoryError::Io { path: abs, source })?;
    let mut note = parse_markdown_note(canonical_rel.as_str(), &raw)?;
    let verification = verify_note(project_root, &note, resolver);

    let redactions = redact_note_in_place(&mut note);

    let mut env = ProvenanceEnvelope::new(
        verification.trust,
        project_root.project_id(),
        MemoryGetPayload { note, verification },
    )
    .with_redactions_count(redactions);

    for reason in &env.data.verification.stale_reasons.clone() {
        env = env.with_warning(format!("STALE anchor: {reason}"));
    }

    Ok(env)
}

/// Create and atomically persist a new Obsidian-compatible Markdown note in `.klens/memory/`.
pub fn add_memory(
    project_root: &ProjectRoot,
    req: AddMemoryRequest,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryWritePayload>, MemoryError> {
    let clean_title = req.title.trim().to_string();
    if clean_title.is_empty() {
        return Err(MemoryError::FrontmatterParse {
            path: ".klens/memory".to_string(),
            reason: "note `title` cannot be empty".to_string(),
        });
    }

    let id = match req.id {
        Some(explicit) => {
            let valid = validate_note_id(&explicit)?;
            let rel = note_rel_path(&valid)?;
            if project_root.root().join(rel.as_str()).exists() {
                return Err(MemoryError::AlreadyExists(valid));
            }
            valid
        }
        None => allocate_unique_id(project_root, req.kind, &clean_title)?,
    };

    let mut anchors: Vec<MemoryAnchor> = Vec::with_capacity(req.anchors.len());
    for spec in &req.anchors {
        anchors.push(compute_anchor(project_root, spec, resolver)?);
    }
    anchors.sort();
    anchors.dedup();

    let now_utc = now_iso8601_utc();
    let frontmatter = MemoryFrontmatter {
        schema_version: SCHEMA_VERSION,
        id: id.clone(),
        title: clean_title,
        kind: req.kind,
        created_at: now_utc.clone(),
        updated_at: now_utc,
        status: MemoryStatus::Active,
        anchors,
        tags: normalize_tags(&req.tags),
    };
    frontmatter.validate()?;

    let rel = note_rel_path(&id)?;
    let (abs, canonical_rel) = project_root.resolve_for_write(rel.as_str())?;

    let rendered = serialize_markdown_note(&frontmatter, &req.body);
    write_atomic(&abs, rendered.as_bytes())?;

    let mut note = parse_markdown_note(canonical_rel.as_str(), &rendered)?;
    let verification = verify_note(project_root, &note, resolver);
    let redactions = redact_note_in_place(&mut note);

    Ok(ProvenanceEnvelope::new(
        verification.trust,
        project_root.project_id(),
        MemoryWritePayload {
            action: "add".to_string(),
            note,
            verification,
        },
    )
    .with_redactions_count(redactions))
}

/// Update fields of an existing memory note while preserving untouched metadata and `created_at`.
pub fn update_memory(
    project_root: &ProjectRoot,
    req: UpdateMemoryRequest,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryWritePayload>, MemoryError> {
    let rel = note_rel_path(&req.id)?;
    let (abs, canonical_rel) = match project_root.resolve_existing(rel.as_str()) {
        Ok(pair) => pair,
        Err(klens_core::PathError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Err(MemoryError::NotFound(req.id.trim().to_string()));
        }
        Err(err) => return Err(MemoryError::Path(err)),
    };

    let raw = fs::read_to_string(&abs).map_err(|source| MemoryError::Io {
        path: abs.clone(),
        source,
    })?;
    let existing = parse_markdown_note(canonical_rel.as_str(), &raw)?;

    let mut fm = existing.frontmatter;
    if let Some(title) = req.title {
        let trimmed = title.trim().to_string();
        if trimmed.is_empty() {
            return Err(MemoryError::FrontmatterParse {
                path: canonical_rel.as_str().to_string(),
                reason: "updated `title` cannot be empty".to_string(),
            });
        }
        fm.title = trimmed;
    }
    if let Some(kind) = req.kind {
        fm.kind = kind;
    }
    if let Some(status) = req.status {
        fm.status = status;
    }
    if let Some(tags) = req.tags {
        fm.tags = normalize_tags(&tags);
    }

    if let Some(anchor_specs) = req.anchors {
        let mut computed = Vec::with_capacity(anchor_specs.len());
        for spec in &anchor_specs {
            computed.push(compute_anchor(project_root, spec, resolver)?);
        }
        computed.sort();
        computed.dedup();
        fm.anchors = computed;
    } else if req.refresh_anchors {
        let mut recomputed = Vec::with_capacity(fm.anchors.len());
        for existing_anchor in &fm.anchors {
            let spec = AnchorSpec {
                path: existing_anchor.path.clone(),
                symbol: existing_anchor.symbol.clone(),
            };
            recomputed.push(compute_anchor(project_root, &spec, resolver)?);
        }
        recomputed.sort();
        recomputed.dedup();
        fm.anchors = recomputed;
    }

    fm.updated_at = now_iso8601_utc();
    fm.validate()?;

    let new_body = req.body.unwrap_or(existing.body);
    let rendered = serialize_markdown_note(&fm, &new_body);
    let (write_abs, _) = project_root.resolve_for_write(canonical_rel.as_str())?;
    write_atomic(&write_abs, rendered.as_bytes())?;

    let mut note = parse_markdown_note(canonical_rel.as_str(), &rendered)?;
    let verification = verify_note(project_root, &note, resolver);
    let redactions = redact_note_in_place(&mut note);

    let mut env = ProvenanceEnvelope::new(
        verification.trust,
        project_root.project_id(),
        MemoryWritePayload {
            action: "update".to_string(),
            note,
            verification,
        },
    )
    .with_redactions_count(redactions);

    for reason in &env.data.verification.stale_reasons.clone() {
        env = env.with_warning(format!("STALE anchor: {reason}"));
    }

    Ok(env)
}

/// Recompute fresh BLAKE3 anchor hashes for an existing note after human/AI review,
/// preserving any hand-edited Markdown body verbatim.
pub fn refresh_memory(
    project_root: &ProjectRoot,
    id: &str,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryWritePayload>, MemoryError> {
    let rel = note_rel_path(id)?;
    let (abs, canonical_rel) = match project_root.resolve_existing(rel.as_str()) {
        Ok(pair) => pair,
        Err(klens_core::PathError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Err(MemoryError::NotFound(id.trim().to_string()));
        }
        Err(err) => return Err(MemoryError::Path(err)),
    };

    let raw = fs::read_to_string(&abs).map_err(|source| MemoryError::Io {
        path: abs.clone(),
        source,
    })?;
    let existing = parse_markdown_note(canonical_rel.as_str(), &raw)?;

    let mut fm = existing.frontmatter;
    let mut refreshed_anchors = Vec::with_capacity(fm.anchors.len());
    for anchor in &fm.anchors {
        let spec = AnchorSpec {
            path: anchor.path.clone(),
            symbol: anchor.symbol.clone(),
        };
        refreshed_anchors.push(compute_anchor(project_root, &spec, resolver)?);
    }
    refreshed_anchors.sort();
    refreshed_anchors.dedup();
    fm.anchors = refreshed_anchors;
    fm.status = MemoryStatus::Active;
    fm.updated_at = now_iso8601_utc();
    fm.validate()?;

    // Preserve the user's hand-edited Markdown body verbatim!
    let preserved_body = normalize_line_endings(&existing.body).into_owned();
    let rendered = serialize_markdown_note(&fm, &preserved_body);
    let (write_abs, _) = project_root.resolve_for_write(canonical_rel.as_str())?;
    write_atomic(&write_abs, rendered.as_bytes())?;

    let mut note = parse_markdown_note(canonical_rel.as_str(), &rendered)?;
    let verification = verify_note(project_root, &note, resolver);
    let redactions = redact_note_in_place(&mut note);

    Ok(ProvenanceEnvelope::new(
        verification.trust,
        project_root.project_id(),
        MemoryWritePayload {
            action: "refresh".to_string(),
            note,
            verification,
        },
    )
    .with_redactions_count(redactions))
}

/// Delete a memory note by ID from `.klens/memory/`.
pub fn delete_memory(
    project_root: &ProjectRoot,
    id: &str,
) -> Result<ProvenanceEnvelope<MemoryDeletePayload>, MemoryError> {
    let clean_id = validate_note_id(id)?;
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

    fs::remove_file(&abs).map_err(|source| MemoryError::Io { path: abs, source })?;

    Ok(ProvenanceEnvelope::new(
        TrustLevel::VerifiedRaw,
        project_root.project_id(),
        MemoryDeletePayload {
            id: clean_id,
            rel_path: canonical_rel.as_str().to_string(),
            deleted: true,
        },
    ))
}

fn allocate_unique_id(
    project_root: &ProjectRoot,
    kind: MemoryKind,
    title: &str,
) -> Result<String, MemoryError> {
    let base = slugify_note_id(kind, title);
    let base_rel = note_rel_path(&base)?;
    if !project_root.root().join(base_rel.as_str()).exists() {
        return Ok(base);
    }

    for suffix in 2..=9_999u32 {
        let candidate = format!("{base}-{suffix}");
        let rel = note_rel_path(&candidate)?;
        if !project_root.root().join(rel.as_str()).exists() {
            return Ok(candidate);
        }
    }

    Err(MemoryError::AlreadyExists(base))
}

fn redact_note_in_place(note: &mut MemoryNote) -> usize {
    let red_title = redact_secrets(&note.frontmatter.title);
    let red_body = redact_secrets(&note.body);
    let total = red_title.redactions_count + red_body.redactions_count;
    if red_title.redactions_count > 0 {
        note.frontmatter.title = red_title.text;
    }
    if red_body.redactions_count > 0 {
        note.body = red_body.text;
        note.wikilinks = extract_wikilinks(&note.body);
    }
    total
}
