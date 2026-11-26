//! Deterministic plain-text formatters for `klens-memory` CLI and MCP outputs.

use std::fmt::Write as _;

use klens_core::ProvenanceEnvelope;

use crate::types::{
    BugfixMatch, MemoryDeletePayload, MemoryGetPayload, MemoryIndexPayload, MemorySearchPayload,
    MemoryVerifyPayload, MemoryWritePayload, StaleReason, trust_label,
};

/// Render progressive-disclosure `index` / `list` payload (strictly NO note bodies).
pub fn format_memory_index_text(envelope: &ProvenanceEnvelope<MemoryIndexPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] memory index notes={} stale={}",
        trust_label(envelope.trust),
        data.total_notes,
        data.stale_count
    );

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    if data.entries.is_empty() {
        let _ = writeln!(out, "(no memory notes in .klens/memory/)");
        return out;
    }

    for entry in &data.entries {
        let tags = if entry.tags.is_empty() {
            String::new()
        } else {
            format!(" tags=[{}]", entry.tags.join(","))
        };
        let anchors = if entry.anchor_paths.is_empty() {
            String::new()
        } else {
            format!(" anchors=[{}]", entry.anchor_paths.join(", "))
        };
        let _ = writeln!(
            out,
            "- [{}] {} ({}) \"{}\"{tags}{anchors}",
            trust_label(entry.trust),
            entry.id,
            entry.kind.as_str(),
            entry.title
        );
        for stale in &entry.stale_anchors {
            let reason = stale.stale_reason.map_or("stale", StaleReason::as_str);
            let target = match &stale.symbol {
                Some(sym) => format!("{}#{sym}", stale.path),
                None => stale.path.clone(),
            };
            let _ = writeln!(out, "    ! STALE {target} ({reason})");
        }
    }

    out
}

/// Render a full single memory note with live BLAKE3 verification status.
pub fn format_memory_get_text(envelope: &ProvenanceEnvelope<MemoryGetPayload>) -> String {
    let note = &envelope.data.note;
    let ver = &envelope.data.verification;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] memory get id={} kind={} status={} path={}",
        trust_label(envelope.trust),
        note.frontmatter.id,
        note.frontmatter.kind.as_str(),
        note.frontmatter.status.as_str(),
        note.rel_path
    );
    let _ = writeln!(out, "Title: {}", note.frontmatter.title);
    if !note.frontmatter.tags.is_empty() {
        let _ = writeln!(out, "Tags: {}", note.frontmatter.tags.join(", "));
    }
    if !note.wikilinks.is_empty() {
        let _ = writeln!(out, "Wikilinks: {}", note.wikilinks.join(", "));
    }
    if !ver.anchor_checks.is_empty() {
        let _ = writeln!(out, "Anchors:");
        for chk in &ver.anchor_checks {
            let target = match &chk.symbol {
                Some(sym) => format!("{}#{sym}", chk.path),
                None => chk.path.clone(),
            };
            if chk.fresh {
                let _ = writeln!(out, "  - [FRESH] {target}");
            } else {
                let reason = chk.stale_reason.map_or("stale", StaleReason::as_str);
                let _ = writeln!(out, "  - [STALE:{reason}] {target}");
            }
        }
    }
    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }
    if !note.body.trim().is_empty() {
        let _ = writeln!(out);
        out.push_str(note.body.trim_end());
        out.push('\n');
    }

    out
}

/// Render deterministic FTS5 search hits (progressive disclosure: index metadata only).
pub fn format_memory_search_text(envelope: &ProvenanceEnvelope<MemorySearchPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] memory search query={:?} hits={}",
        trust_label(envelope.trust),
        data.query,
        data.total_hits
    );

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    if data.hits.is_empty() {
        let _ = writeln!(out, "(no matching memory notes)");
        return out;
    }

    for hit in &data.hits {
        let entry = &hit.entry;
        let fields = if hit.matched_in.is_empty() {
            String::new()
        } else {
            format!(" matched=[{}]", hit.matched_in.join(","))
        };
        let _ = writeln!(
            out,
            "- [{}] {} ({}) \"{}\" path={}{fields}",
            trust_label(entry.trust),
            entry.id,
            entry.kind.as_str(),
            entry.title,
            entry.rel_path
        );
    }

    out
}

/// Render `add` / `update` / `refresh` write confirmation.
pub fn format_memory_write_text(envelope: &ProvenanceEnvelope<MemoryWritePayload>) -> String {
    let data = &envelope.data;
    let fm = &data.note.frontmatter;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] memory {} id={} kind={} anchors={} path={}",
        trust_label(envelope.trust),
        data.action,
        fm.id,
        fm.kind.as_str(),
        fm.anchors.len(),
        data.note.rel_path
    );
    let _ = writeln!(out, "Title: {}", fm.title);
    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }
    out
}

/// Render `delete` confirmation.
pub fn format_memory_delete_text(envelope: &ProvenanceEnvelope<MemoryDeletePayload>) -> String {
    format!(
        "[{}] memory delete id={} path={} deleted={}\n",
        trust_label(envelope.trust),
        envelope.data.id,
        envelope.data.rel_path,
        envelope.data.deleted
    )
}

/// Render `verify` report summarizing fresh and stale notes.
pub fn format_memory_verify_text(envelope: &ProvenanceEnvelope<MemoryVerifyPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] memory verify total={} fresh={} stale={}",
        trust_label(envelope.trust),
        data.total_notes,
        data.fresh_count,
        data.stale_count
    );

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    for stale in &data.stale_notes {
        let _ = writeln!(
            out,
            "  [STALE] {} ({}) \"{}\" — {}",
            stale.id,
            stale.kind.as_str(),
            stale.title,
            stale.stale_reasons.join("; ")
        );
    }

    out
}

/// Format verified `kind: bugfix` matches as single-line hints attached to failing `klens run` output.
///
/// Zero speculation: emits ONLY verified note title, relative path, and freshness badge (`Taze` / `STALE`).
pub fn format_bugfix_matches_inline(matches: &[BugfixMatch]) -> String {
    let mut out = String::new();
    for m in matches {
        let _ = writeln!(
            out,
            "[bugfix] \"{}\" ({}) [{}]",
            m.title,
            m.rel_path,
            m.freshness_label()
        );
    }
    out.trim_end().to_string()
}
