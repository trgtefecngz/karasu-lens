//! Progressive-disclosure memory index (`index` / `list`) and SQLite FTS5 search (`search`).
//!
//! Guarantees (`docs/phases/phase-4.md` & Constitution Articles 5 & 6):
//! - `list_memory_index` NEVER leaks note bodies — returns compact metadata + live BLAKE3 trust.
//! - Deterministic lexicographical / score-ordered output.
//! - FTS5 search uses SQLite's `unicode61` tokenizer on a disposable in-memory FTS5 table built
//!   from the filesystem single source of truth (zero footprint in `--read-only` mode).

use std::collections::{BTreeMap, BTreeSet};

use klens_core::{ProjectRoot, ProvenanceEnvelope, TrustLevel, redact_secrets};
use rusqlite::{Connection, params};

use crate::error::MemoryError;
use crate::types::{
    DEFAULT_SEARCH_LIMIT, MemoryIndexEntry, MemoryIndexPayload, MemoryKind, MemoryNote,
    MemorySearchHit, MemorySearchPayload, SymbolResolver,
};
use crate::verify::{load_vault_notes, verify_note};

/// Build a compact progressive-disclosure index entry (strictly NO body text).
pub(crate) fn build_index_entry(
    project_root: &ProjectRoot,
    note: &MemoryNote,
    resolver: &mut dyn SymbolResolver,
) -> (MemoryIndexEntry, usize) {
    let verification = verify_note(project_root, note, resolver);
    let red_title = redact_secrets(&note.frontmatter.title);
    let redactions = red_title.redactions_count;

    let mut anchor_paths: Vec<String> = note
        .frontmatter
        .anchors
        .iter()
        .map(|a| match &a.symbol {
            Some(sym) => format!("{}#{sym}", a.path),
            None => a.path.clone(),
        })
        .collect();
    anchor_paths.sort();
    anchor_paths.dedup();

    let stale_anchors = verification
        .anchor_checks
        .into_iter()
        .filter(|c| !c.fresh)
        .collect();

    let entry = MemoryIndexEntry {
        id: note.frontmatter.id.clone(),
        title: red_title.text,
        kind: note.frontmatter.kind,
        status: note.frontmatter.status,
        trust: verification.trust,
        created_at: note.frontmatter.created_at.clone(),
        updated_at: note.frontmatter.updated_at.clone(),
        tags: note.frontmatter.tags.clone(),
        anchor_paths,
        wikilinks: note.wikilinks.clone(),
        rel_path: note.rel_path.clone(),
        stale_anchors,
    };

    (entry, redactions)
}

/// Progressive-disclosure listing of `.klens/memory/` notes (metadata + live trust, zero bodies).
pub fn list_memory_index(
    project_root: &ProjectRoot,
    kind_filter: Option<MemoryKind>,
    tag_filter: Option<&str>,
    stale_only: bool,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryIndexPayload>, MemoryError> {
    let tags: Vec<String> = tag_filter
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| vec![s.to_string()])
        .unwrap_or_default();
    list_memory_index_with_tags(project_root, kind_filter, &tags, stale_only, resolver)
}

/// Progressive-disclosure listing filtered by zero or more required tags (AND semantics).
pub fn list_memory_index_with_tags(
    project_root: &ProjectRoot,
    kind_filter: Option<MemoryKind>,
    tags_filter: &[String],
    stale_only: bool,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemoryIndexPayload>, MemoryError> {
    let (notes, warnings) = load_vault_notes(project_root)?;
    let required_tags: Vec<String> = tags_filter
        .iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut entries = Vec::new();
    let mut stale_count = 0usize;
    let mut total_redactions = 0usize;

    for note in &notes {
        if let Some(kind) = kind_filter
            && note.frontmatter.kind != kind
        {
            continue;
        }
        if !required_tags.is_empty()
            && !required_tags.iter().all(|req| {
                note.frontmatter
                    .tags
                    .iter()
                    .any(|t| t.to_lowercase() == *req)
            })
        {
            continue;
        }

        let (entry, redactions) = build_index_entry(project_root, note, resolver);
        total_redactions += redactions;
        let is_stale = entry.trust == TrustLevel::Stale;
        if is_stale {
            stale_count += 1;
        }
        if stale_only && !is_stale {
            continue;
        }
        entries.push(entry);
    }

    // Deterministic order: id ASC.
    entries.sort_by(|a, b| a.id.cmp(&b.id));

    let total_notes = entries.len();
    let payload = MemoryIndexPayload {
        total_notes,
        stale_count,
        entries,
    };

    let mut env =
        ProvenanceEnvelope::new(TrustLevel::VerifiedRaw, project_root.project_id(), payload)
            .with_redactions_count(total_redactions);
    for w in warnings {
        env = env.with_warning(w);
    }
    if stale_count > 0 {
        env = env.with_warning(format!(
            "{stale_count} memory note(s) have STALE BLAKE3 anchors"
        ));
    }

    Ok(env)
}

/// Deterministic FTS5 + metadata search across `.klens/memory/` notes.
///
/// Searches titles, tags, wikilinks, anchor paths, and bodies using SQLite FTS5 (`unicode61`)
/// plus Unicode-safe substring matching for punctuation-heavy identifiers (e.g. `src/save.rs`,
/// `impl World::save`, `[[wikilink]]`, `E0382`). Returns progressive-disclosure index entries.
pub fn search_memory(
    project_root: &ProjectRoot,
    query: &str,
    kind_filter: Option<MemoryKind>,
    limit: Option<usize>,
    resolver: &mut dyn SymbolResolver,
) -> Result<ProvenanceEnvelope<MemorySearchPayload>, MemoryError> {
    let trimmed = query.trim();
    let effective_limit = limit.unwrap_or(DEFAULT_SEARCH_LIMIT).max(1);
    let (notes, warnings) = load_vault_notes(project_root)?;

    let filtered_notes: Vec<&MemoryNote> = notes
        .iter()
        .filter(|n| kind_filter.is_none_or(|k| n.frontmatter.kind == k))
        .collect();

    if trimmed.is_empty() || filtered_notes.is_empty() {
        let payload = MemorySearchPayload {
            query: trimmed.to_string(),
            total_hits: 0,
            hits: Vec::new(),
        };
        let mut env =
            ProvenanceEnvelope::new(TrustLevel::VerifiedRaw, project_root.project_id(), payload);
        for w in warnings {
            env = env.with_warning(w);
        }
        return Ok(env);
    }

    let scores = score_notes_with_fts5(&filtered_notes, trimmed)?;

    let mut ranked: Vec<(&MemoryNote, i64, Vec<String>)> = Vec::new();
    for note in &filtered_notes {
        if let Some((score, matched_in)) = scores.get(&note.frontmatter.id) {
            ranked.push((*note, *score, matched_in.clone()));
        }
    }

    // Deterministic tie-breaking: score DESC, id ASC.
    ranked.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.frontmatter.id.cmp(&b.0.frontmatter.id))
    });

    let total_hits = ranked.len();
    let mut hits = Vec::new();
    let mut total_redactions = 0usize;
    let mut stale_hits = 0usize;

    for (note, score, matched_in) in ranked.into_iter().take(effective_limit) {
        let (entry, redactions) = build_index_entry(project_root, note, resolver);
        total_redactions += redactions;
        if entry.trust == TrustLevel::Stale {
            stale_hits += 1;
        }
        hits.push(MemorySearchHit {
            entry,
            matched_in,
            score,
        });
    }

    let payload = MemorySearchPayload {
        query: trimmed.to_string(),
        total_hits,
        hits,
    };

    let mut env =
        ProvenanceEnvelope::new(TrustLevel::VerifiedRaw, project_root.project_id(), payload)
            .with_redactions_count(total_redactions);
    for w in warnings {
        env = env.with_warning(w);
    }
    if stale_hits > 0 {
        env = env.with_warning(format!(
            "{stale_hits} search hit(s) have STALE BLAKE3 anchors"
        ));
    }

    Ok(env)
}

/// Build an in-memory SQLite FTS5 index over `notes` and return `(note_id -> (score, matched_fields))`.
pub(crate) fn score_notes_with_fts5(
    notes: &[&MemoryNote],
    query: &str,
) -> Result<BTreeMap<String, (i64, Vec<String>)>, MemoryError> {
    let conn = open_memory_fts_connection(notes)?;
    let terms = extract_search_terms(query);

    let mut scores: BTreeMap<String, (i64, BTreeSet<String>)> = BTreeMap::new();

    // 1. Primary SQLite FTS5 BM25 query (OR-joined safe quoted terms).
    // Column weights match all 6 table columns:
    // (note_id UNINDEXED = 0.0, title = 10.0, tags = 6.0, wikilinks = 5.0, anchor_paths = 4.0, body = 2.0).
    if let Some(fts_query) = build_fts5_or_query(&terms) {
        let mut stmt = conn.prepare(
            "SELECT note_id, bm25(memory_fts, 0.0, 10.0, 6.0, 5.0, 4.0, 2.0) AS rank
             FROM memory_fts
             WHERE memory_fts MATCH ?1
             ORDER BY rank ASC, note_id ASC",
        )?;
        let rows = stmt.query_map(params![fts_query], |row| {
            let id: String = row.get(0)?;
            let rank: f64 = row.get(1)?;
            Ok((id, rank))
        })?;
        for row in rows.flatten() {
            let (id, bm25_rank) = row;
            // SQLite bm25() returns negative scores where more negative = better match.
            let boost = ((-bm25_rank * 100.0).round() as i64).clamp(1, 50_000);
            let entry = scores.entry(id).or_insert_with(|| (0, BTreeSet::new()));
            entry.0 = entry.0.saturating_add(boost);
            entry.1.insert("fts5".to_string());
        }
    }

    // 2. Deterministic exact / substring enrichment (handles paths, `[[wikilink]]`, Turkish case,
    //    error codes like `E0382`, and exact IDs).
    let query_lower = query.to_lowercase();
    let lower_terms: Vec<String> = terms.iter().map(|t| t.to_lowercase()).collect();

    for note in notes {
        let mut extra_score: i64 = 0;
        let mut fields: BTreeSet<String> = BTreeSet::new();

        let id_l = note.frontmatter.id.to_lowercase();
        let title_l = note.frontmatter.title.to_lowercase();
        let body_l = note.body.to_lowercase();
        let tags_l: Vec<String> = note
            .frontmatter
            .tags
            .iter()
            .map(|t| t.to_lowercase())
            .collect();
        let links_l: Vec<String> = note.wikilinks.iter().map(|w| w.to_lowercase()).collect();
        let anchors_l: Vec<String> = note
            .frontmatter
            .anchors
            .iter()
            .map(|a| match &a.symbol {
                Some(sym) => format!("{}#{}", a.path, sym).to_lowercase(),
                None => a.path.to_lowercase(),
            })
            .collect();

        if id_l == query_lower {
            extra_score += 500;
            fields.insert("id".to_string());
        } else if id_l.contains(&query_lower) {
            extra_score += 200;
            fields.insert("id".to_string());
        }

        if title_l.contains(&query_lower) {
            extra_score += 300;
            fields.insert("title".to_string());
        }
        if tags_l
            .iter()
            .any(|t| t == &query_lower || t.contains(&query_lower))
        {
            extra_score += 220;
            fields.insert("tags".to_string());
        }
        if links_l.iter().any(|w| w.contains(&query_lower)) {
            extra_score += 200;
            fields.insert("wikilinks".to_string());
        }
        if anchors_l.iter().any(|a| a.contains(&query_lower)) {
            extra_score += 180;
            fields.insert("anchors".to_string());
        }
        if body_l.contains(&query_lower) {
            extra_score += 120;
            fields.insert("body".to_string());
        }

        for term in &lower_terms {
            if term.len() < 2 {
                continue;
            }
            if title_l.contains(term) {
                extra_score += 60;
                fields.insert("title".to_string());
            }
            if tags_l.iter().any(|t| t.contains(term)) {
                extra_score += 50;
                fields.insert("tags".to_string());
            }
            if links_l.iter().any(|w| w.contains(term)) {
                extra_score += 45;
                fields.insert("wikilinks".to_string());
            }
            if anchors_l.iter().any(|a| a.contains(term)) {
                extra_score += 40;
                fields.insert("anchors".to_string());
            }
            if body_l.contains(term) {
                extra_score += 25;
                fields.insert("body".to_string());
            }
        }

        if extra_score > 0 {
            let entry = scores
                .entry(note.frontmatter.id.clone())
                .or_insert_with(|| (0, BTreeSet::new()));
            entry.0 = entry.0.saturating_add(extra_score);
            entry.1.extend(fields);
        }
    }

    Ok(scores
        .into_iter()
        .map(|(id, (score, fields))| (id, (score, fields.into_iter().collect())))
        .collect())
}

pub(crate) fn open_memory_fts_connection(notes: &[&MemoryNote]) -> Result<Connection, MemoryError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
        "CREATE VIRTUAL TABLE memory_fts USING fts5(
            note_id UNINDEXED,
            title,
            tags,
            wikilinks,
            anchor_paths,
            body,
            tokenize='unicode61'
        );",
    )?;

    let mut insert = conn.prepare(
        "INSERT INTO memory_fts (note_id, title, tags, wikilinks, anchor_paths, body)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;

    for note in notes {
        let tags_joined = note.frontmatter.tags.join(" ");
        let links_joined = note.wikilinks.join(" ");
        let anchors_joined = note
            .frontmatter
            .anchors
            .iter()
            .map(|a| match &a.symbol {
                Some(sym) => format!("{} {sym}", a.path),
                None => a.path.clone(),
            })
            .collect::<Vec<_>>()
            .join(" ");

        insert.execute(params![
            note.frontmatter.id,
            note.frontmatter.title,
            tags_joined,
            links_joined,
            anchors_joined,
            note.body,
        ])?;
    }

    drop(insert);
    Ok(conn)
}

/// Extract clean Unicode word/code tokens from an arbitrary search query.
pub(crate) fn extract_search_terms(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cur = String::new();

    for ch in query.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '-' {
            cur.push(ch);
        } else if !cur.is_empty() {
            push_term(&mut cur, &mut seen, &mut terms);
        }
    }
    if !cur.is_empty() {
        push_term(&mut cur, &mut seen, &mut terms);
    }

    terms
}

fn push_term(cur: &mut String, seen: &mut BTreeSet<String>, out: &mut Vec<String>) {
    let trimmed = cur.trim_matches(['-', '_']);
    if trimmed.chars().count() >= 2 {
        let key = trimmed.to_lowercase();
        if seen.insert(key) {
            out.push(trimmed.to_string());
        }
    }
    cur.clear();
}

/// Build an FTS5 `OR` expression safely quoting every token so punctuation/keywords (`AND`, `NOT`,
/// `NEAR`, `:`, `-`) can never trigger SQLite FTS5 syntax errors.
pub(crate) fn build_fts5_or_query(terms: &[String]) -> Option<String> {
    if terms.is_empty() {
        return None;
    }
    let quoted: Vec<String> = terms
        .iter()
        .take(24)
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect();
    Some(quoted.join(" OR "))
}
