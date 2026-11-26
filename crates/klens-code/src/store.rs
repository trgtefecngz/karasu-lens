use std::fs;
use std::path::{Path, PathBuf};

use klens_core::{CodeEdge, EdgeConfidence, EdgeRelation, RelPath, SymbolInfo, SymbolKind};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::error::CodeError;
use crate::store_schema::{configure_connection, init_schema};

/// Parse outcome status persisted per file in SQLite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseStatus {
    Parsed,
    Partial,
    ExternalParsed,
    ExternalPartial,
    Fallback,
}

impl ParseStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parsed => "parsed",
            Self::Partial => "partial",
            Self::ExternalParsed => "external_parsed",
            Self::ExternalPartial => "external_partial",
            Self::Fallback => "fallback",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "parsed" => Self::Parsed,
            "partial" => Self::Partial,
            "external_parsed" => Self::ExternalParsed,
            "external_partial" => Self::ExternalPartial,
            _ => Self::Fallback,
        }
    }

    pub const fn is_external(self) -> bool {
        matches!(self, Self::ExternalParsed | Self::ExternalPartial)
    }

    pub const fn is_builtin_parsed(self) -> bool {
        matches!(self, Self::Parsed | Self::Partial)
    }
}

/// Persisted symbol row paired with its owning normalized file path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedSymbolRow {
    pub file_path: RelPath,
    pub symbol: SymbolInfo,
}

/// Candidate file returned by an FTS5 search against `files_fts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtsFileHit {
    pub path: RelPath,
    pub content: String,
}

/// Persisted file metadata row in `.klens/cache/index.db`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedFileRecord {
    pub path: RelPath,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
    pub size_bytes: u64,
    pub blake3: String,
    pub parse_cache_key: String,
    pub parser_id: String,
    pub parser_version: String,
    pub language_id: Option<String>,
    pub line_count: usize,
    pub parse_status: ParseStatus,
    pub parse_warning: Option<String>,
}

/// SQLite WAL + FTS5 incremental cache backing `klens-code`.
///
/// Disposable accelerator (Constitution Article 6): deleting the database file
/// triggers a 100% deterministic rebuild from the filesystem.
pub struct IndexStore {
    conn: Connection,
    db_path: PathBuf,
}

impl IndexStore {
    /// Open or create the SQLite index at `db_path` with mandatory WAL + busy_timeout pragmas.
    pub fn open(db_path: impl AsRef<Path>, project_id: &str) -> Result<Self, CodeError> {
        let db_path = db_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| CodeError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let mut conn = Connection::open(&db_path)?;
        configure_connection(&conn)?;
        init_schema(&mut conn, project_id)?;

        Ok(Self { conn, db_path })
    }

    /// Filesystem path of the underlying SQLite database.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Query active SQLite `journal_mode` pragma (expected `"wal"`).
    pub fn journal_mode(&self) -> Result<String, CodeError> {
        let mode: String = self
            .conn
            .query_row("PRAGMA journal_mode;", [], |row| row.get(0))?;
        Ok(mode)
    }

    /// Query active SQLite `busy_timeout` pragma in milliseconds (expected `5000`).
    pub fn busy_timeout_ms(&self) -> Result<i64, CodeError> {
        let ms: i64 = self
            .conn
            .query_row("PRAGMA busy_timeout;", [], |row| row.get(0))?;
        Ok(ms)
    }

    /// Check whether the `files_fts` FTS5 virtual table is present.
    pub fn fts_table_exists(&self) -> Result<bool, CodeError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'files_fts';",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Look up a single indexed file by normalized relative path.
    pub fn get_file(&self, path: &RelPath) -> Result<Option<IndexedFileRecord>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT path, mtime_secs, mtime_nanos, size_bytes, blake3,
                    parse_cache_key, parser_id, parser_version,
                    language_id, line_count, parse_status, parse_warning
             FROM files WHERE path = ?1",
        )?;
        let row = stmt
            .query_row(params![path.as_str()], row_to_file_record)
            .optional()?;
        Ok(row)
    }

    /// List all indexed files in deterministic lexicographical path order.
    pub fn list_files(&self) -> Result<Vec<IndexedFileRecord>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT path, mtime_secs, mtime_nanos, size_bytes, blake3,
                    parse_cache_key, parser_id, parser_version,
                    language_id, line_count, parse_status, parse_warning
             FROM files ORDER BY path ASC",
        )?;
        let rows = stmt.query_map([], row_to_file_record)?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Update only mtime/size metadata when file content BLAKE3 hash is unchanged.
    pub fn touch_file_mtime(
        &self,
        path: &RelPath,
        mtime_secs: i64,
        mtime_nanos: i64,
        size_bytes: u64,
    ) -> Result<(), CodeError> {
        self.conn.execute(
            "UPDATE files SET mtime_secs = ?2, mtime_nanos = ?3, size_bytes = ?4 WHERE path = ?1",
            params![path.as_str(), mtime_secs, mtime_nanos, size_bytes as i64],
        )?;
        Ok(())
    }

    /// Atomically replace a file's metadata, symbols, edges, and FTS5 entry.
    pub fn upsert_file(
        &mut self,
        record: &IndexedFileRecord,
        symbols: &[SymbolInfo],
        edges: &[CodeEdge],
        fts_content: &str,
    ) -> Result<(), CodeError> {
        self.upsert_file_with_byte_ranges(record, symbols, &[], edges, fts_content)
    }

    /// Atomically replace a file's metadata, symbols (with optional byte ranges), edges, and FTS5 entry.
    pub fn upsert_file_with_byte_ranges(
        &mut self,
        record: &IndexedFileRecord,
        symbols: &[SymbolInfo],
        byte_ranges: &[Option<(usize, usize)>],
        edges: &[CodeEdge],
        fts_content: &str,
    ) -> Result<(), CodeError> {
        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO files (
                path, mtime_secs, mtime_nanos, size_bytes, blake3,
                parse_cache_key, parser_id, parser_version,
                language_id, line_count, parse_status, parse_warning
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(path) DO UPDATE SET
                mtime_secs = excluded.mtime_secs,
                mtime_nanos = excluded.mtime_nanos,
                size_bytes = excluded.size_bytes,
                blake3 = excluded.blake3,
                parse_cache_key = excluded.parse_cache_key,
                parser_id = excluded.parser_id,
                parser_version = excluded.parser_version,
                language_id = excluded.language_id,
                line_count = excluded.line_count,
                parse_status = excluded.parse_status,
                parse_warning = excluded.parse_warning",
            params![
                record.path.as_str(),
                record.mtime_secs,
                record.mtime_nanos,
                record.size_bytes as i64,
                record.blake3,
                record.parse_cache_key,
                record.parser_id,
                record.parser_version,
                record.language_id,
                record.line_count as i64,
                record.parse_status.as_str(),
                record.parse_warning,
            ],
        )?;

        tx.execute(
            "DELETE FROM symbols WHERE file_path = ?1",
            params![record.path.as_str()],
        )?;
        {
            let mut sym_stmt = tx.prepare(
                "INSERT INTO symbols (
                    file_path, name, qualified_name, kind, signature,
                    start_line, end_line, start_byte, end_byte, parent, ordinal
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            for (ordinal, sym) in symbols.iter().enumerate() {
                let (sb, eb) = match byte_ranges.get(ordinal).copied().flatten() {
                    Some((s, e)) => (Some(s as i64), Some(e as i64)),
                    None => (None, None),
                };
                sym_stmt.execute(params![
                    record.path.as_str(),
                    sym.name,
                    sym.qualified_name,
                    symbol_kind_to_str(sym.kind),
                    sym.signature,
                    sym.start_line as i64,
                    sym.end_line as i64,
                    sb,
                    eb,
                    sym.parent,
                    ordinal as i64,
                ])?;
            }
        }

        tx.execute(
            "DELETE FROM edges WHERE file_path = ?1",
            params![record.path.as_str()],
        )?;
        {
            let mut edge_stmt = tx.prepare(
                "INSERT INTO edges (
                    file_path, from_node, to_node, relation, confidence, evidence
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for edge in edges {
                edge_stmt.execute(params![
                    record.path.as_str(),
                    edge.from,
                    edge.to,
                    edge_relation_to_str(edge.relation),
                    edge_confidence_to_str(edge.confidence),
                    edge.evidence,
                ])?;
            }
        }

        // Sync FTS5 row for fast future search (defense-in-depth secret redaction).
        let raw_symbols_text = symbols
            .iter()
            .map(|s| format!("{} {}", s.qualified_name, s.signature))
            .collect::<Vec<_>>()
            .join("\n");
        let symbols_text = klens_core::redact_secrets(&raw_symbols_text).text;
        tx.execute(
            "DELETE FROM files_fts WHERE path = ?1",
            params![record.path.as_str()],
        )?;
        tx.execute(
            "INSERT INTO files_fts (path, symbols_text, content) VALUES (?1, ?2, ?3)",
            params![record.path.as_str(), symbols_text, fts_content],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Delete a file and its cascading symbols, edges, and FTS5 entry.
    pub fn delete_file(&mut self, path: &RelPath) -> Result<(), CodeError> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM files WHERE path = ?1", params![path.as_str()])?;
        tx.execute(
            "DELETE FROM files_fts WHERE path = ?1",
            params![path.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Count total indexed symbols for a single file without loading symbol payloads.
    pub fn count_symbols_for_file(&self, path: &RelPath) -> Result<usize, CodeError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM symbols WHERE file_path = ?1",
            params![path.as_str()],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as usize)
    }

    /// Read stored FTS5 content for a file (primarily for diagnostics and tests).
    pub fn get_fts_content_for_file(&self, path: &RelPath) -> Result<Option<String>, CodeError> {
        let content: Option<String> = self
            .conn
            .query_row(
                "SELECT content FROM files_fts WHERE path = ?1",
                params![path.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(content)
    }

    /// Fetch stored optional byte ranges `(start_byte, end_byte)` for a file's symbols
    /// in the same deterministic order as [`Self::get_symbols_for_file`].
    pub fn get_symbol_byte_ranges_for_file(
        &self,
        path: &RelPath,
    ) -> Result<Vec<Option<(usize, usize)>>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT start_byte, end_byte
             FROM symbols
             WHERE file_path = ?1
             ORDER BY start_line ASC, end_line ASC, ordinal ASC, qualified_name ASC",
        )?;
        let rows = stmt.query_map(params![path.as_str()], |row| {
            let sb: Option<i64> = row.get(0)?;
            let eb: Option<i64> = row.get(1)?;
            Ok(match (sb, eb) {
                (Some(s), Some(e)) if s >= 0 && e >= s => Some((s as usize, e as usize)),
                _ => None,
            })
        })?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Fetch the complete, untruncated symbol list for a file in deterministic order.
    pub fn get_symbols_for_file(&self, path: &RelPath) -> Result<Vec<SymbolInfo>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT name, qualified_name, kind, signature, start_line, end_line, parent
             FROM symbols
             WHERE file_path = ?1
             ORDER BY start_line ASC, end_line ASC, ordinal ASC, qualified_name ASC",
        )?;
        let rows = stmt.query_map(params![path.as_str()], |row| {
            let kind_str: String = row.get(2)?;
            let start_line: i64 = row.get(4)?;
            let end_line: i64 = row.get(5)?;
            Ok(SymbolInfo {
                name: row.get(0)?,
                qualified_name: row.get(1)?,
                kind: symbol_kind_from_str(&kind_str),
                signature: row.get(3)?,
                start_line: start_line.max(0) as usize,
                end_line: end_line.max(0) as usize,
                parent: row.get(6)?,
            })
        })?;

        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Fetch all extracted code edges for a file in deterministic order.
    pub fn get_edges_for_file(&self, path: &RelPath) -> Result<Vec<CodeEdge>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT from_node, to_node, relation, confidence, evidence
             FROM edges
             WHERE file_path = ?1
             ORDER BY from_node ASC, to_node ASC, relation ASC, evidence ASC",
        )?;
        let rows = stmt.query_map(params![path.as_str()], |row| {
            let rel_str: String = row.get(2)?;
            let conf_str: String = row.get(3)?;
            Ok(CodeEdge {
                from: row.get(0)?,
                to: row.get(1)?,
                relation: edge_relation_from_str(&rel_str),
                confidence: edge_confidence_from_str(&conf_str),
                evidence: row.get(4)?,
            })
        })?;

        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Fetch ALL indexed symbols across the entire workspace in deterministic order.
    pub fn list_all_symbols(&self) -> Result<Vec<IndexedSymbolRow>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, name, qualified_name, kind, signature, start_line, end_line, parent
             FROM symbols
             ORDER BY file_path ASC, start_line ASC, end_line ASC, ordinal ASC, qualified_name ASC",
        )?;
        let rows = stmt.query_map([], row_to_indexed_symbol)?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Fetch ALL extracted code edges across the entire workspace in deterministic order.
    pub fn list_all_edges(&self) -> Result<Vec<(RelPath, CodeEdge)>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, from_node, to_node, relation, confidence, evidence
             FROM edges
             ORDER BY file_path ASC, from_node ASC, to_node ASC, relation ASC, evidence ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let raw_path: String = row.get(0)?;
            let path = RelPath::normalize(&raw_path).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            let rel_str: String = row.get(3)?;
            let conf_str: String = row.get(4)?;
            Ok((
                path,
                CodeEdge {
                    from: row.get(1)?,
                    to: row.get(2)?,
                    relation: edge_relation_from_str(&rel_str),
                    confidence: edge_confidence_from_str(&conf_str),
                    evidence: row.get(5)?,
                },
            ))
        })?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Search indexed symbols case-insensitively by `name`, `qualified_name`, or `signature`.
    pub fn search_symbols(&self, needle: &str) -> Result<Vec<IndexedSymbolRow>, CodeError> {
        let escaped = escape_like_pattern(&needle.to_lowercase());
        let like_pattern = format!("%{escaped}%");
        let mut stmt = self.conn.prepare(
            "SELECT file_path, name, qualified_name, kind, signature, start_line, end_line, parent
             FROM symbols
             WHERE lower(name) LIKE ?1 ESCAPE '\\'
                OR lower(qualified_name) LIKE ?1 ESCAPE '\\'
                OR lower(signature) LIKE ?1 ESCAPE '\\'
             ORDER BY file_path ASC, start_line ASC, end_line ASC, ordinal ASC, qualified_name ASC",
        )?;
        let rows = stmt.query_map(params![like_pattern], row_to_indexed_symbol)?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Query the FTS5 virtual table (`files_fts`) with a pre-sanitized MATCH expression.
    pub fn search_fts(
        &self,
        fts_match_expr: &str,
        max_files: usize,
    ) -> Result<Vec<FtsFileHit>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT path, content
             FROM files_fts
             WHERE files_fts MATCH ?1
             ORDER BY bm25(files_fts) ASC, path ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![fts_match_expr, max_files as i64], |row| {
            let raw_path: String = row.get(0)?;
            let path = RelPath::normalize(&raw_path).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            let content: String = row.get(1)?;
            Ok(FtsFileHit { path, content })
        })?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Fallback case-insensitive substring search across indexed `files_fts` content
    /// (catches camelCase / mid-word substrings such as `"Timeout"` in `handleTimeout`).
    pub fn search_fts_substring(
        &self,
        needle: &str,
        max_files: usize,
    ) -> Result<Vec<FtsFileHit>, CodeError> {
        let escaped = escape_like_pattern(&needle.to_lowercase());
        let like_pattern = format!("%{escaped}%");
        let mut stmt = self.conn.prepare(
            "SELECT path, content
             FROM files_fts
             WHERE lower(content) LIKE ?1 ESCAPE '\\'
             ORDER BY path ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![like_pattern, max_files as i64], |row| {
            let raw_path: String = row.get(0)?;
            let path = RelPath::normalize(&raw_path).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            let content: String = row.get(1)?;
            Ok(FtsFileHit { path, content })
        })?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }

    /// Fetch all `(path, content)` rows stored in `files_fts` in deterministic path order.
    pub fn list_all_fts_contents(&self) -> Result<Vec<FtsFileHit>, CodeError> {
        let mut stmt = self.conn.prepare(
            "SELECT path, content
             FROM files_fts
             ORDER BY path ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let raw_path: String = row.get(0)?;
            let path = RelPath::normalize(&raw_path).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            let content: String = row.get(1)?;
            Ok(FtsFileHit { path, content })
        })?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item?);
        }
        Ok(out)
    }
}

fn row_to_indexed_symbol(row: &rusqlite::Row<'_>) -> rusqlite::Result<IndexedSymbolRow> {
    let raw_path: String = row.get(0)?;
    let file_path = RelPath::normalize(&raw_path).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })?;
    let kind_str: String = row.get(3)?;
    let start_line: i64 = row.get(5)?;
    let end_line: i64 = row.get(6)?;
    Ok(IndexedSymbolRow {
        file_path,
        symbol: SymbolInfo {
            name: row.get(1)?,
            qualified_name: row.get(2)?,
            kind: symbol_kind_from_str(&kind_str),
            signature: row.get(4)?,
            start_line: start_line.max(0) as usize,
            end_line: end_line.max(0) as usize,
            parent: row.get(7)?,
        },
    })
}

fn escape_like_pattern(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

fn row_to_file_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<IndexedFileRecord> {
    let raw_path: String = row.get(0)?;
    let path = RelPath::normalize(&raw_path).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })?;
    let size_bytes: i64 = row.get(3)?;
    let line_count: i64 = row.get(9)?;
    let status_str: String = row.get(10)?;
    Ok(IndexedFileRecord {
        path,
        mtime_secs: row.get(1)?,
        mtime_nanos: row.get(2)?,
        size_bytes: size_bytes.max(0) as u64,
        blake3: row.get(4)?,
        parse_cache_key: row.get(5)?,
        parser_id: row.get(6)?,
        parser_version: row.get(7)?,
        language_id: row.get(8)?,
        line_count: line_count.max(0) as usize,
        parse_status: ParseStatus::from_db(&status_str),
        parse_warning: row.get(11)?,
    })
}

fn symbol_kind_to_str(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Function => "function",
        SymbolKind::Method => "method",
        SymbolKind::Struct => "struct",
        SymbolKind::Enum => "enum",
        SymbolKind::Trait => "trait",
        SymbolKind::Interface => "interface",
        SymbolKind::Class => "class",
        SymbolKind::TypeAlias => "type_alias",
        SymbolKind::Const => "const",
        SymbolKind::Static => "static",
        SymbolKind::Module => "module",
        SymbolKind::Macro => "macro",
        SymbolKind::Variable => "variable",
        SymbolKind::Other => "other",
    }
}

fn symbol_kind_from_str(s: &str) -> SymbolKind {
    match s {
        "function" => SymbolKind::Function,
        "method" => SymbolKind::Method,
        "struct" => SymbolKind::Struct,
        "enum" => SymbolKind::Enum,
        "trait" => SymbolKind::Trait,
        "interface" => SymbolKind::Interface,
        "class" => SymbolKind::Class,
        "type_alias" => SymbolKind::TypeAlias,
        "const" => SymbolKind::Const,
        "static" => SymbolKind::Static,
        "module" => SymbolKind::Module,
        "macro" => SymbolKind::Macro,
        "variable" => SymbolKind::Variable,
        _ => SymbolKind::Other,
    }
}

fn edge_relation_to_str(rel: EdgeRelation) -> &'static str {
    match rel {
        EdgeRelation::Imports => "imports",
        EdgeRelation::Calls => "calls",
        EdgeRelation::Implements => "implements",
        EdgeRelation::Extends => "extends",
        EdgeRelation::References => "references",
    }
}

fn edge_relation_from_str(s: &str) -> EdgeRelation {
    match s {
        "imports" => EdgeRelation::Imports,
        "calls" => EdgeRelation::Calls,
        "implements" => EdgeRelation::Implements,
        "extends" => EdgeRelation::Extends,
        _ => EdgeRelation::References,
    }
}

fn edge_confidence_to_str(conf: EdgeConfidence) -> &'static str {
    match conf {
        EdgeConfidence::Extracted => "EXTRACTED",
        EdgeConfidence::Inferred => "INFERRED",
        EdgeConfidence::Ambiguous => "AMBIGUOUS",
        EdgeConfidence::VerifiedLsp => "VERIFIED_LSP",
    }
}

fn edge_confidence_from_str(s: &str) -> EdgeConfidence {
    match s {
        "EXTRACTED" => EdgeConfidence::Extracted,
        "INFERRED" => EdgeConfidence::Inferred,
        "VERIFIED_LSP" => EdgeConfidence::VerifiedLsp,
        _ => EdgeConfidence::Ambiguous,
    }
}
