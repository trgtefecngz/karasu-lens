//! SQLite connection pragma setup and disposable WAL+FTS5 schema DDL for `klens-code`.
//!
//! Strict leaf module: depends only on `error` and `rusqlite` (never `store`).

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::error::CodeError;

/// Disposable SQLite `index.db` accelerator schema version (independent of JSON `SCHEMA_VERSION`).
pub const INDEX_DB_SCHEMA_VERSION: u32 = 2;

const CONNECTION_PRAGMAS_SQL: &str = "PRAGMA journal_mode = WAL;
     PRAGMA busy_timeout = 5000;
     PRAGMA foreign_keys = ON;
     PRAGMA synchronous = NORMAL;";

const CREATE_META_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );";

const DROP_CACHE_TABLES_SQL: &str = "DROP TABLE IF EXISTS edges;
     DROP TABLE IF EXISTS symbols;
     DROP TABLE IF EXISTS files_fts;
     DROP TABLE IF EXISTS files;";

const CREATE_CACHE_SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS files (
        path TEXT PRIMARY KEY,
        mtime_secs INTEGER NOT NULL,
        mtime_nanos INTEGER NOT NULL,
        size_bytes INTEGER NOT NULL,
        blake3 TEXT NOT NULL,
        parse_cache_key TEXT NOT NULL,
        parser_id TEXT NOT NULL,
        parser_version TEXT NOT NULL,
        language_id TEXT,
        line_count INTEGER NOT NULL,
        parse_status TEXT NOT NULL,
        parse_warning TEXT
    );

    CREATE TABLE IF NOT EXISTS symbols (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
        name TEXT NOT NULL,
        qualified_name TEXT NOT NULL,
        kind TEXT NOT NULL,
        signature TEXT NOT NULL,
        start_line INTEGER NOT NULL,
        end_line INTEGER NOT NULL,
        start_byte INTEGER,
        end_byte INTEGER,
        parent TEXT,
        ordinal INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_symbols_file_path ON symbols(file_path);
    CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
    CREATE INDEX IF NOT EXISTS idx_symbols_qualified_name ON symbols(qualified_name);

    CREATE TABLE IF NOT EXISTS edges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
        from_node TEXT NOT NULL,
        to_node TEXT NOT NULL,
        relation TEXT NOT NULL,
        confidence TEXT NOT NULL,
        evidence TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_edges_file_path ON edges(file_path);
    CREATE INDEX IF NOT EXISTS idx_edges_to_node ON edges(to_node);

    CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
        path,
        symbols_text,
        content,
        tokenize = 'unicode61'
    );";

pub(crate) fn configure_connection(conn: &Connection) -> Result<(), CodeError> {
    conn.busy_timeout(Duration::from_millis(5000))?;
    conn.execute_batch(CONNECTION_PRAGMAS_SQL)?;
    Ok(())
}

pub(crate) fn init_schema(conn: &mut Connection, project_id: &str) -> Result<(), CodeError> {
    let expected_version = INDEX_DB_SCHEMA_VERSION.to_string();

    // Fast read-only path: when `meta` already matches v2 and `project_id`, avoid any
    // write transaction so concurrent WAL readers never contend for write locks.
    let meta_exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
        [],
        |row| row.get(0),
    )?;
    if meta_exists > 0 {
        let existing_version: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let existing_project: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'project_id'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if existing_version.as_deref() == Some(expected_version.as_str())
            && existing_project.as_deref() == Some(project_id)
        {
            return Ok(());
        }
    }

    // Use `BEGIN IMMEDIATE` so `busy_timeout = 5000` is honored cleanly without
    // SQLite read-to-write upgrade `SQLITE_BUSY` failures during concurrent opens.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(CREATE_META_TABLE_SQL)?;

    let existing_version: Option<String> = tx
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;

    let existing_project: Option<String> = tx
        .query_row(
            "SELECT value FROM meta WHERE key = 'project_id'",
            [],
            |row| row.get(0),
        )
        .optional()?;

    // Atomic v1 -> v2 (or any version mismatch) drop/recreate inside a single transaction.
    // A cache built for another project (copied in, or committed into a repository) is never
    // adopted: its symbols/FTS rows could describe code that is not there.
    if existing_version.as_deref() != Some(expected_version.as_str())
        || existing_project.as_deref() != Some(project_id)
    {
        tx.execute_batch(DROP_CACHE_TABLES_SQL)?;
    }
    tx.execute_batch(CREATE_CACHE_SCHEMA_SQL)?;
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![expected_version],
    )?;
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('project_id', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![project_id],
    )?;
    tx.commit()?;

    Ok(())
}
