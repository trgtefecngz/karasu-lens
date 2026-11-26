#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

//! Verifiable Obsidian-compatible Markdown + `[[wikilink]]` second brain (`klens-memory`).
//!
//! Features:
//! - Obsidian-compatible UTF-8 `.md` notes under `.klens/memory/` with YAML frontmatter and `[[wikilink]]`s.
//! - BLAKE3 file/symbol anchor staleness verification (`TrustLevel::VerifiedRaw` vs `TrustLevel::Stale`).
//! - Progressive-disclosure index (`list_memory_index`) that never leaks note bodies.
//! - Deterministic SQLite FTS5 search (`search_memory`) and error → bugfix matcher (`match_error`).
//! - Zero coupling to `klens-code` or `klens-exec` (symbol resolution injected via [`SymbolResolver`]).

pub mod batch;
pub mod crud;
pub mod error;
pub mod format;
pub mod index;
pub mod markdown;
pub mod match_error;
pub mod types;
pub mod verify;

pub use batch::{
    BatchRefreshEntry, BatchRefreshFailure, BatchRefreshItemOutcome, ExportedMemoryItem,
    MemoryBatchRefreshPayload, MemoryExportFormat, MemoryExportPayload, MemoryExportRequest,
    export_memory, format_memory_batch_refresh_text, format_memory_export_text, refresh_memories,
};
pub use crud::{
    AddMemoryRequest, UpdateMemoryRequest, add_memory, delete_memory, get_memory, refresh_memory,
    update_memory,
};
pub use error::MemoryError;
pub use format::{
    format_bugfix_matches_inline, format_memory_delete_text, format_memory_get_text,
    format_memory_index_text, format_memory_search_text, format_memory_verify_text,
    format_memory_write_text,
};
pub use index::{list_memory_index, list_memory_index_with_tags, search_memory};
pub use markdown::{extract_wikilinks, parse_markdown_note, serialize_markdown_note};
pub use match_error::match_error;
pub use types::{
    AnchorCheck, AnchorSpec, BugfixMatch, DEFAULT_BUGFIX_MATCH_LIMIT, DEFAULT_SEARCH_LIMIT,
    MEMORY_DIR_REL, MemoryAnchor, MemoryDeletePayload, MemoryFrontmatter, MemoryGetPayload,
    MemoryIndexEntry, MemoryIndexPayload, MemoryKind, MemoryNote, MemorySearchHit,
    MemorySearchPayload, MemoryStatus, MemoryVerifyPayload, MemoryWritePayload, NoteVerification,
    StaleNoteReport, StaleReason, SymbolLookupResult, SymbolResolver, normalize_tags,
    note_rel_path, slugify_note_id, trust_label, validate_note_id,
};
pub use verify::{
    HeuristicSymbolResolver, compute_anchor, verify_all_notes, verify_anchor, verify_note,
};
