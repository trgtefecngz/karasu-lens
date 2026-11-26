//! Leaf data types, validation helpers, and `SymbolResolver` trait for `klens-memory`.

use std::fmt;

use klens_core::{RelPath, SCHEMA_VERSION, TrustLevel};
use serde::{Deserialize, Serialize};

use crate::error::MemoryError;

/// Relative directory inside a project root holding Obsidian-compatible memory notes.
pub const MEMORY_DIR_REL: &str = ".klens/memory";

/// Default search hit limit when unspecified.
pub const DEFAULT_SEARCH_LIMIT: usize = 20;

/// Default bugfix match limit attached to failing `klens run` output.
pub const DEFAULT_BUGFIX_MATCH_LIMIT: usize = 3;

/// Category of a persistent memory note (`docs/02-DATA-SCHEMAS.md` Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    Decision,
    Bugfix,
    Architecture,
    Feedback,
    Constraint,
}

impl MemoryKind {
    /// Parse a case-insensitive note kind identifier.
    pub fn parse(input: &str) -> Result<Self, MemoryError> {
        match input.trim().to_ascii_lowercase().as_str() {
            "decision" => Ok(Self::Decision),
            "bugfix" => Ok(Self::Bugfix),
            "architecture" => Ok(Self::Architecture),
            "feedback" => Ok(Self::Feedback),
            "constraint" => Ok(Self::Constraint),
            other => Err(MemoryError::InvalidKind(other.to_string())),
        }
    }

    /// Canonical lowercase YAML/JSON identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::Bugfix => "bugfix",
            Self::Architecture => "architecture",
            Self::Feedback => "feedback",
            Self::Constraint => "constraint",
        }
    }
}

impl fmt::Display for MemoryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle status stored in a note's YAML frontmatter.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    #[default]
    Active,
    Stale,
    Archived,
}

impl MemoryStatus {
    /// Parse a case-insensitive status value.
    pub fn parse(input: &str) -> Result<Self, MemoryError> {
        match input.trim().to_ascii_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "stale" => Ok(Self::Stale),
            "archived" => Ok(Self::Archived),
            other => Err(MemoryError::InvalidStatus(other.to_string())),
        }
    }

    /// Canonical lowercase YAML/JSON identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Archived => "archived",
        }
    }
}

impl fmt::Display for MemoryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// User-provided anchor specification (`path` + optional `symbol`) before hashing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AnchorSpec {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

impl AnchorSpec {
    /// Create a file-level anchor specification.
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            symbol: None,
        }
    }

    /// Create a symbol-level anchor specification.
    pub fn symbol(path: impl Into<String>, symbol: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            symbol: Some(symbol.into()),
        }
    }

    /// Parse `<path>` or `<path>#<symbol>` into an [`AnchorSpec`].
    pub fn parse(spec: &str) -> Result<Self, MemoryError> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err(MemoryError::AnchorResolveFailed {
                path: String::new(),
                symbol: None,
                reason: "anchor specification cannot be empty".to_string(),
            });
        }
        if let Some((raw_path, raw_sym)) = trimmed.split_once('#') {
            let path = raw_path.trim();
            let sym = raw_sym.trim();
            if path.is_empty() {
                return Err(MemoryError::AnchorResolveFailed {
                    path: trimmed.to_string(),
                    symbol: None,
                    reason: "anchor path before `#` cannot be empty".to_string(),
                });
            }
            if sym.is_empty() {
                return Err(MemoryError::AnchorResolveFailed {
                    path: path.to_string(),
                    symbol: None,
                    reason: "anchor symbol after `#` cannot be empty".to_string(),
                });
            }
            let rel = RelPath::normalize(path)?;
            Ok(Self {
                path: rel.as_str().to_string(),
                symbol: Some(sym.to_string()),
            })
        } else {
            let rel = RelPath::normalize(trimmed)?;
            Ok(Self {
                path: rel.as_str().to_string(),
                symbol: None,
            })
        }
    }
}

/// Persisted BLAKE3 code anchor inside a note's YAML frontmatter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemoryAnchor {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub blake3: String,
}

/// Structured YAML frontmatter of an Obsidian-compatible `.klens/memory/<id>.md` note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryFrontmatter {
    pub schema_version: u32,
    pub id: String,
    pub title: String,
    pub kind: MemoryKind,
    pub created_at: String,
    pub updated_at: String,
    pub status: MemoryStatus,
    #[serde(default)]
    pub anchors: Vec<MemoryAnchor>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl MemoryFrontmatter {
    /// Validate required frontmatter invariants (`schema_version == 1`, valid ID, non-empty title).
    pub fn validate(&self) -> Result<(), MemoryError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(MemoryError::Core(
                klens_core::KlensError::InvalidSchemaVersion {
                    expected: SCHEMA_VERSION,
                    found: self.schema_version,
                },
            ));
        }
        let _ = validate_note_id(&self.id)?;
        if self.title.trim().is_empty() {
            return Err(MemoryError::FrontmatterParse {
                path: format!("{MEMORY_DIR_REL}/{}.md", self.id),
                reason: "frontmatter `title` cannot be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Full parsed Markdown memory note from `.klens/memory/<id>.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryNote {
    pub frontmatter: MemoryFrontmatter,
    pub body: String,
    #[serde(default)]
    pub wikilinks: Vec<String>,
    pub rel_path: String,
}

/// Machine-readable reason why a code anchor failed BLAKE3 verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleReason {
    ChangedHash,
    MissingFile,
    MissingSymbol,
    AmbiguousSymbol,
    InvalidAnchorPath,
}

impl StaleReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChangedHash => "changed_hash",
            Self::MissingFile => "missing_file",
            Self::MissingSymbol => "missing_symbol",
            Self::AmbiguousSymbol => "ambiguous_symbol",
            Self::InvalidAnchorPath => "invalid_anchor_path",
        }
    }
}

impl fmt::Display for StaleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Verification result for a single [`MemoryAnchor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorCheck {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub expected_blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_blake3: Option<String>,
    pub fresh: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_reason: Option<StaleReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Aggregated verification verdict for a [`MemoryNote`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteVerification {
    pub trust: TrustLevel,
    pub fresh: bool,
    #[serde(default)]
    pub anchor_checks: Vec<AnchorCheck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_reasons: Vec<String>,
}

/// Outcome of resolving an anchored symbol inside a source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolLookupResult {
    /// Unambiguous symbol resolved with exact LF-normalized source lines (`start_line..=end_line`).
    Found {
        qualified_name: String,
        source_snippet: String,
        start_line: usize,
        end_line: usize,
    },
    /// Short name matched multiple distinct symbols (Constitution Article 3).
    Ambiguous(Vec<String>),
    /// File exists, but the anchored symbol was deleted or renamed.
    Missing,
    /// File could not be parsed cleanly (broken syntax / unsupported extension).
    Unparsed(String),
}

/// Port trait decoupling `klens-memory` from `klens-code` (Zero Cross-Crate Coupling).
///
/// Higher layers (`klens-cli`, `klens-mcp`) pass a Tree-sitter AST-backed implementation,
/// while standalone callers and unit tests can use [`crate::HeuristicSymbolResolver`].
pub trait SymbolResolver {
    fn resolve_symbol(&mut self, path: &RelPath, symbol: &str) -> SymbolLookupResult;
}

/// Compact progressive-disclosure index row (NEVER carries the Markdown note body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryIndexEntry {
    pub id: String,
    pub title: String,
    pub kind: MemoryKind,
    pub status: MemoryStatus,
    pub trust: TrustLevel,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub anchor_paths: Vec<String>,
    #[serde(default)]
    pub wikilinks: Vec<String>,
    pub rel_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_anchors: Vec<AnchorCheck>,
}

/// Payload for `klens memory list` / `klens_memory(action="index")`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryIndexPayload {
    pub total_notes: usize,
    pub stale_count: usize,
    pub entries: Vec<MemoryIndexEntry>,
}

/// Payload for `klens memory get <id>` / `klens_memory(action="get")`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGetPayload {
    pub note: MemoryNote,
    pub verification: NoteVerification,
}

/// Single hit returned by FTS5 memory search (progressive disclosure: index metadata only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySearchHit {
    pub entry: MemoryIndexEntry,
    #[serde(default)]
    pub matched_in: Vec<String>,
    pub score: i64,
}

/// Payload for `klens memory search <query>` / `klens_memory(action="search")`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySearchPayload {
    pub query: String,
    pub total_hits: usize,
    pub hits: Vec<MemorySearchHit>,
}

/// Payload for `add`, `update`, and `refresh` mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryWritePayload {
    pub action: String,
    pub note: MemoryNote,
    pub verification: NoteVerification,
}

/// Payload for `delete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDeletePayload {
    pub id: String,
    pub rel_path: String,
    pub deleted: bool,
}

/// Single stale note summary returned by `verify_all`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleNoteReport {
    pub id: String,
    pub title: String,
    pub kind: MemoryKind,
    pub rel_path: String,
    pub trust: TrustLevel,
    pub stale_anchors: Vec<AnchorCheck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_reasons: Vec<String>,
}

/// Payload for `klens memory verify` / `klens_memory(action="verify")`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryVerifyPayload {
    pub total_notes: usize,
    pub fresh_count: usize,
    pub stale_count: usize,
    pub stale_notes: Vec<StaleNoteReport>,
    pub fresh_ids: Vec<String>,
}

/// Verified `kind: bugfix` note matched against a failing command's error output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BugfixMatch {
    pub id: String,
    pub title: String,
    pub rel_path: String,
    pub trust: TrustLevel,
    pub is_stale: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_terms: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_reasons: Vec<String>,
}

impl BugfixMatch {
    /// Human-readable freshness badge (`Taze` vs `STALE`).
    pub const fn freshness_label(&self) -> &'static str {
        if self.is_stale { "STALE" } else { "Taze" }
    }
}

/// Validate a memory note identifier so it maps safely to `.klens/memory/<id>.md` on all OSes.
pub fn validate_note_id(raw: &str) -> Result<String, MemoryError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 120 {
        return Err(MemoryError::InvalidId(raw.to_string()));
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') || trimmed.ends_with(' ') {
        return Err(MemoryError::InvalidId(raw.to_string()));
    }
    if trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains(':')
        || trimmed.contains('\0')
    {
        return Err(MemoryError::InvalidId(raw.to_string()));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(MemoryError::InvalidId(raw.to_string()));
    }

    // Reject Windows reserved device filenames (CON, PRN, AUX, NUL, COM1..9, LPT1..9).
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        return Err(MemoryError::InvalidId(raw.to_string()));
    }

    Ok(trimmed.to_string())
}

/// Generate a safe, ASCII, Obsidian-friendly slug ID from a note kind and UTF-8/Turkish title.
pub fn slugify_note_id(kind: MemoryKind, title: &str) -> String {
    let prefix = match kind {
        MemoryKind::Decision => "adr",
        MemoryKind::Bugfix => "bug",
        MemoryKind::Architecture => "arch",
        MemoryKind::Feedback => "fb",
        MemoryKind::Constraint => "const",
    };

    let mut slug = String::new();
    let mut prev_dash = false;
    for ch in title.chars() {
        if matches!(ch, '\'' | '’') {
            continue;
        }
        let mapped: Option<char> = match ch {
            'a'..='z' | '0'..='9' => Some(ch),
            'A'..='Z' => Some(ch.to_ascii_lowercase()),
            'ç' | 'Ç' => Some('c'),
            'ğ' | 'Ğ' => Some('g'),
            'ı' | 'İ' => Some('i'),
            'ö' | 'Ö' => Some('o'),
            'ş' | 'Ş' => Some('s'),
            'ü' | 'Ü' => Some('u'),
            _ => None,
        };
        if let Some(ascii) = mapped {
            if slug.len() < 48 {
                slug.push(ascii);
                prev_dash = false;
            }
        } else if !slug.is_empty() && !prev_dash && slug.len() < 48 {
            slug.push('-');
            prev_dash = true;
        }
    }

    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        format!("{prefix}-note")
    } else {
        format!("{prefix}-{trimmed}")
    }
}

/// Build the normalized relative vault path `.klens/memory/<id>.md` for a validated ID.
pub fn note_rel_path(id: &str) -> Result<RelPath, MemoryError> {
    let clean = validate_note_id(id)?;
    Ok(RelPath::normalize(&format!("{MEMORY_DIR_REL}/{clean}.md"))?)
}

/// Deduplicate and deterministically sort a tag list while trimming whitespace.
pub fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut cleaned: Vec<String> = tags
        .iter()
        .flat_map(|t| t.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    cleaned.sort();
    cleaned.dedup();
    cleaned
}

/// Canonical string label for a [`TrustLevel`] in plain-text formatters.
pub const fn trust_label(trust: TrustLevel) -> &'static str {
    match trust {
        TrustLevel::VerifiedAst => "VERIFIED_AST",
        TrustLevel::ExternalParser => "EXTERNAL_PARSER",
        TrustLevel::VerifiedRaw => "VERIFIED_RAW",
        TrustLevel::UserLocked => "USER_LOCKED",
        TrustLevel::Inferred => "INFERRED",
        TrustLevel::Stale => "STALE",
        TrustLevel::UnparsedFallback => "UNPARSED_FALLBACK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_note_ids_and_blocks_traversal_and_windows_reserved_names() {
        assert_eq!(
            validate_note_id("adr-001-chunk-save").unwrap(),
            "adr-001-chunk-save"
        );
        assert_eq!(
            validate_note_id("bug_sqlite.wal").unwrap(),
            "bug_sqlite.wal"
        );
        for bad in [
            "",
            "../escape",
            "dir/note",
            r"dir\note",
            ".hidden",
            "trailing.",
            "CON",
            "nul.md",
            "bad:stream",
            "has space",
            "türkçe-id",
        ] {
            assert!(
                validate_note_id(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn slugifies_turkish_and_emoji_titles_safely() {
        assert_eq!(
            slugify_note_id(
                MemoryKind::Decision,
                "Şişli'deki 16x16 parçalı dünya kaydı 🚀"
            ),
            "adr-sislideki-16x16-parcali-dunya-kaydi"
        );
        assert_eq!(
            slugify_note_id(MemoryKind::Bugfix, "ĞÜŞİÖÇ bağlantı hatası"),
            "bug-gusioc-baglanti-hatasi"
        );
        assert_eq!(slugify_note_id(MemoryKind::Feedback, "🚀✨"), "fb-note");
    }

    #[test]
    fn parses_file_and_symbol_anchor_specs() {
        let f = AnchorSpec::parse(r"src\world\save.rs").unwrap();
        assert_eq!(f.path, "src/world/save.rs");
        assert!(f.symbol.is_none());

        let s = AnchorSpec::parse("src/world/save.rs#impl World::save_chunk").unwrap();
        assert_eq!(s.path, "src/world/save.rs");
        assert_eq!(s.symbol.as_deref(), Some("impl World::save_chunk"));

        assert!(AnchorSpec::parse("../outside.rs").is_err());
        assert!(AnchorSpec::parse("src/a.rs#").is_err());
    }
}
