use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use ignore::WalkBuilder;
use klens_core::{
    ParseOutcome, ProjectConfig, ProjectMode, ProjectRoot, RelPath, blake3_file,
    blake3_normalized_bytes, blake3_parse_cache_key, normalize_line_endings,
    redact_secrets_by_line,
};

use crate::error::CodeError;
use crate::languages::AnalyzerRegistry;
use crate::sidecar::SidecarManager;
use crate::sidecar::common::{ExternalParseOutcome, build_external_import_edges};
use crate::store::{IndexStore, IndexedFileRecord, ParseStatus};

/// Default directory names always excluded from indexing even without a `.gitignore`.
const SKIPPED_DIRS: &[&str] = &[".git", ".klens", "node_modules", "target", ".venv"];

/// Upper size bound (4 MiB) for loading a file into RAM for AST / FTS5 indexing.
///
/// Larger files are recorded fail-closed as [`ParseStatus::Fallback`] with an explicit
/// warning and empty FTS5 content so huge generated blobs cannot exhaust memory.
pub const MAX_INDEXABLE_BYTES: u64 = 4 * 1024 * 1024;

/// Outcome of incrementally synchronizing a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSyncOutcome {
    /// File was newly added or its normalized BLAKE3 hash changed and it was re-parsed.
    Parsed,
    /// File's normalized BLAKE3 hash matched the cache; parsing was skipped.
    Unchanged,
    /// File appeared to be binary or non-UTF-8 and was skipped.
    SkippedBinary,
}

/// Summary counters returned by [`CodeIndex::sync_workspace`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStats {
    pub discovered: usize,
    pub parsed: usize,
    pub unchanged: usize,
    pub removed: usize,
    pub skipped_binary: usize,
}

/// Incremental Tree-sitter + SQLite WAL/FTS5 code index for a confined [`ProjectRoot`].
pub struct CodeIndex {
    project_root: ProjectRoot,
    project_config: ProjectConfig,
    store: IndexStore,
    registry: AnalyzerRegistry,
    sidecars: SidecarManager,
    read_only: bool,
}

impl CodeIndex {
    /// Open or initialize an incremental code index for `project_root`.
    ///
    /// - Active mode (`read_only = false` and `config.mode != ProjectMode::ReadOnly`):
    ///   stores SQLite cache at `<root>/.klens/cache/index.db`.
    /// - Read-only mode (`read_only = true` OR `config.mode == ProjectMode::ReadOnly`):
    ///   NEVER writes into `<root>`; stores SQLite cache at
    ///   `~/.klens/readonly-cache/<project_id>/index.db`.
    pub fn open(project_root: ProjectRoot, read_only: bool) -> Result<Self, CodeError> {
        Self::open_internal(project_root, read_only, None, None)
    }

    /// Open a read-only (or active) index using an explicit read-only cache root directory
    /// (useful for deterministic isolated tests).
    pub fn open_with_readonly_cache_dir(
        project_root: ProjectRoot,
        read_only: bool,
        readonly_cache_dir: impl AsRef<Path>,
    ) -> Result<Self, CodeError> {
        Self::open_internal(
            project_root,
            read_only,
            Some(readonly_cache_dir.as_ref().to_path_buf()),
            None,
        )
    }

    /// Open an index with explicit global config path (for isolated tests without mutating env).
    pub fn open_with_global_config(
        project_root: ProjectRoot,
        read_only: bool,
        readonly_cache_dir: Option<&Path>,
        global_cfg_path: Option<&Path>,
    ) -> Result<Self, CodeError> {
        Self::open_internal(
            project_root,
            read_only,
            readonly_cache_dir.map(Path::to_path_buf),
            global_cfg_path.map(Path::to_path_buf),
        )
    }

    fn open_internal(
        project_root: ProjectRoot,
        read_only: bool,
        readonly_cache_base: Option<PathBuf>,
        global_cfg_override: Option<PathBuf>,
    ) -> Result<Self, CodeError> {
        let cfg_path = project_root.root().join(".klens").join("config.toml");
        let project_config = ProjectConfig::load_or_default(&cfg_path)?;
        let effective_read_only = read_only || project_config.mode == ProjectMode::ReadOnly;

        let db_path = if effective_read_only {
            let base = match readonly_cache_base {
                Some(dir) => dir,
                None => default_readonly_cache_root()?,
            };
            base.join(project_root.project_id()).join("index.db")
        } else {
            project_root
                .root()
                .join(".klens")
                .join("cache")
                .join("index.db")
        };

        if !effective_read_only {
            ensure_cache_ignored_by_git(&db_path);
        }
        let store = IndexStore::open(&db_path, project_root.project_id())?;
        let global_cfg_path = global_cfg_override.or_else(default_global_config_path);
        // Sidecars are trusted ONLY from `~/.klens` (never from the project's own config).
        let sidecars = SidecarManager::load(global_cfg_path.as_deref(), &project_root);

        Ok(Self {
            project_root,
            project_config,
            store,
            registry: AnalyzerRegistry::new(),
            sidecars,
            read_only: effective_read_only,
        })
    }

    pub fn project_root(&self) -> &ProjectRoot {
        &self.project_root
    }

    pub fn project_config(&self) -> &ProjectConfig {
        &self.project_config
    }

    pub fn store(&self) -> &IndexStore {
        &self.store
    }

    /// Which external sidecar (custom `ext-lang-*` or ctags) would handle a non-built-in file.
    pub(crate) fn external_parser_slot(
        &mut self,
        rel: &RelPath,
    ) -> Option<crate::sidecar::ExternalParserSlot> {
        self.sidecars.resolve_slot(rel)
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Discover all non-ignored, non-sensitive, confined regular files under `root` (or `subdir`)
    /// in deterministic lexicographical order.
    pub fn discover_files(&self, subdir: Option<&RelPath>) -> Result<Vec<RelPath>, CodeError> {
        let walk_root = match subdir {
            Some(rel) => {
                let (abs, _) = self.project_root.resolve_existing_with_extra(
                    rel.as_str(),
                    &self.project_config.extra_sensitive_patterns,
                )?;
                abs
            }
            None => self.project_root.root().to_path_buf(),
        };

        let mut builder = WalkBuilder::new(&walk_root);
        builder
            .hidden(false)
            .follow_links(false)
            .git_ignore(true)
            .git_global(false)
            .git_exclude(true)
            .ignore(true)
            .parents(true)
            .require_git(false)
            .filter_entry(move |entry| {
                if entry.depth() == 0 {
                    return true;
                }
                if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                    let name = entry.file_name().to_string_lossy();
                    if SKIPPED_DIRS
                        .iter()
                        .any(|skip| name.eq_ignore_ascii_case(skip))
                    {
                        return false;
                    }
                }
                true
            });

        let mut discovered = BTreeSet::new();
        for result in builder.build() {
            let Ok(entry) = result else {
                continue;
            };
            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            let Ok(stripped) = entry.path().strip_prefix(self.project_root.root()) else {
                continue;
            };
            let Ok(rel) = RelPath::from_relative_path(stripped) else {
                continue;
            };
            if self.project_config.is_sensitive_file(&rel) {
                continue;
            }
            // Enforce full path confinement (blocks symlink escapes).
            if self
                .project_root
                .resolve_existing_with_extra(
                    rel.as_str(),
                    &self.project_config.extra_sensitive_patterns,
                )
                .is_err()
            {
                continue;
            }
            discovered.insert(rel);
        }

        Ok(discovered.into_iter().collect())
    }

    /// Incrementally synchronize a single file into the SQLite index.
    ///
    /// Re-parses ONLY when the file's CRLF-normalized BLAKE3 digest changed.
    pub fn sync_file(&mut self, rel: &RelPath) -> Result<FileSyncOutcome, CodeError> {
        let (abs_path, canonical_rel) = self.project_root.resolve_existing_with_extra(
            rel.as_str(),
            &self.project_config.extra_sensitive_patterns,
        )?;

        let meta = fs::metadata(&abs_path).map_err(|source| CodeError::Io {
            path: abs_path.clone(),
            source,
        })?;
        if !meta.is_file() {
            return Err(CodeError::NotAFile(canonical_rel.as_str().to_string()));
        }

        let (mtime_secs, mtime_nanos) = extract_mtime(&meta);
        let size_bytes = meta.len();

        if size_bytes > MAX_INDEXABLE_BYTES {
            if let Some(existing) = self.store.get_file(&canonical_rel)?
                && existing.parse_status == ParseStatus::Fallback
                && existing.mtime_secs == mtime_secs
                && existing.mtime_nanos == mtime_nanos
                && existing.size_bytes == size_bytes
            {
                return Ok(FileSyncOutcome::Unchanged);
            }

            let digest = blake3_file(&abs_path).map_err(|source| CodeError::Io {
                path: abs_path.clone(),
                source,
            })?;
            let language_id = self
                .registry
                .analyzer_for_path(&canonical_rel)
                .map(|a| a.language_id().to_string());
            let parser_id = "oversized".to_string();
            let parser_version = env!("CARGO_PKG_VERSION").to_string();
            let parse_cache_key = blake3_parse_cache_key(&digest, &parser_id, &parser_version);
            let record = IndexedFileRecord {
                path: canonical_rel,
                mtime_secs,
                mtime_nanos,
                size_bytes,
                blake3: digest,
                parse_cache_key,
                parser_id,
                parser_version,
                language_id,
                line_count: 0,
                parse_status: ParseStatus::Fallback,
                parse_warning: Some(format!(
                    "file exceeds maximum indexable size ({size_bytes} bytes > {MAX_INDEXABLE_BYTES} bytes); skipped AST and FTS5 indexing (fail-closed)"
                )),
            };
            self.store.upsert_file(&record, &[], &[], "")?;
            return Ok(FileSyncOutcome::Parsed);
        }

        let bytes = fs::read(&abs_path).map_err(|source| CodeError::Io {
            path: abs_path.clone(),
            source,
        })?;

        if is_binary_bytes(&bytes) {
            self.store.delete_file(&canonical_rel)?;
            return Ok(FileSyncOutcome::SkippedBinary);
        }

        let text = match std::str::from_utf8(&bytes) {
            Ok(s) => s,
            Err(_) => {
                self.store.delete_file(&canonical_rel)?;
                return Ok(FileSyncOutcome::SkippedBinary);
            }
        };

        let digest = blake3_normalized_bytes(&bytes);
        let normalized = normalize_line_endings(text);

        // Layer 1 (built-in AST / structured docs) ALWAYS takes precedence over Layer 2/3 sidecars.
        let builtin_lang = self
            .registry
            .analyzer_for_path(&canonical_rel)
            .map(|a| a.language_id());
        let external_slot = if builtin_lang.is_none() {
            self.sidecars.resolve_slot(&canonical_rel)
        } else {
            None
        };

        let (parser_id, parser_version) = if let Some(lang) = builtin_lang {
            (
                format!("builtin:{lang}"),
                env!("CARGO_PKG_VERSION").to_string(),
            )
        } else if let Some(slot) = &external_slot {
            (
                slot.parser_id().to_string(),
                slot.parser_version().to_string(),
            )
        } else {
            ("none".to_string(), "0".to_string())
        };

        let expected_cache_key = blake3_parse_cache_key(&normalized, &parser_id, &parser_version);

        if let Some(existing) = self.store.get_file(&canonical_rel)?
            && existing.parse_cache_key == expected_cache_key
        {
            if existing.mtime_secs != mtime_secs
                || existing.mtime_nanos != mtime_nanos
                || existing.size_bytes != size_bytes
            {
                self.store
                    .touch_file_mtime(&canonical_rel, mtime_secs, mtime_nanos, size_bytes)?;
            }
            return Ok(FileSyncOutcome::Unchanged);
        }

        let line_count = count_lines(&normalized);

        let (language_id, parse_status, parse_warning, symbols, byte_ranges, edges) = if let Some(
            analyzer,
        ) =
            self.registry.analyzer_for_path(&canonical_rel)
        {
            match analyzer.parse_symbols(&normalized, &canonical_rel) {
                ParseOutcome::Parsed(file_symbols) => {
                    let edges = analyzer.extract_edges(&normalized, &file_symbols);
                    (
                        Some(file_symbols.language_id),
                        ParseStatus::Parsed,
                        None,
                        file_symbols.symbols,
                        Vec::new(),
                        edges,
                    )
                }
                ParseOutcome::Partial { value, warnings } => {
                    let edges = analyzer.extract_edges(&normalized, &value);
                    (
                        Some(value.language_id),
                        ParseStatus::Partial,
                        Some(warnings.join("; ")),
                        value.symbols,
                        Vec::new(),
                        edges,
                    )
                }
                ParseOutcome::Fallback { reason } => (
                    Some(analyzer.language_id().to_string()),
                    ParseStatus::Fallback,
                    Some(reason),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            }
        } else if let Some(slot) = &external_slot {
            match self.sidecars.parse_with_slot(
                slot,
                &canonical_rel,
                &normalized,
                &digest,
                line_count,
            ) {
                ExternalParseOutcome::Parsed(ok) => {
                    let edges = build_external_import_edges(
                        &canonical_rel,
                        &ok.parser_id,
                        &ok.parser_version,
                        &ok.imports,
                    );
                    let warning = (!ok.warnings.is_empty()).then(|| ok.warnings.join("; "));
                    (
                        Some(ok.language_id),
                        ok.status,
                        warning,
                        ok.symbols,
                        ok.byte_ranges,
                        edges,
                    )
                }
                ExternalParseOutcome::Fallback {
                    language_id,
                    reason,
                    ..
                } => (
                    language_id,
                    ParseStatus::Fallback,
                    Some(reason),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            }
        } else {
            (
                None,
                ParseStatus::Fallback,
                Some(format!(
                    "unsupported file type `{}`; no AST parser available (fail-closed, no regex fallback)",
                    canonical_rel.as_str()
                )),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        };

        let record = IndexedFileRecord {
            path: canonical_rel,
            mtime_secs,
            mtime_nanos,
            size_bytes,
            blake3: digest,
            parse_cache_key: expected_cache_key,
            parser_id,
            parser_version,
            language_id,
            line_count,
            parse_status,
            parse_warning,
        };

        // Line-preserving: a PEM key block becomes one placeholder per line, so `klens_find` and
        // `klens_impact` line numbers after a key block stay true.
        let redacted_for_fts = redact_secrets_by_line(&normalized).text;
        self.store.upsert_file_with_byte_ranges(
            &record,
            &symbols,
            &byte_ranges,
            &edges,
            &redacted_for_fts,
        )?;

        Ok(FileSyncOutcome::Parsed)
    }

    /// Incrementally synchronize the entire project workspace.
    pub fn sync_workspace(&mut self) -> Result<SyncStats, CodeError> {
        self.sidecars.reset_circuit_breakers();
        let res = self.sync_workspace_inner();
        self.sidecars.shutdown_all();
        res
    }

    fn sync_workspace_inner(&mut self) -> Result<SyncStats, CodeError> {
        let discovered = self.discover_files(None)?;
        let discovered_set: BTreeSet<RelPath> = discovered.iter().cloned().collect();

        let existing = self.store.list_files()?;
        let mut stats = SyncStats {
            discovered: discovered.len(),
            ..SyncStats::default()
        };

        for old in existing {
            if !discovered_set.contains(&old.path) {
                self.store.delete_file(&old.path)?;
                stats.removed += 1;
            }
        }

        for rel in &discovered {
            match self.sync_file(rel)? {
                FileSyncOutcome::Parsed => stats.parsed += 1,
                FileSyncOutcome::Unchanged => stats.unchanged += 1,
                FileSyncOutcome::SkippedBinary => stats.skipped_binary += 1,
            }
        }

        Ok(stats)
    }

    /// Discover and incrementally sync all files under `subdir` (or workspace root if `None`).
    pub fn sync_directory(&mut self, subdir: Option<&RelPath>) -> Result<Vec<RelPath>, CodeError> {
        self.sidecars.reset_circuit_breakers();
        let res = self.sync_directory_inner(subdir);
        self.sidecars.shutdown_all();
        res
    }

    fn sync_directory_inner(
        &mut self,
        subdir: Option<&RelPath>,
    ) -> Result<Vec<RelPath>, CodeError> {
        let files = self.discover_files(subdir)?;
        let mut indexed = Vec::with_capacity(files.len());
        for rel in files {
            match self.sync_file(&rel)? {
                FileSyncOutcome::Parsed | FileSyncOutcome::Unchanged => indexed.push(rel),
                FileSyncOutcome::SkippedBinary => {}
            }
        }
        Ok(indexed)
    }
}

/// Resolve `~/.klens/config.toml` cross-platform without failing if home is unset.
fn default_global_config_path() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(home).join(".klens").join("config.toml"))
}

/// The in-project cache folder ignores itself (`*`), so projects that never ran
/// `klens attach` show no untracked `.klens/cache` files. Best effort: a failure here only
/// means the folder stays visible to git.
fn ensure_cache_ignored_by_git(db_path: &Path) {
    let Some(cache_dir) = db_path.parent() else {
        return;
    };
    let ignore = cache_dir.join(".gitignore");
    if ignore.exists() || std::fs::create_dir_all(cache_dir).is_err() {
        return;
    }
    let _ = klens_core::write_atomic(
        &ignore,
        b"# Created by klens: disposable index cache, never committed.\n*\n",
    );
}

/// Resolve `~/.klens/readonly-cache` cross-platform.
pub fn default_readonly_cache_root() -> Result<PathBuf, CodeError> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .ok_or(CodeError::MissingHomeDir)?;
    Ok(PathBuf::from(home).join(".klens").join("readonly-cache"))
}

/// Heuristic binary check: NUL byte within the first 8 KiB.
pub fn is_binary_bytes(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(8192);
    bytes[..sample_len].contains(&0)
}

fn extract_mtime(meta: &fs::Metadata) -> (i64, i64) {
    match meta.modified() {
        Ok(time) => match time.duration_since(UNIX_EPOCH) {
            Ok(dur) => (dur.as_secs() as i64, i64::from(dur.subsec_nanos())),
            Err(_) => (0, 0),
        },
        Err(_) => (0, 0),
    }
}

fn count_lines(normalized: &str) -> usize {
    if normalized.is_empty() {
        return 0;
    }
    normalized.lines().count()
}
