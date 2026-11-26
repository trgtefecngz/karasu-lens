//! Phase 4 mandatory unit & adversarial tests for `klens-memory`.
//!
//! Enforces all 4 mandatory test gates of `docs/phases/phase-4.md`:
//! 1. Staleness detection (`TrustLevel::VerifiedRaw` -> edit 1 line -> `TrustLevel::Stale` + `changed_hash`,
//!    plus CRLF/LF immunity and `missing_file`).
//! 2. Deleted symbol staleness (`TrustLevel::Stale` + `missing_symbol`).
//! 3. Obsidian & UTF-8 Turkish compatibility (`ğüşiöçĞÜŞİÖÇ`, `[[wikilink]]`, verbatim body preservation on `refresh`).
//! 4. Progressive-disclosure index budget (50 long notes -> zero body leak + deterministic order).
//!
//! Plus full CRUD, feedback kind, secret redaction, FTS5 search, and `match_error` bugfix matching.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::{ProjectRoot, TrustLevel};
use klens_memory::{
    AddMemoryRequest, AnchorSpec, HeuristicSymbolResolver, MemoryError, MemoryKind, MemoryStatus,
    StaleReason, UpdateMemoryRequest, add_memory, delete_memory, format_bugfix_matches_inline,
    format_memory_index_text, get_memory, list_memory_index, match_error, parse_markdown_note,
    refresh_memory, search_memory, update_memory, verify_all_notes,
};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-memory-test-{label}-{}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, content).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Gate 1: Staleness Detection (`changed_hash`, CRLF/LF normalization, `missing_file`)
// ---------------------------------------------------------------------------

#[test]
fn gate_1_staleness_detects_single_line_edit_missing_file_and_ignores_crlf_only_changes() {
    let sb = Sandbox::new("staleness");
    sb.write(
        "src/save.rs",
        "pub fn save_chunk(id: u32) -> bool {\n    id > 0\n}\n",
    );

    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    let added = add_memory(
        &root,
        AddMemoryRequest {
            id: Some("adr-001-chunk-save".to_string()),
            title: "16x16 chunk binary save decision".to_string(),
            kind: MemoryKind::Decision,
            body: "## Karar\nBinary chunk format chosen over monolithic JSON.\n".to_string(),
            anchors: vec![AnchorSpec::file("src/save.rs")],
            tags: vec!["world".to_string(), "storage".to_string()],
        },
        &mut resolver,
    )
    .unwrap();
    assert_eq!(added.trust, TrustLevel::VerifiedRaw);

    // 1. Fresh read immediately after creation.
    let fresh = get_memory(&root, "adr-001-chunk-save", &mut resolver).unwrap();
    assert_eq!(fresh.trust, TrustLevel::VerifiedRaw);
    assert!(fresh.data.verification.fresh);

    // 2. Converting LF -> CRLF without content change MUST stay fresh (Article 8).
    sb.write(
        "src/save.rs",
        "pub fn save_chunk(id: u32) -> bool {\r\n    id > 0\r\n}\r\n",
    );
    let crlf_check = get_memory(&root, "adr-001-chunk-save", &mut resolver).unwrap();
    assert_eq!(
        crlf_check.trust,
        TrustLevel::VerifiedRaw,
        "CRLF line endings must not cause false STALE alarms"
    );

    // 3. Modifying a single line MUST immediately flip to `TrustLevel::Stale` + `changed_hash`.
    sb.write(
        "src/save.rs",
        "pub fn save_chunk(id: u32) -> bool {\n    id >= 1\n}\n",
    );
    let stale = get_memory(&root, "adr-001-chunk-save", &mut resolver).unwrap();
    assert_eq!(stale.trust, TrustLevel::Stale);
    assert!(!stale.data.verification.fresh);
    assert_eq!(
        stale.data.verification.anchor_checks[0].stale_reason,
        Some(StaleReason::ChangedHash)
    );
    assert!(
        stale.warnings.iter().any(|w| w.contains("changed_hash")),
        "warnings must mention changed_hash, got: {:?}",
        stale.warnings
    );

    // 4. Deleting the anchored file MUST report `STALE` + `missing_file`.
    fs::remove_file(sb.path().join("src/save.rs")).unwrap();
    let missing = get_memory(&root, "adr-001-chunk-save", &mut resolver).unwrap();
    assert_eq!(missing.trust, TrustLevel::Stale);
    assert_eq!(
        missing.data.verification.anchor_checks[0].stale_reason,
        Some(StaleReason::MissingFile)
    );
}

// ---------------------------------------------------------------------------
// Gate 2: Deleted Symbol Staleness (`missing_symbol`)
// ---------------------------------------------------------------------------

#[test]
fn gate_2_deleted_symbol_triggers_stale_missing_symbol_while_unrelated_edits_stay_fresh() {
    let sb = Sandbox::new("deleted-sym");
    sb.write(
        "src/world/save.rs",
        concat!(
            "pub struct World;\n",
            "impl World {\n",
            "    pub fn save_chunk(&self, id: u32) -> bool {\n",
            "        id > 0\n",
            "    }\n",
            "}\n",
            "pub fn unrelated_helper() -> usize {\n",
            "    1\n",
            "}\n",
        ),
    );

    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    let added = add_memory(
        &root,
        AddMemoryRequest {
            id: Some("adr-save-chunk".to_string()),
            title: "World::save_chunk contract".to_string(),
            kind: MemoryKind::Architecture,
            body: "Anchored strictly to `impl World::save_chunk`.\n".to_string(),
            anchors: vec![AnchorSpec::symbol(
                "src/world/save.rs",
                "impl World::save_chunk",
            )],
            tags: vec!["world".to_string()],
        },
        &mut resolver,
    )
    .unwrap();
    assert_eq!(added.trust, TrustLevel::VerifiedRaw);

    // Editing an unrelated function in the same file keeps the symbol anchor fresh.
    sb.write(
        "src/world/save.rs",
        concat!(
            "// Added top comment shifting line numbers\n",
            "pub struct World;\n",
            "impl World {\n",
            "    pub fn save_chunk(&self, id: u32) -> bool {\n",
            "        id > 0\n",
            "    }\n",
            "}\n",
            "pub fn unrelated_helper() -> usize {\n",
            "    999\n",
            "}\n",
        ),
    );
    let still_fresh = get_memory(&root, "adr-save-chunk", &mut resolver).unwrap();
    assert_eq!(still_fresh.trust, TrustLevel::VerifiedRaw);

    // Deleting `save_chunk` MUST report `STALE` + `missing_symbol`.
    sb.write(
        "src/world/save.rs",
        concat!(
            "pub struct World;\n",
            "impl World {\n",
            "    pub fn other_fn(&self) {}\n",
            "}\n",
        ),
    );
    let deleted_sym = get_memory(&root, "adr-save-chunk", &mut resolver).unwrap();
    assert_eq!(deleted_sym.trust, TrustLevel::Stale);
    assert_eq!(
        deleted_sym.data.verification.anchor_checks[0].stale_reason,
        Some(StaleReason::MissingSymbol)
    );
    assert!(
        deleted_sym
            .warnings
            .iter()
            .any(|w| w.contains("missing_symbol")),
        "expected missing_symbol warning, got: {:?}",
        deleted_sym.warnings
    );
}

// ---------------------------------------------------------------------------
// Gate 3: Obsidian & Turkish UTF-8 Compatibility + Body Preservation on `refresh`
// ---------------------------------------------------------------------------

#[test]
fn gate_3_obsidian_utf8_turkish_wikilinks_and_verbatim_body_preservation_on_refresh() {
    let sb = Sandbox::new("obsidian-utf8");
    sb.write(
        "src/kayit.rs",
        "pub fn kaydet() -> &'static str { \"v1\" }\n",
    );

    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("adr-turkce-kayit".to_string()),
            title: "Dünya kayıt sistemi: ğüşiöçĞÜŞİÖÇ & 🚀".to_string(),
            kind: MemoryKind::Decision,
            body: "## Karar\nİlk not içeriği.\n\n- [[PROJECT_CONTRACT]]\n- [[kayit.rs]]\n"
                .to_string(),
            anchors: vec![AnchorSpec::file("src/kayit.rs")],
            tags: vec!["depolama".to_string(), "türkçe".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    let note_path = sb.path().join(".klens/memory/adr-turkce-kayit.md");
    let disk_before = fs::read_to_string(&note_path).unwrap();
    assert!(disk_before.starts_with("---\n"));
    assert!(disk_before.contains("schema_version: 1"));
    assert!(disk_before.contains("ğüşiöçĞÜŞİÖÇ"));
    assert!(disk_before.contains("[[PROJECT_CONTRACT]]"));
    assert!(disk_before.contains("[[kayit.rs]]"));

    // Simulate a user hand-editing the Markdown body in Obsidian with rich formatting & Turkish text.
    let hand_edited_body = concat!(
        "## Karar (Obsidian'da Elle Düzenlendi)\n",
        "Şişli'den özel not: ğüşiöçĞÜŞİÖÇ — ışık hızında indeksleme 🚀\n",
        "\n",
        "- [x] [[PROJECT_CONTRACT|Kilitli Sözleşme]]\n",
        "- [ ] [[Mimari Harita#Önbellek]]\n",
        "\n",
        "```rust\n",
        "// Elle eklenen kod örneği (dokunulmamalı!)\n",
        "let x = \"ğüşiöç\";\n",
        "```\n",
    );
    let parsed_orig =
        parse_markdown_note(".klens/memory/adr-turkce-kayit.md", &disk_before).unwrap();
    let custom_md =
        klens_memory::serialize_markdown_note(&parsed_orig.frontmatter, hand_edited_body);
    fs::write(&note_path, &custom_md).unwrap();

    // Modify source file -> note becomes STALE.
    sb.write(
        "src/kayit.rs",
        "pub fn kaydet() -> &'static str { \"v2\" }\n",
    );
    let stale = get_memory(&root, "adr-turkce-kayit", &mut resolver).unwrap();
    assert_eq!(stale.trust, TrustLevel::Stale);

    // Refresh anchor hashes -> note becomes fresh AND hand-edited Markdown body is preserved verbatim!
    let refreshed = refresh_memory(&root, "adr-turkce-kayit", &mut resolver).unwrap();
    assert_eq!(refreshed.trust, TrustLevel::VerifiedRaw);
    assert_eq!(refreshed.data.note.body, hand_edited_body);
    assert_eq!(
        refreshed.data.note.wikilinks,
        vec!["Mimari Harita", "PROJECT_CONTRACT"]
    );

    let after_get = get_memory(&root, "adr-turkce-kayit", &mut resolver).unwrap();
    assert_eq!(after_get.trust, TrustLevel::VerifiedRaw);
    assert_eq!(after_get.data.note.body, hand_edited_body);
}

// ---------------------------------------------------------------------------
// Gate 4: Progressive-Disclosure Index Budget (50 Long Notes, Zero Body Leak)
// ---------------------------------------------------------------------------

#[test]
fn gate_4_progressive_index_with_50_long_notes_never_leaks_bodies_and_is_deterministic() {
    let sb = Sandbox::new("progressive-50");
    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    let filler = "Detaylı uzun karar metni — ğüşiöç ".repeat(120);
    for i in 0..50 {
        let id = format!("note-{i:03}");
        let unique_body_marker = format!("SECRET_BODY_MARKER_DO_NOT_LEAK_{i:03}");
        add_memory(
            &root,
            AddMemoryRequest {
                id: Some(id),
                title: format!("Architectural note #{i:03}"),
                kind: if i % 2 == 0 {
                    MemoryKind::Decision
                } else {
                    MemoryKind::Feedback
                },
                body: format!("## Body {i}\n{unique_body_marker}\n{filler}\n"),
                anchors: Vec::new(),
                tags: vec![format!("grp-{}", i % 5)],
            },
            &mut resolver,
        )
        .unwrap();
    }

    let idx1 = list_memory_index(&root, None, None, false, &mut resolver).unwrap();
    let idx2 = list_memory_index(&root, None, None, false, &mut resolver).unwrap();
    assert_eq!(idx1.data.total_notes, 50);

    let json1 = idx1.to_deterministic_json().unwrap();
    let json2 = idx2.to_deterministic_json().unwrap();
    assert_eq!(
        json1, json2,
        "progressive index JSON must be byte-for-byte deterministic"
    );

    let text1 = format_memory_index_text(&idx1);
    let text2 = format_memory_index_text(&idx2);
    assert_eq!(
        text1, text2,
        "progressive index text must be byte-for-byte deterministic"
    );

    // Verify deterministic ascending ID order and ZERO body leakage!
    for (i, entry) in idx1.data.entries.iter().enumerate().take(50) {
        assert_eq!(entry.id, format!("note-{i:03}"));
        let marker = format!("SECRET_BODY_MARKER_DO_NOT_LEAK_{i:03}");
        assert!(
            !json1.contains(&marker),
            "index JSON leaked body marker `{marker}`!"
        );
        assert!(
            !text1.contains(&marker),
            "index text leaked body marker `{marker}`!"
        );
    }
}

// ---------------------------------------------------------------------------
// CRUD, FTS5 Search, Redaction, Path Confinement, and `match_error`
// ---------------------------------------------------------------------------

#[test]
fn crud_fts5_search_secret_redaction_and_bugfix_error_matching() {
    let sb = Sandbox::new("crud-search-match");
    sb.write("src/db.rs", "pub fn open_db() -> bool { true }\n");

    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    let fake_token = format!("ghp_{}", "1234567890abcdefghij1234567890abcdef");

    // 1. Add a bugfix note and a decision note.
    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("bug-sqlite-busy".to_string()),
            title: "SQLITE_BUSY kilidi için WAL + busy_timeout çözümü".to_string(),
            kind: MemoryKind::Bugfix,
            body: format!(
                "## Kök Neden\nEşzamanlı bağlantılarda SQLITE_BUSY hatası.\nTest token: {fake_token}\n"
            ),
            anchors: vec![AnchorSpec::file("src/db.rs")],
            tags: vec!["sqlite".to_string(), "wal".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("adr-unrelated".to_string()),
            title: "SQLITE_BUSY mimari notu (decision, bugfix değil)".to_string(),
            kind: MemoryKind::Decision,
            body: "Bu bir karar notudur, bugfix değildir.\n".to_string(),
            anchors: Vec::new(),
            tags: vec!["sqlite".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    // 2. Output gate redacts secrets automatically.
    let got = get_memory(&root, "bug-sqlite-busy", &mut resolver).unwrap();
    assert_eq!(got.redactions_count, 1);
    assert!(got.data.note.body.contains("[REDACTED:GITHUB_TOKEN]"));
    assert!(!got.data.note.body.contains(&fake_token));

    // 3. FTS5 search matches Turkish + error code deterministically.
    let searched =
        search_memory(&root, "SQLITE_BUSY kilidi", None, Some(10), &mut resolver).unwrap();
    assert!(!searched.data.hits.is_empty());
    assert_eq!(searched.data.hits[0].entry.id, "bug-sqlite-busy");

    // 4. `match_error` matches ONLY `kind: bugfix` notes and reports `[Taze]`.
    let matches = match_error(
        &root,
        "error: database returned SQLITE_BUSY in src/db.rs:14",
        3,
        &mut resolver,
    )
    .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, "bug-sqlite-busy");
    assert!(!matches[0].is_stale);
    let inline = format_bugfix_matches_inline(&matches);
    assert!(inline.contains("[Taze]"));
    assert!(inline.contains(".klens/memory/bug-sqlite-busy.md"));

    // 5. Mutating `src/db.rs` flips `match_error` badge to `[STALE]` immediately!
    sb.write("src/db.rs", "pub fn open_db() -> bool { false }\n");
    let stale_matches = match_error(&root, "fatal: SQLITE_BUSY", 3, &mut resolver).unwrap();
    assert_eq!(stale_matches.len(), 1);
    assert!(stale_matches[0].is_stale);
    assert!(format_bugfix_matches_inline(&stale_matches).contains("[STALE]"));

    // 6. `verify_all_notes` catches the stale note.
    let verified = verify_all_notes(&root, &mut resolver).unwrap();
    assert_eq!(verified.trust, TrustLevel::Stale);
    assert_eq!(verified.data.stale_count, 1);
    assert_eq!(verified.data.stale_notes[0].id, "bug-sqlite-busy");

    // 7. Update & delete + traversal rejection.
    let updated = update_memory(
        &root,
        UpdateMemoryRequest {
            id: "adr-unrelated".to_string(),
            title: Some("Güncellenmiş karar".to_string()),
            kind: Some(MemoryKind::Feedback),
            status: Some(MemoryStatus::Archived),
            body: None,
            anchors: None,
            tags: Some(vec!["review".to_string()]),
            refresh_anchors: false,
        },
        &mut resolver,
    )
    .unwrap();
    assert_eq!(updated.data.note.frontmatter.kind, MemoryKind::Feedback);
    assert_eq!(updated.data.note.frontmatter.status, MemoryStatus::Archived);

    let del = delete_memory(&root, "adr-unrelated").unwrap();
    assert!(del.data.deleted);
    assert!(matches!(
        get_memory(&root, "adr-unrelated", &mut resolver),
        Err(MemoryError::NotFound(_))
    ));
    assert!(matches!(
        get_memory(&root, "../escape", &mut resolver),
        Err(MemoryError::InvalidId(_))
    ));
}

// ---------------------------------------------------------------------------
// Regression Locks for Review Fixes #1, #3, #5
// ---------------------------------------------------------------------------

#[test]
fn regression_leading_newline_body_roundtrips_verbatim_through_serialize_and_refresh() {
    let sb = Sandbox::new("leading-nl");
    sb.write("src/app.rs", "pub fn run() -> i32 { 1 }\n");

    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    let body_with_leading_blank = "\n## Başlık\nİçerik (ğüşiöç)\n\n- [[PROJECT_CONTRACT]]\n";
    let added = add_memory(
        &root,
        AddMemoryRequest {
            id: Some("adr-leading-nl".to_string()),
            title: "Leading newline body preservation".to_string(),
            kind: MemoryKind::Decision,
            body: body_with_leading_blank.to_string(),
            anchors: vec![AnchorSpec::file("src/app.rs")],
            tags: vec!["format".to_string()],
        },
        &mut resolver,
    )
    .unwrap();
    assert_eq!(added.data.note.body, body_with_leading_blank);

    sb.write("src/app.rs", "pub fn run() -> i32 { 2 }\n");
    let refreshed = refresh_memory(&root, "adr-leading-nl", &mut resolver).unwrap();
    assert_eq!(refreshed.trust, TrustLevel::VerifiedRaw);
    assert_eq!(
        refreshed.data.note.body, body_with_leading_blank,
        "refresh_memory must preserve leading blank line verbatim"
    );

    let fetched = get_memory(&root, "adr-leading-nl", &mut resolver).unwrap();
    assert_eq!(fetched.data.note.body, body_with_leading_blank);
}

#[test]
fn regression_windows_drive_path_bugfix_match_fts5_bm25_weights_and_refresh_anchor_sort() {
    let sb = Sandbox::new("win-path-fts-sort");
    sb.write("src/alpha.rs", "pub fn a() {}\n");
    sb.write("src/db.rs", "pub fn connect() {}\n");

    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    // 1. FTS5 6-column bm25 weights: title match must outrank body-only match cleanly.
    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("note-body-only".to_string()),
            title: "General storage overview".to_string(),
            kind: MemoryKind::Decision,
            body: "Mentions quorumlock once inside body text.\n".to_string(),
            anchors: Vec::new(),
            tags: Vec::new(),
        },
        &mut resolver,
    )
    .unwrap();
    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("note-title-hit".to_string()),
            title: "Quorumlock consensus protocol".to_string(),
            kind: MemoryKind::Decision,
            body: "Detailed architecture notes.\n".to_string(),
            anchors: Vec::new(),
            tags: Vec::new(),
        },
        &mut resolver,
    )
    .unwrap();

    let search = search_memory(&root, "quorumlock", None, Some(10), &mut resolver).unwrap();
    assert_eq!(search.data.hits.len(), 2);
    assert_eq!(
        search.data.hits[0].entry.id, "note-title-hit",
        "6-column FTS5 bm25 must rank title hit ahead of body-only hit"
    );

    // 2. Windows drive-letter absolute path (`C:\repo\src\db.rs:14:5`) matches anchored bugfix!
    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("bug-win-db".to_string()),
            title: "Connection pool reset checklist".to_string(),
            kind: MemoryKind::Bugfix,
            body: "Restart handle cleanly when pool closes.\n".to_string(),
            anchors: vec![AnchorSpec::file("src/db.rs")],
            tags: vec!["database".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    let win_matches = match_error(
        &root,
        r"thread 'main' panicked at C:\repo\src\db.rs:14:5: unexpected close",
        3,
        &mut resolver,
    )
    .unwrap();
    assert_eq!(win_matches.len(), 1);
    assert_eq!(win_matches[0].id, "bug-win-db");
    assert!(
        win_matches[0]
            .matched_terms
            .iter()
            .any(|t| t == "src/db.rs"),
        "expected Windows path C:\\repo\\src\\db.rs:14:5 to correlate with anchor src/db.rs, got: {:?}",
        win_matches[0].matched_terms
    );

    // 3. Hand-edited unsorted/duplicate anchors are canonically sorted & deduped by `refresh_memory`.
    let raw_unsorted = concat!(
        "---\n",
        "schema_version: 1\n",
        "id: adr-unsorted-anchors\n",
        "title: Unsorted anchors test\n",
        "kind: decision\n",
        "created_at: 2026-11-22T18:40:00Z\n",
        "updated_at: 2026-11-22T18:40:00Z\n",
        "status: active\n",
        "anchors:\n",
        "  - path: src/db.rs\n",
        "    blake3: \"deadbeef\"\n",
        "  - path: src/alpha.rs\n",
        "    blake3: \"deadbeef\"\n",
        "  - path: src/db.rs\n",
        "    blake3: \"deadbeef\"\n",
        "tags: []\n",
        "---\n",
        "\n",
        "Body.\n",
    );
    sb.write(".klens/memory/adr-unsorted-anchors.md", raw_unsorted);

    let refreshed = refresh_memory(&root, "adr-unsorted-anchors", &mut resolver).unwrap();
    let paths: Vec<&str> = refreshed
        .data
        .note
        .frontmatter
        .anchors
        .iter()
        .map(|a| a.path.as_str())
        .collect();
    assert_eq!(paths, vec!["src/alpha.rs", "src/db.rs"]);
}
