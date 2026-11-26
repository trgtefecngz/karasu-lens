//! Phase 3 tests for `klens-memory` batch export (`export_memory`) and batch refresh (`refresh_memories`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::{ProjectRoot, TrustLevel};
use klens_memory::{
    AddMemoryRequest, AnchorSpec, BatchRefreshItemOutcome, HeuristicSymbolResolver, MemoryError,
    MemoryExportFormat, MemoryExportRequest, MemoryKind, add_memory, export_memory,
    format_memory_batch_refresh_text, format_memory_export_text, get_memory, parse_markdown_note,
    refresh_memories, serialize_markdown_note,
};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-memory-batch-{label}-{}-{n}",
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

fn snapshot_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.is_file()
                    && let Ok(bytes) = fs::read(&path)
                {
                    out.insert(path, bytes);
                }
            }
        }
    }
    let mut map = BTreeMap::new();
    walk(root, &mut map);
    map
}

#[test]
fn export_memory_deterministic_filtering_staleness_secret_redaction_and_zero_writes() {
    assert_eq!(
        MemoryExportFormat::parse("md").unwrap(),
        MemoryExportFormat::Markdown
    );
    assert_eq!(
        MemoryExportFormat::parse("MARKDOWN").unwrap(),
        MemoryExportFormat::Markdown
    );
    assert_eq!(
        MemoryExportFormat::parse("json").unwrap(),
        MemoryExportFormat::Json
    );
    assert!(matches!(
        MemoryExportFormat::parse("yaml"),
        Err(MemoryError::InvalidExportFormat(_))
    ));

    let sb = Sandbox::new("export");
    sb.write("src/a.rs", "pub fn alpha() -> i32 { 1 }\n");
    sb.write("src/b.rs", "pub fn beta() -> i32 { 2 }\n");

    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    let fake_token = format!("ghp_{}", "abcdef1234567890abcdef1234567890abcd");

    // Create notes out of alphabetical ID order to prove deterministic sorting.
    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("z-bugfix-secret".to_string()),
            title: format!("Fix token leak with {fake_token}"),
            kind: MemoryKind::Bugfix,
            body: format!("## Root Cause\nLeaked key `{fake_token}` in logs.\n"),
            anchors: vec![AnchorSpec::file("src/b.rs")],
            tags: vec!["security".to_string(), "ops".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("a-decision-core".to_string()),
            title: "Deterministic core design (ğüşiöç)".to_string(),
            kind: MemoryKind::Decision,
            body: "## Decision\nKeep [[PROJECT_CONTRACT]] canonical.\n".to_string(),
            anchors: vec![AnchorSpec::file("src/a.rs")],
            tags: vec!["core".to_string(), "ops".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    // Add a corrupt frontmatter file to verify warnings are never silently swallowed.
    sb.write(".klens/memory/corrupt-broken.md", "no frontmatter here\n");

    // Mutate `src/b.rs` so `z-bugfix-secret` becomes STALE while `a-decision-core` stays fresh.
    sb.write("src/b.rs", "pub fn beta() -> i32 { 99 }\n");

    let before_snap = snapshot_files(sb.path());

    // 1. Full Markdown export.
    let exp_md1 = export_memory(
        &root,
        MemoryExportRequest {
            kind: None,
            tag: None,
            stale_only: false,
            format: MemoryExportFormat::Markdown,
        },
        &mut resolver,
    )
    .unwrap();
    let exp_md2 = export_memory(
        &root,
        MemoryExportRequest {
            kind: None,
            tag: None,
            stale_only: false,
            format: MemoryExportFormat::Markdown,
        },
        &mut resolver,
    )
    .unwrap();

    assert_eq!(exp_md1.trust, TrustLevel::Stale);
    assert_eq!(exp_md1.data.total_notes, 2);
    assert_eq!(exp_md1.data.stale_count, 1);
    assert!(
        exp_md1.redactions_count >= 2,
        "expected >= 2 secret redactions (title + body), got {}",
        exp_md1.redactions_count
    );

    // Deterministic ID order: a-decision-core before z-bugfix-secret.
    let ids: Vec<&str> = exp_md1
        .data
        .notes
        .iter()
        .map(|n| n.note.frontmatter.id.as_str())
        .collect();
    assert_eq!(ids, vec!["a-decision-core", "z-bugfix-secret"]);

    // Byte-for-byte deterministic Markdown and JSON outputs.
    let rendered_md = exp_md1
        .data
        .rendered_markdown
        .as_deref()
        .expect("markdown export must populate rendered_markdown");
    assert_eq!(
        rendered_md,
        exp_md2.data.rendered_markdown.as_deref().unwrap()
    );
    assert_eq!(format_memory_export_text(&exp_md1), rendered_md);
    assert!(rendered_md.contains("a-decision-core"));
    assert!(rendered_md.contains("z-bugfix-secret"));
    assert!(rendered_md.contains("[VERIFIED_RAW]"));
    assert!(rendered_md.contains("[STALE]"));
    assert!(rendered_md.contains("[REDACTED:GITHUB_TOKEN]"));
    assert!(
        !rendered_md.contains(&fake_token),
        "rendered Markdown leaked raw secret!"
    );

    // Corrupt frontmatter file MUST appear in warnings.
    assert!(
        exp_md1
            .warnings
            .iter()
            .any(|w| w.contains("corrupt-broken.md")),
        "expected corrupt-broken.md warning, got: {:?}",
        exp_md1.warnings
    );

    // 2. JSON export with `stale_only = true`, `kind`, and `tag` filters.
    let exp_json = export_memory(
        &root,
        MemoryExportRequest {
            kind: Some(MemoryKind::Bugfix),
            tag: Some("SECURITY".to_string()),
            stale_only: true,
            format: MemoryExportFormat::Json,
        },
        &mut resolver,
    )
    .unwrap();
    assert_eq!(exp_json.data.total_notes, 1);
    assert_eq!(exp_json.data.stale_count, 1);
    assert!(exp_json.data.rendered_markdown.is_none());
    assert_eq!(
        exp_json.data.notes[0].note.frontmatter.id,
        "z-bugfix-secret"
    );
    assert!(exp_json.redactions_count >= 2);
    let json_text = exp_json.to_deterministic_json().unwrap();
    assert!(
        !json_text.contains(&fake_token),
        "JSON export leaked raw secret!"
    );

    // 3. Zero-write invariant: `export_memory` wrote 0 bytes anywhere in the project!
    let after_snap = snapshot_files(sb.path());
    assert_eq!(before_snap, after_snap, "export_memory must write 0 bytes");
}

#[test]
fn refresh_memories_dry_run_writes_zero_bytes_and_apply_preserves_body_and_isolates_broken_anchors()
{
    let sb = Sandbox::new("refresh-batch");
    sb.write("src/fresh.rs", "pub fn fresh_fn() -> i32 { 1 }\n");
    sb.write("src/stale_ok.rs", "pub fn evolve() -> i32 {\n    10\n}\n");
    sb.write("src/deleted_file.rs", "pub fn soon_gone() -> i32 { 0 }\n");
    sb.write(
        "src/deleted_sym.rs",
        "pub fn target_sym() -> i32 {\n    7\n}\npub fn keeper() {}\n",
    );

    let root = ProjectRoot::new(sb.path()).unwrap();
    let mut resolver = HeuristicSymbolResolver::new(&root);

    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("note-1-fresh".to_string()),
            title: "Already fresh note".to_string(),
            kind: MemoryKind::Decision,
            body: "Untouched fresh body.\n".to_string(),
            anchors: vec![AnchorSpec::file("src/fresh.rs")],
            tags: vec!["fresh".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("note-2-stale-ok".to_string()),
            title: "Healthy stale note".to_string(),
            kind: MemoryKind::Architecture,
            body: "Initial body.\n".to_string(),
            anchors: vec![AnchorSpec::symbol("src/stale_ok.rs", "fn evolve")],
            tags: vec!["arch".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("note-3-missing-file".to_string()),
            title: "Deleted file anchor note".to_string(),
            kind: MemoryKind::Bugfix,
            body: "Must never be corrupted when file vanishes.\n".to_string(),
            anchors: vec![AnchorSpec::file("src/deleted_file.rs")],
            tags: vec!["broken".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    add_memory(
        &root,
        AddMemoryRequest {
            id: Some("note-4-missing-sym".to_string()),
            title: "Deleted symbol anchor note".to_string(),
            kind: MemoryKind::Feedback,
            body: "Must never receive a fake hash when symbol disappears.\n".to_string(),
            anchors: vec![AnchorSpec::symbol("src/deleted_sym.rs", "fn target_sym")],
            tags: vec!["broken".to_string()],
        },
        &mut resolver,
    )
    .unwrap();

    // Hand-edit `note-2-stale-ok.md` in Obsidian style with Turkish UTF-8 & wikilinks.
    let stale_note_path = sb.path().join(".klens/memory/note-2-stale-ok.md");
    let orig_disk = fs::read_to_string(&stale_note_path).unwrap();
    let parsed_orig = parse_markdown_note(".klens/memory/note-2-stale-ok.md", &orig_disk).unwrap();
    let hand_edited_body = concat!(
        "## Elle Düzenlenen Bölüm (ğüşiöçĞÜŞİÖÇ)\n",
        "Özel not — [[PROJECT_CONTRACT]] bağlantısı korunmalı.\n",
        "\n",
        "```rust\n",
        "assert_eq!(1 + 1, 2);\n",
        "```\n",
    );
    fs::write(
        &stale_note_path,
        serialize_markdown_note(&parsed_orig.frontmatter, hand_edited_body),
    )
    .unwrap();

    // Mutate `src/stale_ok.rs`, delete `src/deleted_file.rs`, and delete `target_sym` in `src/deleted_sym.rs`.
    sb.write("src/stale_ok.rs", "pub fn evolve() -> i32 {\n    42\n}\n");
    fs::remove_file(sb.path().join("src/deleted_file.rs")).unwrap();
    sb.write("src/deleted_sym.rs", "pub fn keeper() {}\n");

    let missing_file_note_before =
        fs::read(sb.path().join(".klens/memory/note-3-missing-file.md")).unwrap();
    let missing_sym_note_before =
        fs::read(sb.path().join(".klens/memory/note-4-missing-sym.md")).unwrap();
    let fresh_note_before = fs::read(sb.path().join(".klens/memory/note-1-fresh.md")).unwrap();

    // 1. Dry-run `--all` writes ZERO bytes to disk while reporting exact planned refresh & failures.
    let before_dry = snapshot_files(sb.path());
    let dry_env = refresh_memories(&root, None, false, true, &mut resolver).unwrap();
    let after_dry = snapshot_files(sb.path());
    assert_eq!(
        before_dry, after_dry,
        "refresh_memories(dry_run = true) must write 0 bytes to disk"
    );
    assert_eq!(dry_env.trust, TrustLevel::Stale);
    assert!(dry_env.data.dry_run);
    assert_eq!(dry_env.data.total_scanned, 4);
    assert_eq!(dry_env.data.refreshed.len(), 1);
    assert_eq!(dry_env.data.refreshed[0].id, "note-2-stale-ok");
    assert!(dry_env.data.refreshed[0].changed);
    assert_eq!(dry_env.data.refreshed[0].previous_trust, TrustLevel::Stale);
    assert_eq!(dry_env.data.refreshed[0].new_trust, TrustLevel::VerifiedRaw);
    assert_eq!(dry_env.data.refreshed[0].updated_anchors, 1);
    assert_eq!(
        dry_env.data.refreshed[0].outcome,
        BatchRefreshItemOutcome::Refreshed
    );
    assert_eq!(dry_env.data.unchanged, vec!["note-1-fresh"]);
    assert_eq!(dry_env.data.failed.len(), 2);
    assert!(!dry_env.warnings.is_empty());
    let dry_text = format_memory_batch_refresh_text(&dry_env);
    assert!(dry_text.contains("mode=dry-run"));
    assert!(dry_text.contains("[WOULD_REFRESH] note-2-stale-ok"));
    assert!(dry_text.contains("[FAILED] note-3-missing-file"));
    assert!(dry_text.contains("[FAILED] note-4-missing-sym"));

    // 2. Real apply `--all`: refreshes healthy stale note verbatim, leaves fresh & broken notes untouched!
    let apply_env = refresh_memories(&root, None, false, false, &mut resolver).unwrap();
    assert_eq!(apply_env.trust, TrustLevel::Stale);
    assert!(!apply_env.data.dry_run);
    assert_eq!(apply_env.data.refreshed.len(), 1);
    assert_eq!(apply_env.data.refreshed[0].id, "note-2-stale-ok");
    assert_eq!(apply_env.data.unchanged, vec!["note-1-fresh"]);
    assert_eq!(apply_env.data.failed.len(), 2);
    assert!(
        apply_env
            .warnings
            .iter()
            .any(|w| w.contains("note-3-missing-file") && w.contains("note-4-missing-sym")),
        "warnings must surface failed note IDs, got: {:?}",
        apply_env.warnings
    );

    // Verify healthy stale note is now fresh AND its hand-edited body was preserved byte-for-byte!
    let refreshed_note = get_memory(&root, "note-2-stale-ok", &mut resolver).unwrap();
    assert_eq!(refreshed_note.trust, TrustLevel::VerifiedRaw);
    assert_eq!(refreshed_note.data.note.body, hand_edited_body);

    // Verify fresh note and both broken-anchor notes are 100% byte-for-byte untouched on disk!
    assert_eq!(
        fs::read(sb.path().join(".klens/memory/note-1-fresh.md")).unwrap(),
        fresh_note_before
    );
    assert_eq!(
        fs::read(sb.path().join(".klens/memory/note-3-missing-file.md")).unwrap(),
        missing_file_note_before
    );
    assert_eq!(
        fs::read(sb.path().join(".klens/memory/note-4-missing-sym.md")).unwrap(),
        missing_sym_note_before
    );

    // 3. Re-running with `stale_only = true` skips both now-fresh notes without touching disk.
    let second_run = refresh_memories(&root, None, true, false, &mut resolver).unwrap();
    assert!(second_run.data.refreshed.is_empty());
    assert_eq!(
        second_run.data.unchanged,
        vec!["note-1-fresh", "note-2-stale-ok"]
    );
    assert_eq!(second_run.data.failed.len(), 2);
}
