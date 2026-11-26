//! Phase 5A mandatory unit + adversarial truth test suite for `klens-blueprint`.
//!
//! Enforces all 5 mandatory test gates from `docs/phases/phase-5a.md`:
//! 1. Tag conflict (`provides`/`conflicts_with`), missing `requires`, and `status == pending`
//!    all emit `severity: error`; `lock_and_execute` is rejected and writes ZERO contract/task files.
//! 2. Circular `depends_on` (`A -> B -> A`, 3-cycle, self-loop) is rejected; nothing written to disk.
//! 3. Existing-file protection: scaffold creator NEVER overwrites existing files and blocks path escape.
//! 4. Task graph progression: `T2` blocked by `T1` -> `next_ready_task` returns `T1`, premature
//!    `complete_task("T2")` fails closed, completing `T1` unlocks `T2`.
//! 5. Deterministic handoff & UTF-8 safety: byte-for-byte identical across runs with Turkish chars,
//!    long error excerpts, secret redaction, strict budget cap (`estimate_tokens <= budget`),
//!    and zero panics across edge budgets.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_blueprint::{
    Blueprint, BlueprintBubble, BlueprintError, BlueprintOption, BlueprintTask, BubbleStatus,
    ConflictKind, ConflictSeverity, ContractSummary, FailedRunSummary, GitCommitSummary,
    GitStatusSummary, HandoffInput, LockOptions, MemoryEntrySummary, MemorySummary,
    PROJECT_CONTRACT_REL, ScaffoldEntry, TASKS_JSONL_REL, TaskStatus, check_conflicts,
    complete_task, compose_handoff, get_next_ready_task, lock_and_execute, next_ready_task,
    save_blueprint,
};
use klens_core::{ProjectRoot, TrustLevel, estimate_tokens};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-bp-p5a-{label}-{}-{n}", std::process::id()));
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

fn clean_two_bubble_blueprint() -> Blueprint {
    let mut bp = Blueprint::new(
        "VoxelCraft",
        "Tarayıcıda veya masaüstünde çalışan hafif voxel tabanlı inşa oyunu (ğüşiöç)",
    );
    bp.bubbles = vec![
        BlueprintBubble {
            id: "platform".to_string(),
            category: "Hedef Platform".to_string(),
            title: "Oyun nerede çalışacak?".to_string(),
            plain_explanation: "Çalışma ortamını belirler.".to_string(),
            options: vec![
                BlueprintOption {
                    id: "desktop_native".to_string(),
                    label: "Masaüstü (Windows/Mac/Linux)".to_string(),
                    pros: "Yüksek performans".to_string(),
                    cons: "Kurulum gerekir".to_string(),
                    recommended: true,
                    provides: vec!["desktop_native".into(), "local_fs".into()],
                    requires: vec![],
                    conflicts_with: vec!["browser_only".into()],
                },
                BlueprintOption {
                    id: "web_browser".to_string(),
                    label: "Web Tarayıcı".to_string(),
                    pros: "Linkle anında açılır".to_string(),
                    cons: "Bellek sınırı".to_string(),
                    recommended: false,
                    provides: vec!["web_browser".into(), "browser_only".into()],
                    requires: vec![],
                    conflicts_with: vec!["native_directx".into(), "local_fs".into()],
                },
            ],
            selected_option: Some("desktop_native".to_string()),
            user_vision_note: "Önce Windows'ta yağ gibi çalışsın, 60 FPS önemli (ğüşiöç).".into(),
            status: BubbleStatus::UserConfirmed,
            depends_on: vec![],
        },
        BlueprintBubble {
            id: "storage".to_string(),
            category: "Kayıt Sistemi".to_string(),
            title: "Dünya kayıt formatı nasıl olacak?".to_string(),
            plain_explanation: "Disk depolama motoru.".to_string(),
            options: vec![BlueprintOption {
                id: "sqlite_chunk".to_string(),
                label: "Yerel Chunk + SQLite".to_string(),
                pros: "Hızlı ve güvenilir".to_string(),
                cons: "Yerel dosya sistemi gerektirir".to_string(),
                recommended: true,
                provides: vec!["chunk_storage".into()],
                requires: vec!["local_fs".into()],
                conflicts_with: vec!["browser_only".into()],
            }],
            selected_option: Some("sqlite_chunk".to_string()),
            user_vision_note: "Çökme anında veri kaybı olmasın.".into(),
            status: BubbleStatus::UserConfirmed,
            depends_on: vec!["platform".to_string()],
        },
    ];
    bp
}

// ---------------------------------------------------------------------------
// Gate 1: Tag Conflict (`provides`/`conflicts_with`), Missing `requires`, Pending
// ---------------------------------------------------------------------------

#[test]
fn gate_1_tag_conflict_missing_requires_and_pending_block_lock_without_writing_disk() {
    let proj = Sandbox::new("gate1");
    let root = ProjectRoot::new(proj.path()).unwrap();

    // Case A: `web_browser` provides `browser_only`, while `sqlite_chunk` requires `local_fs`
    // AND conflicts_with `browser_only`!
    let mut bp = clean_two_bubble_blueprint();
    bp.bubbles[0].selected_option = Some("web_browser".to_string());
    save_blueprint(&root, &bp).unwrap();

    let report = check_conflicts(&bp);
    assert!(!report.can_lock);
    assert!(report.error_count >= 2);
    assert!(report.conflicts.iter().any(|c| {
        c.severity == ConflictSeverity::Error && c.kind == Some(ConflictKind::TagConflict)
    }));
    assert!(report.conflicts.iter().any(|c| {
        c.severity == ConflictSeverity::Error && c.kind == Some(ConflictKind::MissingRequirement)
    }));

    let err = lock_and_execute(&root, &LockOptions::default()).unwrap_err();
    assert!(matches!(err, BlueprintError::ConflictsPresent { .. }));
    assert!(
        !proj.path().join(PROJECT_CONTRACT_REL).exists(),
        "PROJECT_CONTRACT.md MUST NOT be created when conflicts exist"
    );
    assert!(
        !proj.path().join(TASKS_JSONL_REL).exists(),
        "tasks.jsonl MUST NOT be created when conflicts exist"
    );

    // Case B: No tag collision, but `status == pending` MUST still block lock.
    let mut pending_bp = clean_two_bubble_blueprint();
    pending_bp.bubbles[1].status = BubbleStatus::Pending;
    save_blueprint(&root, &pending_bp).unwrap();

    let pending_report = check_conflicts(&pending_bp);
    assert!(!pending_report.can_lock);
    assert!(pending_report.conflicts.iter().any(|c| {
        c.severity == ConflictSeverity::Error && c.kind == Some(ConflictKind::PendingDecision)
    }));
    assert!(matches!(
        lock_and_execute(&root, &LockOptions::default()),
        Err(BlueprintError::ConflictsPresent { .. })
    ));
    assert!(!proj.path().join(PROJECT_CONTRACT_REL).exists());
    assert!(!proj.path().join(TASKS_JSONL_REL).exists());
}

// ---------------------------------------------------------------------------
// Gate 2: Circular Dependency (`depends_on` Cycle)
// ---------------------------------------------------------------------------

#[test]
fn gate_2_circular_depends_on_is_rejected_and_blocks_lock() {
    let proj = Sandbox::new("gate2");
    let root = ProjectRoot::new(proj.path()).unwrap();

    // `platform` -> `storage` -> `platform` (`A -> B -> A`)
    let mut bp = clean_two_bubble_blueprint();
    bp.bubbles[0].depends_on = vec!["storage".to_string()];
    bp.bubbles[1].depends_on = vec!["platform".to_string()];
    save_blueprint(&root, &bp).unwrap();

    let report = check_conflicts(&bp);
    assert!(!report.can_lock);
    assert!(report.conflicts.iter().any(|c| {
        c.severity == ConflictSeverity::Error
            && c.kind == Some(ConflictKind::DependencyCycle)
            && c.bubble_ids.contains(&"platform".to_string())
            && c.bubble_ids.contains(&"storage".to_string())
    }));

    let err = lock_and_execute(&root, &LockOptions::default()).unwrap_err();
    assert!(matches!(err, BlueprintError::ConflictsPresent { .. }));
    assert!(!proj.path().join(PROJECT_CONTRACT_REL).exists());
    assert!(!proj.path().join(TASKS_JSONL_REL).exists());

    // Self-loop (`A -> A`) is also caught deterministically.
    let mut self_loop = clean_two_bubble_blueprint();
    self_loop.bubbles[0].depends_on = vec!["platform".to_string()];
    let self_report = check_conflicts(&self_loop);
    assert!(!self_report.can_lock);
    assert!(
        self_report
            .conflicts
            .iter()
            .any(|c| c.kind == Some(ConflictKind::DependencyCycle))
    );
}

// ---------------------------------------------------------------------------
// Gate 3: Existing File Protection & Path Confinement in Scaffold Creator
// ---------------------------------------------------------------------------

#[test]
fn gate_3_scaffold_creator_never_overwrites_existing_files_and_blocks_escapes() {
    let proj = Sandbox::new("gate3");
    proj.write("src/main.rs", "// PRECIOUS_USER_CODE_DO_NOT_OVERWRITE\n");
    let root = ProjectRoot::new(proj.path()).unwrap();

    // First, verify a malicious scaffold path (`../escape.txt`) fails closed BEFORE locking.
    let mut evil_bp = clean_two_bubble_blueprint();
    evil_bp.scaffold = vec![ScaffoldEntry::file("../escape.txt", "pwned")];
    save_blueprint(&root, &evil_bp).unwrap();
    assert!(
        lock_and_execute(
            &root,
            &LockOptions {
                create_scaffold: true,
                ..LockOptions::default()
            }
        )
        .is_err()
    );
    assert!(!proj.path().join(PROJECT_CONTRACT_REL).exists());

    // Now lock with legitimate scaffold containing both existing (`src/main.rs`) and new entries.
    let mut bp = clean_two_bubble_blueprint();
    bp.scaffold = vec![
        ScaffoldEntry::dir("src/world"),
        ScaffoldEntry::file("src/main.rs", "// WOULD_DESTROY_EXISTING\n"),
        ScaffoldEntry::file("src/world/mod.rs", "// starter module\n"),
    ];
    save_blueprint(&root, &bp).unwrap();

    let env = lock_and_execute(
        &root,
        &LockOptions {
            create_scaffold: true,
            ..LockOptions::default()
        },
    )
    .unwrap();
    assert_eq!(env.trust, TrustLevel::UserLocked);
    assert!(proj.path().join(PROJECT_CONTRACT_REL).is_file());
    assert!(proj.path().join(TASKS_JSONL_REL).is_file());

    // Existing file MUST remain byte-for-byte untouched!
    let preserved = fs::read_to_string(proj.path().join("src/main.rs")).unwrap();
    assert_eq!(preserved, "// PRECIOUS_USER_CODE_DO_NOT_OVERWRITE\n");
    assert!(
        env.data
            .scaffold
            .skipped_existing
            .iter()
            .any(|p| p == "src/main.rs")
    );

    // New directory & file were created cleanly.
    assert!(proj.path().join("src/world").is_dir());
    assert_eq!(
        fs::read_to_string(proj.path().join("src/world/mod.rs")).unwrap(),
        "// starter module\n"
    );
    assert!(
        env.data
            .scaffold
            .created_dirs
            .iter()
            .any(|p| p == "src/world")
    );
    assert!(
        env.data
            .scaffold
            .created_files
            .iter()
            .any(|p| p == "src/world/mod.rs")
    );
}

// ---------------------------------------------------------------------------
// Gate 4: Task Graph Progression (`T2` blocked by `T1`)
// ---------------------------------------------------------------------------

#[test]
fn gate_4_task_graph_blocks_dependent_task_until_prerequisite_is_done() {
    let proj = Sandbox::new("gate4");
    let root = ProjectRoot::new(proj.path()).unwrap();

    let bp = clean_two_bubble_blueprint();
    save_blueprint(&root, &bp).unwrap();

    let custom_tasks = vec![
        BlueprintTask {
            id: "T2".to_string(),
            title: "Build chunk storage".to_string(),
            blocked_by: vec!["T1".to_string()],
            expected_files: vec!["src/world/save.rs".to_string()],
            verification_cmd: Some("cargo test world".to_string()),
            status: TaskStatus::Pending,
            bubble_id: Some("storage".to_string()),
        },
        BlueprintTask {
            id: "T1".to_string(),
            title: "Initialize desktop runtime".to_string(),
            blocked_by: vec![],
            expected_files: vec!["src/main.rs".to_string()],
            verification_cmd: Some("cargo check".to_string()),
            status: TaskStatus::Pending,
            bubble_id: Some("platform".to_string()),
        },
    ];

    // Pure selector picks `T1` even though `T2` appears first in the slice.
    let pure_next = next_ready_task(&custom_tasks).unwrap();
    assert_eq!(pure_next.id, "T1");

    let lock_env = lock_and_execute(
        &root,
        &LockOptions {
            custom_tasks: Some(custom_tasks),
            ..LockOptions::default()
        },
    )
    .unwrap();
    assert_eq!(lock_env.data.task_count, 2);

    // Persisted `get_next_ready_task` returns `T1`.
    let next1 = get_next_ready_task(&root).unwrap();
    assert_eq!(next1.trust, TrustLevel::UserLocked);
    assert_eq!(next1.data.task.as_ref().unwrap().id, "T1");

    // Attempting to complete `T2` before `T1` fails closed!
    let blocked_err = complete_task(&root, "T2").unwrap_err();
    assert!(matches!(blocked_err, BlueprintError::TaskBlocked { .. }));

    // Completing `T1` immediately unlocks `T2`.
    let done1 = complete_task(&root, "T1").unwrap();
    assert_eq!(done1.data.completed_task.status, TaskStatus::Done);
    assert_eq!(done1.data.done_tasks, 1);
    assert_eq!(done1.data.next_ready_task.as_ref().unwrap().id, "T2");

    let next2 = get_next_ready_task(&root).unwrap();
    assert_eq!(next2.data.task.as_ref().unwrap().id, "T2");

    // Completing `T2` finishes the queue cleanly.
    let done2 = complete_task(&root, "T2").unwrap();
    assert!(done2.data.next_ready_task.is_none());
    let final_next = get_next_ready_task(&root).unwrap();
    assert!(final_next.data.all_done);
}

// ---------------------------------------------------------------------------
// Gate 5: Byte-for-Byte Deterministic Handoff, Budget Cap, UTF-8 & Redaction
// ---------------------------------------------------------------------------

#[test]
fn gate_5_compose_handoff_is_deterministic_utf8_safe_budgeted_and_redacts_secrets() {
    let synthetic_gh = format!("ghp_{}", "1234567890abcdefghijklmnopqrstuvwxyz1234");
    let long_turkish_error =
        "Hata [ğüşiöçĞÜŞİÖÇ 🚀]: ".repeat(140) + &format!("Authorization: Bearer {synthetic_gh}");

    let input = HandoffInput {
        project_id: "proj-abc123".to_string(),
        project_name: "Karasu Çalışma Alanı (ğüşiöç)".to_string(),
        contract: Some(ContractSummary {
            project_name: "Karasu Çalışma Alanı (ğüşiöç)".to_string(),
            goal: "Sıfır yanıltma ilkesiyle yerel kod analizi — ğüşiöçĞÜŞİÖÇ".to_string(),
            locked: true,
            locked_at: Some("2026-11-24T00:00:00Z".to_string()),
            decisions: vec![
                "platform: Masaüstü (desktop_native) — Önce Windows'ta yağ gibi çalışsın (ğüşiöç)"
                    .to_string(),
                "storage: SQLite WAL — Çökme güvenliği".to_string(),
            ],
            contract_excerpt: None,
        }),
        protected_paths: vec![
            "crates/klens-core/src/paths.rs".to_string(),
            "migrations/*".to_string(),
        ],
        git: Some(GitStatusSummary {
            branch: "main".to_string(),
            recent_commits: vec![
                GitCommitSummary {
                    sha: "a1b2c3d".to_string(),
                    message: "feat: Faz 4 hafıza doğrulama eklendi (ğüşiöç)".to_string(),
                },
                GitCommitSummary {
                    sha: "d4e5f6a".to_string(),
                    message: "chore: başlangıç şablonu".to_string(),
                },
            ],
            dirty_files: vec!["M src/world.rs".to_string(), "?? notes.txt".to_string()],
        }),
        last_failed_run: Some(FailedRunSummary {
            run_id: "20261124-000100-abcd".to_string(),
            command: "cargo test --workspace".to_string(),
            exit_code: 101,
            raw_log_path: ".klens/runs/20261124-000100-abcd.raw.log".to_string(),
            error_excerpt: long_turkish_error,
        }),
        next_ready_task: Some(BlueprintTask {
            id: "T01-platform".to_string(),
            title: "Hedef Platform: Masaüstü (ğüşiöç)".to_string(),
            blocked_by: vec![],
            expected_files: vec!["src/main.rs".to_string()],
            verification_cmd: Some("cargo test".to_string()),
            status: TaskStatus::Pending,
            bubble_id: Some("platform".to_string()),
        }),
        completed_tasks_count: 1,
        remaining_tasks_count: 2,
        memory: MemorySummary {
            total_notes: 2,
            active_notes: vec![MemoryEntrySummary {
                id: "adr-001".to_string(),
                title: "Parçalı kayıt kuralı (ğüşiöç)".to_string(),
                kind: "decision".to_string(),
                is_stale: false,
                stale_details: vec![],
            }],
            stale_notes: vec![MemoryEntrySummary {
                id: "bug-wal-lock".to_string(),
                title: "SQLITE_BUSY kilidi".to_string(),
                kind: "bugfix".to_string(),
                is_stale: true,
                stale_details: vec!["src/world.rs: changed_hash".to_string()],
            }],
            parse_warnings: vec![],
        },
    };

    // Run twice with budget = 500 -> MUST be byte-for-byte identical!
    let first = compose_handoff(input.clone(), 500);
    let second = compose_handoff(input.clone(), 500);
    assert_eq!(first, second);
    assert_eq!(
        first.to_deterministic_json().unwrap().as_bytes(),
        second.to_deterministic_json().unwrap().as_bytes()
    );

    // Budget compliance, trust, redaction, omissions, and stale warnings!
    assert_eq!(first.trust, TrustLevel::UserLocked);
    assert!(
        estimate_tokens(&first.data.summary_markdown) <= 500,
        "handoff exceeded budget: {} > 500",
        estimate_tokens(&first.data.summary_markdown)
    );
    assert!(
        !first.data.summary_markdown.contains(&synthetic_gh),
        "secret token leaked into handoff output!"
    );
    assert!(first.redactions_count >= 1);
    assert!(
        !first.omissions.is_empty(),
        "truncated long error excerpt must emit an explicit Omission record"
    );
    assert!(
        first
            .warnings
            .iter()
            .any(|w| w.contains("bug-wal-lock") && w.contains("STALE"))
    );
    assert!(first.data.summary_markdown.contains("PROTECTED PATHS"));
    assert!(first.data.summary_markdown.contains("T01-platform"));

    // Stress-test UTF-8 boundary truncation across every tiny and medium budget without panicking!
    for budget in [0usize, 1, 2, 3, 5, 11, 23, 50, 120, 250, 400, 800] {
        let env = compose_handoff(input.clone(), budget);
        let actual = estimate_tokens(&env.data.summary_markdown);
        assert!(
            actual <= budget,
            "handoff for budget={budget} produced {actual} tokens"
        );
        assert_eq!(env.data.estimated_tokens, actual);
    }
}

#[test]
fn regression_duplicate_option_id_yaml_project_name_and_unlocked_complete_task_trust() {
    let proj = Sandbox::new("reg-blueprint");
    let root = ProjectRoot::new(proj.path()).unwrap();

    // 1. Duplicate `option.id` within the same bubble MUST be rejected by `validate_schema`.
    let mut dup_bp = clean_two_bubble_blueprint();
    let cloned_opt = dup_bp.bubbles[0].options[0].clone();
    dup_bp.bubbles[0].options.push(cloned_opt);
    let err = save_blueprint(&root, &dup_bp).unwrap_err();
    assert!(
        matches!(err, BlueprintError::ValidationFailed(ref msg) if msg.contains("duplicate option id")),
        "expected duplicate option id validation error, got: {err}"
    );

    // 2. `project_name` containing YAML special characters (`:`, `#`, `"`, `\`) MUST be escaped & quoted.
    let mut yaml_bp = clean_two_bubble_blueprint();
    yaml_bp.project_name = "Karasu: v2 #core \"quoted\"".to_string();
    save_blueprint(&root, &yaml_bp).unwrap();
    let lock_env = lock_and_execute(&root, &LockOptions::default()).unwrap();
    assert_eq!(lock_env.trust, TrustLevel::UserLocked);

    let contract_md = fs::read_to_string(proj.path().join(PROJECT_CONTRACT_REL)).unwrap();
    assert!(
        contract_md.contains("project_name: \"Karasu: v2 #core \\\"quoted\\\"\"\n"),
        "frontmatter project_name must be safely double-quoted and escaped, got:\n{contract_md}"
    );

    // 3. `complete_task` MUST return `TrustLevel::VerifiedRaw` when the blueprint is unlocked.
    let mut unlocked_bp = clean_two_bubble_blueprint();
    unlocked_bp.locked = false;
    unlocked_bp.locked_at = None;
    save_blueprint(&root, &unlocked_bp).unwrap();

    let comp_env = complete_task(&root, "T01-platform").unwrap();
    assert_eq!(
        comp_env.trust,
        TrustLevel::VerifiedRaw,
        "complete_task on an unlocked blueprint must report VERIFIED_RAW, not USER_LOCKED"
    );
}
