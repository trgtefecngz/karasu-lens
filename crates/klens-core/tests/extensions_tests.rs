use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::{
    CTAGS_EXTENSION_ID, EXTENSION_MANIFEST_FILE, ExtensionHealthStatus, ExtensionKind,
    ExtensionScope, ExtensionSlot, GlobalConfig, KlensError, ProjectConfig, ProjectRoot,
    known_extensions, list_extensions, set_extension_enabled, validate_extension_id,
};

static EXT_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> std::path::PathBuf {
    let seq = EXT_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("klens-ext-{label}-{}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn all_known_extensions_are_disabled_by_default_and_sorted() {
    let catalog = known_extensions();
    assert_eq!(catalog.len(), 7);
    assert!(catalog.iter().any(|s| s.id == CTAGS_EXTENSION_ID));
    for spec in catalog {
        assert!(!spec.is_enabled_by_default());
        assert!(validate_extension_id(spec.id).is_ok());
    }
    let ids: Vec<&str> = catalog.iter().map(|s| s.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "catalog must be deterministically sorted");
}

#[test]
fn validate_extension_id_fails_closed_on_invalid_or_unknown_ids() {
    for bad in [
        "",
        "   ",
        "ext-unknown",
        "EXT-LSP-BRIDGE",
        " ext-lsp-bridge",
        "../evil",
        "ext-lsp-bridge\n",
        "lsp-bridge",
    ] {
        assert!(
            matches!(
                validate_extension_id(bad),
                Err(KlensError::InvalidExtensionId { .. })
            ),
            "expected InvalidExtensionId for `{bad}`"
        );
    }
}

#[test]
fn enable_disable_roundtrip_global_and_project_atomic() {
    let dir = temp_dir("roundtrip");
    let global_cfg = dir.join("home").join(".klens").join("config.toml");
    let proj_dir = dir.join("proj");
    fs::create_dir_all(&proj_dir).unwrap();
    let project_root = ProjectRoot::new(&proj_dir).unwrap();

    // Initially everything is off and listing writes nothing.
    let initial = list_extensions(&global_cfg, Some(&project_root)).unwrap();
    assert!(initial.global_enabled.is_empty());
    assert!(initial.project_enabled.is_empty());
    assert!(initial.extensions.iter().all(|e| !e.effective_enabled));
    assert!(!global_cfg.exists());
    assert!(!proj_dir.join(".klens").exists());

    // Enable in project scope.
    let r1 = set_extension_enabled(
        "ext-lsp-bridge",
        true,
        ExtensionScope::Project,
        &global_cfg,
        Some(&project_root),
    )
    .unwrap();
    assert!(r1.changed);
    assert!(r1.enabled);
    assert_eq!(r1.enabled_extensions, vec!["ext-lsp-bridge"]);
    assert!(proj_dir.join(".klens").join("config.toml").is_file());

    // Idempotent repeat returns changed=false.
    let r2 = set_extension_enabled(
        "ext-lsp-bridge",
        true,
        ExtensionScope::Project,
        &global_cfg,
        Some(&project_root),
    )
    .unwrap();
    assert!(!r2.changed);

    // Enable another in global scope.
    let r3 = set_extension_enabled(
        "ext-live-docs",
        true,
        ExtensionScope::Global,
        &global_cfg,
        Some(&project_root),
    )
    .unwrap();
    assert!(r3.changed);
    assert!(global_cfg.is_file());

    let after = list_extensions(&global_cfg, Some(&project_root)).unwrap();
    assert_eq!(after.global_enabled, vec!["ext-live-docs"]);
    assert_eq!(after.project_enabled, vec!["ext-lsp-bridge"]);
    assert!(
        after
            .extensions
            .iter()
            .find(|e| e.id == "ext-lsp-bridge")
            .unwrap()
            .effective_enabled
    );
    assert!(
        after
            .extensions
            .iter()
            .find(|e| e.id == "ext-live-docs")
            .unwrap()
            .effective_enabled
    );

    // Disable in project scope.
    let r4 = set_extension_enabled(
        "ext-lsp-bridge",
        false,
        ExtensionScope::Project,
        &global_cfg,
        Some(&project_root),
    )
    .unwrap();
    assert!(r4.changed);
    assert!(r4.enabled_extensions.is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn disable_removes_existing_unregistered_entry_but_still_rejects_absent_unknown_id() {
    let dir = temp_dir("disable-unregistered");
    let global_cfg = dir.join("home").join(".klens").join("config.toml");
    let proj_dir = dir.join("proj");
    fs::create_dir_all(&proj_dir).unwrap();
    let project_root = ProjectRoot::new(&proj_dir).unwrap();

    let proj_cfg_path = proj_dir.join(".klens").join("config.toml");
    ProjectConfig {
        enabled_extensions: vec![
            "ext-custom-legacy".to_string(),
            "ext-lsp-bridge".to_string(),
        ],
        ..ProjectConfig::default()
    }
    .save_atomic(&proj_cfg_path)
    .unwrap();
    GlobalConfig {
        enabled_extensions: vec!["ext-global-legacy".to_string()],
        ..GlobalConfig::default()
    }
    .save_atomic(&global_cfg)
    .unwrap();

    // Enabling an unknown ID MUST still fail closed.
    assert!(matches!(
        set_extension_enabled(
            "ext-custom-legacy",
            true,
            ExtensionScope::Project,
            &global_cfg,
            Some(&project_root),
        ),
        Err(KlensError::InvalidExtensionId { .. })
    ));

    // Disabling an unregistered entry that IS present removes it atomically.
    let proj_res = set_extension_enabled(
        "ext-custom-legacy",
        false,
        ExtensionScope::Project,
        &global_cfg,
        Some(&project_root),
    )
    .unwrap();
    assert!(proj_res.changed);
    assert!(!proj_res.enabled);
    assert_eq!(proj_res.id, "ext-custom-legacy");
    assert_eq!(proj_res.enabled_extensions, vec!["ext-lsp-bridge"]);
    assert_eq!(
        ProjectConfig::load(&proj_cfg_path)
            .unwrap()
            .enabled_extensions,
        vec!["ext-lsp-bridge"]
    );

    let global_res = set_extension_enabled(
        "ext-global-legacy",
        false,
        ExtensionScope::Global,
        &global_cfg,
        Some(&project_root),
    )
    .unwrap();
    assert!(global_res.changed);
    assert!(global_res.enabled_extensions.is_empty());

    // Disabling an absent unknown ID MUST fail closed.
    assert!(matches!(
        set_extension_enabled(
            "ext-custom-legacy",
            false,
            ExtensionScope::Project,
            &global_cfg,
            Some(&project_root),
        ),
        Err(KlensError::InvalidExtensionId { .. })
    ));
    assert!(matches!(
        set_extension_enabled(
            "ext-typo-never-existed",
            false,
            ExtensionScope::Global,
            &global_cfg,
            Some(&project_root),
        ),
        Err(KlensError::InvalidExtensionId { .. })
    ));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn discovered_language_manifest_can_be_listed_and_toggled_while_uninstalled_fails_closed() {
    let dir = temp_dir("discovered-lang");
    let global_cfg = dir.join("home").join(".klens").join("config.toml");
    let proj_dir = dir.join("proj");
    fs::create_dir_all(&proj_dir).unwrap();
    // Trusted manifests live ONLY in the user-global `~/.klens/extensions/` (v0.3.2+).
    let ext_dir = dir
        .join("home")
        .join(".klens")
        .join("extensions")
        .join("ext-lang-java");
    fs::create_dir_all(&ext_dir).unwrap();
    fs::write(
        ext_dir.join(EXTENSION_MANIFEST_FILE),
        r#"
id = "ext-lang-java"
kind = "language-parser"
version = "0.1.0"
protocol_version = 1
description = "Java parser sidecar"
extensions = ["java"]
command = "klens-ext-lang-java"
"#,
    )
    .unwrap();

    let project_root = ProjectRoot::new(&proj_dir).unwrap();

    let list = list_extensions(&global_cfg, Some(&project_root)).unwrap();
    let java_entry = list
        .extensions
        .iter()
        .find(|e| e.id == "ext-lang-java")
        .expect("ext-lang-java should be merged into list");
    assert!(java_entry.known);
    assert_eq!(java_entry.kind, Some(ExtensionKind::LanguageParser));
    assert_eq!(java_entry.extensions, vec!["java"]);
    assert_eq!(java_entry.command.as_deref(), Some("klens-ext-lang-java"));
    assert_eq!(java_entry.health, Some(ExtensionHealthStatus::Disabled));
    assert!(!java_entry.effective_enabled);

    // Language parsers spawn external processes: project scope MUST fail closed.
    assert!(matches!(
        set_extension_enabled(
            "ext-lang-java",
            true,
            ExtensionScope::Project,
            &global_cfg,
            Some(&project_root),
        ),
        Err(KlensError::ProjectScopedLanguageParser { .. })
    ));

    // Valid discovered ext-lang-java can be enabled/disabled in the trusted global scope.
    let en = set_extension_enabled(
        "ext-lang-java",
        true,
        ExtensionScope::Global,
        &global_cfg,
        Some(&project_root),
    )
    .unwrap();
    assert!(en.changed);
    assert_eq!(en.enabled_extensions, vec!["ext-lang-java"]);

    let dis = set_extension_enabled(
        "ext-lang-java",
        false,
        ExtensionScope::Global,
        &global_cfg,
        Some(&project_root),
    )
    .unwrap();
    assert!(dis.changed);
    assert!(dis.enabled_extensions.is_empty());

    // Uninstalled ext-lang-nonexistent MUST fail closed!
    assert!(matches!(
        set_extension_enabled(
            "ext-lang-nonexistent",
            true,
            ExtensionScope::Global,
            &global_cfg,
            Some(&project_root),
        ),
        Err(KlensError::InvalidExtensionId { .. })
    ));

    let _ = fs::remove_dir_all(&dir);
}
