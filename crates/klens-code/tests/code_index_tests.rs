use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_code::{
    CodeError, CodeIndex, FileSyncOutcome, LineRange, MAX_INDEXABLE_BYTES, ParseStatus,
    outline_file, outline_path, read_lines, read_symbol, verify_tree_sitter_abi,
};
use klens_core::{
    OmissionKind, ProjectConfig, ProjectMode, ProjectRoot, RelPath, SymbolKind, TrustLevel,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "klens-code-test-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.path.join(rel);
        if let Some(p) = full.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(full, content).unwrap();
    }

    fn write_bytes(&self, rel: &str, content: &[u8]) {
        let full = self.path.join(rel);
        if let Some(p) = full.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(full, content).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn abi_smoke_loads_all_ten_languages_and_tsx() {
    let infos = verify_tree_sitter_abi().expect("all tree-sitter grammars must load cleanly");
    assert_eq!(infos.len(), 11);
    let ids: Vec<&str> = infos.iter().map(|i| i.language_id).collect();
    assert_eq!(
        ids,
        vec![
            "rust",
            "typescript",
            "tsx",
            "python",
            "go",
            "c",
            "cpp",
            "java",
            "csharp",
            "php",
            "ruby"
        ]
    );
}

#[test]
fn sqlite_wal_busy_timeout_fts5_and_incremental_blake3_rebuild() {
    let proj = TempDir::new("incremental");
    proj.write(".gitignore", "ignored_out/\n*.tmp\n");
    proj.write("ignored_out/skip.rs", "fn should_not_be_indexed() {}\n");
    proj.write("temp.tmp", "fn also_ignored() {}\n");
    proj.write(".env", "API_KEY=secret\n");
    proj.write_bytes("assets/logo.bin", &[0x89, b'P', b'N', b'G', 0x00, 0x01]);
    proj.write("src/lib.rs", "pub fn alpha() -> u32 {\n    1\n}\n");
    proj.write("src/util.py", "def helper():\n    return 2\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open(root.clone(), false).unwrap();

    // Verify mandatory SQLite pragmas and FTS5 table.
    assert_eq!(index.store().journal_mode().unwrap().to_lowercase(), "wal");
    assert_eq!(index.store().busy_timeout_ms().unwrap(), 5000);
    assert!(index.store().fts_table_exists().unwrap());

    // First sync parses the 2 text source files (plus `.gitignore` as fallback) and skips binary/ignored/.env.
    let s1 = index.sync_workspace().unwrap();
    assert!(s1.parsed >= 2);
    assert_eq!(s1.skipped_binary, 1);

    let indexed_paths: Vec<String> = index
        .store()
        .list_files()
        .unwrap()
        .into_iter()
        .map(|f| f.path.as_str().to_string())
        .collect();
    assert!(indexed_paths.contains(&"src/lib.rs".to_string()));
    assert!(indexed_paths.contains(&"src/util.py".to_string()));
    assert!(!indexed_paths.iter().any(|p| p.contains("ignored_out")));
    assert!(!indexed_paths.iter().any(|p| p.ends_with(".tmp")));
    assert!(!indexed_paths.iter().any(|p| p == ".env"));
    assert!(!indexed_paths.iter().any(|p| p.contains("logo.bin")));

    // Second sync with zero edits parses 0 files.
    let s2 = index.sync_workspace().unwrap();
    assert_eq!(s2.parsed, 0);
    assert!(s2.unchanged >= 2);

    // Converting LF -> CRLF preserves normalized BLAKE3 hash -> zero re-parsing!
    proj.write("src/lib.rs", "pub fn alpha() -> u32 {\r\n    1\r\n}\r\n");
    let crlf_outcome = index
        .sync_file(&RelPath::normalize("src/lib.rs").unwrap())
        .unwrap();
    assert_eq!(crlf_outcome, FileSyncOutcome::Unchanged);

    // Modifying actual content re-parses ONLY the modified file.
    proj.write(
        "src/lib.rs",
        "pub fn alpha() -> u32 {\n    1\n}\npub fn beta() -> u32 {\n    2\n}\n",
    );
    let s3 = index.sync_workspace().unwrap();
    assert_eq!(s3.parsed, 1);
    assert!(s3.unchanged >= 1);

    // Snapshot deterministic JSON before deleting DB.
    let before = outline_path(&mut index, None, None)
        .unwrap()
        .to_deterministic_json()
        .unwrap();
    drop(index);

    // Delete `.klens/cache/index.db` and rebuild -> 100% byte-for-byte deterministic!
    fs::remove_dir_all(proj.path().join(".klens")).unwrap();
    let mut rebuilt = CodeIndex::open(root, false).unwrap();
    rebuilt.sync_workspace().unwrap();
    let after = outline_path(&mut rebuilt, None, None)
        .unwrap()
        .to_deterministic_json()
        .unwrap();
    assert_eq!(before.as_bytes(), after.as_bytes());
}

#[test]
fn read_only_mode_writes_zero_files_to_target_project() {
    let proj = TempDir::new("ro-project");
    let ro_cache = TempDir::new("ro-cache");
    proj.write("src/main.rs", "fn main() {\n    let x = 42;\n}\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();
    assert!(index.is_read_only());

    let stats = index.sync_workspace().unwrap();
    assert_eq!(stats.parsed, 1);

    let env = outline_file(
        &mut index,
        &RelPath::normalize("src/main.rs").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(env.trust, TrustLevel::VerifiedAst);
    assert_eq!(env.data.total_symbols, 1);

    // Zero `.klens` directory or cache file written inside the target project!
    assert!(!proj.path().join(".klens").exists());
    // Cache lives under `ro_cache/<project_id>/index.db`.
    assert!(index.store().db_path().starts_with(ro_cache.path()));
    assert!(index.store().db_path().is_file());
}

#[test]
fn structured_documents_markdown_json_toml_yaml_extract_exact_lines() {
    let proj = TempDir::new("docs");
    let ro_cache = TempDir::new("docs-cache");

    proj.write(
        "README.md",
        concat!(
            "# Project Title\n",
            "Intro text.\n",
            "```bash\n",
            "# not a heading inside code fence\n",
            "echo hi\n",
            "```\n",
            "## Setup\n",
            "Install steps.\n",
            "### Windows\n",
            "Win details.\n",
            "#### Notes\n",
            "Extra note.\n",
        ),
    );
    proj.write(
        "package.json",
        concat!(
            "{\n",
            "  \"name\": \"demo\",\n",
            "  \"scripts\": {\n",
            "    \"build\": \"tsc\"\n",
            "  },\n",
            "  \"version\": \"1.0.0\"\n",
            "}\n",
        ),
    );
    proj.write(
        "Cargo.toml",
        concat!(
            "edition = \"2024\"\n",
            "\n",
            "[package]\n",
            "name = \"demo\"\n",
            "\n",
            "[dependencies]\n",
            "serde = \"1.0\"\n",
        ),
    );
    proj.write(
        "config.yaml",
        concat!(
            "---\n",
            "service: api\n",
            "database:\n",
            "  host: localhost\n",
            "  port: 5432\n",
            "features:\n",
            "  - fast\n",
        ),
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();

    // Markdown: fenced `#` ignored, `#`..`####` extracted with exact lines.
    let md_out = outline_file(&mut index, &RelPath::normalize("README.md").unwrap(), None).unwrap();
    assert_eq!(md_out.trust, TrustLevel::VerifiedAst);
    let md_syms = &md_out.data.files[0].symbols;
    let md_names: Vec<(&str, usize, usize)> = md_syms
        .iter()
        .map(|s| (s.name.as_str(), s.start_line, s.end_line))
        .collect();
    assert_eq!(
        md_names,
        vec![
            ("Project Title", 1, 12),
            ("Setup", 7, 12),
            ("Windows", 9, 12),
            ("Notes", 11, 12),
        ]
    );

    // JSON top-level keys.
    let json_out = outline_file(
        &mut index,
        &RelPath::normalize("package.json").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(json_out.trust, TrustLevel::VerifiedAst);
    let json_keys: Vec<(&str, usize, usize)> = json_out.data.files[0]
        .symbols
        .iter()
        .map(|s| (s.name.as_str(), s.start_line, s.end_line))
        .collect();
    assert_eq!(
        json_keys,
        vec![("name", 2, 2), ("scripts", 3, 5), ("version", 6, 7)]
    );

    // TOML root keys + sections.
    let toml_out =
        outline_file(&mut index, &RelPath::normalize("Cargo.toml").unwrap(), None).unwrap();
    assert_eq!(toml_out.trust, TrustLevel::VerifiedAst);
    let toml_syms: Vec<(&str, SymbolKind, usize)> = toml_out.data.files[0]
        .symbols
        .iter()
        .map(|s| (s.name.as_str(), s.kind, s.start_line))
        .collect();
    assert_eq!(
        toml_syms,
        vec![
            ("edition", SymbolKind::Variable, 1),
            ("package", SymbolKind::Module, 3),
            ("dependencies", SymbolKind::Module, 6),
        ]
    );

    // YAML top-level keys.
    let yaml_out = outline_file(
        &mut index,
        &RelPath::normalize("config.yaml").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(yaml_out.trust, TrustLevel::VerifiedAst);
    let yaml_syms: Vec<(&str, usize, usize)> = yaml_out.data.files[0]
        .symbols
        .iter()
        .map(|s| (s.name.as_str(), s.start_line, s.end_line))
        .collect();
    assert_eq!(
        yaml_syms,
        vec![("service", 2, 2), ("database", 3, 5), ("features", 6, 7)]
    );

    // Verify reading a Markdown section returns L<n>| lines.
    let read_win = read_symbol(
        &mut index,
        &RelPath::normalize("README.md").unwrap(),
        "Windows",
    )
    .unwrap();
    let content = read_win.data.content.unwrap();
    assert!(content.starts_with("L9| ### Windows\n"));
    assert!(content.contains("L10| Win details."));
}

#[test]
fn outline_budget_emits_explicit_omissions_and_line_read_formats_lines() {
    let proj = TempDir::new("budget");
    let ro_cache = TempDir::new("budget-cache");

    let mut rust_src = String::new();
    for i in 1..=30 {
        rust_src.push_str(&format!(
            "pub fn function_number_{i:02}(arg_one: usize, arg_two: &str) -> usize {{\n    arg_one + arg_two.len() + {i}\n}}\n\n"
        ));
    }
    proj.write("src/many.rs", &rust_src);

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();

    let rel = RelPath::normalize("src/many.rs").unwrap();
    let outlined = outline_file(&mut index, &rel, Some(60)).unwrap();
    assert_eq!(outlined.trust, TrustLevel::VerifiedAst);
    assert!(outlined.data.files[0].symbols.len() < 30);
    assert_eq!(outlined.data.files[0].total_symbols, 30);
    assert_eq!(outlined.data.files[0].parse_status, ParseStatus::Parsed);
    assert!(
        outlined
            .omissions
            .iter()
            .any(|o| o.kind == OmissionKind::Symbols && o.reason == "token_budget_exceeded"),
        "expected explicit symbol omission on tight token budget, got: {:?}",
        outlined.omissions
    );

    // Line range read works verbatim with `L<n>| ` prefix.
    let lines_env = read_lines(&index, &rel, LineRange::new(1, 3).unwrap()).unwrap();
    assert_eq!(lines_env.trust, TrustLevel::VerifiedRaw);
    let body = lines_env.data.content.unwrap();
    assert!(body.contains("L1| pub fn function_number_01"));
    assert!(body.contains("L2|     arg_one + arg_two.len() + 1"));
    assert!(body.contains("L3| }"));
}

#[test]
fn extra_edge_cases_jsx_decorated_python_grouped_go_and_broken_docs() {
    let proj = TempDir::new("edges");
    let ro_cache = TempDir::new("edges-cache");

    proj.write(
        "web/Widget.jsx",
        concat!(
            "import React from 'react';\n",
            "const Widget = React.memo((props) => {\n",
            "  return <span>{props.label}</span>;\n",
            "});\n",
            "export default Widget;\n",
        ),
    );
    proj.write(
        "py/models.py",
        concat!(
            "API_TIMEOUT: int = 30\n",
            "@dataclass\n",
            "class User:\n",
            "    @classmethod\n",
            "    def from_dict(cls, data):\n",
            "        return cls()\n",
        ),
    );
    proj.write(
        "go/consts.go",
        concat!(
            "package cfg\n",
            "const (\n",
            "    Alpha = 1\n",
            "    Beta = 2\n",
            ")\n",
        ),
    );
    proj.write("bad.json", "{ \"unclosed\": [1, 2 }\n");
    proj.write("bad.toml", "[broken\nkey = \n");
    proj.write("bad.yaml", "\tbad_tab: 1\n");
    proj.write("bad.py", "def broken(:\n    pass\n");
    proj.write("bad.ts", "export function oops( { return 1;\n");
    proj.write("bad.go", "package main\nfunc broken( {\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();

    // `read(symbol="Widget")` unambiguously resolves `const Widget = React.memo(...)`,
    // not colliding with `export default Widget;`.
    let w_rel = RelPath::normalize("web/Widget.jsx").unwrap();
    let w = read_symbol(&mut index, &w_rel, "Widget").unwrap();
    assert_eq!(w.trust, TrustLevel::VerifiedAst);
    assert_eq!(
        w.data.qualified_name.as_deref(),
        Some("const Widget = memo(...)")
    );
    assert_eq!(w.data.start_line, Some(2));
    assert_eq!(w.data.end_line, Some(4));

    // Decorated Python class/method + typed constant.
    let py_rel = RelPath::normalize("py/models.py").unwrap();
    let py_out = outline_file(&mut index, &py_rel, None).unwrap();
    let py_syms = &py_out.data.files[0].symbols;
    assert!(
        py_syms
            .iter()
            .any(|s| s.qualified_name == "const API_TIMEOUT" && s.start_line == 1)
    );
    assert!(
        py_syms
            .iter()
            .any(|s| s.qualified_name == "class User" && s.start_line == 2)
    );
    assert!(
        py_syms
            .iter()
            .any(|s| s.qualified_name == "class User.from_dict" && s.start_line == 4)
    );

    // Grouped Go constants.
    let go_rel = RelPath::normalize("go/consts.go").unwrap();
    let go_out = outline_file(&mut index, &go_rel, None).unwrap();
    let go_syms = &go_out.data.files[0].symbols;
    assert!(
        go_syms
            .iter()
            .any(|s| s.qualified_name == "const Alpha" && s.start_line == 3)
    );
    assert!(
        go_syms
            .iter()
            .any(|s| s.qualified_name == "const Beta" && s.start_line == 4)
    );

    // All broken files fail closed with `UNPARSED_FALLBACK` + non-empty warning.
    for broken in [
        "bad.json", "bad.toml", "bad.yaml", "bad.py", "bad.ts", "bad.go",
    ] {
        let rel = RelPath::normalize(broken).unwrap();
        let out = outline_file(&mut index, &rel, None).unwrap();
        assert_eq!(
            out.trust,
            TrustLevel::UnparsedFallback,
            "expected UNPARSED_FALLBACK for `{broken}`"
        );
        assert!(
            !out.warnings.is_empty(),
            "expected explicit warning for `{broken}`"
        );
    }
}

#[test]
fn config_mode_read_only_forces_readonly_cache_even_without_cli_flag() {
    let proj = TempDir::new("cfg-ro");
    let ro_cache = TempDir::new("cfg-ro-cache");
    proj.write("src/lib.rs", "pub fn ok() -> u8 {\n    1\n}\n");

    let cfg = ProjectConfig {
        mode: ProjectMode::ReadOnly,
        ..ProjectConfig::default()
    };
    cfg.save_atomic(&proj.path().join(".klens").join("config.toml"))
        .unwrap();

    let root = ProjectRoot::new(proj.path()).unwrap();
    // Pass `read_only = false` explicitly: `ProjectMode::ReadOnly` in config MUST still win!
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, false, ro_cache.path()).unwrap();
    assert!(index.is_read_only());

    let stats = index.sync_workspace().unwrap();
    assert_eq!(stats.parsed, 1);

    // Must NEVER write `.klens/cache/` into the project directory.
    assert!(!proj.path().join(".klens").join("cache").exists());
    // Cache MUST reside under the read-only cache root.
    assert!(index.store().db_path().starts_with(ro_cache.path()));
    assert!(index.store().db_path().is_file());
}

#[test]
fn budgeted_directory_outline_keeps_total_symbols_consistent_with_total_files() {
    let proj = TempDir::new("dir-budget");
    let ro_cache = TempDir::new("dir-budget-cache");

    for file_idx in 1..=5 {
        let mut src = String::new();
        for fn_idx in 1..=4 {
            src.push_str(&format!(
                "pub fn f{file_idx}_fn_{fn_idx}(value: usize) -> usize {{\n    value + {fn_idx}\n}}\n\n"
            ));
        }
        proj.write(&format!("src/mod_{file_idx}.rs"), &src);
    }

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();

    // Very tight token budget forces early break before visiting all 5 files.
    let env = outline_path(
        &mut index,
        Some(&RelPath::normalize("src").unwrap()),
        Some(40),
    )
    .unwrap();
    assert_eq!(env.trust, TrustLevel::VerifiedAst);
    assert_eq!(env.data.total_files, 5);
    assert_eq!(
        env.data.total_symbols, 20,
        "total_symbols must report true count across all 5 files even when budget truncates early"
    );
    assert!(env.data.files.len() < 5);
    assert!(
        env.omissions
            .iter()
            .any(|o| o.kind == OmissionKind::Items && o.reason == "token_budget_exceeded"),
        "expected explicit omitted-files record, got: {:?}",
        env.omissions
    );
}

#[test]
fn toml_multiline_strings_inside_sections_do_not_emit_fake_sections() {
    let proj = TempDir::new("toml-multiline");
    let ro_cache = TempDir::new("toml-multiline-cache");

    proj.write(
        "Cargo.toml",
        concat!(
            "[package]\n",
            "name = \"demo\"\n",
            "description = \"\"\"\n",
            "[fake_section]\n",
            "[[fake_array]]\n",
            "\"\"\"\n",
            "notes = '''\n",
            "[another_fake]\n",
            "'''\n",
            "escaped = \"\"\"line with \\\"\"\" escaped quotes\n",
            "[still_inside_multiline]\n",
            "\"\"\"\n",
            "\n",
            "[dependencies]\n",
            "serde = \"1.0\"\n",
        ),
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();

    let env = outline_file(&mut index, &RelPath::normalize("Cargo.toml").unwrap(), None).unwrap();
    assert_eq!(env.trust, TrustLevel::VerifiedAst);
    let names: Vec<&str> = env.data.files[0]
        .symbols
        .iter()
        .map(|s| s.qualified_name.as_str())
        .collect();
    assert_eq!(names, vec!["[package]", "[dependencies]"]);
}

#[test]
fn oversized_file_above_max_indexable_bytes_falls_back_without_fts_bloat() {
    let proj = TempDir::new("oversized");
    let ro_cache = TempDir::new("oversized-cache");

    let mut huge = String::with_capacity(MAX_INDEXABLE_BYTES as usize + 256);
    huge.push_str("// OVERSIZED_SENTINEL_NEVER_IN_FTS\npub fn too_big() {}\n");
    let pad_line = "// 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    while (huge.len() as u64) <= MAX_INDEXABLE_BYTES + 64 {
        huge.push_str(pad_line);
    }
    proj.write("src/huge_blob.rs", &huge);

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();

    let rel = RelPath::normalize("src/huge_blob.rs").unwrap();
    let outcome1 = index.sync_file(&rel).unwrap();
    assert_eq!(outcome1, FileSyncOutcome::Parsed);

    let record = index.store().get_file(&rel).unwrap().unwrap();
    assert_eq!(record.parse_status, ParseStatus::Fallback);
    assert!(
        record
            .parse_warning
            .as_deref()
            .unwrap_or("")
            .contains("maximum indexable size")
    );
    assert!(index.store().get_symbols_for_file(&rel).unwrap().is_empty());
    assert_eq!(
        index.store().get_fts_content_for_file(&rel).unwrap(),
        Some(String::new()),
        "oversized file body must never be stored in FTS5"
    );

    // Outline reports honest `UNPARSED_FALLBACK` + explicit warning + `--lines 1:100` hint.
    let env = outline_file(&mut index, &rel, None).unwrap();
    assert_eq!(env.trust, TrustLevel::UnparsedFallback);
    assert!(!env.warnings.is_empty());
    let hint = env.raw_fallback.as_ref().and_then(|fb| fb.hint.as_deref());
    assert!(
        hint.is_some_and(|h| h.contains("--lines 1:100")),
        "expected `--lines 1:100` hint for oversized fallback file, got: {hint:?}"
    );

    // Second sync on unchanged oversized file skips work cleanly.
    let outcome2 = index.sync_file(&rel).unwrap();
    assert_eq!(outcome2, FileSyncOutcome::Unchanged);
}

#[test]
fn read_lines_on_directory_returns_not_a_file_error() {
    let proj = TempDir::new("read-dir");
    let ro_cache = TempDir::new("read-dir-cache");
    proj.write("src/lib.rs", "pub fn x() {}\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();

    let err = read_lines(
        &index,
        &RelPath::normalize("src").unwrap(),
        LineRange::new(1, 5).unwrap(),
    )
    .unwrap_err();
    assert!(
        matches!(err, CodeError::NotAFile(ref p) if p == "src"),
        "expected CodeError::NotAFile(\"src\"), got: {err:?}"
    );
}

#[test]
fn read_lines_refuses_oversized_files_instead_of_loading_them() {
    let proj = TempDir::new("read-huge");
    let ro_cache = TempDir::new("read-huge-cache");
    let limit = usize::try_from(klens_code::read::MAX_READ_BYTES).unwrap();
    proj.write("big.log", &"a".repeat(limit + 1));

    let root = ProjectRoot::new(proj.path()).unwrap();
    let index = CodeIndex::open_with_readonly_cache_dir(root, true, ro_cache.path()).unwrap();

    let err = read_lines(
        &index,
        &RelPath::normalize("big.log").unwrap(),
        LineRange::new(1, 2).unwrap(),
    )
    .unwrap_err();
    assert!(
        matches!(err, CodeError::FileTooLarge { .. }),
        "expected FileTooLarge, got: {err:?}"
    );
}

/// A cache database is only trusted by the project that built it. One copied in from
/// elsewhere (or committed into a repository) must not feed fake symbols to agents.
#[test]
fn cache_db_from_another_project_is_discarded() {
    let a = TempDir::new("poison-a");
    let b = TempDir::new("poison-b");
    a.write("src/lib.rs", "pub fn real() {}\n");
    b.write("src/lib.rs", "pub fn real() {}\n");

    drop(CodeIndex::open(ProjectRoot::new(a.path()).unwrap(), false).unwrap());
    let a_db = a.path().join(".klens").join("cache").join("index.db");
    {
        let conn = rusqlite::Connection::open(&a_db).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        conn.execute(
            "INSERT INTO symbols (file_path, name, qualified_name, kind, signature, \
             start_line, end_line, ordinal) VALUES ('src/lib.rs', 'totally_fake', \
             'totally_fake', 'fn', 'fn totally_fake()', 1, 1, 0)",
            [],
        )
        .unwrap();
    }
    let b_cache = b.path().join(".klens").join("cache");
    fs::create_dir_all(&b_cache).unwrap();
    fs::copy(&a_db, b_cache.join("index.db")).unwrap();

    drop(CodeIndex::open(ProjectRoot::new(b.path()).unwrap(), false).unwrap());

    let conn = rusqlite::Connection::open(b_cache.join("index.db")).unwrap();
    let fake: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM symbols WHERE name = 'totally_fake'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fake, 0, "foreign cache rows were adopted");
}
