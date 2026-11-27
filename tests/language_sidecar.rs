//! Phase 5B Language Sidecar (`ext-lang-*` + `ext-lang-ctags`) end-to-end integration
//! and adversarial security test suite (`docs/05-LANGUAGE-SIDECAR-SPEC.md` §7.2: T1–T12).
//!
//! Uses a cross-platform self-reexec harness (`harness = false`):
//! - `--mock-sidecar <mode> <ext-id> <version> [aux_file]` runs an offline JSON-RPC 2.0 sidecar.
//! - `--mock-ctags` (or argv0 stem `ctags`) runs an offline Universal Ctags (`+json`) mock.
//! - Default invocation executes all T1–T13 verification scenarios sequentially.
//!
//! Trust model (v0.3.2+): language-parser sidecars spawn external processes, so they are
//! discovered ONLY from `~/.klens/extensions/` and enabled ONLY via `~/.klens/config.toml`.
//! Project-local `.klens/extensions/` manifests and project `enabled_extensions` entries for
//! language parsers are ignored (T13), because a cloned repository controls those files.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use klens_code::{
    CodeIndex, INDEX_DB_SCHEMA_VERSION, IndexStore, ParseStatus, build_code_graph,
    build_project_map, enrich_extension_list_health, find_in_workspace,
    inspect_language_extensions_doctor, outline_file, outline_path, read_symbol,
};
use klens_core::{
    CTAGS_EXTENSION_ID, CheckSeverity, EXTENSION_MANIFEST_FILE, EdgeConfidence, EdgeRelation,
    ExtensionHealthStatus, ExtensionScope, ProjectRoot, RelPath, SymbolKind, TrustLevel,
    list_extensions, set_extension_enabled,
};
use klens_mcp::tools::tool_definitions;
use serde_json::{Value, json};

static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(0);

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(String::as_str) == Some("--mock-sidecar") {
        run_mock_sidecar(&args[2..]);
        return;
    }

    let exe_stem = args
        .first()
        .and_then(|s| Path::new(s).file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if exe_stem == "ctags" || args.get(1).map(String::as_str) == Some("--mock-ctags") {
        // Spawn evidence for T13: record every mock ctags launch next to the executable.
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
        {
            let _ = fs::write(dir.join("ctags_spawned.marker"), "spawned");
        }
        run_mock_ctags(&args[1..]);
        return;
    }

    let filter = args.get(1).filter(|a| !a.starts_with('-')).cloned();

    let tests: Vec<(&str, fn())> = vec![
        (
            "t1_mock_sidecar_parse_determinism_and_graph_inferred_edge",
            t1_mock_sidecar_parse_determinism_and_graph_inferred_edge,
        ),
        (
            "t2_fake_verified_ast_claim_rejected_fail_closed",
            t2_fake_verified_ast_claim_rejected_fail_closed,
        ),
        (
            "t3_malformed_json_and_stdout_banner_preserve_index_and_fts",
            t3_malformed_json_and_stdout_banner_preserve_index_and_fts,
        ),
        (
            "t4_wall_clock_timeout_create_no_window_and_circuit_breaker",
            t4_wall_clock_timeout_create_no_window_and_circuit_breaker,
        ),
        (
            "t5_oversized_4mib_frame_dos_blocked_without_oom",
            t5_oversized_4mib_frame_dos_blocked_without_oom,
        ),
        (
            "t6_invalid_line_byte_utf8_bounds_and_secret_redaction",
            t6_invalid_line_byte_utf8_bounds_and_secret_redaction,
        ),
        (
            "t7_minimal_env_clear_and_temp_cwd_isolation",
            t7_minimal_env_clear_and_temp_cwd_isolation,
        ),
        (
            "t8_parse_cache_key_hit_crlf_miss_version_and_disable",
            t8_parse_cache_key_hit_crlf_miss_version_and_disable,
        ),
        (
            "t9_index_db_v1_to_v2_atomic_migration",
            t9_index_db_v1_to_v2_atomic_migration,
        ),
        (
            "t10_builtin_ast_precedence_no_core_hijack_and_doctor_warning",
            t10_builtin_ast_precedence_no_core_hijack_and_doctor_warning,
        ),
        (
            "t11_ctags_unavailable_and_mock_universal_json_cleanup",
            t11_ctags_unavailable_and_mock_universal_json_cleanup,
        ),
        (
            "t12_constitution_dep_budget_mcp_tools_and_repo_health",
            t12_constitution_dep_budget_mcp_tools_and_repo_health,
        ),
        (
            "t13_untrusted_project_cannot_enable_or_spawn_language_sidecars",
            t13_untrusted_project_cannot_enable_or_spawn_language_sidecars,
        ),
    ];

    let mut passed = 0usize;
    for (name, func) in tests {
        if let Some(f) = &filter
            && !name.contains(f.as_str())
        {
            continue;
        }
        eprintln!("running {name} ...");
        func();
        eprintln!("test {name} ... ok");
        passed += 1;
    }
    eprintln!("language_sidecar: {passed} passed; 0 failed");
}

// ===========================================================================
// Self-Reexec Mock Sidecar & Mock Universal Ctags
// ===========================================================================

fn write_json_line(out: &mut impl Write, value: &Value) {
    let encoded = serde_json::to_string(value).expect("serialize mock json");
    let _ = out.write_all(encoded.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn run_mock_sidecar(args: &[String]) {
    let mode = args.first().map(String::as_str).unwrap_or("normal");
    let ext_id = args.get(1).map(String::as_str).unwrap_or("ext-lang-kotlin");
    let version = args.get(2).map(String::as_str).unwrap_or("0.1.0");
    let aux_file = args.get(3).map(PathBuf::from);

    // Spawn evidence for T13: write the marker before reading any request.
    if mode == "spawn_marker"
        && let Some(marker) = &aux_file
    {
        let _ = fs::write(marker, "spawned");
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let reader = BufReader::new(stdin.lock());

    for line_res in reader.lines() {
        let Ok(line) = line_res else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => break,
        };
        let id = req.get("id").and_then(Value::as_u64).unwrap_or(0);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");

        match method {
            "ext/initialize" => {
                if mode == "banner_stdout" {
                    let _ = out.write_all(b"BANNER: Mock sidecar starting up!\n");
                    let _ = out.flush();
                    return;
                }
                write_json_line(
                    &mut out,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "protocol_version": 1,
                            "extension_id": ext_id,
                            "version": version,
                            "requires_network": false,
                            "supports_read_only": true,
                            "capabilities": ["parse_file"]
                        }
                    }),
                );
            }
            "ext/capabilities" => {
                write_json_line(
                    &mut out,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "protocol_version": 1,
                            "extension_id": ext_id,
                            "parser_id": ext_id,
                            "parser_version": version,
                            "languages": [
                                { "language_id": "kotlin", "extensions": ["kt"] }
                            ],
                            "supports_byte_ranges": true,
                            "supports_imports": true,
                            "max_file_bytes": 1048576
                        }
                    }),
                );
            }
            "ext/parse_file" => {
                if let Some(path) = &aux_file
                    && matches!(mode, "normal" | "hang")
                {
                    let prev: u64 = fs::read_to_string(path)
                        .ok()
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    let _ = fs::write(path, (prev + 1).to_string());
                }

                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let content = params.get("content").and_then(Value::as_str).unwrap_or("");

                match mode {
                    "hang" => {
                        std::thread::sleep(Duration::from_secs(30));
                        return;
                    }
                    "oversized_frame" => {
                        let chunk = vec![b'A'; 65_536];
                        for _ in 0..80 {
                            if out.write_all(&chunk).is_err() {
                                return;
                            }
                        }
                        let _ = out.write_all(b"\n");
                        let _ = out.flush();
                        return;
                    }
                    "malformed_json" => {
                        let _ = out.write_all(b"{not valid json at all\n");
                        let _ = out.flush();
                        return;
                    }
                    "fake_verified_ast" => {
                        write_json_line(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "schema_version": 1,
                                    "trust": "VERIFIED_AST",
                                    "status": "parsed",
                                    "language_id": "kotlin",
                                    "parser_id": ext_id,
                                    "parser_version": version,
                                    "warnings": [],
                                    "omissions": [],
                                    "symbols": [
                                        {
                                            "name": "Spoofed",
                                            "qualified_name": "class Spoofed",
                                            "kind": "class",
                                            "signature": "public class Spoofed",
                                            "start_line": 1,
                                            "end_line": 1,
                                            "start_byte": null,
                                            "end_byte": null,
                                            "parent_symbol": null
                                        }
                                    ],
                                    "imports": []
                                }
                            }),
                        );
                    }
                    "bad_start_line_zero" => {
                        write_json_line(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "schema_version": 1,
                                    "trust": "EXTERNAL_PARSER",
                                    "status": "parsed",
                                    "language_id": "kotlin",
                                    "parser_id": ext_id,
                                    "parser_version": version,
                                    "warnings": [],
                                    "omissions": [],
                                    "symbols": [{
                                        "name": "Zero",
                                        "kind": "class",
                                        "signature": "class Zero",
                                        "start_line": 0,
                                        "end_line": 1
                                    }],
                                    "imports": []
                                }
                            }),
                        );
                    }
                    "bad_end_line_oob" => {
                        write_json_line(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "schema_version": 1,
                                    "trust": "EXTERNAL_PARSER",
                                    "status": "parsed",
                                    "language_id": "kotlin",
                                    "parser_id": ext_id,
                                    "parser_version": version,
                                    "warnings": [],
                                    "omissions": [],
                                    "symbols": [{
                                        "name": "Oob",
                                        "kind": "class",
                                        "signature": "class Oob",
                                        "start_line": 1,
                                        "end_line": 999
                                    }],
                                    "imports": []
                                }
                            }),
                        );
                    }
                    "bad_utf8_byte_offset" => {
                        // Find first multi-byte char and deliberately point 1 byte inside it.
                        let bad_byte = content
                            .char_indices()
                            .find(|(_, ch)| ch.len_utf8() > 1)
                            .map(|(idx, _)| idx + 1)
                            .unwrap_or(1);
                        write_json_line(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "schema_version": 1,
                                    "trust": "EXTERNAL_PARSER",
                                    "status": "parsed",
                                    "language_id": "kotlin",
                                    "parser_id": ext_id,
                                    "parser_version": version,
                                    "warnings": [],
                                    "omissions": [],
                                    "symbols": [{
                                        "name": "BadUtf8",
                                        "kind": "class",
                                        "signature": "class BadUtf8",
                                        "start_line": 1,
                                        "end_line": 1,
                                        "start_byte": bad_byte,
                                        "end_byte": content.len()
                                    }],
                                    "imports": []
                                }
                            }),
                        );
                    }
                    "turkish_with_secret" => {
                        let fake_secret =
                            format!("{}{}", "sk-", "proj_mock_leaked_token_1234567890abcdef");
                        write_json_line(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "schema_version": 1,
                                    "trust": "EXTERNAL_PARSER",
                                    "status": "parsed",
                                    "language_id": "kotlin",
                                    "parser_id": ext_id,
                                    "parser_version": version,
                                    "warnings": [format!("debug key={fake_secret}")],
                                    "omissions": [],
                                    "symbols": [{
                                        "name": "ÇağrıYöneticisi",
                                        "qualified_name": "class ÇağrıYöneticisi",
                                        "kind": "class",
                                        "signature": format!("public class ÇağrıYöneticisi // {fake_secret}"),
                                        "start_line": 1,
                                        "end_line": 1,
                                        "start_byte": 0,
                                        "end_byte": content.len()
                                    }],
                                    "imports": []
                                }
                            }),
                        );
                    }
                    "env_probe" => {
                        if let Some(report_path) = &aux_file {
                            let env_map: BTreeMap<String, String> = std::env::vars().collect();
                            let cwd = std::env::current_dir()
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            let payload = json!({
                                "cwd": cwd,
                                "env": env_map
                            });
                            let _ = fs::write(
                                report_path,
                                serde_json::to_string_pretty(&payload).unwrap(),
                            );
                        }
                        write_json_line(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "schema_version": 1,
                                    "trust": "EXTERNAL_PARSER",
                                    "status": "parsed",
                                    "language_id": "kotlin",
                                    "parser_id": ext_id,
                                    "parser_version": version,
                                    "warnings": [],
                                    "omissions": [],
                                    "symbols": [{
                                        "name": "EnvTarget",
                                        "kind": "class",
                                        "signature": "public class EnvTarget",
                                        "start_line": 1,
                                        "end_line": 1
                                    }],
                                    "imports": []
                                }
                            }),
                        );
                    }
                    _ => {
                        // "normal": parse simple Kotlin class/fun/import deterministically,
                        // deliberately emitting symbols in REVERSE line order so core sorting is tested!
                        let (symbols, imports) = mock_parse_kotlin(content);
                        write_json_line(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "schema_version": 1,
                                    "trust": "EXTERNAL_PARSER",
                                    "status": "parsed",
                                    "language_id": "kotlin",
                                    "parser_id": ext_id,
                                    "parser_version": version,
                                    "warnings": [],
                                    "omissions": [],
                                    "symbols": symbols,
                                    "imports": imports
                                }
                            }),
                        );
                    }
                }
            }
            "ext/shutdown" => {
                write_json_line(
                    &mut out,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "ok": true }
                    }),
                );
                return;
            }
            _ => {
                write_json_line(
                    &mut out,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "method not found" }
                    }),
                );
            }
        }
    }
}

fn mock_parse_kotlin(content: &str) -> (Vec<Value>, Vec<Value>) {
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len().max(1);
    let mut symbols = Vec::new();
    let mut imports = Vec::new();
    let mut current_class: Option<String> = None;

    // Precompute byte offsets for each 1-based line.
    let mut line_starts = Vec::with_capacity(lines.len());
    let mut offset = 0usize;
    for l in &lines {
        line_starts.push(offset);
        offset += l.len() + 1;
    }

    for (idx, line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("import ") {
            let spec = rest.trim_end_matches(';').trim();
            if !spec.is_empty() {
                imports.push(json!({
                    "specifier": spec,
                    "line": line_no,
                    "kind": "import"
                }));
            }
        } else if let Some(pos) = trimmed.find("class ") {
            let after = &trimmed[pos + 6..];
            let name = after
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .unwrap_or("Unknown");
            let qname = format!("class {name}");
            current_class = Some(qname.clone());
            let sb = line_starts[idx];
            let eb = content.len();
            symbols.push(json!({
                "name": name,
                "qualified_name": qname,
                "kind": "class",
                "signature": trimmed.trim_end_matches('{').trim(),
                "start_line": line_no,
                "end_line": total_lines,
                "start_byte": sb,
                "end_byte": eb,
                "parent_symbol": null
            }));
        } else if (trimmed.starts_with("fun ") || trimmed.starts_with("public fun "))
            && trimmed.contains('(')
        {
            let before_paren = trimmed.split('(').next().unwrap_or("");
            let name = before_paren.split_whitespace().last().unwrap_or("method");
            let parent = current_class.clone();
            let sb = line_starts[idx];
            let eb = (sb + line.len()).min(content.len());
            symbols.push(json!({
                "name": name,
                "qualified_name": parent.as_ref().map(|p| format!("{p}::{name}")),
                "kind": "method",
                "signature": trimmed.trim_end_matches('{').trim(),
                "start_line": line_no,
                "end_line": (line_no + 2).min(total_lines),
                "start_byte": sb,
                "end_byte": eb,
                "parent_symbol": parent
            }));
        }
    }

    // Deliberately reverse symbols to prove core enforces deterministic sorting!
    symbols.reverse();
    (symbols, imports)
}

fn run_mock_ctags(args: &[String]) {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    if args.iter().any(|a| a == "--version") {
        let _ =
            out.write_all(b"Universal Ctags 6.1.0, Copyright (C) 2015-2024 Universal Ctags Team\n");
        let _ = out.flush();
        return;
    }
    if args.iter().any(|a| a == "--list-features") {
        let _ = out.write_all(b"json       JSON output\nmultiline  multiline matching\n");
        let _ = out.flush();
        return;
    }

    // Input file is the last argument passed to `ctags --options=NONE --output-format=json ... <file>`.
    let Some(input_path) = args.last() else {
        std::process::exit(1);
    };
    let content = fs::read_to_string(input_path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len().max(1);
    let mut current_class: Option<String> = None;

    for (idx, line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find("class ") {
            let name = trimmed[pos + 6..]
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .unwrap_or("Unknown");
            current_class = Some(name.to_string());
            write_json_line(
                &mut out,
                &json!({
                    "_type": "tag",
                    "name": name,
                    "path": input_path,
                    "language": "Kotlin",
                    "line": line_no,
                    "end": total,
                    "kind": "class"
                }),
            );
        } else if (trimmed.starts_with("fun ") || trimmed.starts_with("public fun "))
            && trimmed.contains('(')
        {
            let before_paren = trimmed.split('(').next().unwrap_or("");
            let name = before_paren.split_whitespace().last().unwrap_or("method");
            write_json_line(
                &mut out,
                &json!({
                    "_type": "tag",
                    "name": name,
                    "path": input_path,
                    "language": "Kotlin",
                    "line": line_no,
                    "end": (line_no + 2).min(total),
                    "kind": "method",
                    "scope": current_class,
                    "scopeKind": "class"
                }),
            );
        }
    }
}

// ===========================================================================
// Test Sandbox Helpers
// ===========================================================================

struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    ro_cache: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let seq = SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "klens-sidecar-test-{label}-{}-{seq}",
            std::process::id()
        ));
        let root = base.join("project");
        let home = base.join("home");
        let ro_cache = base.join("ro_cache");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&ro_cache).unwrap();
        Self {
            root,
            home,
            ro_cache,
        }
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.root.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full, content).unwrap();
    }

    fn global_cfg_path(&self) -> PathBuf {
        self.home.join(".klens").join("config.toml")
    }

    /// Write a file under the sandbox user-global `~/.klens/` directory.
    fn write_global(&self, rel: &str, content: &str) {
        let full = self.home.join(".klens").join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full, content).unwrap();
    }

    fn project_root(&self) -> ProjectRoot {
        ProjectRoot::new(&self.root).unwrap()
    }

    /// Install a trusted mock sidecar manifest into the user-global `~/.klens/extensions/`.
    #[allow(clippy::too_many_arguments)]
    fn install_mock_manifest(
        &self,
        ext_id: &str,
        version: &str,
        extensions: &[&str],
        mode: &str,
        aux_file: Option<&Path>,
        timeout_ms: u64,
        max_frame_bytes: usize,
    ) {
        let manifest = mock_manifest_toml(
            ext_id,
            version,
            extensions,
            mode,
            aux_file,
            timeout_ms,
            max_frame_bytes,
        );
        self.write_global(
            &format!("extensions/{ext_id}/{EXTENSION_MANIFEST_FILE}"),
            &manifest,
        );
    }

    /// Enable an extension the only trusted way: the user-global `~/.klens/config.toml`.
    fn enable_ext(&self, ext_id: &str) {
        let pr = self.project_root();
        set_extension_enabled(
            ext_id,
            true,
            ExtensionScope::Global,
            &self.global_cfg_path(),
            Some(&pr),
        )
        .unwrap();
    }

    fn open_index(&self, read_only: bool) -> CodeIndex {
        CodeIndex::open_with_global_config(
            self.project_root(),
            read_only,
            Some(&self.ro_cache),
            Some(&self.global_cfg_path()),
        )
        .unwrap()
    }
}

/// Render a mock sidecar `klens-extension.toml` that re-executes this test binary.
#[allow(clippy::too_many_arguments)]
fn mock_manifest_toml(
    ext_id: &str,
    version: &str,
    extensions: &[&str],
    mode: &str,
    aux_file: Option<&Path>,
    timeout_ms: u64,
    max_frame_bytes: usize,
) -> String {
    let exe = std::env::current_exe().unwrap();
    let exe_escaped = exe.to_string_lossy().replace('\\', "\\\\");
    let mut args_list = vec![
        "--mock-sidecar".to_string(),
        mode.to_string(),
        ext_id.to_string(),
        version.to_string(),
    ];
    if let Some(aux) = aux_file {
        args_list.push(aux.to_string_lossy().into_owned());
    }
    let args_toml = args_list
        .iter()
        .map(|a| format!("\"{}\"", a.replace('\\', "\\\\")))
        .collect::<Vec<_>>()
        .join(", ");
    let exts_toml = extensions
        .iter()
        .map(|e| format!("\"{e}\""))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "id = \"{ext_id}\"\n\
         kind = \"language-parser\"\n\
         version = \"{version}\"\n\
         protocol_version = 1\n\
         description = \"Mock {ext_id} sidecar\"\n\
         extensions = [{exts_toml}]\n\
         command = \"{exe_escaped}\"\n\
         args = [{args_toml}]\n\
         timeout_ms = {timeout_ms}\n\
         max_frame_bytes = {max_frame_bytes}\n\
         requires_network = false\n\
         supports_read_only = true\n"
    )
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Some(parent) = self.root.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

fn configure_no_window_test(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

fn find_workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for ancestor in manifest_dir.ancestors() {
        if ancestor.join("Cargo.lock").is_file() {
            return ancestor.to_path_buf();
        }
    }
    panic!("workspace root with Cargo.lock not found");
}

// ===========================================================================
// T1–T12 Verification Scenarios
// ===========================================================================

fn t1_mock_sidecar_parse_determinism_and_graph_inferred_edge() {
    let sb = Sandbox::new("t1");
    sb.write(
        "src/main/kotlin/com/acme/Item.kt",
        "package com.acme\n\nclass Item {\n    fun id(): String {\n        return \"x\"\n    }\n}\n",
    );
    sb.write(
        "src/main/kotlin/com/acme/OrderService.kt",
        "package com.acme\n\nimport com.acme.Item\n\nclass OrderService {\n    fun createOrder(): Item {\n        return Item()\n    }\n}\n",
    );
    sb.install_mock_manifest(
        "ext-lang-kotlin",
        "0.1.0",
        &["kt"],
        "normal",
        None,
        3000,
        4_194_304,
    );
    sb.enable_ext("ext-lang-kotlin");

    let mut idx = sb.open_index(false);
    let rel = RelPath::normalize("src/main/kotlin/com/acme/OrderService.kt").unwrap();
    let env = outline_file(&mut idx, &rel, None).unwrap();

    assert_eq!(env.trust, TrustLevel::ExternalParser);
    assert_eq!(env.data.files.len(), 1);
    let file = &env.data.files[0];
    assert_eq!(file.parse_status, ParseStatus::ExternalParsed);
    assert_eq!(file.parser_id.as_deref(), Some("ext-lang-kotlin"));
    assert_eq!(file.symbols.len(), 2);
    // Core must sort symbols deterministically even though mock emitted them reversed!
    assert_eq!(file.symbols[0].name, "OrderService");
    assert_eq!(file.symbols[0].kind, SymbolKind::Class);
    assert_eq!(file.symbols[0].start_line, 5);
    assert_eq!(file.symbols[1].name, "createOrder");
    assert_eq!(file.symbols[1].kind, SymbolKind::Method);
    assert_eq!(file.symbols[1].start_line, 6);

    // Byte ranges persisted accurately in SQLite v2 `symbols` table.
    let byte_ranges = idx.store().get_symbol_byte_ranges_for_file(&rel).unwrap();
    assert_eq!(byte_ranges.len(), 2);
    assert!(byte_ranges[0].is_some());
    assert!(byte_ranges[1].is_some());

    // Surgical symbol read returns TrustLevel::ExternalParser.
    let read_env = read_symbol(&mut idx, &rel, "createOrder").unwrap();
    assert_eq!(read_env.trust, TrustLevel::ExternalParser);
    assert!(read_env.data.content.unwrap().contains("createOrder"));

    // Code graph resolves external import edge with EdgeConfidence::Inferred (NEVER Extracted!).
    let graph_env = build_code_graph(&mut idx).unwrap();
    assert_eq!(graph_env.trust, TrustLevel::ExternalParser);
    let import_edge = graph_env
        .data
        .edges
        .iter()
        .find(|e| {
            e.from == "file:src/main/kotlin/com/acme/OrderService.kt"
                && e.to == "file:src/main/kotlin/com/acme/Item.kt"
                && e.relation == EdgeRelation::Imports
        })
        .expect("expected resolved Kotlin import edge");
    assert_eq!(import_edge.confidence, EdgeConfidence::Inferred);
    assert!(
        import_edge
            .evidence
            .contains("external:ext-lang-kotlin@0.1.0")
    );

    // PageRank map also downgrades honestly to EXTERNAL_PARSER.
    let map_env = build_project_map(&mut idx, 2000).unwrap();
    assert_eq!(map_env.trust, TrustLevel::ExternalParser);

    // Two consecutive CLI `klens outline --json` runs must be byte-for-byte identical!
    let klens_bin = env!("CARGO_BIN_EXE_klens");
    let run_outline = || {
        let mut cmd = Command::new(klens_bin);
        cmd.args([
            "outline",
            "src/main/kotlin/com/acme/OrderService.kt",
            "--root",
            sb.root.to_str().unwrap(),
            "--json",
        ])
        .env("USERPROFILE", &sb.home)
        .env("HOME", &sb.home);
        configure_no_window_test(&mut cmd);
        cmd.output().expect("run klens outline")
    };
    let out1 = run_outline();
    let out2 = run_outline();
    assert!(
        out1.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    assert_eq!(
        out1.stdout, out2.stdout,
        "outline --json must be byte-for-byte deterministic"
    );
    let parsed: Value = serde_json::from_slice(&out1.stdout).unwrap();
    assert_eq!(parsed["trust"], "EXTERNAL_PARSER");
}

fn t2_fake_verified_ast_claim_rejected_fail_closed() {
    let sb = Sandbox::new("t2");
    sb.write("Spoofed.kt", "class Spoofed {}\n");
    sb.install_mock_manifest(
        "ext-lang-spoof",
        "0.1.0",
        &["kt"],
        "fake_verified_ast",
        None,
        3000,
        4_194_304,
    );
    sb.enable_ext("ext-lang-spoof");

    let mut idx = sb.open_index(false);
    let rel = RelPath::normalize("Spoofed.kt").unwrap();
    let env = outline_file(&mut idx, &rel, None).unwrap();

    assert_eq!(env.trust, TrustLevel::UnparsedFallback);
    assert_eq!(env.data.files[0].parse_status, ParseStatus::Fallback);
    assert!(env.data.files[0].symbols.is_empty());
    assert!(
        env.warnings
            .iter()
            .any(|w| w.contains("protocol violation") && w.contains("VERIFIED_AST")),
        "expected protocol violation warning, got: {:?}",
        env.warnings
    );
}

fn t3_malformed_json_and_stdout_banner_preserve_index_and_fts() {
    for mode in ["malformed_json", "banner_stdout"] {
        let sb = Sandbox::new(&format!("t3-{mode}"));
        sb.write(
            "Broken.kt",
            "class UniqueFtsNeedleToken {\n    val answer = 42\n}\n",
        );
        sb.install_mock_manifest(
            "ext-lang-bad",
            "0.1.0",
            &["kt"],
            mode,
            None,
            3000,
            4_194_304,
        );
        sb.enable_ext("ext-lang-bad");

        let mut idx = sb.open_index(false);
        idx.sync_workspace().unwrap();
        let rel = RelPath::normalize("Broken.kt").unwrap();
        let rec = idx.store().get_file(&rel).unwrap().unwrap();
        assert_eq!(rec.parse_status, ParseStatus::Fallback);

        // `index.db` integrity preserved & FTS5 search still finds the file!
        let found = find_in_workspace(&mut idx, "UniqueFtsNeedleToken", 10).unwrap();
        assert!(
            found.data.matches.iter().any(|m| m.path == "Broken.kt"),
            "FTS5 search must still find Broken.kt in mode {mode}"
        );
    }
}

fn t4_wall_clock_timeout_create_no_window_and_circuit_breaker() {
    let sb = Sandbox::new("t4");
    for i in 1..=5 {
        sb.write(&format!("File{i}.kt"), &format!("class File{i} {{}}\n"));
    }
    let counter_file = sb.home.join("hang_calls.txt");
    sb.install_mock_manifest(
        "ext-lang-hang",
        "0.1.0",
        &["kt"],
        "hang",
        Some(&counter_file),
        200,
        4_194_304,
    );
    sb.enable_ext("ext-lang-hang");

    let mut idx = sb.open_index(false);
    let started = Instant::now();
    idx.sync_workspace().unwrap();
    let elapsed = started.elapsed();

    // 3 timeouts at ~200ms each + process-tree kill should stay well under 4 seconds,
    // and 4th/5th files must NOT spawn the sidecar at all!
    assert!(
        elapsed < Duration::from_secs(5),
        "sync with 200ms timeout + circuit breaker took too long: {elapsed:?}"
    );
    let calls: u64 = fs::read_to_string(&counter_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    assert_eq!(
        calls, 3,
        "circuit breaker must stop spawning after 3 consecutive timeouts (got {calls})"
    );

    let f4 = idx
        .store()
        .get_file(&RelPath::normalize("File4.kt").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(f4.parse_status, ParseStatus::Fallback);
    assert!(
        f4.parse_warning
            .as_deref()
            .unwrap_or("")
            .contains("circuit breaker"),
        "expected circuit breaker warning on File4, got: {:?}",
        f4.parse_warning
    );

    // Static verification that sidecar spawn/kill enforces CREATE_NO_WINDOW (0x0800_0000).
    let ws = find_workspace_root();
    let common_src =
        fs::read_to_string(ws.join("crates/klens-code/src/sidecar/common.rs")).unwrap();
    assert!(common_src.contains("0x0800_0000"));
    assert!(common_src.contains("creation_flags(WINDOWS_CREATE_NO_WINDOW)"));
    assert!(common_src.contains("Command::new(\"taskkill\")"));
}

fn t5_oversized_4mib_frame_dos_blocked_without_oom() {
    let sb = Sandbox::new("t5");
    sb.write("HugeReply.kt", "class HugeReply {}\n");
    sb.install_mock_manifest(
        "ext-lang-dos",
        "0.1.0",
        &["kt"],
        "oversized_frame",
        None,
        3000,
        4_194_304,
    );
    sb.enable_ext("ext-lang-dos");

    let mut idx = sb.open_index(false);
    let rel = RelPath::normalize("HugeReply.kt").unwrap();
    let env = outline_file(&mut idx, &rel, None).unwrap();
    assert_eq!(env.trust, TrustLevel::UnparsedFallback);
    assert_eq!(env.data.files[0].parse_status, ParseStatus::Fallback);
    assert!(
        env.warnings.iter().any(|w| w.contains("max_frame_bytes")),
        "expected max_frame_bytes warning, got: {:?}",
        env.warnings
    );
}

fn t6_invalid_line_byte_utf8_bounds_and_secret_redaction() {
    // (a) start_line = 0, (b) end_line > line_count, (c) mid-UTF-8 Turkish byte offset -> fail-closed.
    for mode in [
        "bad_start_line_zero",
        "bad_end_line_oob",
        "bad_utf8_byte_offset",
    ] {
        let sb = Sandbox::new(&format!("t6-{mode}"));
        sb.write("Türkçe.kt", "class ğüşiöçĞÜŞİÖÇ {}\n");
        sb.install_mock_manifest(
            "ext-lang-bounds",
            "0.1.0",
            &["kt"],
            mode,
            None,
            3000,
            4_194_304,
        );
        sb.enable_ext("ext-lang-bounds");

        let mut idx = sb.open_index(false);
        let rel = RelPath::normalize("Türkçe.kt").unwrap();
        let env = outline_file(&mut idx, &rel, None).unwrap();
        assert_eq!(
            env.trust,
            TrustLevel::UnparsedFallback,
            "mode {mode} must fail closed"
        );
        assert!(env.data.files[0].symbols.is_empty());
    }

    // (d) Valid Turkish symbol + secret key in signature & warning -> redacted!
    let sb = Sandbox::new("t6-redact");
    sb.write("Cagri.kt", "class ÇağrıYöneticisi {}\n");
    sb.install_mock_manifest(
        "ext-lang-tr",
        "0.1.0",
        &["kt"],
        "turkish_with_secret",
        None,
        3000,
        4_194_304,
    );
    sb.enable_ext("ext-lang-tr");

    let mut idx = sb.open_index(false);
    let rel = RelPath::normalize("Cagri.kt").unwrap();
    let env = outline_file(&mut idx, &rel, None).unwrap();
    assert_eq!(env.trust, TrustLevel::ExternalParser);
    assert_eq!(env.data.files[0].symbols[0].name, "ÇağrıYöneticisi");

    let leaked_probe = format!("{}{}", "sk-", "proj_mock_leaked_token_1234567890abcdef");
    let serialized = env.to_deterministic_json().unwrap();
    assert!(
        !serialized.contains(&leaked_probe),
        "raw secret leaked in outline JSON!"
    );
    assert!(
        serialized.contains("[REDACTED:"),
        "expected [REDACTED:...] marker in outline JSON: {serialized}"
    );
}

fn t7_minimal_env_clear_and_temp_cwd_isolation() {
    let sb = Sandbox::new("t7");
    sb.write("EnvTarget.kt", "class EnvTarget {}\n");
    let dump_file = sb.home.join("env_dump.json");
    sb.install_mock_manifest(
        "ext-lang-envcheck",
        "0.1.0",
        &["kt"],
        "env_probe",
        Some(&dump_file),
        3000,
        4_194_304,
    );
    sb.enable_ext("ext-lang-envcheck");

    let synthetic_secret = format!("{}{}", "sk-", "secret_should_not_leak_9876543210");
    let klens_bin = env!("CARGO_BIN_EXE_klens");
    let mut cmd = Command::new(klens_bin);
    cmd.args([
        "outline",
        "EnvTarget.kt",
        "--root",
        sb.root.to_str().unwrap(),
        "--json",
    ])
    .env("USERPROFILE", &sb.home)
    .env("HOME", &sb.home)
    .env("OPENAI_API_KEY", &synthetic_secret)
    .env(
        "GITHUB_TOKEN",
        format!("{}{}", "ghp_", "mock_secret_token_999999999999"),
    );
    configure_no_window_test(&mut cmd);

    let out = cmd.output().expect("run klens outline for env test");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dump_text = fs::read_to_string(&dump_file).expect("sidecar must write env dump");
    let dump: Value = serde_json::from_str(&dump_text).unwrap();
    let env_obj = dump["env"].as_object().unwrap();
    assert!(
        !env_obj.contains_key("OPENAI_API_KEY"),
        "OPENAI_API_KEY leaked into sidecar env!"
    );
    assert!(
        !env_obj.contains_key("GITHUB_TOKEN"),
        "GITHUB_TOKEN leaked into sidecar env!"
    );
    assert!(
        !env_obj.contains_key("KLENS_PROJECT_ROOT"),
        "KLENS_PROJECT_ROOT must NOT be passed to language-parser sidecar!"
    );
    assert_eq!(
        env_obj.get("KLENS_READ_ONLY").and_then(Value::as_str),
        Some("1")
    );
    assert_eq!(
        env_obj
            .get("KLENS_PROTOCOL_VERSION")
            .and_then(Value::as_str),
        Some("1")
    );
    assert_eq!(
        env_obj.get("KLENS_EXTENSION_ID").and_then(Value::as_str),
        Some("ext-lang-envcheck")
    );

    let sidecar_cwd = PathBuf::from(dump["cwd"].as_str().unwrap());
    let proj_canon = fs::canonicalize(&sb.root).unwrap();
    let cwd_canon = fs::canonicalize(&sidecar_cwd).unwrap_or(sidecar_cwd);
    assert_ne!(
        cwd_canon, proj_canon,
        "sidecar cwd must be isolated temp_dir, never project_root"
    );
}

fn t8_parse_cache_key_hit_crlf_miss_version_and_disable() {
    let sb = Sandbox::new("t8");
    let lf_src = "class CacheDemo {\n    fun calc(): Int {\n        return 1\n    }\n}\n";
    sb.write("CacheDemo.kt", lf_src);
    let counter_file = sb.home.join("cache_calls.txt");
    sb.install_mock_manifest(
        "ext-lang-kotlin",
        "0.1.0",
        &["kt"],
        "normal",
        Some(&counter_file),
        3000,
        4_194_304,
    );
    sb.enable_ext("ext-lang-kotlin");

    let read_calls = || -> u64 {
        fs::read_to_string(&counter_file)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };

    // First sync: cache MISS -> call count == 1.
    {
        let mut idx = sb.open_index(false);
        let stats = idx.sync_workspace().unwrap();
        assert_eq!(stats.parsed, 1);
        assert_eq!(read_calls(), 1);
    }

    // (a) Second sync without changes: cache HIT -> lazy sidecar NOT spawned, count stays 1!
    {
        let mut idx = sb.open_index(false);
        let stats = idx.sync_workspace().unwrap();
        assert_eq!(stats.unchanged, 1);
        assert_eq!(stats.parsed, 0);
        assert_eq!(read_calls(), 1);
    }

    // (b) CRLF-only line ending change: cache HIT -> count stays 1!
    sb.write("CacheDemo.kt", &lf_src.replace('\n', "\r\n"));
    {
        let mut idx = sb.open_index(false);
        let stats = idx.sync_workspace().unwrap();
        assert_eq!(stats.unchanged, 1);
        assert_eq!(read_calls(), 1);
    }

    // (c) Real content change: cache MISS -> count becomes 2!
    sb.write(
        "CacheDemo.kt",
        "class CacheDemo {\n    fun calc(): Int {\n        return 2\n    }\n}\n",
    );
    {
        let mut idx = sb.open_index(false);
        let stats = idx.sync_workspace().unwrap();
        assert_eq!(stats.parsed, 1);
        assert_eq!(read_calls(), 2);
    }

    // (d) Manifest version bump 0.1.0 -> 0.2.0: cache MISS -> count becomes 3!
    sb.install_mock_manifest(
        "ext-lang-kotlin",
        "0.2.0",
        &["kt"],
        "normal",
        Some(&counter_file),
        3000,
        4_194_304,
    );
    {
        let mut idx = sb.open_index(false);
        let stats = idx.sync_workspace().unwrap();
        assert_eq!(stats.parsed, 1);
        assert_eq!(read_calls(), 3);
        let rec = idx
            .store()
            .get_file(&RelPath::normalize("CacheDemo.kt").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(rec.parser_version, "0.2.0");
    }

    // (e) Disable extension -> automatic invalidation, symbols wiped, UNPARSED_FALLBACK!
    let pr = sb.project_root();
    set_extension_enabled(
        "ext-lang-kotlin",
        false,
        ExtensionScope::Global,
        &sb.global_cfg_path(),
        Some(&pr),
    )
    .unwrap();
    {
        let mut idx = sb.open_index(false);
        let stats = idx.sync_workspace().unwrap();
        assert_eq!(stats.parsed, 1);
        let rel = RelPath::normalize("CacheDemo.kt").unwrap();
        let rec = idx.store().get_file(&rel).unwrap().unwrap();
        assert_eq!(rec.parse_status, ParseStatus::Fallback);
        assert_eq!(rec.parser_id, "none");
        assert!(idx.store().get_symbols_for_file(&rel).unwrap().is_empty());
    }
}

fn t9_index_db_v1_to_v2_atomic_migration() {
    let sb = Sandbox::new("t9");
    sb.write("src/lib.rs", "pub fn hello() -> usize { 1 }\n");

    let db_path = sb.root.join(".klens").join("cache").join("index.db");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();

    // Seed a legacy SQLite v1 index schema (9-column `files`, no `parse_cache_key`/`start_byte`).
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta (key, value) VALUES ('schema_version', '1');
             INSERT INTO meta (key, value) VALUES ('project_id', 'legacy');
             CREATE TABLE files (
                 path TEXT PRIMARY KEY,
                 mtime_secs INTEGER NOT NULL,
                 mtime_nanos INTEGER NOT NULL,
                 size_bytes INTEGER NOT NULL,
                 blake3 TEXT NOT NULL,
                 language_id TEXT,
                 line_count INTEGER NOT NULL,
                 parse_status TEXT NOT NULL,
                 parse_warning TEXT
             );
             INSERT INTO files VALUES ('src/lib.rs', 0, 0, 10, 'deadbeef', 'rust', 1, 'parsed', NULL);
             CREATE TABLE symbols (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 file_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                 name TEXT NOT NULL,
                 qualified_name TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 signature TEXT NOT NULL,
                 start_line INTEGER NOT NULL,
                 end_line INTEGER NOT NULL,
                 parent TEXT,
                 ordinal INTEGER NOT NULL
             );
             CREATE TABLE edges (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 file_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                 from_node TEXT NOT NULL,
                 to_node TEXT NOT NULL,
                 relation TEXT NOT NULL,
                 confidence TEXT NOT NULL,
                 evidence TEXT NOT NULL
             );
             CREATE VIRTUAL TABLE files_fts USING fts5(path, symbols_text, content);",
        )
        .unwrap();
    }

    // Open with v2 IndexStore -> migrates cleanly with zero errors.
    let store = IndexStore::open(&db_path, "proj-v2").unwrap();
    assert!(store.list_files().unwrap().is_empty());
    drop(store);

    // Verify `schema_version = 2` and new columns exist.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let ver: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ver, INDEX_DB_SCHEMA_VERSION.to_string());
    }

    // `CodeIndex::sync_workspace` cleanly re-indexes the workspace!
    let mut idx = sb.open_index(false);
    let stats = idx.sync_workspace().unwrap();
    assert_eq!(stats.parsed, 1);
    let rel = RelPath::normalize("src/lib.rs").unwrap();
    let rec = idx.store().get_file(&rel).unwrap().unwrap();
    assert_eq!(rec.parse_status, ParseStatus::Parsed);
    assert_eq!(rec.parser_id, "builtin:rust");
}

fn t10_builtin_ast_precedence_no_core_hijack_and_doctor_warning() {
    let sb = Sandbox::new("t10");
    sb.write("src/lib.rs", "pub fn core_rust() -> i32 { 42 }\n");
    sb.write(
        "src/App.java",
        "public class App {\n    public void run() {}\n}\n",
    );
    sb.write(
        "src/service.cpp",
        "namespace App {\nint run() { return 1; }\n}\n",
    );
    sb.write("src/Helper.kt", "class Helper {\n    fun run() {}\n}\n");

    // Malicious/overbroad manifest claiming built-in `rs`, `java`, and `cpp` alongside `kt`.
    sb.install_mock_manifest(
        "ext-lang-hijack",
        "0.1.0",
        &["rs", "java", "cpp", "kt"],
        "normal",
        None,
        3000,
        4_194_304,
    );
    sb.enable_ext("ext-lang-hijack");

    let mut idx = sb.open_index(false);
    idx.sync_workspace().unwrap();

    let rs_rel = RelPath::normalize("src/lib.rs").unwrap();
    let java_rel = RelPath::normalize("src/App.java").unwrap();
    let cpp_rel = RelPath::normalize("src/service.cpp").unwrap();
    let kt_rel = RelPath::normalize("src/Helper.kt").unwrap();

    let rs_rec = idx.store().get_file(&rs_rel).unwrap().unwrap();
    assert_eq!(rs_rec.parse_status, ParseStatus::Parsed);
    assert_eq!(rs_rec.parser_id, "builtin:rust");

    let java_rec = idx.store().get_file(&java_rel).unwrap().unwrap();
    assert_eq!(java_rec.parse_status, ParseStatus::Parsed);
    assert_eq!(java_rec.parser_id, "builtin:java");

    let cpp_rec = idx.store().get_file(&cpp_rel).unwrap().unwrap();
    assert_eq!(cpp_rec.parse_status, ParseStatus::Parsed);
    assert_eq!(cpp_rec.parser_id, "builtin:cpp");

    let kt_rec = idx.store().get_file(&kt_rel).unwrap().unwrap();
    assert_eq!(kt_rec.parse_status, ParseStatus::ExternalParsed);
    assert_eq!(kt_rec.parser_id, "ext-lang-hijack");

    // Individual outlines keep honest separation.
    assert_eq!(
        outline_file(&mut idx, &rs_rel, None).unwrap().trust,
        TrustLevel::VerifiedAst
    );
    assert_eq!(
        outline_file(&mut idx, &java_rel, None).unwrap().trust,
        TrustLevel::VerifiedAst
    );
    assert_eq!(
        outline_file(&mut idx, &cpp_rel, None).unwrap().trust,
        TrustLevel::VerifiedAst
    );
    assert_eq!(
        outline_file(&mut idx, &kt_rel, None).unwrap().trust,
        TrustLevel::ExternalParser
    );

    // Mixed directory outline MUST downgrade to EXTERNAL_PARSER with warning!
    let dir_outline = outline_path(&mut idx, None, None).unwrap();
    assert_eq!(dir_outline.trust, TrustLevel::ExternalParser);
    assert!(
        dir_outline
            .warnings
            .iter()
            .any(|w| w.contains("trust downgraded from VERIFIED_AST to EXTERNAL_PARSER")),
        "expected downgrade warning in mixed directory outline: {:?}",
        dir_outline.warnings
    );

    // `klens doctor` MUST emit a Warning for shadowed built-in extensions `cpp`, `java`, `rs`!
    let pr = sb.project_root();
    let checks = inspect_language_extensions_doctor(&sb.global_cfg_path(), &pr);
    assert!(
        checks.iter().any(|c| {
            c.severity == CheckSeverity::Warning
                && c.message.contains("built-in extension(s)")
                && c.message.contains("cpp")
                && c.message.contains("java")
                && c.message.contains("rs")
        }),
        "expected shadowed built-in extension warning in doctor checks: {checks:?}"
    );
}

fn t11_ctags_unavailable_and_mock_universal_json_cleanup() {
    // (a) Unavailable ctags -> honest UNPARSED_FALLBACK + doctor Warning + UI health=unavailable.
    {
        let sb = Sandbox::new("t11a");
        sb.write("Service.kt", "class Service {}\n");
        // Override command to a guaranteed-missing binary name (no PATH race!).
        sb.write_global(
            &format!("extensions/{CTAGS_EXTENSION_ID}/{EXTENSION_MANIFEST_FILE}"),
            &format!(
                "id = \"{CTAGS_EXTENSION_ID}\"\n\
                 kind = \"language-parser\"\n\
                 version = \"0.1.0\"\n\
                 protocol_version = 1\n\
                 extensions = [\"kt\"]\n\
                 command = \"nonexistent-universal-ctags-binary-klens-test\"\n\
                 requires_network = false\n\
                 supports_read_only = true\n"
            ),
        );
        sb.enable_ext(CTAGS_EXTENSION_ID);

        let mut idx = sb.open_index(false);
        let rel = RelPath::normalize("Service.kt").unwrap();
        let env = outline_file(&mut idx, &rel, None).unwrap();
        assert_eq!(env.trust, TrustLevel::UnparsedFallback);
        assert_eq!(env.data.files[0].parse_status, ParseStatus::Fallback);
        assert!(
            env.warnings.iter().any(|w| w.contains("Universal Ctags")),
            "expected Universal Ctags fallback warning: {:?}",
            env.warnings
        );

        let pr = sb.project_root();
        let doctor = inspect_language_extensions_doctor(&sb.global_cfg_path(), &pr);
        assert!(
            doctor.iter().any(
                |c| c.severity == CheckSeverity::Warning && c.name.contains(CTAGS_EXTENSION_ID)
            ),
            "expected doctor Warning for unavailable ctags: {doctor:?}"
        );

        let mut report = list_extensions(&sb.global_cfg_path(), Some(&pr)).unwrap();
        enrich_extension_list_health(&mut report, &sb.global_cfg_path(), Some(&pr));
        let entry = report
            .extensions
            .iter()
            .find(|e| e.id == CTAGS_EXTENSION_ID)
            .unwrap();
        assert_eq!(entry.health, Some(ExtensionHealthStatus::Unavailable));
    }

    // (b) Mock Universal Ctags binary -> SymbolInfo + ExternalParser + 0 leftover temp dirs!
    {
        let sb = Sandbox::new("t11b");
        sb.write(
            "Billing.kt",
            "class Billing {\n    fun charge(): Int {\n        return 99\n    }\n}\n",
        );

        // Create a mock `ctags` executable by copying current test binary to `<home>/bin/ctags(.exe)`.
        let mock_bin_dir = sb.home.join("bin");
        fs::create_dir_all(&mock_bin_dir).unwrap();
        let mock_ctags_name = if cfg!(windows) { "ctags.exe" } else { "ctags" };
        let mock_ctags_path = mock_bin_dir.join(mock_ctags_name);
        let cur_exe = std::env::current_exe().unwrap();
        if fs::hard_link(&cur_exe, &mock_ctags_path).is_err() {
            fs::copy(&cur_exe, &mock_ctags_path).unwrap();
        }
        let escaped_ctags = mock_ctags_path.to_string_lossy().replace('\\', "\\\\");

        sb.write_global(
            &format!("extensions/{CTAGS_EXTENSION_ID}/{EXTENSION_MANIFEST_FILE}"),
            &format!(
                "id = \"{CTAGS_EXTENSION_ID}\"\n\
                 kind = \"language-parser\"\n\
                 version = \"0.1.0\"\n\
                 protocol_version = 1\n\
                 extensions = [\"kt\"]\n\
                 command = \"{escaped_ctags}\"\n\
                 requires_network = false\n\
                 supports_read_only = true\n"
            ),
        );
        sb.enable_ext(CTAGS_EXTENSION_ID);

        let mut idx = sb.open_index(false);
        let rel = RelPath::normalize("Billing.kt").unwrap();
        let env = outline_file(&mut idx, &rel, None).unwrap();
        assert_eq!(env.trust, TrustLevel::ExternalParser);
        assert_eq!(env.data.files[0].parse_status, ParseStatus::ExternalParsed);
        assert_eq!(
            env.data.files[0].parser_id.as_deref(),
            Some(CTAGS_EXTENSION_ID)
        );
        assert_eq!(env.data.files[0].symbols.len(), 2);
        assert_eq!(env.data.files[0].symbols[0].name, "Billing");
        assert_eq!(env.data.files[0].symbols[0].kind, SymbolKind::Class);
        assert_eq!(env.data.files[0].symbols[1].name, "charge");
        assert_eq!(env.data.files[0].symbols[1].kind, SymbolKind::Method);
        assert_eq!(
            env.data.files[0].symbols[1].parent.as_deref(),
            Some("class Billing")
        );

        let rec = idx.store().get_file(&rel).unwrap().unwrap();
        assert!(rec.parser_version.contains("+ctags-6.1.0"));

        // Verify zero leftover `klens-ctags-<pid>-*` temp dirs remain!
        let prefix = format!("klens-ctags-{}-", std::process::id());
        let leftovers: Vec<_> = fs::read_dir(std::env::temp_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .collect();
        assert!(
            leftovers.is_empty(),
            "RAII temp dir cleanup failed; leftovers: {leftovers:?}"
        );

        let pr = sb.project_root();
        let doctor = inspect_language_extensions_doctor(&sb.global_cfg_path(), &pr);
        assert!(
            doctor
                .iter()
                .any(|c| c.severity == CheckSeverity::Ok
                    && c.message.contains("Universal Ctags 6.1.0")),
            "expected Ok doctor check for mock Universal Ctags: {doctor:?}"
        );

        let mut report = list_extensions(&sb.global_cfg_path(), Some(&pr)).unwrap();
        enrich_extension_list_health(&mut report, &sb.global_cfg_path(), Some(&pr));
        let entry = report
            .extensions
            .iter()
            .find(|e| e.id == CTAGS_EXTENSION_ID)
            .unwrap();
        assert_eq!(entry.health, Some(ExtensionHealthStatus::Ready));
    }
}

fn t12_constitution_dep_budget_mcp_tools_and_repo_health() {
    let ws = find_workspace_root();

    // 1. Cargo.lock package count <= 105 (budget with 10 built-in Tree-sitter languages).
    let lock_text = fs::read_to_string(ws.join("Cargo.lock")).unwrap();
    let pkg_count = lock_text
        .lines()
        .filter(|l| l.trim() == "[[package]]")
        .count();
    assert!(
        pkg_count <= 105,
        "Cargo.lock package budget exceeded: {pkg_count} > 105"
    );

    // 2. MCP tool surface remains fixed at 9 core tools (< 1200 tokens).
    let tools = tool_definitions();
    assert_eq!(tools.len(), 9, "core MCP tool count must stay fixed at 9");
    let tools_json = serde_json::to_string(&tools).unwrap();
    let est_tokens = klens_core::estimate_tokens(&tools_json);
    assert!(
        est_tokens <= 1200,
        "MCP tool schema token budget exceeded: {est_tokens} > 1200"
    );

    // 3. `klens health --read-only --json` on workspace: 0 circular deps & 0 production files > 800 lines.
    let sb = Sandbox::new("t12-home");
    let klens_bin = env!("CARGO_BIN_EXE_klens");
    let mut cmd = Command::new(klens_bin);
    cmd.args([
        "health",
        "--root",
        ws.to_str().unwrap(),
        "--read-only",
        "--json",
    ])
    .env("USERPROFILE", &sb.home)
    .env("HOME", &sb.home)
    .stdin(Stdio::null());
    configure_no_window_test(&mut cmd);
    let out = cmd.output().expect("run klens health --read-only");
    assert!(
        out.status.success(),
        "klens health stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let health: Value = serde_json::from_slice(&out.stdout).unwrap();
    let checks = health["data"]["checks"].as_array().unwrap();
    let cycles_check = checks
        .iter()
        .find(|c| c["id"] == "cycles")
        .expect("missing cycles check");
    assert_eq!(
        cycles_check["light"], "GREEN",
        "cycles check not GREEN: {cycles_check}"
    );

    let god_check = checks
        .iter()
        .find(|c| c["id"] == "god_nodes")
        .expect("missing god_nodes check");
    assert_ne!(
        god_check["light"], "RED",
        "production god node (>800 lines) detected: {god_check}"
    );
}

/// T13: a cloned (untrusted) repository ships its own `.klens/extensions/` manifests and a
/// project `.klens/config.toml` that "enables" them. Indexing, outlining, `klens doctor`
/// probes, and the Web UI extension list MUST NOT spawn any of those processes.
fn t13_untrusted_project_cannot_enable_or_spawn_language_sidecars() {
    let sb = Sandbox::new("t13");
    sb.write("Evil.kt", "class Evil {}\n");
    sb.write("evil.zig", "const x = 1;\n");

    // Hostile custom JSON-RPC sidecar shipped inside the repository.
    let rpc_marker = sb.home.join("rpc_spawned.marker");
    sb.write(
        &format!(".klens/extensions/ext-lang-kotlin/{EXTENSION_MANIFEST_FILE}"),
        &mock_manifest_toml(
            "ext-lang-kotlin",
            "0.1.0",
            &["kt"],
            "spawn_marker",
            Some(&rpc_marker),
            3000,
            4_194_304,
        ),
    );

    // Hostile `ext-lang-ctags` override pointing at an attacker-chosen executable.
    let evil_bin = sb.root.parent().unwrap().join("evil_bin");
    fs::create_dir_all(&evil_bin).unwrap();
    let evil_ctags = evil_bin.join(if cfg!(windows) { "ctags.exe" } else { "ctags" });
    let cur_exe = std::env::current_exe().unwrap();
    if fs::hard_link(&cur_exe, &evil_ctags).is_err() {
        fs::copy(&cur_exe, &evil_ctags).unwrap();
    }
    let ctags_marker = evil_bin.join("ctags_spawned.marker");
    let escaped_ctags = evil_ctags.to_string_lossy().replace('\\', "\\\\");
    sb.write(
        &format!(".klens/extensions/{CTAGS_EXTENSION_ID}/{EXTENSION_MANIFEST_FILE}"),
        &format!(
            "id = \"{CTAGS_EXTENSION_ID}\"\n\
             kind = \"language-parser\"\n\
             version = \"0.1.0\"\n\
             protocol_version = 1\n\
             extensions = [\"zig\"]\n\
             command = \"{escaped_ctags}\"\n\
             requires_network = false\n\
             supports_read_only = true\n"
        ),
    );

    // The repository "enables" both itself.
    sb.write(
        ".klens/config.toml",
        &format!("enabled_extensions = [\"ext-lang-kotlin\", \"{CTAGS_EXTENSION_ID}\"]\n"),
    );

    let assert_nothing_spawned = |stage: &str| {
        assert!(
            !rpc_marker.exists(),
            "[{stage}] untrusted project sidecar was spawned"
        );
        assert!(
            !ctags_marker.exists(),
            "[{stage}] untrusted project ctags override was spawned"
        );
    };

    // 1. Index sync + outline (what `klens_map` / `klens_outline` trigger).
    {
        let mut idx = sb.open_index(false);
        idx.sync_workspace().unwrap();
        let rel = RelPath::normalize("Evil.kt").unwrap();
        let env = outline_file(&mut idx, &rel, None).unwrap();
        assert_eq!(env.data.files[0].parse_status, ParseStatus::Fallback);
    }
    assert_nothing_spawned("index");

    // 2. `klens doctor` and Web UI `GET /api/extensions` health probes.
    let pr = sb.project_root();
    let doctor = inspect_language_extensions_doctor(&sb.global_cfg_path(), &pr);
    let mut report = list_extensions(&sb.global_cfg_path(), Some(&pr)).unwrap();
    enrich_extension_list_health(&mut report, &sb.global_cfg_path(), Some(&pr));
    assert_nothing_spawned("doctor/list");

    // Honest reporting (Constitution Art. 2): ignored items are surfaced, never hidden.
    assert!(
        doctor.iter().any(|c| c.severity == CheckSeverity::Warning
            && c.message.contains("ignored")
            && c.message.contains("ext-lang-kotlin")),
        "expected doctor warning about ignored project-local extensions: {doctor:?}"
    );
    for id in ["ext-lang-kotlin", CTAGS_EXTENSION_ID] {
        if let Some(entry) = report.extensions.iter().find(|e| e.id == id) {
            assert!(
                !entry.effective_enabled,
                "{id} must not be effectively enabled by project config"
            );
        }
    }

    // 3. Project scope can no longer enable a process-spawning language parser.
    assert!(
        set_extension_enabled(
            CTAGS_EXTENSION_ID,
            true,
            ExtensionScope::Project,
            &sb.global_cfg_path(),
            Some(&pr),
        )
        .is_err(),
        "project-scoped enable of a language parser must fail closed"
    );

    // 4. Real CLI binary path (`klens outline`, `klens doctor`) with sandboxed HOME.
    let klens_bin = env!("CARGO_BIN_EXE_klens");
    for args in [
        vec!["outline", "Evil.kt", "--root", sb.root.to_str().unwrap()],
        vec!["doctor", "--project", sb.root.to_str().unwrap()],
    ] {
        let mut cmd = Command::new(klens_bin);
        cmd.args(&args)
            .env("USERPROFILE", &sb.home)
            .env("HOME", &sb.home);
        configure_no_window_test(&mut cmd);
        let _ = cmd.output().expect("run klens CLI");
    }
    assert_nothing_spawned("cli");

    // 5. Positive control: the SAME sidecar installed + enabled globally by the user DOES run,
    //    proving the markers above would have detected a spawn.
    sb.install_mock_manifest(
        "ext-lang-kotlin",
        "0.1.0",
        &["kt"],
        "spawn_marker",
        Some(&rpc_marker),
        3000,
        4_194_304,
    );
    sb.enable_ext("ext-lang-kotlin");
    {
        let mut idx = sb.open_index(false);
        let rel = RelPath::normalize("Evil.kt").unwrap();
        let _ = outline_file(&mut idx, &rel, None).unwrap();
    }
    assert!(
        rpc_marker.exists(),
        "positive control failed: globally trusted sidecar should have been spawned"
    );
}
