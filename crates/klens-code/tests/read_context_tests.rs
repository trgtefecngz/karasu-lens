//! Integration tests for `klens_read` context bundle (`imports`, `impact`, determinism,
//! truncation omissions, and byte-for-byte backward compatibility when `include` is omitted).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_code::{
    CodeIndex, LineRange, MAX_CONTEXT_IMPACT_HITS, MAX_CONTEXT_IMPORT_LINES,
    MAX_CONTEXT_MEMORY_SNIPPET_CHARS, ReadInclude, ReadStatus, ReadTarget,
    attach_code_context_to_batch, attach_code_context_to_read, extract_imports_from_source,
    format_batch_read_text, format_read_text, read_batch, read_lines, read_symbol,
    sanitize_memory_snippet,
};
use klens_core::{OmissionKind, ProjectRoot, RelPath};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-read-ctx-{label}-{}-{n}", std::process::id()));
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

#[test]
fn read_context_bundle_is_byte_deterministic_and_preserves_legacy_output_without_include() {
    let proj = Sandbox::new("determinism");
    let cache = Sandbox::new("determinism-cache");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"ctx_demo\"\nversion = \"0.1.0\"\n",
    );
    proj.write(
        "src/core.rs",
        concat!(
            "use std::collections::{\n",
            "    BTreeMap,\n",
            "    BTreeSet,\n",
            "};\n",
            "use std::fmt;\n",
            "\n",
            "pub fn compute_hash(input: &str) -> usize {\n",
            "    let _m: BTreeMap<usize, usize> = BTreeMap::new();\n",
            "    let _s: BTreeSet<usize> = BTreeSet::new();\n",
            "    let _ = fmt::Error;\n",
            "    input.len()\n",
            "}\n",
        ),
    );
    proj.write(
        "src/caller_a.rs",
        "use crate::core::compute_hash;\npub fn run_a() -> usize { compute_hash(\"a\") }\n",
    );
    proj.write(
        "src/caller_b.rs",
        "use crate::core::compute_hash;\npub fn run_b() -> usize { compute_hash(\"b\") }\n",
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let rel = RelPath::normalize("src/core.rs").unwrap();

    // Baseline without `include` must have `context: None` and omit `"context"` in JSON.
    let baseline = read_symbol(&mut index, &rel, "compute_hash").unwrap();
    assert!(baseline.data.context.is_none());
    let baseline_json = baseline.to_deterministic_json().unwrap();
    assert!(!baseline_json.contains("\"context\""));
    let baseline_text = format_read_text(&baseline);
    assert!(!baseline_text.contains("## Context:"));

    // Calling with empty includes slice must be byte-for-byte identical.
    let mut with_empty = read_symbol(&mut index, &rel, "compute_hash").unwrap();
    attach_code_context_to_read(&mut index, &mut with_empty, &[]).unwrap();
    assert_eq!(with_empty.to_deterministic_json().unwrap(), baseline_json);
    assert_eq!(format_read_text(&with_empty), baseline_text);

    // Two consecutive context-enriched calls must be byte-for-byte identical in both JSON and text.
    let includes = [ReadInclude::Imports, ReadInclude::Impact];
    let mut first = read_symbol(&mut index, &rel, "compute_hash").unwrap();
    attach_code_context_to_read(&mut index, &mut first, &includes).unwrap();
    let mut second = read_symbol(&mut index, &rel, "compute_hash").unwrap();
    attach_code_context_to_read(&mut index, &mut second, &includes).unwrap();

    assert_eq!(
        first.to_deterministic_json().unwrap().as_bytes(),
        second.to_deterministic_json().unwrap().as_bytes()
    );
    assert_eq!(format_read_text(&first), format_read_text(&second));

    let ctx = first
        .data
        .context
        .as_ref()
        .expect("context must be present");
    let imports = ctx
        .imports
        .as_ref()
        .expect("imports context must be present");
    assert_eq!(imports.total_import_lines, 5);
    assert!(!imports.truncated);
    assert!(imports.lines[0].contains("use std::collections::{"));

    let impact = ctx.impact.as_ref().expect("impact context must be present");
    assert_eq!(impact.target, "src/core.rs#fn compute_hash");
    assert!(impact.total_hits >= 2);
    assert!(!impact.truncated);

    let text = format_read_text(&first);
    assert!(text.contains("## Context: Imports"));
    assert!(text.contains("## Context: Impact"));
    assert!(!proj.path().join(".klens").exists());
}

#[test]
fn read_context_truncates_imports_over_40_and_impact_over_10_with_explicit_omissions() {
    let proj = Sandbox::new("limits");
    let cache = Sandbox::new("limits-cache");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"limit_demo\"\nversion = \"0.1.0\"\n",
    );

    let mut lib_src = String::new();
    let synthetic_secret = format!("AIzaSy{}", "1234567890abcdefghijklmnopqrstuvw");
    lib_src.push_str(&format!("use std::io; // leak={synthetic_secret}\n"));
    for i in 1..44 {
        lib_src.push_str(&format!("use std::fmt as fmt_{i};\n"));
    }
    lib_src.push_str("pub fn shared_target() -> usize { 42 }\n");
    proj.write("src/lib.rs", &lib_src);

    // Create 13 distinct callers so impact hits exceed MAX_CONTEXT_IMPACT_HITS (10).
    for i in 0..13 {
        proj.write(
            &format!("src/caller_{i:02}.rs"),
            &format!(
                "use crate::shared_target;\npub fn call_{i:02}() -> usize {{ shared_target() }}\n"
            ),
        );
    }

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let rel = RelPath::normalize("src/lib.rs").unwrap();

    let mut env = read_lines(&index, &rel, LineRange::new(45, 45).unwrap()).unwrap();
    attach_code_context_to_read(
        &mut index,
        &mut env,
        &[ReadInclude::Imports, ReadInclude::Impact],
    )
    .unwrap();

    let ctx = env.data.context.as_ref().unwrap();
    let imports = ctx.imports.as_ref().unwrap();
    assert_eq!(imports.total_import_lines, 44);
    assert_eq!(imports.lines.len(), MAX_CONTEXT_IMPORT_LINES);
    assert!(imports.truncated);
    assert!(env.redactions_count >= 1);
    assert!(!imports.lines[0].contains(&synthetic_secret));

    let impact = ctx.impact.as_ref().unwrap();
    assert!(impact.total_hits >= 13);
    assert_eq!(impact.hits.len(), MAX_CONTEXT_IMPACT_HITS);
    assert!(impact.truncated);

    assert!(
        env.omissions.iter().any(|o| o.kind == OmissionKind::Lines
            && o.reason == "read_context_imports_limit"
            && o.count == 4),
        "expected explicit imports omission, got {:?}",
        env.omissions
    );
    assert!(
        env.omissions.iter().any(|o| o.kind == OmissionKind::Items
            && o.reason == "read_context_impact_limit"
            && o.count >= 3),
        "expected explicit impact omission, got {:?}",
        env.omissions
    );

    // Batch mode attaches context only to `Ok` items and skips `NotFound` items.
    let targets = [
        ReadTarget::symbol("src/lib.rs", "shared_target"),
        ReadTarget::symbol("src/lib.rs", "nonexistent_fn"),
    ];
    let mut batch = read_batch(&mut index, &targets).unwrap();
    attach_code_context_to_batch(&mut index, &mut batch, &[ReadInclude::Imports]).unwrap();
    assert_eq!(batch.data.targets[0].result.status, ReadStatus::Ok);
    assert!(batch.data.targets[0].result.context.is_some());
    assert_eq!(batch.data.targets[1].result.status, ReadStatus::NotFound);
    assert!(batch.data.targets[1].result.context.is_none());
    let batch_text = format_batch_read_text(&batch);
    assert!(batch_text.contains("## Context: Imports (40/44, truncated)"));
}

#[test]
fn parse_read_include_is_fail_closed() {
    assert_eq!(ReadInclude::parse("imports").unwrap(), ReadInclude::Imports);
    assert_eq!(ReadInclude::parse(" MEMORY ").unwrap(), ReadInclude::Memory);
    assert_eq!(ReadInclude::parse("Impact").unwrap(), ReadInclude::Impact);
    assert!(ReadInclude::parse("bogus").is_err());
    assert!(ReadInclude::parse("").is_err());
}

#[test]
fn extract_imports_supports_rust_ts_python_go_and_other() {
    let rust_src = concat!(
        "//! module doc\n",
        "#![forbid(unsafe_code)]\n",
        "use std::fs;\n",
        "pub use crate::alpha::{\n",
        "    One,\n",
        "    Two,\n",
        "};\n",
        "pub(crate) use std::path::Path;\n",
        "extern crate alloc;\n",
        "pub fn work() {\n",
        "    use std::io::Write;\n",
        "}\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    use super::*;\n",
        "}\n",
    );
    let rust_res = extract_imports_from_source("src/lib.rs", rust_src);
    assert_eq!(rust_res.context.total_import_lines, 7);
    assert!(!rust_res.context.truncated);
    assert!(rust_res.omission.is_none());
    assert!(rust_res.context.lines[0].contains("L3| use std::fs;"));
    assert!(rust_res.context.lines[1].contains("L4| pub use crate::alpha::{"));
    assert!(rust_res.context.lines[4].contains("L7| };"));
    assert!(rust_res.context.lines[6].contains("L9| extern crate alloc;"));
    assert!(
        !rust_res
            .context
            .lines
            .iter()
            .any(|l| l.contains("Write") || l.contains("super::*"))
    );

    let ts_src = concat!(
        "\"use client\";\n",
        "import React from 'react';\n",
        "import {\n",
        "  alpha,\n",
        "  beta,\n",
        "} from './mod';\n",
        "export { gamma } from './gamma';\n",
        "const fs = require('node:fs');\n",
        "export function App() { return null; }\n",
    );
    let ts_res = extract_imports_from_source("web/app.tsx", ts_src);
    assert_eq!(ts_res.context.total_import_lines, 7);
    assert!(ts_res.context.lines[0].contains("L2| import React from 'react';"));
    assert!(ts_res.context.lines[5].contains("L7| export { gamma } from './gamma';"));
    assert!(ts_res.context.lines[6].contains("L8| const fs = require('node:fs');"));

    let py_src = concat!(
        "\"\"\"\n",
        "Example: import fake_in_docstring\n",
        "\"\"\"\n",
        "import os\n",
        "from pkg.sub import (\n",
        "    alpha,\n",
        "    beta,\n",
        ")\n",
        "def main():\n",
        "    import inside_fn\n",
    );
    let py_res = extract_imports_from_source("app/main.py", py_src);
    assert_eq!(py_res.context.total_import_lines, 5);
    assert!(py_res.context.lines[0].contains("L4| import os"));
    assert!(py_res.context.lines[4].contains("L8| )"));
    assert!(
        !py_res
            .context
            .lines
            .iter()
            .any(|l| l.contains("fake_in_docstring") || l.contains("inside_fn"))
    );

    let go_src = concat!(
        "package main\n",
        "import \"fmt\"\n",
        "import (\n",
        "\t\"os\"\n",
        "\t\"strings\"\n",
        ")\n",
        "func main() {}\n",
    );
    let go_res = extract_imports_from_source("cmd/main.go", go_src);
    assert_eq!(go_res.context.total_import_lines, 5);
    assert!(go_res.context.lines[0].contains("L2| import \"fmt\""));
    assert!(go_res.context.lines[4].contains("L6| )"));

    let cpp_src = "#include <vector>\nusing namespace std;\nint main() { return 0; }\n";
    let cpp_res = extract_imports_from_source("src/main.cpp", cpp_src);
    assert_eq!(cpp_res.context.total_import_lines, 2);
}

#[test]
fn sanitize_memory_snippet_is_utf8_safe_and_redacts_secrets_before_truncation() {
    let fake_token = format!("sk-proj-{}", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789");
    let long_turkish = format!(
        "{} {} {}",
        "ğüşiöç ".repeat(38),
        fake_token,
        "devam ".repeat(20)
    );
    let (snippet, redactions) = sanitize_memory_snippet(&long_turkish);
    assert!(redactions >= 1);
    assert!(!snippet.contains(&fake_token));
    assert!(snippet.chars().count() <= MAX_CONTEXT_MEMORY_SNIPPET_CHARS);
    assert!(snippet.ends_with('…'));
}
