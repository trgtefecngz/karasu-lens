//! Dependency budget lock test (`tests/dep_budget.rs`).
//!
//! Enforces two architectural invariants from `docs/01-ARCHITECTURE.md`:
//! 1. Total crate count in `Cargo.lock` stays within the strict Phase 0 budget.
//! 2. Heavy or out-of-scope crates (async runtimes, heavy web frameworks, HTTP/LLM
//!    clients, OpenSSL/TLS stacks, heavy ML/ORM crates) are strictly forbidden in core.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Maximum allowed total `[[package]]` entries in `Cargo.lock`.
///
/// Phase 0 baseline was 65; raised to 95 for Phase 1A (`ignore`, bundled `rusqlite`,
/// `tree-sitter`, and 4 language grammars); raised deliberately to 105 in `v0.3.1`
/// for the 6 new built-in Tree-sitter language grammars (`c`, `cpp`, `java`, `c-sharp`,
/// `php`, `ruby`).
const MAX_LOCKFILE_PACKAGES: usize = 105;

/// Heavy or out-of-scope crates forbidden in the Karasu Lens core binary.
const FORBIDDEN_CRATES: &[&str] = &[
    // Async runtimes & heavy web/RPC frameworks (core UI uses synchronous `tiny_http`)
    "tokio",
    "async-std",
    "smol",
    "axum",
    "actix-web",
    "rocket",
    "warp",
    "hyper",
    "tonic",
    // Outbound HTTP clients & LLM SDKs (core is offline and zero-network)
    "reqwest",
    "ureq",
    "surf",
    "isahc",
    "async-openai",
    // Heavy TLS / OpenSSL bindings
    "openssl",
    "openssl-sys",
    "rustls",
    "native-tls",
    // Heavy ML / ORM stacks & forbidden date/time crates (core uses `klens_core::time`)
    "chrono",
    "ort",
    "candle-core",
    "tch",
    "burn",
    "diesel",
    "sea-orm",
];

fn find_workspace_lockfile() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for ancestor in manifest_dir.ancestors() {
        let candidate = ancestor.join("Cargo.lock");
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "Cargo.lock not found while walking ancestors of {}",
        manifest_dir.display()
    );
}

fn parse_lockfile_packages(contents: &str) -> Vec<String> {
    let mut packages = Vec::new();
    let mut in_package = false;

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line == "[[package]]" {
            in_package = true;
            continue;
        }
        if line.starts_with('[') {
            in_package = false;
            continue;
        }
        if in_package && let Some(rest) = line.strip_prefix("name = \"") {
            if let Some(name) = rest.strip_suffix('"') {
                packages.push(name.to_string());
            }
            in_package = false;
        }
    }

    packages
}

#[test]
fn cargo_lock_respects_dependency_budget_and_forbids_heavy_crates() {
    let lock_path = find_workspace_lockfile();
    let contents = fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", lock_path.display()));

    let packages = parse_lockfile_packages(&contents);
    assert!(
        !packages.is_empty(),
        "parsed 0 packages from {}; lockfile parser mismatch",
        lock_path.display()
    );

    assert!(
        packages.len() <= MAX_LOCKFILE_PACKAGES,
        "Cargo.lock has {} packages, exceeding Phase 1A budget limit of {MAX_LOCKFILE_PACKAGES}",
        packages.len()
    );

    let forbidden_set: BTreeSet<&str> = FORBIDDEN_CRATES.iter().copied().collect();
    let violations: Vec<&str> = packages
        .iter()
        .map(String::as_str)
        .filter(|name| forbidden_set.contains(name))
        .collect();

    assert!(
        violations.is_empty(),
        "forbidden heavy crate(s) found in Cargo.lock: {violations:?}"
    );
}
