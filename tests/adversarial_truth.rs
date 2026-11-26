//! Adversarial truth & constitutional regression tests for Phase 1A (`tests/adversarial_truth.rs`).
//!
//! Enforces the 6 mandatory test gates of `docs/phases/phase-1a.md` and the
//! Zero-Misleading Constitution (`docs/00-VISION-AND-CONSTITUTION.md`):
//! 1. Tree-sitter ABI lockstep smoke test (all 4 languages + TSX).
//! 2. Same-name symbol collision (`impl A::new` vs `impl B::new`) → `AMBIGUOUS_SYMBOL`, never silent first-match.
//! 3. Huge 15,000+ token file truncation guard → `read(symbol="bottom_fn")` always succeeds from untruncated AST/SQLite.
//! 4. Full 4-language coverage matrix (Rust `function_signature_item` & `macro_rules!`;
//!    TS `export default`, `memo(...)`, `forwardRef(...)`, class arrow property, `.d.ts declare`;
//!    Python `async def` / class / methods / constants; Go receiver method `(w *World) Save` & interface).
//! 5. Batch reading (`targets: [...]`) & broken syntax fail-closed (`UNPARSED_FALLBACK` + explicit warning).
//! 6. Secret redaction, path confinement, and deterministic CLI output (`klens outline`, `klens read`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_code::{
    CodeIndex, LineRange, ReadStatus, ReadTarget, outline_file, read_batch, read_lines,
    read_symbol, verify_tree_sitter_abi,
};
use klens_core::{
    OmissionKind, PathError, ProjectRoot, RelPath, SymbolKind, TrustLevel, estimate_tokens,
};

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-adv-{label}-{}-{seq}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn write(&self, rel: &str, content: &str) {
        let target = self.dir.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(target, content).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Test 1: Tree-sitter ABI Smoke Test
// ---------------------------------------------------------------------------

#[test]
fn gate_1_tree_sitter_abi_lockstep_smoke_test() {
    let infos = verify_tree_sitter_abi().expect("all 10 language grammars must load without panic");
    assert_eq!(infos.len(), 11);
    for info in &infos {
        assert!(
            info.abi_version >= 13,
            "unexpected ABI version {} for {}",
            info.abi_version,
            info.language_id
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: Same-Name Symbol Collision (Constitution Article 3)
// ---------------------------------------------------------------------------

#[test]
fn gate_2_ambiguous_symbol_never_silently_picks_first() {
    let proj = Sandbox::new("ambiguous");
    let cache = Sandbox::new("ambiguous-cache");

    proj.write(
        "src/models.rs",
        concat!(
            "pub struct A {\n",
            "    pub val: i32,\n",
            "}\n",
            "\n",
            "impl A {\n",
            "    pub fn new(val: i32) -> Self {\n",
            "        Self { val }\n",
            "    }\n",
            "}\n",
            "\n",
            "pub struct B {\n",
            "    pub tag: String,\n",
            "}\n",
            "\n",
            "impl B {\n",
            "    pub fn new(tag: String) -> Self {\n",
            "        Self { tag }\n",
            "    }\n",
            "}\n",
        ),
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let rel = RelPath::normalize("src/models.rs").unwrap();

    // Short name `new` MUST return AMBIGUOUS_SYMBOL with BOTH candidates and zero body leakage.
    let amb = read_symbol(&mut index, &rel, "new").unwrap();
    assert_eq!(amb.trust, TrustLevel::VerifiedAst);
    assert_eq!(amb.data.status, ReadStatus::AmbiguousSymbol);
    assert!(amb.data.content.is_none());
    assert_eq!(amb.data.candidates.len(), 2);

    let c0 = &amb.data.candidates[0];
    assert_eq!(c0.qualified_name, "impl A::new");
    assert_eq!(c0.parent.as_deref(), Some("impl A"));
    assert_eq!(c0.start_line, 6);
    assert_eq!(c0.end_line, 8);
    assert!(c0.signature.contains("pub fn new(val: i32) -> Self"));

    let c1 = &amb.data.candidates[1];
    assert_eq!(c1.qualified_name, "impl B::new");
    assert_eq!(c1.parent.as_deref(), Some("impl B"));
    assert_eq!(c1.start_line, 16);
    assert_eq!(c1.end_line, 18);
    assert!(c1.signature.contains("pub fn new(tag: String) -> Self"));

    // Qualified name `impl B::new` MUST return ONLY B's body with compact `L<n>| ` line numbers.
    let exact = read_symbol(&mut index, &rel, "impl B::new").unwrap();
    assert_eq!(exact.trust, TrustLevel::VerifiedAst);
    assert_eq!(exact.data.status, ReadStatus::Ok);
    assert_eq!(exact.data.qualified_name.as_deref(), Some("impl B::new"));
    assert_eq!(exact.data.start_line, Some(16));
    assert_eq!(exact.data.end_line, Some(18));

    let body = exact.data.content.unwrap();
    assert!(body.contains("L16|     pub fn new(tag: String) -> Self {"));
    assert!(body.contains("L17|         Self { tag }"));
    assert!(body.contains("L18|     }"));
    assert!(!body.contains("val: i32"), "must NOT leak impl A::new body");
}

// ---------------------------------------------------------------------------
// Test 3: 15,000+ Token Huge File Truncation Protection (Constitution Article 2)
// ---------------------------------------------------------------------------

#[test]
fn gate_3_huge_file_bottom_symbol_never_hidden_by_outline_truncation() {
    let proj = Sandbox::new("huge");
    let cache = Sandbox::new("huge-cache");

    // Generate > 15,000 tokens of valid Rust code before `bottom_fn`.
    let mut src = String::with_capacity(90_000);
    for i in 0..450 {
        src.push_str(&format!(
            "pub fn filler_function_{i:04}(alpha_param: usize, beta_param: usize) -> usize {{\n\
             \x20   let intermediate_calculation = alpha_param.wrapping_mul({i}).wrapping_add(beta_param);\n\
             \x20   intermediate_calculation ^ 0xDEAD_BEEF\n\
             }}\n\n"
        ));
    }
    let bottom_start_line = src.lines().count() + 1;
    src.push_str(
        "pub fn bottom_fn(needle: &str) -> String {\n    format!(\"found:{needle}\")\n}\n",
    );

    let est_tokens = estimate_tokens(&src);
    assert!(
        est_tokens >= 15_000,
        "test fixture must be >= 15,000 tokens, got {est_tokens}"
    );

    proj.write("src/giant.rs", &src);

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let rel = RelPath::normalize("src/giant.rs").unwrap();

    // Even with a very small outline budget (150 tokens), outline explicitly omits tail symbols.
    let truncated_outline = outline_file(&mut index, &rel, Some(150)).unwrap();
    assert!(
        !truncated_outline.data.files[0]
            .symbols
            .iter()
            .any(|s| s.name == "bottom_fn"),
        "bottom_fn should be omitted from tiny-budget outline"
    );
    assert!(
        truncated_outline
            .omissions
            .iter()
            .any(|o| o.kind == OmissionKind::Symbols && o.count > 400),
        "omissions must explicitly disclose omitted symbols"
    );

    // Surgical `read_symbol("bottom_fn")` MUST query the untruncated SQLite/AST index and succeed!
    let found = read_symbol(&mut index, &rel, "bottom_fn").unwrap();
    assert_eq!(found.trust, TrustLevel::VerifiedAst);
    assert_eq!(found.data.status, ReadStatus::Ok);
    assert_eq!(found.data.qualified_name.as_deref(), Some("fn bottom_fn"));
    assert_eq!(found.data.start_line, Some(bottom_start_line));
    assert_eq!(found.data.end_line, Some(bottom_start_line + 2));

    let content = found.data.content.unwrap();
    assert!(content.contains(&format!(
        "L{bottom_start_line}| pub fn bottom_fn(needle: &str) -> String {{"
    )));
    assert!(content.contains("format!(\"found:{needle}\")"));
}

// ---------------------------------------------------------------------------
// Test 4: 4-Language Coverage Matrix (Exact Line Numbers)
// ---------------------------------------------------------------------------

#[test]
fn gate_4_four_language_coverage_matrix_exact_lines() {
    let proj = Sandbox::new("matrix");
    let cache = Sandbox::new("matrix-cache");

    // 1. Rust: trait function_signature_item, macro_rules!, struct, enum, impl, type, const, static, mod
    proj.write(
        "src/lib.rs",
        concat!(
            "use std::collections::BTreeMap;\n",           // L1
            "\n",                                          // L2
            "pub const MAX_ITEMS: usize = 64;\n",          // L3
            "pub static GLOBAL_TAG: &str = \"klens\";\n",  // L4
            "pub type ItemId = u64;\n",                    // L5
            "\n",                                          // L6
            "pub trait Storage {\n",                       // L7
            "    fn save(&self, id: ItemId) -> bool;\n",   // L8 (function_signature_item!)
            "    fn flush(&self) {}\n",                    // L9
            "}\n",                                         // L10
            "\n",                                          // L11
            "macro_rules! check_ok {\n",                   // L12 (macro_definition!)
            "    ($e:expr) => { assert!($e); };\n",        // L13
            "}\n",                                         // L14
            "\n",                                          // L15
            "pub struct Repo;\n",                          // L16
            "pub enum Mode { Fast, Safe }\n",              // L17
            "impl Storage for Repo {\n",                   // L18
            "    fn save(&self, _id: ItemId) -> bool {\n", // L19
            "        true\n",                              // L20
            "    }\n",                                     // L21
            "}\n",                                         // L22
            "pub mod inner {\n",                           // L23
            "    pub fn nested() {}\n",                    // L24
            "}\n",                                         // L25
        ),
    );

    // 2. TypeScript / TSX: export default, memo(...), forwardRef(...), class arrow property, export const, interface, type, enum
    proj.write(
        "web/App.tsx",
        concat!(
            "import React, { memo, forwardRef } from 'react';\n", // L1
            "\n",                                                 // L2
            "export interface Props { title: string; }\n",        // L3
            "export type Mode = 'dark' | 'light';\n",             // L4
            "export enum Status { Ready, Busy }\n",               // L5
            "export const API_VERSION = 'v1';\n",                 // L6
            "\n",                                                 // L7
            "export const Dashboard = memo((props: Props) => {\n", // L8
            "  return <div>{props.title}</div>;\n",               // L9
            "});\n",                                              // L10
            "\n",                                                 // L11
            "export const TextInput = forwardRef<HTMLInputElement>((_p, ref) => {\n", // L12
            "  return <input ref={ref} />;\n",                    // L13
            "});\n",                                              // L14
            "\n",                                                 // L15
            "const helperArrow = (x: number) => x + 1;\n",        // L16
            "\n",                                                 // L17
            "export class ButtonHandler {\n",                     // L18
            "  onClick = () => {\n",                              // L19 (class arrow property!)
            "    return helperArrow(1);\n",                       // L20
            "  };\n",                                             // L21
            "  renderLabel(): string {\n",                        // L22
            "    return 'ok';\n",                                 // L23
            "  }\n",                                              // L24
            "}\n",                                                // L25
            "\n",                                                 // L26
            "export default function App(props: Props) {\n",      // L27 (export default!)
            "  return <Dashboard title={props.title} />;\n",      // L28
            "}\n",                                                // L29
        ),
    );

    // 3. TypeScript ambient declarations (`.d.ts`)
    proj.write(
        "web/env.d.ts",
        concat!(
            "declare module \"virtual:theme\" {\n",                // L1
            "  export function getTheme(): string;\n",             // L2
            "  export const DEFAULT_THEME: string;\n",             // L3
            "}\n",                                                 // L4
            "declare function nativeBridge(cmd: string): void;\n", // L5
            "declare const __APP_BUILD__: string;\n",              // L6
        ),
    );

    // 4. Python: def, async def, class + methods, top-level constants, imports
    proj.write(
        "py/engine.py",
        concat!(
            "import os\n",                                    // L1
            "from pathlib import Path\n",                     // L2
            "\n",                                             // L3
            "MAX_WORKERS = 8\n",                              // L4
            "\n",                                             // L5
            "class Engine:\n",                                // L6
            "    def step(self, dt: float) -> None:\n",       // L7
            "        pass\n",                                 // L8
            "\n",                                             // L9
            "    async def sync_remote(self) -> int:\n",      // L10
            "        return 1\n",                             // L11
            "\n",                                             // L12
            "async def boot_engine(root: Path) -> Engine:\n", // L13
            "    return Engine()\n",                          // L14
        ),
    );

    // 5. Go: func, receiver method `(w *World) Save`, struct, interface, const, var, import
    proj.write(
        "go/world.go",
        concat!(
            "package world\n",                             // L1
            "\n",                                          // L2
            "import (\n",                                  // L3
            "    \"fmt\"\n",                               // L4
            ")\n",                                         // L5
            "\n",                                          // L6
            "const DefaultSize = 16\n",                    // L7
            "var ActiveWorld = \"main\"\n",                // L8
            "\n",                                          // L9
            "type Store interface {\n",                    // L10
            "    Persist(path string) error\n",            // L11
            "}\n",                                         // L12
            "\n",                                          // L13
            "type World struct {\n",                       // L14
            "    Name string\n",                           // L15
            "}\n",                                         // L16
            "\n",                                          // L17
            "func NewWorld(name string) *World {\n",       // L18
            "    return &World{Name: name}\n",             // L19
            "}\n",                                         // L20
            "\n",                                          // L21
            "func (w *World) Save(path string) error {\n", // L22
            "    fmt.Println(w.Name, path)\n",             // L23
            "    return nil\n",                            // L24
            "}\n",                                         // L25
        ),
    );

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();
    let stats = index.sync_workspace().unwrap();
    assert_eq!(stats.parsed, 5);

    // --- Verify Rust ---
    let rs_rel = RelPath::normalize("src/lib.rs").unwrap();
    let rs_syms = index.store().get_symbols_for_file(&rs_rel).unwrap();
    let find_rs = |q: &str| {
        rs_syms
            .iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing Rust symbol `{q}` in {rs_syms:#?}"))
    };
    assert_eq!(find_rs("const MAX_ITEMS").start_line, 3);
    assert_eq!(find_rs("static GLOBAL_TAG").start_line, 4);
    assert_eq!(find_rs("type ItemId").start_line, 5);
    let trait_sig = find_rs("trait Storage::save");
    assert_eq!(trait_sig.kind, SymbolKind::Method);
    assert_eq!((trait_sig.start_line, trait_sig.end_line), (8, 8));
    let mac = find_rs("macro_rules! check_ok");
    assert_eq!(mac.kind, SymbolKind::Macro);
    assert_eq!((mac.start_line, mac.end_line), (12, 14));
    assert_eq!(find_rs("struct Repo").start_line, 16);
    assert_eq!(find_rs("enum Mode").start_line, 17);
    assert_eq!(find_rs("impl Storage for Repo::save").start_line, 19);
    assert_eq!(find_rs("mod inner").start_line, 23);
    assert_eq!(find_rs("mod inner::fn nested").start_line, 24);
    assert!(
        index
            .store()
            .get_edges_for_file(&rs_rel)
            .unwrap()
            .iter()
            .any(|e| e.to.contains("std::collections::BTreeMap"))
    );

    // --- Verify TypeScript / TSX ---
    let ts_rel = RelPath::normalize("web/App.tsx").unwrap();
    let ts_syms = index.store().get_symbols_for_file(&ts_rel).unwrap();
    let find_ts = |q: &str| {
        ts_syms
            .iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing TS symbol `{q}` in {ts_syms:#?}"))
    };
    assert_eq!(find_ts("interface Props").start_line, 3);
    assert_eq!(find_ts("type Mode").start_line, 4);
    assert_eq!(find_ts("enum Status").start_line, 5);
    assert_eq!(find_ts("const API_VERSION").start_line, 6);
    let memo_sym = find_ts("const Dashboard = memo(...)");
    assert_eq!((memo_sym.start_line, memo_sym.end_line), (8, 10));
    let fref_sym = find_ts("const TextInput = forwardRef(...)");
    assert_eq!((fref_sym.start_line, fref_sym.end_line), (12, 14));
    assert_eq!(find_ts("const helperArrow").start_line, 16);
    let arrow_prop = find_ts("class ButtonHandler.onClick");
    assert_eq!(arrow_prop.kind, SymbolKind::Method);
    assert_eq!((arrow_prop.start_line, arrow_prop.end_line), (19, 21));
    assert_eq!(find_ts("class ButtonHandler.renderLabel").start_line, 22);
    let exp_def = find_ts("export default App");
    assert_eq!((exp_def.start_line, exp_def.end_line), (27, 29));

    // --- Verify `.d.ts` ambient declarations ---
    let dts_rel = RelPath::normalize("web/env.d.ts").unwrap();
    let dts_syms = index.store().get_symbols_for_file(&dts_rel).unwrap();
    let find_dts = |q: &str| {
        dts_syms
            .iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing .d.ts symbol `{q}` in {dts_syms:#?}"))
    };
    assert_eq!(find_dts("declare module \"virtual:theme\"").start_line, 1);
    assert_eq!(
        find_dts("declare module \"virtual:theme\"::declare function getTheme").start_line,
        2
    );
    assert_eq!(
        find_dts("declare module \"virtual:theme\"::declare const DEFAULT_THEME").start_line,
        3
    );
    assert_eq!(find_dts("declare function nativeBridge").start_line, 5);
    assert_eq!(find_dts("declare const __APP_BUILD__").start_line, 6);

    // --- Verify Python ---
    let py_rel = RelPath::normalize("py/engine.py").unwrap();
    let py_syms = index.store().get_symbols_for_file(&py_rel).unwrap();
    let find_py = |q: &str| {
        py_syms
            .iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing Python symbol `{q}` in {py_syms:#?}"))
    };
    assert_eq!(find_py("const MAX_WORKERS").start_line, 4);
    assert_eq!(find_py("class Engine").start_line, 6);
    assert_eq!(find_py("class Engine.step").start_line, 7);
    assert_eq!(find_py("class Engine.sync_remote").start_line, 10);
    let async_fn = find_py("async def boot_engine");
    assert_eq!((async_fn.start_line, async_fn.end_line), (13, 14));
    let py_edges = index.store().get_edges_for_file(&py_rel).unwrap();
    assert!(py_edges.iter().any(|e| e.to == "import:os"));
    assert!(py_edges.iter().any(|e| e.to == "import:pathlib"));

    // --- Verify Go ---
    let go_rel = RelPath::normalize("go/world.go").unwrap();
    let go_syms = index.store().get_symbols_for_file(&go_rel).unwrap();
    let find_go = |q: &str| {
        go_syms
            .iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing Go symbol `{q}` in {go_syms:#?}"))
    };
    assert_eq!(find_go("const DefaultSize").start_line, 7);
    assert_eq!(find_go("var ActiveWorld").start_line, 8);
    assert_eq!(find_go("interface Store").start_line, 10);
    assert_eq!(find_go("interface Store.Persist").start_line, 11);
    assert_eq!(find_go("struct World").start_line, 14);
    assert_eq!(find_go("func NewWorld").start_line, 18);
    let recv = find_go("(w *World) Save");
    assert_eq!(recv.kind, SymbolKind::Method);
    assert_eq!(recv.parent.as_deref(), Some("World"));
    assert_eq!((recv.start_line, recv.end_line), (22, 25));
    let go_edges = index.store().get_edges_for_file(&go_rel).unwrap();
    assert!(go_edges.iter().any(|e| e.to == "import:fmt"));
}

// ---------------------------------------------------------------------------
// Test 5: Batch Read & Broken Syntax Fail-Closed (`UNPARSED_FALLBACK`)
// ---------------------------------------------------------------------------

#[test]
fn gate_5_batch_read_and_broken_syntax_fail_closed() {
    let proj = Sandbox::new("batch-broken");
    let cache = Sandbox::new("batch-broken-cache");

    proj.write(
        "src/a.rs",
        "pub fn greet() -> &'static str {\n    \"hello\"\n}\n",
    );
    proj.write("src/b.py", "def compute(x):\n    return x * 2\n");
    proj.write("src/broken.rs", "pub fn broken( {\n    let x = ===;\n");
    proj.write("notes.xyz", "unsupported format line 1\nline 2\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    // Batch read across 2 clean files (symbol + line range) succeeds in 1 call.
    let batch = read_batch(
        &mut index,
        &[
            ReadTarget::symbol("src/a.rs", "greet"),
            ReadTarget::lines("src/b.py", LineRange::new(1, 2).unwrap()),
        ],
    )
    .unwrap();
    assert_eq!(batch.data.targets.len(), 2);
    assert_eq!(batch.data.targets[0].result.status, ReadStatus::Ok);
    assert_eq!(batch.data.targets[0].trust, TrustLevel::VerifiedAst);
    assert!(
        batch.data.targets[0]
            .result
            .content
            .as_deref()
            .unwrap()
            .contains("L1| pub fn greet()")
    );
    assert_eq!(batch.data.targets[1].result.status, ReadStatus::Ok);
    assert_eq!(batch.data.targets[1].trust, TrustLevel::VerifiedRaw);
    assert!(
        batch.data.targets[1]
            .result
            .content
            .as_deref()
            .unwrap()
            .contains("L2|     return x * 2")
    );

    // Broken Rust syntax MUST fail closed with `UNPARSED_FALLBACK` + explicit warning (no regex guess!).
    let broken_rel = RelPath::normalize("src/broken.rs").unwrap();
    let broken_outline = outline_file(&mut index, &broken_rel, None).unwrap();
    assert_eq!(broken_outline.trust, TrustLevel::UnparsedFallback);
    assert!(broken_outline.data.files[0].symbols.is_empty());
    assert!(!broken_outline.warnings.is_empty());
    assert!(broken_outline.raw_fallback.is_some());

    let broken_read = read_symbol(&mut index, &broken_rel, "broken").unwrap();
    assert_eq!(broken_read.trust, TrustLevel::UnparsedFallback);
    assert_eq!(broken_read.data.status, ReadStatus::UnparsedFallback);
    assert!(!broken_read.warnings.is_empty());
    assert!(broken_read.raw_fallback.is_some());

    // Unsupported extension `.xyz` also fails closed with `UNPARSED_FALLBACK`.
    let xyz_rel = RelPath::normalize("notes.xyz").unwrap();
    let xyz_outline = outline_file(&mut index, &xyz_rel, None).unwrap();
    assert_eq!(xyz_outline.trust, TrustLevel::UnparsedFallback);
    assert!(!xyz_outline.warnings.is_empty());

    // Raw line read STILL works safely on broken/unsupported files (`VERIFIED_RAW`).
    let raw_broken = read_lines(&index, &broken_rel, LineRange::new(1, 2).unwrap()).unwrap();
    assert_eq!(raw_broken.trust, TrustLevel::VerifiedRaw);
    assert!(
        raw_broken
            .data
            .content
            .unwrap()
            .contains("L1| pub fn broken( {")
    );
}

// ---------------------------------------------------------------------------
// Test 6: Output Secret Redaction, Path Confinement, and Deterministic CLI
// ---------------------------------------------------------------------------

#[test]
fn gate_6_secret_redaction_confinement_and_cli_determinism() {
    let proj = Sandbox::new("cli-det");
    let cache = Sandbox::new("cli-det-cache");

    let synthetic_gh = format!("ghp_{}", "1234567890abcdefghij1234567890abcdef");
    proj.write(
        "src/auth.rs",
        &format!("pub fn token_example() -> &'static str {{\n    \"{synthetic_gh}\"\n}}\n"),
    );
    proj.write(".env", "SUPER_SECRET=123\n");

    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut index = CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap();

    // Reading `.env` is strictly blocked.
    let env_err = read_lines(
        &index,
        &RelPath::normalize(".env").unwrap(),
        LineRange::new(1, 1).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        env_err,
        klens_code::CodeError::Path(PathError::SensitiveFileBlocked(_))
    ));

    // Secret inside source code is automatically redacted at the output gate.
    let read_auth = read_symbol(
        &mut index,
        &RelPath::normalize("src/auth.rs").unwrap(),
        "token_example",
    )
    .unwrap();
    assert_eq!(read_auth.redactions_count, 1);
    let body = read_auth.data.content.unwrap();
    assert!(body.contains("[REDACTED:GITHUB_TOKEN]"));
    assert!(!body.contains(&synthetic_gh));

    // End-to-end CLI binary determinism & zero-footprint `--read-only` test.
    // Redirect USERPROFILE/HOME into our temp cache dir so tests never pollute real `~/.klens`.
    let bin = env!("CARGO_BIN_EXE_klens");
    let run1 = Command::new(bin)
        .args(["outline", "src/auth.rs", "--read-only", "--json"])
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path())
        .output()
        .expect("failed to execute klens binary");
    assert!(
        run1.status.success(),
        "klens outline failed: {}",
        String::from_utf8_lossy(&run1.stderr)
    );

    let run2 = Command::new(bin)
        .args(["outline", "src/auth.rs", "--read-only", "--json"])
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path())
        .output()
        .expect("failed to execute klens binary");
    assert!(run2.status.success());

    // Byte-for-byte deterministic output (Constitution Article 5).
    assert_eq!(run1.stdout, run2.stdout);
    // Zero footprint inside target project; cache lives in `<HOME>/.klens/readonly-cache/`.
    assert!(!proj.path().join(".klens").exists());
    assert!(cache.path().join(".klens").join("readonly-cache").is_dir());

    // CLI `read --symbol` also redacts secrets and returns schema_version = 1.
    let read_cli = Command::new(bin)
        .args([
            "read",
            "src/auth.rs",
            "--symbol",
            "token_example",
            "--read-only",
            "--json",
        ])
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path())
        .output()
        .expect("failed to execute klens read");
    assert!(read_cli.status.success());
    let json: serde_json::Value = serde_json::from_slice(&read_cli.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["trust"], "VERIFIED_AST");
    assert_eq!(json["redactions_count"], 1);
    assert!(
        !json["data"]["content"]
            .as_str()
            .unwrap()
            .contains(&synthetic_gh)
    );
}

// ---------------------------------------------------------------------------
// Phase 1B Mandatory Adversarial Truth Gates (docs/phases/phase-1b.md)
// ---------------------------------------------------------------------------

fn run_git_ok(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().expect("git command failed");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn gate_7_phase1b_map_and_graph_cli_byte_for_byte_determinism() {
    let proj = Sandbox::new("p1b-det");
    let cache = Sandbox::new("p1b-det-cache");

    proj.write(
        "Cargo.toml",
        "[package]\nname = \"det\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\n",
    );
    proj.write("src/core.rs", "pub fn core_helper() -> usize { 7 }\n");
    proj.write(
        "src/service.rs",
        "use crate::core::core_helper;\npub fn serve() -> usize { core_helper() }\n",
    );
    proj.write(
        "src/main.rs",
        "mod core;\nmod service;\nfn main() { let _ = service::serve(); }\n",
    );

    let bin = env!("CARGO_BIN_EXE_klens");

    for args in [
        vec!["map", "--budget", "1200", "--read-only", "--json"],
        vec!["map", "--budget", "1200", "--read-only"],
        vec!["graph", "--read-only", "--json"],
        vec!["graph", "--read-only"],
    ] {
        let out1 = Command::new(bin)
            .args(&args)
            .current_dir(proj.path())
            .env("USERPROFILE", cache.path())
            .env("HOME", cache.path())
            .output()
            .expect("klens failed");
        assert!(
            out1.status.success(),
            "klens {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out1.stderr)
        );

        let out2 = Command::new(bin)
            .args(&args)
            .current_dir(proj.path())
            .env("USERPROFILE", cache.path())
            .env("HOME", cache.path())
            .output()
            .expect("klens failed");
        assert!(out2.status.success());

        // Byte-for-byte identical across consecutive invocations (Constitution Article 5).
        assert_eq!(
            out1.stdout, out2.stdout,
            "non-deterministic CLI output for klens {:?}",
            args
        );
    }

    // Zero footprint in target project under `--read-only`.
    assert!(!proj.path().join(".klens").exists());
}

#[test]
fn gate_8_phase1b_cycle_and_god_node_cli_detection() {
    let proj = Sandbox::new("p1b-cycle-god");
    let cache = Sandbox::new("p1b-cycle-god-cache");

    proj.write("src/a.rs", "use crate::b;\npub fn from_a() {}\n");
    proj.write("src/b.rs", "use crate::a;\npub fn from_b() {}\n");

    let mut huge = String::new();
    for i in 1..=810 {
        huge.push_str(&format!("pub const ITEM_{i:04}: usize = {i};\n"));
    }
    proj.write("src/monolith.rs", &huge);

    let bin = env!("CARGO_BIN_EXE_klens");

    let graph_out = Command::new(bin)
        .args(["graph", "--read-only", "--json"])
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path())
        .output()
        .expect("klens graph failed");
    assert!(graph_out.status.success());

    let graph_json: serde_json::Value = serde_json::from_slice(&graph_out.stdout).unwrap();
    assert_eq!(graph_json["schema_version"], 1);
    let cycles = graph_json["data"]["cycles"].as_array().unwrap();
    assert!(
        cycles.iter().any(|c| {
            c == &serde_json::json!(["file:src/a.rs", "file:src/b.rs", "file:src/a.rs"])
        }),
        "expected a.rs -> b.rs -> a.rs cycle in graph JSON, got: {cycles:?}"
    );
    let god_nodes = graph_json["data"]["god_nodes"].as_array().unwrap();
    assert!(
        god_nodes.iter().any(|g| g == "src/monolith.rs"),
        "expected src/monolith.rs in god_nodes, got: {god_nodes:?}"
    );

    let health_out = Command::new(bin)
        .args(["health", "--read-only", "--json"])
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path())
        .output()
        .expect("klens health failed");
    assert!(health_out.status.success());
    let health_json: serde_json::Value = serde_json::from_slice(&health_out.stdout).unwrap();
    assert_eq!(health_json["data"]["overall"], "RED");
    let checks = health_json["data"]["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 5);
    assert_eq!(
        checks.iter().find(|c| c["id"] == "god_nodes").unwrap()["light"],
        "RED"
    );
    assert_eq!(
        checks.iter().find(|c| c["id"] == "cycles").unwrap()["light"],
        "RED"
    );
    assert!(!proj.path().join(".klens").exists());
}

#[test]
fn gate_9_phase1b_protected_path_and_new_package_red_alert_cli() {
    let proj = Sandbox::new("p1b-diff-alert");
    let cache = Sandbox::new("p1b-diff-alert-cache");

    proj.write(".gitignore", ".env\ntarget/\n");
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"guard\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\n",
    );
    proj.write(
        "src/contract.rs",
        "pub fn enforce_policy() -> bool {\n    true\n}\n",
    );
    proj.write(
        ".klens/config.toml",
        "schema_version = 1\nmode = \"active\"\nprotected_paths = [\"src/contract.rs\"]\n",
    );

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "ci@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "Klens CI"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(proj.path(), &["commit", "-m", "baseline"]);

    // Modify protected file AND add a new external dependency to Cargo.toml.
    proj.write(
        "src/contract.rs",
        "pub fn enforce_policy() -> bool {\n    false\n}\n",
    );
    proj.write(
        "Cargo.toml",
        "[package]\nname = \"guard\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\ntokio = \"1.40\"\n",
    );

    let bin = env!("CARGO_BIN_EXE_klens");
    let out_json = Command::new(bin)
        .args(["diff-check", "--read-only", "--json"])
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path())
        .output()
        .expect("klens diff-check failed");
    assert!(
        out_json.status.success(),
        "diff-check stderr: {}",
        String::from_utf8_lossy(&out_json.stderr)
    );
    let val: serde_json::Value = serde_json::from_slice(&out_json.stdout).unwrap();
    assert_eq!(val["schema_version"], 1);
    assert_eq!(val["data"]["overall_severity"], "error");
    assert_eq!(
        val["data"]["protected_violations"],
        serde_json::json!(["src/contract.rs"])
    );
    assert!(
        val["data"]["added_dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["name"] == "tokio" && d["version"] == "1.40")
    );

    // Plain-text output must clearly display RED alerts for both violations.
    let out_txt = Command::new(bin)
        .args(["diff-check", "--read-only"])
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path())
        .output()
        .expect("klens diff-check text failed");
    assert!(out_txt.status.success());
    let txt = String::from_utf8_lossy(&out_txt.stdout);
    assert!(txt.contains("status=RED"), "expected RED status in:\n{txt}");
    assert!(txt.contains("src/contract.rs"));
    assert!(txt.contains("tokio"));
}

#[test]
fn gate_10_phase1b_fts5_find_never_leaks_gitignored_target_or_node_modules() {
    let proj = Sandbox::new("p1b-fts-ignore");
    let cache = Sandbox::new("p1b-fts-ignore-cache");

    let needle = "SENTINEL_KLENS_FTS5_ONLY_IN_SRC";
    proj.write(".gitignore", "ignored_build/\n*.bak\n");
    proj.write(
        "src/real.rs",
        &format!("pub fn find_me() -> &'static str {{\n    \"{needle}\"\n}}\n"),
    );
    proj.write(
        "target/debug/leak.rs",
        &format!("pub fn leaked_target() {{ let _ = \"{needle}\"; }}\n"),
    );
    proj.write(
        "node_modules/pkg/leak.js",
        &format!("export const leak = \"{needle}\";\n"),
    );
    proj.write(
        "ignored_build/leak.rs",
        &format!("pub fn leaked_gitignored() {{ let _ = \"{needle}\"; }}\n"),
    );
    proj.write("dump.bak", &format!("{needle}\n"));
    proj.write(".env", &format!("API_KEY={needle}\n"));

    let bin = env!("CARGO_BIN_EXE_klens");
    let out = Command::new(bin)
        .args(["find", needle, "--read-only", "--json"])
        .current_dir(proj.path())
        .env("USERPROFILE", cache.path())
        .env("HOME", cache.path())
        .output()
        .expect("klens find failed");
    assert!(
        out.status.success(),
        "klens find stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    let matches = json["data"]["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "expected only 1 match, got: {matches:?}");
    assert_eq!(matches[0]["path"], "src/real.rs");
    assert_eq!(matches[0]["line"], 2);
    assert!(!proj.path().join(".klens").exists());
}

// ---------------------------------------------------------------------------
// Phase 2 Mandatory Adversarial Truth Gates (docs/phases/phase-2.md)
// ---------------------------------------------------------------------------

#[test]
fn gate_11_phase2_cli_run_runs_and_secret_redaction_end_to_end() {
    let proj = Sandbox::new("p2-cli-run");
    let bin = env!("CARGO_BIN_EXE_klens");

    let synthetic_anthropic = format!("sk-ant-api03-{}", "zY9xW8vU7tS6rQ5pO4nM3lK2");
    #[cfg(windows)]
    let cmd_args = [
        "run",
        "--json",
        "--",
        "cmd",
        "/C",
        &format!("echo ok_line & echo ANTHROPIC_API_KEY={synthetic_anthropic}"),
    ];
    #[cfg(not(windows))]
    let cmd_args = [
        "run",
        "--json",
        "--",
        "sh",
        "-c",
        &format!("echo ok_line; echo ANTHROPIC_API_KEY={synthetic_anthropic}"),
    ];

    let out = Command::new(bin)
        .args(cmd_args)
        .current_dir(proj.path())
        .output()
        .expect("klens run failed");
    assert!(
        out.status.success(),
        "klens run stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["data"]["meta"]["schema_version"], 1);
    assert_eq!(json["data"]["meta"]["truncated_errors"], false);
    assert!(json["redactions_count"].as_u64().unwrap() >= 1);

    let output_text = json["data"]["output"].as_str().unwrap();
    assert!(output_text.contains("[REDACTED:ANTHROPIC_KEY]"));
    assert!(!output_text.contains(&synthetic_anthropic));

    let run_id = json["data"]["meta"]["run_id"].as_str().unwrap().to_string();
    let raw_log_rel = json["data"]["meta"]["raw_log_path"].as_str().unwrap();
    assert!(proj.path().join(raw_log_rel).is_file());

    // `klens runs list --json` lists the recorded run.
    let list_out = Command::new(bin)
        .args(["runs", "list", "--json"])
        .current_dir(proj.path())
        .output()
        .expect("klens runs list failed");
    assert!(list_out.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(list_json["data"][0]["run_id"], run_id);

    // `klens runs show <run_id> --raw --json` also redacts at the output gate.
    let show_out = Command::new(bin)
        .args(["runs", "show", &run_id, "--raw", "--json"])
        .current_dir(proj.path())
        .output()
        .expect("klens runs show failed");
    assert!(show_out.status.success());
    let show_json: serde_json::Value = serde_json::from_slice(&show_out.stdout).unwrap();
    assert!(
        show_json["data"]["content"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:ANTHROPIC_KEY]")
    );
    assert!(
        !show_json["data"]["content"]
            .as_str()
            .unwrap()
            .contains(&synthetic_anthropic)
    );
}

#[test]
fn gate_12_phase2_cli_checkpoint_and_rollback_dry_run_and_apply() {
    let proj = Sandbox::new("p2-cli-cp");
    proj.write("src/lib.rs", "pub fn answer() -> i32 { 42 }\n");

    run_git_ok(proj.path(), &["init"]);
    run_git_ok(proj.path(), &["config", "user.email", "ci@klens.local"]);
    run_git_ok(proj.path(), &["config", "user.name", "Klens CI"]);
    run_git_ok(proj.path(), &["add", "."]);
    run_git_ok(proj.path(), &["commit", "-m", "baseline"]);

    let bin = env!("CARGO_BIN_EXE_klens");

    // Create checkpoint via CLI.
    let cp_out = Command::new(bin)
        .args(["checkpoint", "safe point 1", "--json"])
        .current_dir(proj.path())
        .output()
        .expect("klens checkpoint failed");
    assert!(
        cp_out.status.success(),
        "klens checkpoint stderr: {}",
        String::from_utf8_lossy(&cp_out.stderr)
    );
    let cp_json: serde_json::Value = serde_json::from_slice(&cp_out.stdout).unwrap();
    let cp_id = cp_json["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(cp_json["data"]["note"], "safe point 1");

    // Break the file and add an unwanted file.
    proj.write("src/lib.rs", "BROKEN\n");
    proj.write("src/extra.rs", "unwanted\n");

    // List checkpoints via CLI.
    let list_out = Command::new(bin)
        .args(["checkpoints", "--json"])
        .current_dir(proj.path())
        .output()
        .expect("klens checkpoints failed");
    assert!(list_out.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(list_json["data"][0]["id"], cp_id);

    // Dry-run rollback previews without mutating disk.
    let dry_out = Command::new(bin)
        .args(["rollback", &cp_id, "--dry-run", "--json"])
        .current_dir(proj.path())
        .output()
        .expect("klens rollback --dry-run failed");
    assert!(dry_out.status.success());
    let dry_json: serde_json::Value = serde_json::from_slice(&dry_out.stdout).unwrap();
    assert_eq!(dry_json["data"]["dry_run"], true);
    assert_eq!(dry_json["data"]["applied"], false);
    assert_eq!(
        fs::read_to_string(proj.path().join("src/lib.rs")).unwrap(),
        "BROKEN\n"
    );

    // Real rollback restores exact snapshot.
    let apply_out = Command::new(bin)
        .args(["rollback", &cp_id, "--json"])
        .current_dir(proj.path())
        .output()
        .expect("klens rollback failed");
    assert!(apply_out.status.success());
    let apply_json: serde_json::Value = serde_json::from_slice(&apply_out.stdout).unwrap();
    assert_eq!(apply_json["data"]["applied"], true);
    assert_eq!(
        fs::read_to_string(proj.path().join("src/lib.rs")).unwrap(),
        "pub fn answer() -> i32 { 42 }\n"
    );
    assert!(!proj.path().join("src/extra.rs").exists());
}
