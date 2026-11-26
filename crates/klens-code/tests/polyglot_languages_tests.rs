use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_code::{
    CodeIndex, ReadStatus, build_code_graph, build_project_map, builtin_language_extensions,
    extract_imports_from_source, find_in_workspace, outline_file, read_symbol,
};
use klens_core::{DEFAULT_CTAGS_EXTENSIONS, ProjectRoot, RelPath, SymbolKind, TrustLevel};

static POLY_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempWorkspace {
    dir: PathBuf,
}

impl TempWorkspace {
    fn new(label: &str) -> Self {
        let id = POLY_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-polyglot-{label}-{}-{id}",
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

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn open_ro_index(proj: &TempWorkspace, cache: &TempWorkspace) -> CodeIndex {
    let root = ProjectRoot::new(proj.path()).unwrap();
    CodeIndex::open_with_readonly_cache_dir(root, true, cache.path()).unwrap()
}

#[test]
fn ctags_default_extensions_have_zero_overlap_with_builtin_ast() {
    let builtin = builtin_language_extensions();
    for ext in [
        "c", "h", "cpp", "cc", "cxx", "hpp", "hh", "hxx", "java", "cs", "php", "rb",
    ] {
        assert!(
            builtin.contains(ext),
            "expected built-in extension `{ext}` in AnalyzerRegistry"
        );
        assert!(
            !DEFAULT_CTAGS_EXTENSIONS.contains(&ext),
            "built-in extension `{ext}` must not remain in DEFAULT_CTAGS_EXTENSIONS"
        );
    }
    assert_eq!(DEFAULT_CTAGS_EXTENSIONS.len(), 20);
    for ext in DEFAULT_CTAGS_EXTENSIONS {
        assert!(
            !builtin.contains(*ext),
            "ctags extension `{ext}` overlaps with built-in AST"
        );
    }
}

#[test]
fn c_analyzer_outline_read_ambiguous_graph_utf8_and_fail_closed() {
    let proj = TempWorkspace::new("c-lang");
    let cache = TempWorkspace::new("c-lang-cache");

    proj.write(
        "include/types.h",
        concat!(
            "#ifndef TYPES_H\n",                  // L1
            "#define TYPES_H\n",                  // L2
            "#define MAX_BUF 256\n",              // L3
            "#define ADD_ONE(x) ((x) + 1)\n",     // L4
            "// Türkçe açıklama: ğüşiöçĞÜŞİÖÇ\n", // L5
            "struct Packet {\n",                  // L6
            "    int id;\n",                      // L7
            "};\n",                               // L8
            "enum Status {\n",                    // L9
            "    OK = 0,\n",                      // L10
            "    ERR = 1\n",                      // L11
            "};\n",                               // L12
            "union Payload {\n",                  // L13
            "    int i;\n",                       // L14
            "    float f;\n",                     // L15
            "};\n",                               // L16
            "typedef unsigned long u64_t;\n",     // L17
            "#endif\n",                           // L18
        ),
    );
    proj.write(
        "src/main.c",
        concat!(
            "#include <stdio.h>\n",              // L1
            "#include \"../include/types.h\"\n", // L2
            "\n",                                // L3
            "struct init {\n",                   // L4
            "    int code;\n",                   // L5
            "};\n",                              // L6
            "\n",                                // L7
            "int init(int code) {\n",            // L8
            "    return code + 1;\n",            // L9
            "}\n",                               // L10
            "\n",                                // L11
            "int compute(int x) {\n",            // L12
            "    return ADD_ONE(x);\n",          // L13
            "}\n",                               // L14
        ),
    );
    proj.write("src/broken.c", "int broken( { return ;;\n");

    let mut idx = open_ro_index(&proj, &cache);

    let h_rel = RelPath::normalize("include/types.h").unwrap();
    let h_out = outline_file(&mut idx, &h_rel, None).unwrap();
    assert_eq!(h_out.trust, TrustLevel::VerifiedAst);
    let h_syms = &h_out.data.files[0].symbols;
    let find_h = |q: &str| {
        h_syms
            .iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing C header symbol `{q}` in {h_syms:#?}"))
    };
    assert_eq!(find_h("#define MAX_BUF").kind, SymbolKind::Macro);
    assert_eq!(find_h("#define MAX_BUF").start_line, 3);
    assert_eq!(find_h("#define ADD_ONE").kind, SymbolKind::Macro);
    assert_eq!(find_h("struct Packet").kind, SymbolKind::Struct);
    assert_eq!(
        (
            find_h("struct Packet").start_line,
            find_h("struct Packet").end_line
        ),
        (6, 8)
    );
    assert_eq!(find_h("enum Status").kind, SymbolKind::Enum);
    assert_eq!(find_h("union Payload").kind, SymbolKind::Struct);
    assert_eq!(find_h("typedef u64_t").kind, SymbolKind::TypeAlias);

    let c_rel = RelPath::normalize("src/main.c").unwrap();
    let single = read_symbol(&mut idx, &c_rel, "compute").unwrap();
    assert_eq!(single.trust, TrustLevel::VerifiedAst);
    assert_eq!(single.data.status, ReadStatus::Ok);
    assert_eq!(single.data.start_line, Some(12));
    assert_eq!(single.data.end_line, Some(14));

    // Short name `init` collides (`struct init` vs `fn init`) -> AMBIGUOUS_SYMBOL!
    let amb = read_symbol(&mut idx, &c_rel, "init").unwrap();
    assert_eq!(amb.trust, TrustLevel::VerifiedAst);
    assert_eq!(amb.data.status, ReadStatus::AmbiguousSymbol);
    assert_eq!(amb.data.candidates.len(), 2);

    let exact = read_symbol(&mut idx, &c_rel, "fn init").unwrap();
    assert_eq!(exact.data.status, ReadStatus::Ok);
    assert_eq!(exact.data.start_line, Some(8));
    assert!(exact.data.content.unwrap().contains("return code + 1;"));

    // Broken C syntax -> fail-closed UNPARSED_FALLBACK with 0 symbols.
    let broken_out =
        outline_file(&mut idx, &RelPath::normalize("src/broken.c").unwrap(), None).unwrap();
    assert_eq!(broken_out.trust, TrustLevel::UnparsedFallback);
    assert!(broken_out.data.files[0].symbols.is_empty());
    assert!(!broken_out.warnings.is_empty());

    // Graph resolves `#include "../include/types.h"`.
    let g1 = build_code_graph(&mut idx).unwrap();
    let g2 = build_code_graph(&mut idx).unwrap();
    assert_eq!(
        g1.to_deterministic_json().unwrap(),
        g2.to_deterministic_json().unwrap()
    );
    assert!(
        g1.data
            .edges
            .iter()
            .any(|e| { e.from == "file:src/main.c" && e.to == "file:include/types.h" })
    );
}

#[test]
fn cpp_analyzer_outline_read_ambiguous_graph_utf8_and_fail_closed() {
    let proj = TempWorkspace::new("cpp-lang");
    let cache = TempWorkspace::new("cpp-lang-cache");

    proj.write(
        "include/service.hpp",
        concat!(
            "#pragma once\n",                      // L1
            "// Türkçe yorum: ğüşiöçĞÜŞİÖÇ\n",     // L2
            "namespace App {\n",                   // L3
            "using Id = unsigned long;\n",         // L4
            "typedef int Counter;\n",              // L5
            "enum class State { Ready, Busy };\n", // L6
            "struct Config {\n",                   // L7
            "    int retries;\n",                  // L8
            "};\n",                                // L9
            "class Service {\n",                   // L10
            "public:\n",                           // L11
            "    int run(int x) const;\n",         // L12
            "};\n",                                // L13
            "class Worker {\n",                    // L14
            "public:\n",                           // L15
            "    int run(int x) const {\n",        // L16
            "        return x * 2;\n",             // L17
            "    }\n",                             // L18
            "};\n",                                // L19
            "} // namespace App\n",                // L20
        ),
    );
    proj.write(
        "src/service.cpp",
        concat!(
            "#include \"../include/service.hpp\"\n", // L1
            "\n",                                    // L2
            "namespace App {\n",                     // L3
            "int Service::run(int x) const {\n",     // L4
            "    return x + 10;\n",                  // L5
            "}\n",                                   // L6
            "int free_helper(int v) {\n",            // L7
            "    return v;\n",                       // L8
            "}\n",                                   // L9
            "}\n",                                   // L10
        ),
    );
    proj.write(
        "src/broken.cpp",
        "namespace App { class Oops { void bad( ;;;\n",
    );

    let mut idx = open_ro_index(&proj, &cache);

    let hpp_rel = RelPath::normalize("include/service.hpp").unwrap();
    let hpp_out = outline_file(&mut idx, &hpp_rel, None).unwrap();
    assert_eq!(hpp_out.trust, TrustLevel::VerifiedAst);
    let syms = &hpp_out.data.files[0].symbols;
    let find_sym = |q: &str| {
        syms.iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing C++ symbol `{q}` in {syms:#?}"))
    };
    assert_eq!(find_sym("App").kind, SymbolKind::Module);
    assert_eq!(find_sym("App::Id").kind, SymbolKind::TypeAlias);
    assert_eq!(find_sym("App::Counter").kind, SymbolKind::TypeAlias);
    assert_eq!(find_sym("App::State").kind, SymbolKind::Enum);
    assert_eq!(find_sym("App::Config").kind, SymbolKind::Struct);
    assert_eq!(find_sym("App::Service").kind, SymbolKind::Class);
    assert_eq!(find_sym("App::Service::run").kind, SymbolKind::Method);
    assert_eq!(find_sym("App::Worker::run").kind, SymbolKind::Method);

    // Ambiguous `run` between Service::run and Worker::run -> AMBIGUOUS_SYMBOL!
    let amb = read_symbol(&mut idx, &hpp_rel, "run").unwrap();
    assert_eq!(amb.data.status, ReadStatus::AmbiguousSymbol);
    assert_eq!(amb.data.candidates.len(), 2);

    let exact = read_symbol(&mut idx, &hpp_rel, "App::Worker::run").unwrap();
    assert_eq!(exact.data.status, ReadStatus::Ok);
    assert!(exact.data.content.unwrap().contains("return x * 2;"));

    // Out-of-line definition `App::Service::run` in `.cpp`.
    let cpp_rel = RelPath::normalize("src/service.cpp").unwrap();
    let out_of_line = read_symbol(&mut idx, &cpp_rel, "App::Service::run").unwrap();
    assert_eq!(out_of_line.trust, TrustLevel::VerifiedAst);
    assert_eq!(out_of_line.data.status, ReadStatus::Ok);
    assert_eq!(out_of_line.data.start_line, Some(4));

    let free_fn = read_symbol(&mut idx, &cpp_rel, "free_helper").unwrap();
    assert_eq!(free_fn.data.status, ReadStatus::Ok);
    assert_eq!(free_fn.data.kind, Some(SymbolKind::Function));

    // Fail-closed on broken C++.
    let broken = outline_file(
        &mut idx,
        &RelPath::normalize("src/broken.cpp").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(broken.trust, TrustLevel::UnparsedFallback);
    assert!(broken.data.files[0].symbols.is_empty());

    // Graph & map determinism + include edge.
    let g = build_code_graph(&mut idx).unwrap();
    assert!(
        g.data
            .edges
            .iter()
            .any(|e| { e.from == "file:src/service.cpp" && e.to == "file:include/service.hpp" })
    );
}

#[test]
fn java_analyzer_outline_read_ambiguous_graph_utf8_and_fail_closed() {
    let proj = TempWorkspace::new("java-lang");
    let cache = TempWorkspace::new("java-lang-cache");

    proj.write(
        "src/com/acme/Item.java",
        concat!(
            "package com.acme;\n",
            "public record Item(String name, int qty) {}\n",
        ),
    );
    proj.write(
        "src/com/acme/Outer.java",
        concat!(
            "package com.acme;\n",                                 // L1
            "import com.acme.Item;\n",                             // L2
            "import static java.lang.Math.max;\n",                 // L3
            "import java.util.*;\n",                               // L4
            "// Türkçe not: ğüşiöçĞÜŞİÖÇ\n",                       // L5
            "public @interface Audited {\n",                       // L6
            "    String value();\n",                               // L7
            "}\n",                                                 // L8
            "interface Runner {\n",                                // L9
            "    int MAX_STEPS = 10;\n",                           // L10
            "    void run();\n",                                   // L11
            "}\n",                                                 // L12
            "enum Mode { FAST, SAFE }\n",                          // L13
            "public class Outer {\n",                              // L14
            "    public Outer() {}\n",                             // L15
            "    public static class Inner implements Runner {\n", // L16
            "        public void run() {\n",                       // L17
            "            int n = max(1, 2);\n",                    // L18
            "        }\n",                                         // L19
            "    }\n",                                             // L20
            "    public void run() {\n",                           // L21
            "        Item it = new Item(\"ok\", 1);\n",            // L22
            "    }\n",                                             // L23
            "}\n",                                                 // L24
        ),
    );
    proj.write(
        "src/com/acme/Broken.java",
        "public class Broken { void x( { }\n",
    );

    let mut idx = open_ro_index(&proj, &cache);
    let rel = RelPath::normalize("src/com/acme/Outer.java").unwrap();
    let out = outline_file(&mut idx, &rel, None).unwrap();
    assert_eq!(out.trust, TrustLevel::VerifiedAst);
    let syms = &out.data.files[0].symbols;
    let find_sym = |q: &str| {
        syms.iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing Java symbol `{q}` in {syms:#?}"))
    };
    assert_eq!(find_sym("Audited").kind, SymbolKind::Interface);
    assert_eq!(find_sym("Runner").kind, SymbolKind::Interface);
    assert_eq!(find_sym("Runner::MAX_STEPS").kind, SymbolKind::Const);
    assert_eq!(find_sym("Mode").kind, SymbolKind::Enum);
    assert_eq!(find_sym("Outer").kind, SymbolKind::Class);
    assert_eq!(find_sym("Outer::Outer").kind, SymbolKind::Method);
    assert_eq!(find_sym("Outer::Inner").kind, SymbolKind::Class);
    assert_eq!(find_sym("Outer::Inner::run").kind, SymbolKind::Method);
    assert_eq!(find_sym("Outer::run").kind, SymbolKind::Method);

    // Ambiguous `run` across Runner, Outer::Inner, Outer -> AMBIGUOUS_SYMBOL!
    let amb = read_symbol(&mut idx, &rel, "run").unwrap();
    assert_eq!(amb.data.status, ReadStatus::AmbiguousSymbol);
    assert_eq!(amb.data.candidates.len(), 3);

    let exact = read_symbol(&mut idx, &rel, "Outer::Inner::run").unwrap();
    assert_eq!(exact.data.status, ReadStatus::Ok);
    assert_eq!(exact.data.start_line, Some(17));
    assert!(exact.data.content.unwrap().contains("int n = max(1, 2);"));

    // Record file parsed as VerifiedAst.
    let rec_out = outline_file(
        &mut idx,
        &RelPath::normalize("src/com/acme/Item.java").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(rec_out.trust, TrustLevel::VerifiedAst);
    assert!(
        rec_out.data.files[0]
            .symbols
            .iter()
            .any(|s| s.name == "Item")
    );

    // Broken Java -> fail-closed.
    let broken = outline_file(
        &mut idx,
        &RelPath::normalize("src/com/acme/Broken.java").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(broken.trust, TrustLevel::UnparsedFallback);
    assert!(broken.data.files[0].symbols.is_empty());

    // Graph resolves `import com.acme.Item;`.
    let g = build_code_graph(&mut idx).unwrap();
    assert!(g.data.edges.iter().any(|e| {
        e.from == "file:src/com/acme/Outer.java" && e.to == "file:src/com/acme/Item.java"
    }));
}

#[test]
fn csharp_analyzer_outline_read_ambiguous_graph_utf8_and_fail_closed() {
    let proj = TempWorkspace::new("csharp-lang");
    let cache = TempWorkspace::new("csharp-lang-cache");

    proj.write(
        "src/Models/Order.cs",
        concat!(
            "namespace Demo.Models;\n",                     // L1 (file-scoped!)
            "public record Order(int Id, string Title);\n", // L2
            "public struct Point { public int X { get; set; } }\n", // L3
            "public enum OrderState { New, Paid }\n",       // L4
            "public delegate void OnOrder(Order o);\n",     // L5
        ),
    );
    proj.write(
        "src/Services/Engine.cs",
        concat!(
            "using System;\n",                            // L1
            "using Demo.Models.Order;\n",                 // L2
            "// Türkçe not: ğüşiöçĞÜŞİÖÇ\n",              // L3
            "namespace Demo.Services {\n",                // L4
            "    public interface IRunner {\n",           // L5
            "        void Run();\n",                      // L6
            "    }\n",                                    // L7
            "    public class Alpha : IRunner {\n",       // L8
            "        public string Name { get; set; }\n", // L9
            "        public Alpha(string name) {\n",      // L10
            "            Name = name;\n",                 // L11
            "        }\n",                                // L12
            "        public void Run() {\n",              // L13
            "            Console.WriteLine(Name);\n",     // L14
            "        }\n",                                // L15
            "    }\n",                                    // L16
            "    public class Beta : IRunner {\n",        // L17
            "        public void Run() {\n",              // L18
            "            Console.WriteLine(\"beta\");\n", // L19
            "        }\n",                                // L20
            "    }\n",                                    // L21
            "}\n",                                        // L22
        ),
    );
    proj.write(
        "src/Broken.cs",
        "namespace Bad { class Oops { void X( ; }\n",
    );

    let mut idx = open_ro_index(&proj, &cache);

    let models_rel = RelPath::normalize("src/Models/Order.cs").unwrap();
    let models_out = outline_file(&mut idx, &models_rel, None).unwrap();
    assert_eq!(models_out.trust, TrustLevel::VerifiedAst);
    let m_syms = &models_out.data.files[0].symbols;
    assert!(
        m_syms
            .iter()
            .any(|s| s.qualified_name == "Demo.Models" && s.kind == SymbolKind::Module)
    );
    assert!(
        m_syms
            .iter()
            .any(|s| s.qualified_name == "Demo.Models::Order" && s.kind == SymbolKind::Class)
    );
    assert!(
        m_syms
            .iter()
            .any(|s| s.qualified_name == "Demo.Models::Point" && s.kind == SymbolKind::Struct)
    );
    assert!(
        m_syms
            .iter()
            .any(|s| s.qualified_name == "Demo.Models::OrderState" && s.kind == SymbolKind::Enum)
    );
    assert!(
        m_syms
            .iter()
            .any(|s| s.qualified_name == "Demo.Models::OnOrder" && s.kind == SymbolKind::TypeAlias)
    );

    let eng_rel = RelPath::normalize("src/Services/Engine.cs").unwrap();
    let eng_out = outline_file(&mut idx, &eng_rel, None).unwrap();
    assert_eq!(eng_out.trust, TrustLevel::VerifiedAst);
    let e_syms = &eng_out.data.files[0].symbols;
    assert!(e_syms.iter().any(
        |s| s.qualified_name == "Demo.Services::Alpha::Name" && s.kind == SymbolKind::Variable
    ));
    assert!(
        e_syms
            .iter()
            .any(|s| s.qualified_name == "Demo.Services::Alpha::Alpha"
                && s.kind == SymbolKind::Method)
    );

    // Ambiguous `Run` across IRunner, Alpha, Beta -> AMBIGUOUS_SYMBOL.
    let amb = read_symbol(&mut idx, &eng_rel, "Run").unwrap();
    assert_eq!(amb.data.status, ReadStatus::AmbiguousSymbol);
    assert_eq!(amb.data.candidates.len(), 3);

    let exact = read_symbol(&mut idx, &eng_rel, "Demo.Services::Beta::Run").unwrap();
    assert_eq!(exact.data.status, ReadStatus::Ok);
    assert!(exact.data.content.unwrap().contains("\"beta\""));

    // Fail-closed on broken C#.
    let broken = outline_file(
        &mut idx,
        &RelPath::normalize("src/Broken.cs").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(broken.trust, TrustLevel::UnparsedFallback);
    assert!(broken.data.files[0].symbols.is_empty());
}

#[test]
fn php_analyzer_outline_read_ambiguous_graph_utf8_and_fail_closed() {
    let proj = TempWorkspace::new("php-lang");
    let cache = TempWorkspace::new("php-lang-cache");

    proj.write(
        "src/App/Models/User.php",
        concat!(
            "<?php\n",
            "namespace App\\Models;\n",
            "class User {\n",
            "    public function id(): int { return 1; }\n",
            "}\n",
        ),
    );
    proj.write(
        "src/App/helper.php",
        "<?php\nfunction boot_helper(): int { return 7; }\n",
    );
    let service_php = concat!(
        "<?php\n",                                   // L1
        "namespace App\\Billing;\n",                 // L2
        "use App\\Models\\User;\n",                  // L3
        "require_once '../helper.php';\n",           // L4
        "// Türkçe yorum: ğüşiöçĞÜŞİÖÇ\n",           // L5
        "const TAX_RATE = 20;\n",                    // L6
        "interface Payable {\n",                     // L7
        "    public function run(): int;\n",         // L8
        "}\n",                                       // L9
        "trait Auditable {\n",                       // L10
        "    public function audit(): void {}\n",    // L11
        "}\n",                                       // L12
        "enum Currency: string {\n",                 // L13
        "    case TRY = 'TRY';\n",                   // L14
        "}\n",                                       // L15
        "class Invoice implements Payable {\n",      // L16
        "    use Auditable;\n",                      // L17
        "    public function run(): int {\n",        // L18
        "        return TAX_RATE;\n",                // L19
        "    }\n",                                   // L20
        "}\n",                                       // L21
        "function format_total(int $v): string {\n", // L22
        "    return (string)$v;\n",                  // L23
        "}\n",                                       // L24
    );
    proj.write("src/App/Billing/Service.php", service_php);
    proj.write("src/Broken.php", "<?php class Bad { function x( { }\n");

    // Verify `read_context.rs` captures PHP `use ` and `require_once`.
    let imports_ctx = extract_imports_from_source("src/App/Billing/Service.php", service_php);
    assert!(
        imports_ctx
            .context
            .lines
            .iter()
            .any(|l| l.contains("use App\\Models\\User;"))
    );
    assert!(
        imports_ctx
            .context
            .lines
            .iter()
            .any(|l| l.contains("require_once"))
    );

    let mut idx = open_ro_index(&proj, &cache);
    let rel = RelPath::normalize("src/App/Billing/Service.php").unwrap();
    let out = outline_file(&mut idx, &rel, None).unwrap();
    assert_eq!(out.trust, TrustLevel::VerifiedAst);
    let syms = &out.data.files[0].symbols;
    let find_sym = |q: &str| {
        syms.iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing PHP symbol `{q}` in {syms:#?}"))
    };
    assert_eq!(find_sym("App::Billing").kind, SymbolKind::Module);
    assert_eq!(find_sym("App::Billing::TAX_RATE").kind, SymbolKind::Const);
    assert_eq!(
        find_sym("App::Billing::Payable").kind,
        SymbolKind::Interface
    );
    assert_eq!(find_sym("App::Billing::Auditable").kind, SymbolKind::Trait);
    assert_eq!(find_sym("App::Billing::Currency").kind, SymbolKind::Enum);
    assert_eq!(find_sym("App::Billing::Invoice").kind, SymbolKind::Class);
    assert_eq!(
        find_sym("App::Billing::Invoice::run").kind,
        SymbolKind::Method
    );
    assert_eq!(
        find_sym("App::Billing::format_total").kind,
        SymbolKind::Function
    );

    let amb = read_symbol(&mut idx, &rel, "run").unwrap();
    assert_eq!(amb.data.status, ReadStatus::AmbiguousSymbol);
    assert_eq!(amb.data.candidates.len(), 2);

    let exact = read_symbol(&mut idx, &rel, "App::Billing::Invoice::run").unwrap();
    assert_eq!(exact.data.status, ReadStatus::Ok);
    assert!(exact.data.content.unwrap().contains("return TAX_RATE;"));

    let broken = outline_file(
        &mut idx,
        &RelPath::normalize("src/Broken.php").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(broken.trust, TrustLevel::UnparsedFallback);
    assert!(broken.data.files[0].symbols.is_empty());

    let g = build_code_graph(&mut idx).unwrap();
    assert!(g.data.edges.iter().any(|e| {
        e.from == "file:src/App/Billing/Service.php" && e.to == "file:src/App/Models/User.php"
    }));
    assert!(g.data.edges.iter().any(|e| {
        e.from == "file:src/App/Billing/Service.php" && e.to == "file:src/App/helper.php"
    }));
}

#[test]
fn ruby_analyzer_outline_read_ambiguous_graph_utf8_and_fail_closed() {
    let proj = TempWorkspace::new("ruby-lang");
    let cache = TempWorkspace::new("ruby-lang-cache");

    proj.write("lib/tax.rb", "module Tax\n  RATE = 20\nend\n");
    let invoice_rb = concat!(
        "require 'json'\n",               // L1
        "require_relative 'tax'\n",       // L2
        "# Türkçe yorum: ğüşiöçĞÜŞİÖÇ\n", // L3
        "DEFAULT_CURRENCY = 'TRY'\n",     // L4
        "module Billing\n",               // L5
        "  class Invoice\n",              // L6
        "    def self.build(amount)\n",   // L7
        "      new(amount)\n",            // L8
        "    end\n",                      // L9
        "    def total\n",                // L10
        "      100\n",                    // L11
        "    end\n",                      // L12
        "  end\n",                        // L13
        "  class Receipt\n",              // L14
        "    def total\n",                // L15
        "      200\n",                    // L16
        "    end\n",                      // L17
        "  end\n",                        // L18
        "end\n",                          // L19
    );
    proj.write("lib/invoice.rb", invoice_rb);
    proj.write("lib/broken.rb", "module Bad\n  def oops(\n");

    // Verify `read_context.rs` captures Ruby `require` and `require_relative`.
    let imports_ctx = extract_imports_from_source("lib/invoice.rb", invoice_rb);
    assert!(
        imports_ctx
            .context
            .lines
            .iter()
            .any(|l| l.contains("require 'json'"))
    );
    assert!(
        imports_ctx
            .context
            .lines
            .iter()
            .any(|l| l.contains("require_relative 'tax'"))
    );

    let mut idx = open_ro_index(&proj, &cache);
    let rel = RelPath::normalize("lib/invoice.rb").unwrap();
    let out = outline_file(&mut idx, &rel, None).unwrap();
    assert_eq!(out.trust, TrustLevel::VerifiedAst);
    let syms = &out.data.files[0].symbols;
    let find_sym = |q: &str| {
        syms.iter()
            .find(|s| s.qualified_name == q)
            .unwrap_or_else(|| panic!("missing Ruby symbol `{q}` in {syms:#?}"))
    };
    assert_eq!(find_sym("DEFAULT_CURRENCY").kind, SymbolKind::Const);
    assert_eq!(find_sym("Billing").kind, SymbolKind::Module);
    assert_eq!(find_sym("Billing::Invoice").kind, SymbolKind::Class);
    assert_eq!(
        find_sym("Billing::Invoice::self.build").kind,
        SymbolKind::Method
    );
    assert_eq!(find_sym("Billing::Invoice::total").kind, SymbolKind::Method);
    assert_eq!(find_sym("Billing::Receipt::total").kind, SymbolKind::Method);

    // Ambiguous `total` -> AMBIGUOUS_SYMBOL; qualified `Billing::Receipt::total` -> exact read!
    let amb = read_symbol(&mut idx, &rel, "total").unwrap();
    assert_eq!(amb.data.status, ReadStatus::AmbiguousSymbol);
    assert_eq!(amb.data.candidates.len(), 2);

    let exact = read_symbol(&mut idx, &rel, "Billing::Receipt::total").unwrap();
    assert_eq!(exact.data.status, ReadStatus::Ok);
    assert!(exact.data.content.unwrap().contains("200"));

    let singleton = read_symbol(&mut idx, &rel, "Billing::Invoice::self.build").unwrap();
    assert_eq!(singleton.data.status, ReadStatus::Ok);
    assert_eq!(singleton.data.start_line, Some(7));

    // Fail-closed on broken Ruby.
    let broken = outline_file(
        &mut idx,
        &RelPath::normalize("lib/broken.rb").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(broken.trust, TrustLevel::UnparsedFallback);
    assert!(broken.data.files[0].symbols.is_empty());

    // Determinism across map, find, and graph + `require_relative 'tax'` resolution.
    let map1 = build_project_map(&mut idx, 2000)
        .unwrap()
        .to_deterministic_json()
        .unwrap();
    let map2 = build_project_map(&mut idx, 2000)
        .unwrap()
        .to_deterministic_json()
        .unwrap();
    assert_eq!(map1, map2);

    let find1 = find_in_workspace(&mut idx, "Invoice", 20)
        .unwrap()
        .to_deterministic_json()
        .unwrap();
    let find2 = find_in_workspace(&mut idx, "Invoice", 20)
        .unwrap()
        .to_deterministic_json()
        .unwrap();
    assert_eq!(find1, find2);

    let g1 = build_code_graph(&mut idx).unwrap();
    let g2 = build_code_graph(&mut idx).unwrap();
    assert_eq!(
        g1.to_deterministic_json().unwrap(),
        g2.to_deterministic_json().unwrap()
    );
    assert!(
        g1.data
            .edges
            .iter()
            .any(|e| { e.from == "file:lib/invoice.rb" && e.to == "file:lib/tax.rb" })
    );
}
