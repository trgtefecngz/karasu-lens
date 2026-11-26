pub mod c_lang;
pub(crate) mod common;
pub mod cpp;
pub mod csharp;
pub mod go;
pub mod java;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust_lang;
pub mod structured_doc;
pub mod ts_js;

use klens_core::{LanguageAnalyzer, RelPath};
use tree_sitter::{Language, Parser};

use crate::error::CodeError;

pub use c_lang::CAnalyzer;
pub use cpp::CppAnalyzer;
pub use csharp::CSharpAnalyzer;
pub use go::GoAnalyzer;
pub use java::JavaAnalyzer;
pub use php::PhpAnalyzer;
pub use python::PythonAnalyzer;
pub use ruby::RubyAnalyzer;
pub use rust_lang::RustAnalyzer;
pub use structured_doc::StructuredDocAnalyzer;
pub use ts_js::TsJsAnalyzer;

/// ABI metadata reported by [`verify_tree_sitter_abi`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrammarAbiInfo {
    pub language_id: &'static str,
    pub abi_version: usize,
}

/// Verify that all 10 locked Tree-sitter languages (11 grammars including TSX)
/// load cleanly against the workspace `tree-sitter` ABI without panicking.
pub fn verify_tree_sitter_abi() -> Result<Vec<GrammarAbiInfo>, CodeError> {
    let grammars: [(&'static str, Language, &'static str); 11] = [
        ("rust", tree_sitter_rust::LANGUAGE.into(), "fn ok() {}"),
        (
            "typescript",
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            "export const x: number = 1;",
        ),
        (
            "tsx",
            tree_sitter_typescript::LANGUAGE_TSX.into(),
            "export const App = () => <div />;",
        ),
        (
            "python",
            tree_sitter_python::LANGUAGE.into(),
            "def ok():\n    return 1\n",
        ),
        (
            "go",
            tree_sitter_go::LANGUAGE.into(),
            "package main\nfunc ok() {}\n",
        ),
        (
            "c",
            tree_sitter_c::LANGUAGE.into(),
            "int ok(void) { return 1; }\n",
        ),
        (
            "cpp",
            tree_sitter_cpp::LANGUAGE.into(),
            "namespace app { int ok() { return 1; } }\n",
        ),
        (
            "java",
            tree_sitter_java::LANGUAGE.into(),
            "class Ok { int run() { return 1; } }\n",
        ),
        (
            "csharp",
            tree_sitter_c_sharp::LANGUAGE.into(),
            "namespace App { class Ok { int Run() => 1; } }\n",
        ),
        (
            "php",
            tree_sitter_php::LANGUAGE_PHP.into(),
            "<?php function ok(): int { return 1; }\n",
        ),
        (
            "ruby",
            tree_sitter_ruby::LANGUAGE.into(),
            "def ok\n  1\nend\n",
        ),
    ];

    let mut infos = Vec::with_capacity(grammars.len());
    for (id, lang, sample) in grammars {
        let abi_version = lang.abi_version();
        if !(tree_sitter::MIN_COMPATIBLE_LANGUAGE_VERSION..=tree_sitter::LANGUAGE_VERSION)
            .contains(&abi_version)
        {
            return Err(CodeError::TreeSitterAbi {
                language: id.to_string(),
                reason: format!(
                    "ABI {abi_version} outside supported range {}..={}",
                    tree_sitter::MIN_COMPATIBLE_LANGUAGE_VERSION,
                    tree_sitter::LANGUAGE_VERSION
                ),
            });
        }

        let mut parser = Parser::new();
        parser
            .set_language(&lang)
            .map_err(|err| CodeError::TreeSitterAbi {
                language: id.to_string(),
                reason: err.to_string(),
            })?;

        let tree = parser
            .parse(sample, None)
            .ok_or_else(|| CodeError::TreeSitterAbi {
                language: id.to_string(),
                reason: "parser returned None on smoke snippet".to_string(),
            })?;
        if tree.root_node().has_error() {
            return Err(CodeError::TreeSitterAbi {
                language: id.to_string(),
                reason: "smoke snippet produced syntax error".to_string(),
            });
        }

        infos.push(GrammarAbiInfo {
            language_id: id,
            abi_version,
        });
    }

    Ok(infos)
}

/// Registry of all Phase 1A [`LanguageAnalyzer`] implementations.
pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn LanguageAnalyzer>>,
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyzerRegistry {
    /// Create the default built-in registry:
    /// 10 Tree-sitter programming languages + 1 pure-Rust structured document analyzer.
    pub fn new() -> Self {
        Self {
            analyzers: vec![
                Box::new(RustAnalyzer),
                Box::new(TsJsAnalyzer),
                Box::new(PythonAnalyzer),
                Box::new(GoAnalyzer),
                Box::new(CAnalyzer),
                Box::new(CppAnalyzer),
                Box::new(JavaAnalyzer),
                Box::new(CSharpAnalyzer),
                Box::new(PhpAnalyzer),
                Box::new(RubyAnalyzer),
                Box::new(StructuredDocAnalyzer),
            ],
        }
    }

    /// Return the deterministic sorted set of all built-in file extensions owned by core AST/doc analyzers.
    pub fn all_extensions(&self) -> std::collections::BTreeSet<String> {
        let mut set = std::collections::BTreeSet::new();
        for analyzer in &self.analyzers {
            for ext in analyzer.extensions() {
                set.insert((*ext).to_string());
            }
        }
        set
    }

    /// Resolve the matching [`LanguageAnalyzer`] for a normalized relative path.
    pub fn analyzer_for_path(&self, path: &RelPath) -> Option<&dyn LanguageAnalyzer> {
        let lower = path.as_str().to_ascii_lowercase();
        let file_name = lower.rsplit('/').next().unwrap_or(&lower);

        // Handle compound extensions (e.g. `.d.ts`) first, then regular extensions.
        for analyzer in &self.analyzers {
            for ext in analyzer.extensions() {
                if ext.contains('.') {
                    let suffix = format!(".{ext}");
                    if file_name.ends_with(&suffix) {
                        return Some(analyzer.as_ref());
                    }
                }
            }
        }

        let ext = file_name.rsplit_once('.')?.1;
        for analyzer in &self.analyzers {
            if analyzer.extensions().contains(&ext) {
                return Some(analyzer.as_ref());
            }
        }

        None
    }
}
