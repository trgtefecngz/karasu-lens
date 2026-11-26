use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for Rust (`.rs`).
pub struct RustAnalyzer;

impl LanguageAnalyzer for RustAnalyzer {
    fn language_id(&self) -> &'static str {
        "rust"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rs"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_rust::LANGUAGE.into();
        let tree = match parse_tree_strict(&language, source) {
            Ok(t) => t,
            Err(reason) => return ParseOutcome::Fallback { reason },
        };

        let mut symbols = Vec::new();
        collect_items(tree.root_node(), source, None, &mut symbols);

        ParseOutcome::Parsed(FileSymbols {
            path: path.clone(),
            language_id: self.language_id().to_string(),
            symbols,
        })
    }

    fn extract_edges(&self, source: &str, symbols: &FileSymbols) -> Vec<CodeEdge> {
        let language = tree_sitter_rust::LANGUAGE.into();
        let Ok(tree) = parse_tree_strict(&language, source) else {
            return Vec::new();
        };

        let mut edges = Vec::new();
        let from_file = format!("file:{}", symbols.path.as_str());
        collect_edges(
            tree.root_node(),
            source,
            &from_file,
            symbols.path.as_str(),
            &mut edges,
        );
        edges.sort();
        edges.dedup();
        edges
    }
}

fn qualify(parent: Option<&str>, local: &str) -> String {
    match parent {
        Some(p) => format!("{p}::{local}"),
        None => local.to_string(),
    }
}

fn collect_items(
    container: Node<'_>,
    source: &str,
    parent: Option<&str>,
    out: &mut Vec<SymbolInfo>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "function_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let signature =
                        signature_until(child, child.child_by_field_name("body"), source);
                    let (kind, qualified_name) = match parent {
                        Some(p)
                            if p.starts_with("impl ")
                                || p.contains("::impl ")
                                || p.starts_with("trait ")
                                || p.contains("::trait ") =>
                        {
                            (SymbolKind::Method, format!("{p}::{name}"))
                        }
                        Some(p) => (SymbolKind::Function, format!("{p}::fn {name}")),
                        None => (SymbolKind::Function, format!("fn {name}")),
                    };
                    out.push(SymbolInfo {
                        name,
                        qualified_name,
                        kind,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                }
            }
            "function_signature_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let signature = signature_until(child, None, source);
                    let is_trait_member =
                        parent.is_some_and(|p| p.starts_with("trait ") || p.contains("::trait "));
                    let kind = if is_trait_member {
                        SymbolKind::Method
                    } else {
                        SymbolKind::Function
                    };
                    let qualified_name = match parent {
                        Some(p) => format!("{p}::{name}"),
                        None => format!("fn {name}"),
                    };
                    out.push(SymbolInfo {
                        name,
                        qualified_name,
                        kind,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                }
            }
            "macro_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let signature = format!("macro_rules! {name}");
                    let qualified_name = qualify(parent, &signature);
                    out.push(SymbolInfo {
                        name,
                        qualified_name,
                        kind: SymbolKind::Macro,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                }
            }
            "struct_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let signature =
                        signature_until(child, child.child_by_field_name("body"), source);
                    let qualified_name = qualify(parent, &format!("struct {name}"));
                    out.push(SymbolInfo {
                        name,
                        qualified_name,
                        kind: SymbolKind::Struct,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                }
            }
            "enum_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let signature =
                        signature_until(child, child.child_by_field_name("body"), source);
                    let qualified_name = qualify(parent, &format!("enum {name}"));
                    out.push(SymbolInfo {
                        name,
                        qualified_name,
                        kind: SymbolKind::Enum,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                }
            }
            "trait_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let body = child.child_by_field_name("body");
                    let signature = signature_until(child, body, source);
                    let trait_scope = qualify(parent, &format!("trait {name}"));
                    out.push(SymbolInfo {
                        name,
                        qualified_name: trait_scope.clone(),
                        kind: SymbolKind::Trait,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                    if let Some(body_node) = body {
                        collect_items(body_node, source, Some(&trait_scope), out);
                    }
                }
            }
            "impl_item" => {
                let target_type = child
                    .child_by_field_name("type")
                    .map(|n| normalize_signature(node_text(n, source)))
                    .unwrap_or_default();
                if target_type.is_empty() {
                    continue;
                }
                let trait_part = child
                    .child_by_field_name("trait")
                    .map(|n| normalize_signature(node_text(n, source)));
                let local_impl = match trait_part {
                    Some(tr) if !tr.is_empty() => format!("impl {tr} for {target_type}"),
                    _ => format!("impl {target_type}"),
                };
                let impl_scope = qualify(parent, &local_impl);
                let (start_line, end_line) = line_range(child);
                let body = child.child_by_field_name("body");
                let signature = signature_until(child, body, source);
                out.push(SymbolInfo {
                    name: local_impl,
                    qualified_name: impl_scope.clone(),
                    kind: SymbolKind::Other,
                    signature,
                    start_line,
                    end_line,
                    parent: parent.map(str::to_string),
                });
                if let Some(body_node) = body {
                    collect_items(body_node, source, Some(&impl_scope), out);
                }
            }
            "type_item" | "associated_type" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let signature = signature_until(child, None, source);
                    let qualified_name = match parent {
                        Some(p)
                            if p.starts_with("impl ")
                                || p.contains("::impl ")
                                || p.starts_with("trait ")
                                || p.contains("::trait ") =>
                        {
                            format!("{p}::{name}")
                        }
                        Some(p) => format!("{p}::type {name}"),
                        None => format!("type {name}"),
                    };
                    out.push(SymbolInfo {
                        name,
                        qualified_name,
                        kind: SymbolKind::TypeAlias,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                }
            }
            "const_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let signature = signature_until(child, None, source);
                    let qualified_name = match parent {
                        Some(p)
                            if p.starts_with("impl ")
                                || p.contains("::impl ")
                                || p.starts_with("trait ")
                                || p.contains("::trait ") =>
                        {
                            format!("{p}::{name}")
                        }
                        Some(p) => format!("{p}::const {name}"),
                        None => format!("const {name}"),
                    };
                    out.push(SymbolInfo {
                        name,
                        qualified_name,
                        kind: SymbolKind::Const,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                }
            }
            "static_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let signature = signature_until(child, None, source);
                    let qualified_name = qualify(parent, &format!("static {name}"));
                    out.push(SymbolInfo {
                        name,
                        qualified_name,
                        kind: SymbolKind::Static,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                }
            }
            "mod_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(child);
                    let body = child.child_by_field_name("body");
                    let signature = signature_until(child, body, source);
                    let mod_scope = qualify(parent, &format!("mod {name}"));
                    out.push(SymbolInfo {
                        name,
                        qualified_name: mod_scope.clone(),
                        kind: SymbolKind::Module,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                    if let Some(body_node) = body {
                        collect_items(body_node, source, Some(&mod_scope), out);
                    }
                }
            }
            "foreign_mod_item" => {
                if let Some(body_node) = child.child_by_field_name("body") {
                    let extern_scope = qualify(parent, "extern");
                    collect_items(body_node, source, Some(&extern_scope), out);
                }
            }
            _ => {}
        }
    }
}

fn collect_edges(
    container: Node<'_>,
    source: &str,
    from_file: &str,
    rel_path: &str,
    out: &mut Vec<CodeEdge>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "use_declaration" => {
                if let Some(arg) = child.child_by_field_name("argument") {
                    let raw = normalize_signature(node_text(arg, source));
                    if !raw.is_empty() {
                        let line = child.start_position().row + 1;
                        out.push(CodeEdge {
                            from: from_file.to_string(),
                            to: format!("import:{raw}"),
                            relation: EdgeRelation::Imports,
                            confidence: EdgeConfidence::Extracted,
                            evidence: format!("{rel_path}:L{line}"),
                        });
                    }
                }
            }
            "mod_item" => {
                if let Some(body) = child.child_by_field_name("body") {
                    collect_edges(body, source, from_file, rel_path, out);
                } else if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim();
                    if !name.is_empty() {
                        let line = child.start_position().row + 1;
                        out.push(CodeEdge {
                            from: from_file.to_string(),
                            to: format!("mod:{name}"),
                            relation: EdgeRelation::Imports,
                            confidence: EdgeConfidence::Extracted,
                            evidence: format!("{rel_path}:L{line}"),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}
