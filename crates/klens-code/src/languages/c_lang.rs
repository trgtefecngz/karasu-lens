use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for C (`.c`, `.h`).
pub struct CAnalyzer;

impl LanguageAnalyzer for CAnalyzer {
    fn language_id(&self) -> &'static str {
        "c"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["c", "h"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_c::LANGUAGE.into();
        let tree = match parse_tree_strict(&language, source) {
            Ok(t) => t,
            Err(reason) => return ParseOutcome::Fallback { reason },
        };

        let mut symbols = Vec::new();
        collect_items(tree.root_node(), source, &mut symbols);

        ParseOutcome::Parsed(FileSymbols {
            path: path.clone(),
            language_id: self.language_id().to_string(),
            symbols,
        })
    }

    fn extract_edges(&self, source: &str, symbols: &FileSymbols) -> Vec<CodeEdge> {
        let language = tree_sitter_c::LANGUAGE.into();
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

fn collect_items(container: Node<'_>, source: &str, out: &mut Vec<SymbolInfo>) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "function_definition" => extract_function(child, source, out),
            "struct_specifier" => {
                extract_tagged_type(child, SymbolKind::Struct, "struct", source, out)
            }
            "enum_specifier" => extract_tagged_type(child, SymbolKind::Enum, "enum", source, out),
            "union_specifier" => {
                extract_tagged_type(child, SymbolKind::Struct, "union", source, out)
            }
            "type_definition" => extract_typedef(child, source, out),
            "preproc_def" | "preproc_function_def" => extract_macro(child, source, out),
            "declaration" => {
                // Capture standalone named `struct Foo { ... };` / `enum Bar { ... };` / `union Baz { ... };`.
                if let Some(ty) = child.child_by_field_name("type") {
                    match ty.kind() {
                        "struct_specifier" => {
                            extract_tagged_type_with_span(
                                ty,
                                child,
                                SymbolKind::Struct,
                                "struct",
                                source,
                                out,
                            );
                        }
                        "enum_specifier" => {
                            extract_tagged_type_with_span(
                                ty,
                                child,
                                SymbolKind::Enum,
                                "enum",
                                source,
                                out,
                            );
                        }
                        "union_specifier" => {
                            extract_tagged_type_with_span(
                                ty,
                                child,
                                SymbolKind::Struct,
                                "union",
                                source,
                                out,
                            );
                        }
                        _ => {}
                    }
                }
            }
            "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif" => {
                collect_items(child, source, out);
            }
            "linkage_specification" => {
                if let Some(body) = child.child_by_field_name("body") {
                    collect_items(body, source, out);
                }
            }
            _ => {}
        }
    }
}

fn extract_function(node: Node<'_>, source: &str, out: &mut Vec<SymbolInfo>) {
    let Some(decl) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_declarator_ident(decl, source) else {
        return;
    };
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, node.child_by_field_name("body"), source);
    out.push(SymbolInfo {
        name: name.clone(),
        qualified_name: format!("fn {name}"),
        kind: SymbolKind::Function,
        signature,
        start_line,
        end_line,
        parent: None,
    });
}

fn extract_tagged_type(
    spec: Node<'_>,
    kind: SymbolKind,
    prefix: &str,
    source: &str,
    out: &mut Vec<SymbolInfo>,
) {
    extract_tagged_type_with_span(spec, spec, kind, prefix, source, out);
}

fn extract_tagged_type_with_span(
    spec: Node<'_>,
    span_node: Node<'_>,
    kind: SymbolKind,
    prefix: &str,
    source: &str,
    out: &mut Vec<SymbolInfo>,
) {
    let Some(body) = spec.child_by_field_name("body") else {
        return;
    };
    let Some(name_node) = spec.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim().to_string();
    if name.is_empty() {
        return;
    }
    let (start_line, end_line) = line_range(span_node);
    let signature = signature_until(spec, Some(body), source);
    out.push(SymbolInfo {
        name: name.clone(),
        qualified_name: format!("{prefix} {name}"),
        kind,
        signature,
        start_line,
        end_line,
        parent: None,
    });
}

fn extract_typedef(node: Node<'_>, source: &str, out: &mut Vec<SymbolInfo>) {
    let mut alias_names = Vec::new();
    let mut cursor = node.walk();
    for decl in node.children_by_field_name("declarator", &mut cursor) {
        if let Some(name) = extract_declarator_ident(decl, source) {
            alias_names.push(name);
        }
    }

    let ty = node.child_by_field_name("type");
    let mut tagged_name: Option<String> = None;
    if let Some(ty_node) = ty {
        let tagged_meta = match ty_node.kind() {
            "struct_specifier" => Some((SymbolKind::Struct, "struct")),
            "enum_specifier" => Some((SymbolKind::Enum, "enum")),
            "union_specifier" => Some((SymbolKind::Struct, "union")),
            _ => None,
        };
        if let Some((kind, prefix)) = tagged_meta
            && ty_node.child_by_field_name("body").is_some()
            && let Some(name_node) = ty_node.child_by_field_name("name")
        {
            let name = node_text(name_node, source).trim().to_string();
            if !name.is_empty() {
                tagged_name = Some(name.clone());
                let (start_line, end_line) = line_range(node);
                let signature =
                    signature_until(ty_node, ty_node.child_by_field_name("body"), source);
                out.push(SymbolInfo {
                    name: name.clone(),
                    qualified_name: format!("{prefix} {name}"),
                    kind,
                    signature,
                    start_line,
                    end_line,
                    parent: None,
                });
            }
        }
    }

    let (start_line, end_line) = line_range(node);
    let sig_body = ty.and_then(|t| t.child_by_field_name("body"));
    let signature = match sig_body {
        Some(body) => signature_until(node, Some(body), source),
        None => signature_until(node, None, source),
    };

    for alias in alias_names {
        if tagged_name.as_deref() == Some(alias.as_str()) {
            continue;
        }
        out.push(SymbolInfo {
            name: alias.clone(),
            qualified_name: format!("typedef {alias}"),
            kind: SymbolKind::TypeAlias,
            signature: signature.clone(),
            start_line,
            end_line,
            parent: None,
        });
    }
}

fn extract_macro(node: Node<'_>, source: &str, out: &mut Vec<SymbolInfo>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim().to_string();
    if name.is_empty() {
        return;
    }
    let (start_line, end_line) = line_range(node);
    let signature = normalize_signature(node_text(node, source));
    out.push(SymbolInfo {
        name: name.clone(),
        qualified_name: format!("#define {name}"),
        kind: SymbolKind::Macro,
        signature,
        start_line,
        end_line,
        parent: None,
    });
}

fn extract_declarator_ident(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => {
            let text = node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        _ => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                return extract_declarator_ident(inner, source);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if let Some(found) = extract_declarator_ident(child, source) {
                    return Some(found);
                }
            }
            None
        }
    }
}

fn collect_edges(
    root: Node<'_>,
    source: &str,
    from_file: &str,
    rel_path: &str,
    out: &mut Vec<CodeEdge>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "preproc_include" {
            if let Some(path_node) = node.child_by_field_name("path") {
                let target = node_text(path_node, source)
                    .trim()
                    .trim_matches(|c| matches!(c, '"' | '<' | '>'));
                if !target.is_empty() {
                    let line = node.start_position().row + 1;
                    out.push(CodeEdge {
                        from: from_file.to_string(),
                        to: format!("import:{target}"),
                        relation: EdgeRelation::Imports,
                        confidence: EdgeConfidence::Extracted,
                        evidence: format!("{rel_path}:L{line}"),
                    });
                }
            }
            continue;
        }
        if matches!(
            node.kind(),
            "translation_unit"
                | "preproc_ifdef"
                | "preproc_if"
                | "preproc_else"
                | "preproc_elif"
                | "linkage_specification"
                | "declaration_list"
        ) {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }
}
