use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for Go (`.go`).
pub struct GoAnalyzer;

impl LanguageAnalyzer for GoAnalyzer {
    fn language_id(&self) -> &'static str {
        "go"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["go"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_go::LANGUAGE.into();
        let tree = match parse_tree_strict(&language, source) {
            Ok(t) => t,
            Err(reason) => return ParseOutcome::Fallback { reason },
        };

        let mut symbols = Vec::new();
        collect_top_level(tree.root_node(), source, &mut symbols);

        ParseOutcome::Parsed(FileSymbols {
            path: path.clone(),
            language_id: self.language_id().to_string(),
            symbols,
        })
    }

    fn extract_edges(&self, source: &str, symbols: &FileSymbols) -> Vec<CodeEdge> {
        let language = tree_sitter_go::LANGUAGE.into();
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

fn collect_top_level(root: Node<'_>, source: &str, out: &mut Vec<SymbolInfo>) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                let Some(name_node) = child.child_by_field_name("name") else {
                    continue;
                };
                let name = node_text(name_node, source).trim().to_string();
                if name.is_empty() {
                    continue;
                }
                let (start_line, end_line) = line_range(child);
                let signature = signature_until(child, child.child_by_field_name("body"), source);
                out.push(SymbolInfo {
                    name: name.clone(),
                    qualified_name: format!("func {name}"),
                    kind: SymbolKind::Function,
                    signature,
                    start_line,
                    end_line,
                    parent: None,
                });
            }
            "method_declaration" => {
                let Some(name_node) = child.child_by_field_name("name") else {
                    continue;
                };
                let name = node_text(name_node, source).trim().to_string();
                if name.is_empty() {
                    continue;
                }
                let receiver_raw = child
                    .child_by_field_name("receiver")
                    .map(|n| normalize_signature(node_text(n, source)))
                    .unwrap_or_default();
                let parent_type = extract_receiver_type(&receiver_raw);
                let qualified_name = if receiver_raw.is_empty() {
                    format!("func {name}")
                } else {
                    format!("{receiver_raw} {name}")
                };
                let (start_line, end_line) = line_range(child);
                let signature = signature_until(child, child.child_by_field_name("body"), source);
                out.push(SymbolInfo {
                    name,
                    qualified_name,
                    kind: SymbolKind::Method,
                    signature,
                    start_line,
                    end_line,
                    parent: parent_type,
                });
            }
            "type_declaration" => {
                let mut spec_cursor = child.walk();
                let specs: Vec<Node<'_>> = child
                    .children(&mut spec_cursor)
                    .filter(|c| matches!(c.kind(), "type_spec" | "type_alias"))
                    .collect();
                let single = specs.len() == 1;
                for spec in specs {
                    extract_type_spec(child, spec, single, source, out);
                }
            }
            "const_declaration" => {
                extract_value_specs(child, "const_spec", SymbolKind::Const, "const", source, out);
            }
            "var_declaration" => {
                extract_value_specs(child, "var_spec", SymbolKind::Variable, "var", source, out);
            }
            _ => {}
        }
    }
}

fn extract_type_spec(
    decl_node: Node<'_>,
    spec: Node<'_>,
    single: bool,
    source: &str,
    out: &mut Vec<SymbolInfo>,
) {
    let Some(name_node) = spec.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim().to_string();
    if name.is_empty() {
        return;
    }

    let type_node = spec.child_by_field_name("type");
    let (kind, prefix) = match type_node.map(|t| t.kind()) {
        Some("struct_type") => (SymbolKind::Struct, "struct"),
        Some("interface_type") => (SymbolKind::Interface, "interface"),
        _ => (SymbolKind::TypeAlias, "type"),
    };

    let (start_line, end_line) = if single {
        line_range(decl_node)
    } else {
        line_range(spec)
    };
    let sig_node = if single { decl_node } else { spec };
    let body_for_sig = type_node.and_then(|t| match t.kind() {
        "struct_type" | "interface_type" => find_brace_child(t),
        _ => None,
    });
    let signature = signature_until(sig_node, body_for_sig, source);
    let qualified_name = format!("{prefix} {name}");

    out.push(SymbolInfo {
        name,
        qualified_name: qualified_name.clone(),
        kind,
        signature,
        start_line,
        end_line,
        parent: None,
    });

    // Extract interface method signatures.
    if let Some(iface) = type_node.filter(|t| t.kind() == "interface_type") {
        let mut cursor = iface.walk();
        for elem in iface.children(&mut cursor) {
            if elem.kind() == "method_elem"
                && let Some(mname_node) = elem.child_by_field_name("name")
            {
                let mname = node_text(mname_node, source).trim().to_string();
                if mname.is_empty() {
                    continue;
                }
                let (mstart, mend) = line_range(elem);
                let msig = normalize_signature(node_text(elem, source));
                out.push(SymbolInfo {
                    name: mname.clone(),
                    qualified_name: format!("{qualified_name}.{mname}"),
                    kind: SymbolKind::Method,
                    signature: msig,
                    start_line: mstart,
                    end_line: mend,
                    parent: Some(qualified_name.clone()),
                });
            }
        }
    }
}

fn find_brace_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|c| c.kind() == "field_declaration_list" || c.kind() == "{")
}

fn extract_value_specs(
    decl_node: Node<'_>,
    spec_kind: &str,
    sym_kind: SymbolKind,
    prefix: &str,
    source: &str,
    out: &mut Vec<SymbolInfo>,
) {
    let mut cursor = decl_node.walk();
    let specs: Vec<Node<'_>> = decl_node
        .children(&mut cursor)
        .filter(|c| c.kind() == spec_kind)
        .collect();
    let single_spec = specs.len() == 1;

    for spec in specs {
        let mut name_cursor = spec.walk();
        let names: Vec<Node<'_>> = spec
            .children_by_field_name("name", &mut name_cursor)
            .collect();
        let (start_line, end_line) = if single_spec {
            line_range(decl_node)
        } else {
            line_range(spec)
        };
        let sig_node = if single_spec { decl_node } else { spec };
        let signature = normalize_signature(node_text(sig_node, source));

        for name_node in names {
            let name = node_text(name_node, source).trim().to_string();
            if name.is_empty() || name == "_" {
                continue;
            }
            out.push(SymbolInfo {
                name: name.clone(),
                qualified_name: format!("{prefix} {name}"),
                kind: sym_kind,
                signature: signature.clone(),
                start_line,
                end_line,
                parent: None,
            });
        }
    }
}

fn extract_receiver_type(receiver: &str) -> Option<String> {
    let inner = receiver
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    if inner.is_empty() {
        return None;
    }
    let last_token = inner.split_whitespace().last()?;
    let cleaned = last_token.trim_start_matches('*');
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
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
        if node.kind() == "import_spec" {
            if let Some(path_node) = node.child_by_field_name("path") {
                let target = node_text(path_node, source).trim().trim_matches(['"', '`']);
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
            "source_file" | "import_declaration" | "import_spec_list"
        ) {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }
}
