use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for Python (`.py`, `.pyi`).
pub struct PythonAnalyzer;

impl LanguageAnalyzer for PythonAnalyzer {
    fn language_id(&self) -> &'static str {
        "python"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["py", "pyi"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_python::LANGUAGE.into();
        let tree = match parse_tree_strict(&language, source) {
            Ok(t) => t,
            Err(reason) => return ParseOutcome::Fallback { reason },
        };

        let mut symbols = Vec::new();
        collect_block(tree.root_node(), source, None, &mut symbols);

        ParseOutcome::Parsed(FileSymbols {
            path: path.clone(),
            language_id: self.language_id().to_string(),
            symbols,
        })
    }

    fn extract_edges(&self, source: &str, symbols: &FileSymbols) -> Vec<CodeEdge> {
        let language = tree_sitter_python::LANGUAGE.into();
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

fn collect_block(
    container: Node<'_>,
    source: &str,
    parent: Option<&str>,
    out: &mut Vec<SymbolInfo>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "decorated_definition" => {
                if let Some(inner) = child.child_by_field_name("definition") {
                    let span = line_range(child);
                    handle_definition(inner, source, parent, Some(span), out);
                }
            }
            "function_definition" | "class_definition" => {
                handle_definition(child, source, parent, None, out);
            }
            "expression_statement" if parent.is_none() => {
                extract_top_level_constant(child, source, out);
            }
            _ => {}
        }
    }
}

fn handle_definition(
    node: Node<'_>,
    source: &str,
    parent: Option<&str>,
    span_override: Option<(usize, usize)>,
    out: &mut Vec<SymbolInfo>,
) {
    match node.kind() {
        "function_definition" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, source).trim().to_string();
            if name.is_empty() {
                return;
            }
            let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
            let signature = signature_until(node, node.child_by_field_name("body"), source);
            let is_async = signature.starts_with("async ");
            let (kind, qualified_name) = match parent {
                Some(p) => (SymbolKind::Method, format!("{p}.{name}")),
                None => {
                    let prefix = if is_async { "async def" } else { "def" };
                    (SymbolKind::Function, format!("{prefix} {name}"))
                }
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
        "class_definition" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, source).trim().to_string();
            if name.is_empty() {
                return;
            }
            let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
            let body = node.child_by_field_name("body");
            let signature = signature_until(node, body, source);
            let class_scope = match parent {
                Some(p) => format!("{p}.{name}"),
                None => format!("class {name}"),
            };
            out.push(SymbolInfo {
                name,
                qualified_name: class_scope.clone(),
                kind: SymbolKind::Class,
                signature,
                start_line,
                end_line,
                parent: parent.map(str::to_string),
            });
            if let Some(body_node) = body {
                collect_block(body_node, source, Some(&class_scope), out);
            }
        }
        _ => {}
    }
}

fn extract_top_level_constant(expr_stmt: Node<'_>, source: &str, out: &mut Vec<SymbolInfo>) {
    let Some(assign) = expr_stmt.named_child(0) else {
        return;
    };
    if assign.kind() != "assignment" {
        return;
    }
    let Some(left) = assign.child_by_field_name("left") else {
        return;
    };
    if left.kind() != "identifier" {
        return;
    }
    let name = node_text(left, source).trim();
    if !is_python_constant(name) {
        return;
    }
    let (start_line, end_line) = line_range(expr_stmt);
    let signature = normalize_signature(node_text(expr_stmt, source));
    out.push(SymbolInfo {
        name: name.to_string(),
        qualified_name: format!("const {name}"),
        kind: SymbolKind::Const,
        signature,
        start_line,
        end_line,
        parent: None,
    });
}

fn is_python_constant(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut has_upper = false;
    for ch in name.chars() {
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if !(ch.is_ascii_digit() || ch == '_') {
            return false;
        }
    }
    has_upper
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
            "import_statement" => {
                let line = child.start_position().row + 1;
                let mut inner = child.walk();
                for name_node in child.children_by_field_name("name", &mut inner) {
                    let target = match name_node.kind() {
                        "aliased_import" => name_node
                            .child_by_field_name("name")
                            .map(|n| node_text(n, source))
                            .unwrap_or(""),
                        _ => node_text(name_node, source),
                    }
                    .trim();
                    if !target.is_empty() {
                        out.push(CodeEdge {
                            from: from_file.to_string(),
                            to: format!("import:{target}"),
                            relation: EdgeRelation::Imports,
                            confidence: EdgeConfidence::Extracted,
                            evidence: format!("{rel_path}:L{line}"),
                        });
                    }
                }
            }
            "import_from_statement" => {
                let line = child.start_position().row + 1;
                if let Some(module_node) = child.child_by_field_name("module_name") {
                    let target = normalize_signature(node_text(module_node, source));
                    if !target.is_empty() {
                        out.push(CodeEdge {
                            from: from_file.to_string(),
                            to: format!("import:{target}"),
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
