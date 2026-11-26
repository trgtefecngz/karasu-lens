use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for Java (`.java`).
pub struct JavaAnalyzer;

impl LanguageAnalyzer for JavaAnalyzer {
    fn language_id(&self) -> &'static str {
        "java"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["java"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_java::LANGUAGE.into();
        let tree = match parse_tree_strict(&language, source) {
            Ok(t) => t,
            Err(reason) => return ParseOutcome::Fallback { reason },
        };

        let mut symbols = Vec::new();
        collect_declarations(tree.root_node(), source, None, &mut symbols);

        ParseOutcome::Parsed(FileSymbols {
            path: path.clone(),
            language_id: self.language_id().to_string(),
            symbols,
        })
    }

    fn extract_edges(&self, source: &str, symbols: &FileSymbols) -> Vec<CodeEdge> {
        let language = tree_sitter_java::LANGUAGE.into();
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

fn collect_declarations(
    container: Node<'_>,
    source: &str,
    parent: Option<&str>,
    out: &mut Vec<SymbolInfo>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "class_declaration" => {
                extract_container(child, SymbolKind::Class, source, parent, out);
            }
            "interface_declaration" => {
                extract_container(child, SymbolKind::Interface, source, parent, out);
            }
            "enum_declaration" => {
                extract_container(child, SymbolKind::Enum, source, parent, out);
            }
            "record_declaration" => {
                extract_container(child, SymbolKind::Class, source, parent, out);
            }
            "annotation_type_declaration" => {
                extract_container(child, SymbolKind::Interface, source, parent, out);
            }
            "enum_body_declarations" => {
                collect_declarations(child, source, parent, out);
            }
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "annotation_type_element_declaration" => {
                extract_callable(child, source, parent, out);
            }
            "constant_declaration" => {
                extract_constants(child, source, parent, out);
            }
            "field_declaration" if is_static_final(child, source) => {
                extract_constants(child, source, parent, out);
            }
            _ => {}
        }
    }
}

fn extract_container(
    node: Node<'_>,
    kind: SymbolKind,
    source: &str,
    parent: Option<&str>,
    out: &mut Vec<SymbolInfo>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim().to_string();
    if name.is_empty() {
        return;
    }
    let body = node.child_by_field_name("body");
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, body, source);
    let scope = qualify(parent, &name);
    out.push(SymbolInfo {
        name,
        qualified_name: scope.clone(),
        kind,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });
    if let Some(body_node) = body {
        collect_declarations(body_node, source, Some(&scope), out);
    }
}

fn extract_callable(node: Node<'_>, source: &str, parent: Option<&str>, out: &mut Vec<SymbolInfo>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim().to_string();
    if name.is_empty() {
        return;
    }
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, node.child_by_field_name("body"), source);
    out.push(SymbolInfo {
        name: name.clone(),
        qualified_name: qualify(parent, &name),
        kind: SymbolKind::Method,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });
}

fn extract_constants(
    node: Node<'_>,
    source: &str,
    parent: Option<&str>,
    out: &mut Vec<SymbolInfo>,
) {
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, None, source);
    let mut cursor = node.walk();
    for decl in node.children_by_field_name("declarator", &mut cursor) {
        if let Some(name_node) = decl.child_by_field_name("name") {
            let name = node_text(name_node, source).trim().to_string();
            if name.is_empty() {
                continue;
            }
            out.push(SymbolInfo {
                name: name.clone(),
                qualified_name: qualify(parent, &name),
                kind: SymbolKind::Const,
                signature: signature.clone(),
                start_line,
                end_line,
                parent: parent.map(str::to_string),
            });
        }
    }
}

fn is_static_final(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let text = node_text(child, source);
            let mut has_static = false;
            let mut has_final = false;
            for tok in text.split_whitespace() {
                if tok == "static" {
                    has_static = true;
                } else if tok == "final" {
                    has_final = true;
                }
            }
            return has_static && has_final;
        }
    }
    false
}

fn collect_edges(
    root: Node<'_>,
    source: &str,
    from_file: &str,
    rel_path: &str,
    out: &mut Vec<CodeEdge>,
) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "import_declaration" {
            continue;
        }
        let raw = normalize_signature(node_text(child, source));
        let stripped = raw
            .strip_prefix("import ")
            .unwrap_or(&raw)
            .trim()
            .strip_prefix("static ")
            .unwrap_or_else(|| raw.strip_prefix("import ").unwrap_or(&raw).trim())
            .trim()
            .trim_end_matches(';')
            .trim()
            .replace(" . ", ".")
            .replace(" .*", ".*");
        if !stripped.is_empty() {
            let line = child.start_position().row + 1;
            out.push(CodeEdge {
                from: from_file.to_string(),
                to: format!("import:{stripped}"),
                relation: EdgeRelation::Imports,
                confidence: EdgeConfidence::Extracted,
                evidence: format!("{rel_path}:L{line}"),
            });
        }
    }
}
