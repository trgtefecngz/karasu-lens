use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for C# (`.cs`).
pub struct CSharpAnalyzer;

impl LanguageAnalyzer for CSharpAnalyzer {
    fn language_id(&self) -> &'static str {
        "csharp"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["cs"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_c_sharp::LANGUAGE.into();
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
        let language = tree_sitter_c_sharp::LANGUAGE.into();
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
    let mut active_ns: Option<String> = None;
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        let current_parent = active_ns.as_deref().or(parent);
        match child.kind() {
            "namespace_declaration" => {
                extract_container(child, SymbolKind::Module, source, current_parent, out);
            }
            "file_scoped_namespace_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = normalize_signature(node_text(name_node, source)).replace(' ', "");
                    if !name.is_empty() {
                        let scope = qualify(parent, &name);
                        let (start_line, end_line) = line_range(child);
                        let signature = format!("namespace {name}");
                        out.push(SymbolInfo {
                            name,
                            qualified_name: scope.clone(),
                            kind: SymbolKind::Module,
                            signature,
                            start_line,
                            end_line,
                            parent: parent.map(str::to_string),
                        });
                        // Handle both tree-sitter layouts: nested declarations or subsequent siblings.
                        collect_declarations(child, source, Some(&scope), out);
                        active_ns = Some(scope);
                    }
                }
            }
            "class_declaration" => {
                extract_container(child, SymbolKind::Class, source, current_parent, out);
            }
            "struct_declaration" => {
                extract_container(child, SymbolKind::Struct, source, current_parent, out);
            }
            "interface_declaration" => {
                extract_container(child, SymbolKind::Interface, source, current_parent, out);
            }
            "enum_declaration" => {
                extract_container(child, SymbolKind::Enum, source, current_parent, out);
            }
            "record_declaration" => {
                let head = signature_until(child, child.child_by_field_name("body"), source);
                let kind = if head.contains("record struct") {
                    SymbolKind::Struct
                } else {
                    SymbolKind::Class
                };
                extract_container(child, kind, source, current_parent, out);
            }
            "method_declaration" | "constructor_declaration" => {
                extract_callable(child, source, current_parent, out);
            }
            "property_declaration" => {
                extract_property(child, source, current_parent, out);
            }
            "delegate_declaration" => {
                extract_delegate(child, source, current_parent, out);
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
    let name = normalize_signature(node_text(name_node, source)).replace(' ', "");
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
    let body = node.child_by_field_name("body");
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, body, source);
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

fn extract_property(node: Node<'_>, source: &str, parent: Option<&str>, out: &mut Vec<SymbolInfo>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim().to_string();
    if name.is_empty() {
        return;
    }
    let accessors = node.child_by_field_name("accessors");
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, accessors, source);
    out.push(SymbolInfo {
        name: name.clone(),
        qualified_name: qualify(parent, &name),
        kind: SymbolKind::Variable,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });
}

fn extract_delegate(node: Node<'_>, source: &str, parent: Option<&str>, out: &mut Vec<SymbolInfo>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim().to_string();
    if name.is_empty() {
        return;
    }
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, None, source);
    out.push(SymbolInfo {
        name: name.clone(),
        qualified_name: qualify(parent, &name),
        kind: SymbolKind::TypeAlias,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });
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
        if node.kind() == "using_directive" {
            let raw = normalize_signature(node_text(node, source));
            let mut rest = raw.trim().trim_end_matches(';').trim();
            if let Some(after) = rest.strip_prefix("global ") {
                rest = after.trim();
            }
            if let Some(after) = rest.strip_prefix("using ") {
                rest = after.trim();
            }
            if let Some(after) = rest.strip_prefix("static ") {
                rest = after.trim();
            }
            if let Some((_, rhs)) = rest.split_once('=') {
                rest = rhs.trim();
            }
            let target = rest.replace(' ', "");
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
            continue;
        }
        if matches!(
            node.kind(),
            "compilation_unit"
                | "namespace_declaration"
                | "file_scoped_namespace_declaration"
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
