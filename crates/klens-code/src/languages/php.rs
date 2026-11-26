use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for PHP (`.php`).
pub struct PhpAnalyzer;

impl LanguageAnalyzer for PhpAnalyzer {
    fn language_id(&self) -> &'static str {
        "php"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["php"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_php::LANGUAGE_PHP.into();
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
        let language = tree_sitter_php::LANGUAGE_PHP.into();
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

fn normalize_namespace(raw: &str) -> String {
    raw.trim()
        .trim_matches('\\')
        .split('\\')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("::")
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
            "namespace_definition" => {
                let body = child.child_by_field_name("body");
                let ns_name = child
                    .child_by_field_name("name")
                    .map(|n| normalize_namespace(node_text(n, source)))
                    .unwrap_or_default();
                if !ns_name.is_empty() {
                    let scope = qualify(parent, &ns_name);
                    let (start_line, end_line) = line_range(child);
                    let signature = signature_until(child, body, source);
                    out.push(SymbolInfo {
                        name: ns_name,
                        qualified_name: scope.clone(),
                        kind: SymbolKind::Module,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                    if let Some(body_node) = body {
                        collect_declarations(body_node, source, Some(&scope), out);
                    } else {
                        active_ns = Some(scope);
                    }
                } else if let Some(body_node) = body {
                    collect_declarations(body_node, source, parent, out);
                }
            }
            "class_declaration" => {
                extract_container(child, SymbolKind::Class, source, current_parent, out);
            }
            "interface_declaration" => {
                extract_container(child, SymbolKind::Interface, source, current_parent, out);
            }
            "trait_declaration" => {
                extract_container(child, SymbolKind::Trait, source, current_parent, out);
            }
            "enum_declaration" => {
                extract_container(child, SymbolKind::Enum, source, current_parent, out);
            }
            "function_definition" => {
                extract_callable(child, SymbolKind::Function, source, current_parent, out);
            }
            "method_declaration" => {
                extract_callable(child, SymbolKind::Method, source, current_parent, out);
            }
            "const_declaration" => {
                extract_consts(child, source, current_parent, out);
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

fn extract_callable(
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
    out.push(SymbolInfo {
        name: name.clone(),
        qualified_name: qualify(parent, &name),
        kind,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });
}

fn extract_consts(node: Node<'_>, source: &str, parent: Option<&str>, out: &mut Vec<SymbolInfo>) {
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, None, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "const_element" {
            let name_node = child
                .child_by_field_name("name")
                .or_else(|| child.named_child(0));
            if let Some(nn) = name_node {
                let name = node_text(nn, source).trim().to_string();
                if !name.is_empty() {
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
        match node.kind() {
            "namespace_use_declaration" => {
                extract_use_edges(node, source, from_file, rel_path, out);
                continue;
            }
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression" => {
                if let Some(path) = extract_string_arg(node, source) {
                    let line = node.start_position().row + 1;
                    out.push(CodeEdge {
                        from: from_file.to_string(),
                        to: format!("import:{path}"),
                        relation: EdgeRelation::Imports,
                        confidence: EdgeConfidence::Extracted,
                        evidence: format!("{rel_path}:L{line}"),
                    });
                }
                continue;
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
}

fn extract_use_edges(
    node: Node<'_>,
    source: &str,
    from_file: &str,
    rel_path: &str,
    out: &mut Vec<CodeEdge>,
) {
    let line = node.start_position().row + 1;
    let raw = normalize_signature(node_text(node, source));
    let mut body = raw.trim().trim_end_matches(';').trim();
    if let Some(after) = body.strip_prefix("use ") {
        body = after.trim();
    }
    for kw in ["function ", "const "] {
        if let Some(after) = body.strip_prefix(kw) {
            body = after.trim();
        }
    }
    if let (Some(open), Some(close)) = (body.find('{'), body.rfind('}'))
        && close > open
    {
        let prefix = body[..open].trim().trim_matches('\\');
        for item in body[open + 1..close].split(',') {
            let clean = item
                .split(" as ")
                .next()
                .unwrap_or(item)
                .trim()
                .trim_matches('\\');
            if !clean.is_empty() {
                let target = if prefix.is_empty() {
                    clean.to_string()
                } else {
                    format!("{prefix}\\{clean}")
                };
                out.push(CodeEdge {
                    from: from_file.to_string(),
                    to: format!("import:{target}"),
                    relation: EdgeRelation::Imports,
                    confidence: EdgeConfidence::Extracted,
                    evidence: format!("{rel_path}:L{line}"),
                });
            }
        }
        return;
    }

    for item in body.split(',') {
        let clean = item
            .split(" as ")
            .next()
            .unwrap_or(item)
            .trim()
            .trim_matches('\\');
        if !clean.is_empty() {
            out.push(CodeEdge {
                from: from_file.to_string(),
                to: format!("import:{clean}"),
                relation: EdgeRelation::Imports,
                confidence: EdgeConfidence::Extracted,
                evidence: format!("{rel_path}:L{line}"),
            });
        }
    }
}

fn extract_string_arg(node: Node<'_>, source: &str) -> Option<String> {
    let mut stack = vec![node];
    while let Some(cur) = stack.pop() {
        if matches!(cur.kind(), "string" | "encapsed_string") {
            let trimmed = node_text(cur, source)
                .trim()
                .trim_matches(['"', '\''])
                .trim_start_matches('/');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        let mut cursor = cur.walk();
        let children: Vec<Node<'_>> = cur.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}
