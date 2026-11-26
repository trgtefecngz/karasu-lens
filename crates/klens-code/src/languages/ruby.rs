use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for Ruby (`.rb`).
pub struct RubyAnalyzer;

impl LanguageAnalyzer for RubyAnalyzer {
    fn language_id(&self) -> &'static str {
        "ruby"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rb"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_ruby::LANGUAGE.into();
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
        let language = tree_sitter_ruby::LANGUAGE.into();
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

fn collect_block(
    container: Node<'_>,
    source: &str,
    parent: Option<&str>,
    out: &mut Vec<SymbolInfo>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "module" => extract_container(child, SymbolKind::Module, source, parent, out),
            "class" => extract_container(child, SymbolKind::Class, source, parent, out),
            "method" => extract_method(child, source, parent, out),
            "singleton_method" => extract_singleton_method(child, source, parent, out),
            "assignment" => extract_constant(child, source, parent, out),
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
    let raw_name = normalize_signature(node_text(name_node, source)).replace(' ', "");
    let cleaned = raw_name.trim_start_matches("::");
    if cleaned.is_empty() {
        return;
    }
    let short_name = cleaned.rsplit("::").next().unwrap_or(cleaned).to_string();
    let body = node.child_by_field_name("body");
    let (start_line, end_line) = line_range(node);
    let signature = signature_until(node, body, source);
    let scope = qualify(parent, cleaned);
    out.push(SymbolInfo {
        name: short_name,
        qualified_name: scope.clone(),
        kind,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });
    if let Some(body_node) = body {
        collect_block(body_node, source, Some(&scope), out);
    }
}

fn extract_method(node: Node<'_>, source: &str, parent: Option<&str>, out: &mut Vec<SymbolInfo>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim().to_string();
    if name.is_empty() {
        return;
    }
    let body = node.child_by_field_name("body");
    let (start_line, end_line) = line_range(node);
    let signature = first_line_signature(node, body, source);
    let kind = if parent.is_some() {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };
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

fn extract_singleton_method(
    node: Node<'_>,
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
    let receiver = node
        .child_by_field_name("object")
        .map(|n| normalize_signature(node_text(n, source)))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "self".to_string());
    let local_qname = format!("{receiver}.{name}");
    let body = node.child_by_field_name("body");
    let (start_line, end_line) = line_range(node);
    let signature = first_line_signature(node, body, source);
    out.push(SymbolInfo {
        name,
        qualified_name: qualify(parent, &local_qname),
        kind: SymbolKind::Method,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });
}

fn extract_constant(node: Node<'_>, source: &str, parent: Option<&str>, out: &mut Vec<SymbolInfo>) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    if left.kind() != "constant" {
        return;
    }
    let name = node_text(left, source).trim().to_string();
    if name.is_empty() || !name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return;
    }
    let (start_line, end_line) = line_range(node);
    let signature = normalize_signature(node_text(node, source));
    out.push(SymbolInfo {
        name: name.clone(),
        qualified_name: qualify(parent, &name),
        kind: SymbolKind::Const,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });
}

fn first_line_signature(node: Node<'_>, body: Option<Node<'_>>, source: &str) -> String {
    if let Some(b) = body {
        return signature_until(node, Some(b), source);
    }
    let raw = node_text(node, source);
    let first = raw.lines().next().unwrap_or(raw);
    normalize_signature(first)
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
        if node.kind() == "call" {
            let method_name = node
                .child_by_field_name("method")
                .map(|m| node_text(m, source).trim())
                .unwrap_or("");
            if matches!(method_name, "require" | "require_relative" | "load")
                && let Some(args) = node.child_by_field_name("arguments")
                && let Some(target) = extract_first_string(args, source)
            {
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
            "program" | "module" | "class" | "body_statement"
        ) {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }
}

fn extract_first_string(args: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if arg.kind() == "string" {
            let mut inner = arg.walk();
            for part in arg.named_children(&mut inner) {
                if part.kind() == "string_content" {
                    let text = node_text(part, source).trim();
                    if !text.is_empty() {
                        return Some(text.to_string());
                    }
                }
            }
            let fallback = node_text(arg, source).trim().trim_matches(['"', '\'']);
            if !fallback.is_empty() {
                return Some(fallback.to_string());
            }
        }
    }
    None
}
