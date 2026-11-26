use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::Node;

use crate::languages::common::{
    line_range, node_text, normalize_signature, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for C++ (`.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx`).
pub struct CppAnalyzer;

impl LanguageAnalyzer for CppAnalyzer {
    fn language_id(&self) -> &'static str {
        "cpp"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["cpp", "cc", "cxx", "hpp", "hh", "hxx"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let language = tree_sitter_cpp::LANGUAGE.into();
        let tree = match parse_tree_strict(&language, source) {
            Ok(t) => t,
            Err(reason) => return ParseOutcome::Fallback { reason },
        };

        let mut symbols = Vec::new();
        let mut ctx = Ctx {
            source,
            out: &mut symbols,
        };
        ctx.collect(tree.root_node(), None, false);
        ParseOutcome::Parsed(FileSymbols {
            path: path.clone(),
            language_id: self.language_id().to_string(),
            symbols,
        })
    }

    fn extract_edges(&self, source: &str, symbols: &FileSymbols) -> Vec<CodeEdge> {
        let language = tree_sitter_cpp::LANGUAGE.into();
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

struct Ctx<'a> {
    source: &'a str,
    out: &'a mut Vec<SymbolInfo>,
}

fn qualify(parent: Option<&str>, local: &str) -> String {
    match parent {
        Some(p) => format!("{p}::{local}"),
        None => local.to_string(),
    }
}

impl<'a> Ctx<'a> {
    fn collect(&mut self, container: Node<'_>, parent: Option<&str>, in_type: bool) {
        let mut cursor = container.walk();
        for child in container.children(&mut cursor) {
            self.visit(child, parent, in_type, None);
        }
    }

    fn visit(
        &mut self,
        node: Node<'_>,
        parent: Option<&str>,
        in_type: bool,
        span: Option<(usize, usize)>,
    ) {
        match node.kind() {
            "template_declaration" => {
                let outer = span.unwrap_or_else(|| line_range(node));
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() != "template_parameter_list" {
                        self.visit(child, parent, in_type, Some(outer));
                    }
                }
            }
            "namespace_definition" => {
                let body = node.child_by_field_name("body");
                if let Some(nn) = node.child_by_field_name("name") {
                    let name = normalize_signature(node_text(nn, self.source)).replace(' ', "");
                    if !name.is_empty() {
                        let (start_line, end_line) = span.unwrap_or_else(|| line_range(node));
                        let scope = qualify(parent, &name);
                        self.out.push(SymbolInfo {
                            name,
                            qualified_name: scope.clone(),
                            kind: SymbolKind::Module,
                            signature: signature_until(node, body, self.source),
                            start_line,
                            end_line,
                            parent: parent.map(str::to_string),
                        });
                        if let Some(b) = body {
                            self.collect(b, Some(&scope), false);
                        }
                        return;
                    }
                }
                if let Some(b) = body {
                    self.collect(b, parent, false);
                }
            }
            "class_specifier" => self.type_spec(node, SymbolKind::Class, true, parent, span),
            "struct_specifier" => self.type_spec(node, SymbolKind::Struct, true, parent, span),
            "enum_specifier" => self.type_spec(node, SymbolKind::Enum, false, parent, span),
            "function_definition" => self.function(node, parent, in_type, span),
            "declaration" | "field_declaration" => self.declaration(node, parent, in_type, span),
            "alias_declaration" | "type_definition" => self.type_alias(node, parent, span),
            "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif" => {
                self.collect(node, parent, in_type);
            }
            "linkage_specification" => {
                if let Some(b) = node.child_by_field_name("body") {
                    self.collect(b, parent, in_type);
                }
            }
            _ => {}
        }
    }

    fn type_spec(
        &mut self,
        node: Node<'_>,
        kind: SymbolKind,
        recurse: bool,
        parent: Option<&str>,
        span: Option<(usize, usize)>,
    ) {
        let (Some(body), Some(nn)) = (
            node.child_by_field_name("body"),
            node.child_by_field_name("name"),
        ) else {
            return;
        };
        let raw = normalize_signature(node_text(nn, self.source)).replace(' ', "");
        if raw.is_empty() {
            return;
        }
        let short = raw.rsplit("::").next().unwrap_or(&raw).to_string();
        let scope = qualify(parent, &raw);
        let (start_line, end_line) = span.unwrap_or_else(|| line_range(node));
        self.out.push(SymbolInfo {
            name: short,
            qualified_name: scope.clone(),
            kind,
            signature: signature_until(node, Some(body), self.source),
            start_line,
            end_line,
            parent: parent.map(str::to_string),
        });
        if recurse {
            self.collect(body, Some(&scope), true);
        }
    }

    fn function(
        &mut self,
        node: Node<'_>,
        parent: Option<&str>,
        in_type: bool,
        span: Option<(usize, usize)>,
    ) {
        let Some(raw) = node
            .child_by_field_name("declarator")
            .and_then(|d| declarator_name(d, self.source))
        else {
            return;
        };
        let (name, qualified_name, eff_parent, kind) =
            if let Some((owner, member)) = raw.rsplit_once("::") {
                let full_owner = qualify(parent, owner);
                (
                    member.to_string(),
                    format!("{full_owner}::{member}"),
                    Some(full_owner),
                    SymbolKind::Method,
                )
            } else {
                let kind = if in_type {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                };
                (
                    raw.clone(),
                    qualify(parent, &raw),
                    parent.map(str::to_string),
                    kind,
                )
            };
        let (start_line, end_line) = span.unwrap_or_else(|| line_range(node));
        self.out.push(SymbolInfo {
            name,
            qualified_name,
            kind,
            signature: signature_until(node, node.child_by_field_name("body"), self.source),
            start_line,
            end_line,
            parent: eff_parent,
        });
    }

    fn declaration(
        &mut self,
        node: Node<'_>,
        parent: Option<&str>,
        in_type: bool,
        span: Option<(usize, usize)>,
    ) {
        if let Some(ty) = node.child_by_field_name("type")
            && ty.child_by_field_name("body").is_some()
        {
            let outer = span.unwrap_or_else(|| line_range(node));
            let meta = match ty.kind() {
                "class_specifier" => Some((SymbolKind::Class, true)),
                "struct_specifier" => Some((SymbolKind::Struct, true)),
                "enum_specifier" => Some((SymbolKind::Enum, false)),
                _ => None,
            };
            if let Some((kind, recurse)) = meta {
                self.type_spec(ty, kind, recurse, parent, Some(outer));
                return;
            }
        }
        if !in_type {
            return;
        }
        let Some(decl) = node.child_by_field_name("declarator") else {
            return;
        };
        if !has_fn_declarator(decl) {
            return;
        }
        let Some(name) = declarator_name(decl, self.source) else {
            return;
        };
        let short = name.rsplit("::").next().unwrap_or(&name).to_string();
        let (start_line, end_line) = span.unwrap_or_else(|| line_range(node));
        self.out.push(SymbolInfo {
            name: short,
            qualified_name: qualify(parent, &name),
            kind: SymbolKind::Method,
            signature: signature_until(node, None, self.source),
            start_line,
            end_line,
            parent: parent.map(str::to_string),
        });
    }

    fn type_alias(&mut self, node: Node<'_>, parent: Option<&str>, span: Option<(usize, usize)>) {
        let name_opt = if node.kind() == "alias_declaration" {
            node.child_by_field_name("name")
                .map(|n| node_text(n, self.source).trim().to_string())
                .filter(|s| !s.is_empty())
        } else {
            node.child_by_field_name("declarator")
                .and_then(|d| declarator_name(d, self.source))
        };
        let Some(name) = name_opt else {
            return;
        };
        let (start_line, end_line) = span.unwrap_or_else(|| line_range(node));
        let body = node
            .child_by_field_name("type")
            .and_then(|t| t.child_by_field_name("body"));
        self.out.push(SymbolInfo {
            name: name.clone(),
            qualified_name: qualify(parent, &name),
            kind: SymbolKind::TypeAlias,
            signature: signature_until(node, body, self.source),
            start_line,
            end_line,
            parent: parent.map(str::to_string),
        });
    }
}

fn has_fn_declarator(node: Node<'_>) -> bool {
    node.kind() == "function_declarator"
        || node
            .child_by_field_name("declarator")
            .is_some_and(has_fn_declarator)
}

fn declarator_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "destructor_name"
        | "operator_name" => {
            let text = normalize_signature(node_text(node, source));
            (!text.is_empty()).then_some(text)
        }
        "qualified_identifier" => {
            let text = normalize_signature(node_text(node, source)).replace(" :: ", "::");
            let trimmed = text.trim_start_matches("::").trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        _ => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                return declarator_name(inner, source);
            }
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|c| declarator_name(c, source))
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
                    out.push(CodeEdge {
                        from: from_file.to_string(),
                        to: format!("import:{target}"),
                        relation: EdgeRelation::Imports,
                        confidence: EdgeConfidence::Extracted,
                        evidence: format!("{rel_path}:L{}", node.start_position().row + 1),
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
                | "namespace_definition"
        ) {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }
}
