use klens_core::{
    CodeEdge, EdgeConfidence, EdgeRelation, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath,
    SymbolInfo, SymbolKind,
};
use tree_sitter::{Node, Tree};

use crate::languages::common::{
    line_range, node_text, parse_tree_lenient, parse_tree_strict, signature_until,
};

/// Tree-sitter analyzer for TypeScript & JavaScript (`.ts`, `.tsx`, `.d.ts`, `.mts`, `.cts`, `.js`, `.jsx`, `.mjs`, `.cjs`).
pub struct TsJsAnalyzer;

impl LanguageAnalyzer for TsJsAnalyzer {
    fn language_id(&self) -> &'static str {
        "typescript"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["d.ts", "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let tree = match parse_ts_js_tree(source, path) {
            Ok(t) => t,
            Err(reason) => return ParseOutcome::Fallback { reason },
        };

        let mut symbols = Vec::new();
        collect_statements(tree.root_node(), source, None, false, &mut symbols);

        ParseOutcome::Parsed(FileSymbols {
            path: path.clone(),
            language_id: self.language_id().to_string(),
            symbols,
        })
    }

    fn extract_edges(&self, source: &str, symbols: &FileSymbols) -> Vec<CodeEdge> {
        let Ok(tree) = parse_ts_js_tree(source, &symbols.path) else {
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

fn parse_ts_js_tree(source: &str, path: &RelPath) -> Result<Tree, String> {
    let lower = path.as_str().to_ascii_lowercase();
    if lower.ends_with(".tsx") || lower.ends_with(".jsx") {
        let lang = tree_sitter_typescript::LANGUAGE_TSX.into();
        parse_tree_strict(&lang, source)
    } else if lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs") {
        // React projects frequently put JSX in `.js`; try TSX first, fall back to TS grammar.
        let tsx = tree_sitter_typescript::LANGUAGE_TSX.into();
        match parse_tree_strict(&tsx, source) {
            Ok(tree) => Ok(tree),
            Err(tsx_err) => {
                let ts = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
                parse_tree_strict(&ts, source).map_err(|_| tsx_err)
            }
        }
    } else {
        let lang = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
        parse_tree_strict(&lang, source)
    }
}

/// Same grammar choice as [`parse_ts_js_tree`], but keeps a tree that has syntax errors
/// (used by `klens check` to locate them).
pub(crate) fn parse_ts_js_tree_lenient(source: &str, path: &RelPath) -> Result<Tree, String> {
    let lower = path.as_str().to_ascii_lowercase();
    if lower.ends_with(".tsx") || lower.ends_with(".jsx") {
        let lang = tree_sitter_typescript::LANGUAGE_TSX.into();
        parse_tree_lenient(&lang, source)
    } else if lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs") {
        let tsx = tree_sitter_typescript::LANGUAGE_TSX.into();
        let tsx_tree = parse_tree_lenient(&tsx, source)?;
        if !tsx_tree.root_node().has_error() {
            return Ok(tsx_tree);
        }
        let ts = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
        match parse_tree_lenient(&ts, source) {
            Ok(ts_tree) if !ts_tree.root_node().has_error() => Ok(ts_tree),
            _ => Ok(tsx_tree),
        }
    } else {
        let lang = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
        parse_tree_lenient(&lang, source)
    }
}

fn qualify_scope(parent: Option<&str>, local: &str) -> String {
    match parent {
        Some(p) => format!("{p}::{local}"),
        None => local.to_string(),
    }
}

fn collect_statements(
    container: Node<'_>,
    source: &str,
    parent: Option<&str>,
    is_ambient: bool,
    out: &mut Vec<SymbolInfo>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        handle_statement(child, source, parent, false, is_ambient, None, out);
    }
}

fn handle_statement(
    node: Node<'_>,
    source: &str,
    parent: Option<&str>,
    is_exported: bool,
    is_ambient: bool,
    span_override: Option<(usize, usize)>,
    out: &mut Vec<SymbolInfo>,
) {
    match node.kind() {
        "export_statement" => {
            handle_export_statement(node, source, parent, is_ambient, out);
        }
        "ambient_declaration" => {
            handle_ambient_declaration(node, source, parent, out);
        }
        "function_declaration" | "generator_function_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(name_node, source).trim().to_string();
                if name.is_empty() {
                    return;
                }
                let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
                let signature = signature_until(node, node.child_by_field_name("body"), source);
                let prefix = if is_ambient {
                    "declare function"
                } else {
                    "function"
                };
                let qualified_name = qualify_scope(parent, &format!("{prefix} {name}"));
                out.push(SymbolInfo {
                    name,
                    qualified_name,
                    kind: SymbolKind::Function,
                    signature,
                    start_line,
                    end_line,
                    parent: parent.map(str::to_string),
                });
            }
        }
        "function_signature" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(name_node, source).trim().to_string();
                if name.is_empty() {
                    return;
                }
                let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
                let signature = signature_until(node, None, source);
                let prefix = if is_ambient {
                    "declare function"
                } else {
                    "function"
                };
                let qualified_name = qualify_scope(parent, &format!("{prefix} {name}"));
                out.push(SymbolInfo {
                    name,
                    qualified_name,
                    kind: SymbolKind::Function,
                    signature,
                    start_line,
                    end_line,
                    parent: parent.map(str::to_string),
                });
            }
        }
        "class_declaration" | "abstract_class_declaration" => {
            extract_class(node, source, parent, is_ambient, false, span_override, out);
        }
        "interface_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(name_node, source).trim().to_string();
                if name.is_empty() {
                    return;
                }
                let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
                let signature = signature_until(node, node.child_by_field_name("body"), source);
                let prefix = if is_ambient {
                    "declare interface"
                } else {
                    "interface"
                };
                let qualified_name = qualify_scope(parent, &format!("{prefix} {name}"));
                out.push(SymbolInfo {
                    name,
                    qualified_name,
                    kind: SymbolKind::Interface,
                    signature,
                    start_line,
                    end_line,
                    parent: parent.map(str::to_string),
                });
            }
        }
        "type_alias_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(name_node, source).trim().to_string();
                if name.is_empty() {
                    return;
                }
                let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
                let signature = signature_until(node, None, source);
                let prefix = if is_ambient { "declare type" } else { "type" };
                let qualified_name = qualify_scope(parent, &format!("{prefix} {name}"));
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
        "enum_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(name_node, source).trim().to_string();
                if name.is_empty() {
                    return;
                }
                let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
                let signature = signature_until(node, node.child_by_field_name("body"), source);
                let prefix = if is_ambient { "declare enum" } else { "enum" };
                let qualified_name = qualify_scope(parent, &format!("{prefix} {name}"));
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
        "lexical_declaration" | "variable_declaration" => {
            extract_variable_declarators(
                node,
                source,
                parent,
                is_exported,
                is_ambient,
                span_override,
                out,
            );
        }
        "module" | "internal_module" => {
            extract_module_or_namespace(node, source, parent, is_ambient, span_override, out);
        }
        _ => {}
    }
}

fn handle_export_statement(
    node: Node<'_>,
    source: &str,
    parent: Option<&str>,
    is_ambient: bool,
    out: &mut Vec<SymbolInfo>,
) {
    let export_span = line_range(node);
    let is_default = has_keyword_child(node, "default");

    if is_default {
        if let Some(decl) = node.child_by_field_name("declaration") {
            match decl.kind() {
                "function_declaration"
                | "generator_function_declaration"
                | "function_expression" => {
                    let name_opt = decl
                        .child_by_field_name("name")
                        .map(|n| node_text(n, source).trim().to_string())
                        .filter(|s| !s.is_empty());
                    let (name, local_qname) = match name_opt {
                        Some(n) => (n.clone(), format!("export default {n}")),
                        None => ("default".to_string(), "export default".to_string()),
                    };
                    let signature = signature_until(node, decl.child_by_field_name("body"), source);
                    out.push(SymbolInfo {
                        name,
                        qualified_name: qualify_scope(parent, &local_qname),
                        kind: SymbolKind::Function,
                        signature,
                        start_line: export_span.0,
                        end_line: export_span.1,
                        parent: parent.map(str::to_string),
                    });
                    return;
                }
                "class_declaration" | "abstract_class_declaration" | "class" => {
                    extract_class(
                        decl,
                        source,
                        parent,
                        is_ambient,
                        true,
                        Some(export_span),
                        out,
                    );
                    return;
                }
                _ => {}
            }
        }

        if let Some(val) = node.child_by_field_name("value") {
            let unwrapped = unwrap_expression(val);
            let (kind, local_qname) = match unwrapped.kind() {
                "arrow_function" | "function_expression" | "generator_function" => {
                    (SymbolKind::Function, "export default".to_string())
                }
                "call_expression" => {
                    if let Some(wrapper) = detect_react_wrapper(unwrapped, source) {
                        (
                            SymbolKind::Function,
                            format!("export default {wrapper}(...)"),
                        )
                    } else {
                        (SymbolKind::Variable, "export default".to_string())
                    }
                }
                "identifier" => {
                    let ident = node_text(unwrapped, source).trim();
                    (SymbolKind::Variable, format!("export default {ident}"))
                }
                _ => (SymbolKind::Variable, "export default".to_string()),
            };
            let signature = signature_until(node, find_expr_body(unwrapped), source);
            out.push(SymbolInfo {
                name: "default".to_string(),
                qualified_name: qualify_scope(parent, &local_qname),
                kind,
                signature,
                start_line: export_span.0,
                end_line: export_span.1,
                parent: parent.map(str::to_string),
            });
            return;
        }
    }

    if let Some(decl) = node.child_by_field_name("declaration") {
        handle_statement(
            decl,
            source,
            parent,
            true,
            is_ambient,
            Some(export_span),
            out,
        );
    }
}

fn handle_ambient_declaration(
    node: Node<'_>,
    source: &str,
    parent: Option<&str>,
    out: &mut Vec<SymbolInfo>,
) {
    let ambient_span = line_range(node);
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();

    // Handle `declare global { ... }`
    let is_global = children
        .iter()
        .any(|c| c.kind() == "global" || node_text(*c, source).trim() == "global");
    if is_global && let Some(block) = children.iter().find(|c| c.kind() == "statement_block") {
        let scope = qualify_scope(parent, "declare global");
        out.push(SymbolInfo {
            name: "global".to_string(),
            qualified_name: scope.clone(),
            kind: SymbolKind::Module,
            signature: "declare global".to_string(),
            start_line: ambient_span.0,
            end_line: ambient_span.1,
            parent: parent.map(str::to_string),
        });
        collect_statements(*block, source, Some(&scope), true, out);
        return;
    }

    for child in children {
        if child.is_named() {
            handle_statement(child, source, parent, false, true, Some(ambient_span), out);
        }
    }
}

fn extract_module_or_namespace(
    node: Node<'_>,
    source: &str,
    parent: Option<&str>,
    is_ambient: bool,
    span_override: Option<(usize, usize)>,
    out: &mut Vec<SymbolInfo>,
) {
    let name_node = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return,
    };
    let raw_name = node_text(name_node, source).trim();
    if raw_name.is_empty() {
        return;
    }
    let clean_name = raw_name.trim_matches(['"', '\'']).to_string();
    let is_string_module = raw_name.starts_with('"') || raw_name.starts_with('\'');
    let keyword = if is_string_module {
        "module"
    } else if node_text(node, source)
        .trim_start()
        .starts_with("namespace")
    {
        "namespace"
    } else {
        "module"
    };
    let prefix = if is_ambient {
        format!("declare {keyword}")
    } else {
        keyword.to_string()
    };
    let local_qname = format!("{prefix} {raw_name}");
    let scope = qualify_scope(parent, &local_qname);
    let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
    let body = node.child_by_field_name("body");
    let signature = if is_ambient {
        format!("declare {}", signature_until(node, body, source))
    } else {
        signature_until(node, body, source)
    };

    out.push(SymbolInfo {
        name: clean_name,
        qualified_name: scope.clone(),
        kind: SymbolKind::Module,
        signature,
        start_line,
        end_line,
        parent: parent.map(str::to_string),
    });

    if let Some(body_node) = body {
        collect_statements(body_node, source, Some(&scope), is_ambient, out);
    }
}

fn extract_class(
    node: Node<'_>,
    source: &str,
    parent: Option<&str>,
    is_ambient: bool,
    is_default_export: bool,
    span_override: Option<(usize, usize)>,
    out: &mut Vec<SymbolInfo>,
) {
    let name_opt = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source).trim().to_string())
        .filter(|s| !s.is_empty());

    let (name, local_qname) = match (is_default_export, name_opt) {
        (true, Some(n)) => (n.clone(), format!("export default {n}")),
        (true, None) => ("default".to_string(), "export default".to_string()),
        (false, Some(n)) => {
            let prefix = if is_ambient { "declare class" } else { "class" };
            (n.clone(), format!("{prefix} {n}"))
        }
        (false, None) => return,
    };

    let class_scope = qualify_scope(parent, &local_qname);
    let (start_line, end_line) = span_override.unwrap_or_else(|| line_range(node));
    let body = node.child_by_field_name("body");
    let signature = signature_until(node, body, source);

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
        collect_class_members(body_node, source, &class_scope, out);
    }
}

fn collect_class_members(
    class_body: Node<'_>,
    source: &str,
    class_scope: &str,
    out: &mut Vec<SymbolInfo>,
) {
    let mut cursor = class_body.walk();
    for member in class_body.children(&mut cursor) {
        match member.kind() {
            "method_definition" | "abstract_method_signature" | "method_signature" => {
                if let Some(name_node) = member.child_by_field_name("name") {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(member);
                    let signature =
                        signature_until(member, member.child_by_field_name("body"), source);
                    out.push(SymbolInfo {
                        name: name.clone(),
                        qualified_name: format!("{class_scope}.{name}"),
                        kind: SymbolKind::Method,
                        signature,
                        start_line,
                        end_line,
                        parent: Some(class_scope.to_string()),
                    });
                }
            }
            "public_field_definition" | "field_definition" => {
                let Some(name_node) = member.child_by_field_name("name") else {
                    continue;
                };
                let Some(value_node) = member.child_by_field_name("value") else {
                    continue;
                };
                let unwrapped = unwrap_expression(value_node);
                if matches!(
                    unwrapped.kind(),
                    "arrow_function" | "function_expression" | "generator_function"
                ) {
                    let name = node_text(name_node, source).trim().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let (start_line, end_line) = line_range(member);
                    let signature = signature_until(member, find_expr_body(unwrapped), source);
                    out.push(SymbolInfo {
                        name: name.clone(),
                        qualified_name: format!("{class_scope}.{name}"),
                        kind: SymbolKind::Method,
                        signature,
                        start_line,
                        end_line,
                        parent: Some(class_scope.to_string()),
                    });
                }
            }
            _ => {}
        }
    }
}

fn extract_variable_declarators(
    decl_node: Node<'_>,
    source: &str,
    parent: Option<&str>,
    is_exported: bool,
    is_ambient: bool,
    span_override: Option<(usize, usize)>,
    out: &mut Vec<SymbolInfo>,
) {
    let decl_text = node_text(decl_node, source).trim_start();
    let is_const = decl_text.starts_with("const ");
    let mut cursor = decl_node.walk();
    let declarators: Vec<Node<'_>> = decl_node
        .children(&mut cursor)
        .filter(|c| c.kind() == "variable_declarator")
        .collect();
    let single_declarator = declarators.len() == 1;

    for declarator in declarators {
        let Some(name_node) = declarator.child_by_field_name("name") else {
            continue;
        };
        if name_node.kind() != "identifier" {
            continue;
        }
        let name = node_text(name_node, source).trim().to_string();
        if name.is_empty() {
            continue;
        }

        let value_opt = declarator
            .child_by_field_name("value")
            .map(unwrap_expression);
        let (start_line, end_line) = if single_declarator {
            span_override.unwrap_or_else(|| line_range(decl_node))
        } else {
            line_range(declarator)
        };

        if let Some(value) = value_opt {
            match value.kind() {
                "arrow_function" | "function_expression" | "generator_function" => {
                    let prefix = if is_ambient { "declare const" } else { "const" };
                    let signature = signature_until(
                        if single_declarator {
                            decl_node
                        } else {
                            declarator
                        },
                        find_expr_body(value),
                        source,
                    );
                    out.push(SymbolInfo {
                        name: name.clone(),
                        qualified_name: qualify_scope(parent, &format!("{prefix} {name}")),
                        kind: SymbolKind::Function,
                        signature,
                        start_line,
                        end_line,
                        parent: parent.map(str::to_string),
                    });
                    continue;
                }
                "call_expression" => {
                    if let Some(wrapper) = detect_react_wrapper(value, source) {
                        let prefix = if is_ambient { "declare const" } else { "const" };
                        let local_qname = format!("{prefix} {name} = {wrapper}(...)");
                        let sig_node = if single_declarator {
                            decl_node
                        } else {
                            declarator
                        };
                        let signature =
                            signature_until(sig_node, find_first_arrow_body(value), source);
                        out.push(SymbolInfo {
                            name: name.clone(),
                            qualified_name: qualify_scope(parent, &local_qname),
                            kind: SymbolKind::Function,
                            signature,
                            start_line,
                            end_line,
                            parent: parent.map(str::to_string),
                        });
                        continue;
                    }
                }
                _ => {}
            }
        }

        // Top-level `export const` / `declare const` / `export let` / `declare var`.
        if is_exported || is_ambient {
            let kind = if is_const {
                SymbolKind::Const
            } else {
                SymbolKind::Variable
            };
            let kw = if is_const { "const" } else { "var" };
            let prefix = if is_ambient {
                format!("declare {kw}")
            } else {
                kw.to_string()
            };
            let sig_node = if single_declarator {
                decl_node
            } else {
                declarator
            };
            let signature = signature_until(sig_node, None, source);
            out.push(SymbolInfo {
                name: name.clone(),
                qualified_name: qualify_scope(parent, &format!("{prefix} {name}")),
                kind,
                signature,
                start_line,
                end_line,
                parent: parent.map(str::to_string),
            });
        }
    }
}

fn unwrap_expression(mut node: Node<'_>) -> Node<'_> {
    loop {
        match node.kind() {
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    node = inner;
                } else {
                    break;
                }
            }
            "as_expression" | "satisfies_expression" => {
                if let Some(inner) = node.named_child(0) {
                    node = inner;
                } else {
                    break;
                }
            }
            "type_assertion" => {
                if let Some(inner) = node.named_child(1) {
                    node = inner;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    node
}

fn detect_react_wrapper(call_node: Node<'_>, source: &str) -> Option<&'static str> {
    let func = call_node.child_by_field_name("function")?;
    let text = node_text(func, source).trim();
    match text {
        "memo" | "React.memo" => Some("memo"),
        "forwardRef" | "React.forwardRef" => Some("forwardRef"),
        _ => None,
    }
}

fn find_expr_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .filter(|b| b.kind() == "statement_block")
}

fn find_first_arrow_body(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![node];
    while let Some(cur) = stack.pop() {
        if matches!(
            cur.kind(),
            "arrow_function" | "function_expression" | "generator_function"
        ) && let Some(body) = cur.child_by_field_name("body")
            && body.kind() == "statement_block"
        {
            return Some(body);
        }
        let mut cursor = cur.walk();
        let children: Vec<Node<'_>> = cur.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

fn has_keyword_child(node: Node<'_>, kw: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|c| !c.is_named() && c.kind() == kw)
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
        if matches!(child.kind(), "import_statement" | "export_statement")
            && let Some(src_node) = child.child_by_field_name("source")
        {
            let target = node_text(src_node, source).trim().trim_matches(['"', '\'']);
            if !target.is_empty() {
                let line = child.start_position().row + 1;
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
}
