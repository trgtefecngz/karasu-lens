use tree_sitter::{Language, Node, Parser, Tree};

/// Parse source text with Tree-sitter and fail closed if any syntax error exists.
pub(crate) fn parse_tree_strict(language: &Language, source: &str) -> Result<Tree, String> {
    let mut parser = Parser::new();
    parser
        .set_language(language)
        .map_err(|err| format!("failed to load tree-sitter language: {err}"))?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "tree-sitter parser returned no syntax tree".to_string())?;

    let root = tree.root_node();
    if root.has_error() {
        let error_lines = collect_error_lines(root);
        let lines_desc = if error_lines.is_empty() {
            "unknown line".to_string()
        } else {
            error_lines
                .iter()
                .map(|l| format!("L{l}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(format!("syntax error detected at {lines_desc}"));
    }

    Ok(tree)
}

fn collect_error_lines(root: Node<'_>) -> Vec<usize> {
    let mut stack = vec![root];
    let mut lines = Vec::new();

    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() {
            let line = node.start_position().row + 1;
            if !lines.contains(&line) {
                lines.push(line);
            }
            if lines.len() >= 8 {
                break;
            }
            continue;
        }
        if node.has_error() {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                if child.has_error() || child.is_error() || child.is_missing() {
                    stack.push(child);
                }
            }
        }
    }

    lines.sort_unstable();
    lines
}

/// Extract UTF-8 text covered by a Tree-sitter node.
pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}

/// Convert a Tree-sitter node's span into 1-based inclusive `(start_line, end_line)`.
pub(crate) fn line_range(node: Node<'_>) -> (usize, usize) {
    let start = node.start_position().row + 1;
    let end_pos = node.end_position();
    let end = if end_pos.row > node.start_position().row && end_pos.column == 0 {
        end_pos.row
    } else {
        end_pos.row + 1
    };
    (start, end.max(start))
}

/// Collapse arbitrary whitespace / newlines into single spaces and bound length safely.
pub(crate) fn normalize_signature(raw: &str) -> String {
    let mut collapsed = String::with_capacity(raw.len().min(200));
    let mut prev_ws = false;

    for ch in raw.trim().chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                collapsed.push(' ');
                prev_ws = true;
            }
        } else {
            collapsed.push(ch);
            prev_ws = false;
        }
        if collapsed.chars().count() >= 180 {
            collapsed.push_str("...");
            break;
        }
    }

    collapsed.trim().to_string()
}

/// Build a clean signature slice from `node.start_byte()` up to `body.start_byte()` (if any).
pub(crate) fn signature_until(node: Node<'_>, body: Option<Node<'_>>, source: &str) -> String {
    let start = node.start_byte();
    let end = match body {
        Some(b) if b.start_byte() >= start => b.start_byte(),
        _ => node.end_byte(),
    };
    let slice = source.get(start..end).unwrap_or("");
    let trimmed = slice
        .trim()
        .trim_end_matches('{')
        .trim_end_matches(':')
        .trim_end_matches(';')
        .trim();
    normalize_signature(trimmed)
}
