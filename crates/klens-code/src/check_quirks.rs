//! Guards against known false alarms in `klens check`: JSON with comments (JSONC) and
//! C/C++ errors caused by `#if`/`#ifdef` blocks (the grammars do not run the preprocessor).

use tree_sitter::Node;

/// Nodes visited inside one error region before giving up and treating it as doubtful.
const MAX_ERROR_SUBTREE_NODES: usize = 20_000;

/// `true` for C/C++ header files (`.h`), which may hold either C or C++.
pub(crate) fn is_header_path(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".h")
}

/// Config files whose readers accept comments and trailing commas (JSONC).
pub(crate) fn is_jsonc_config_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let in_dir =
        |dir: &str| lower.starts_with(&format!("{dir}/")) || lower.contains(&format!("/{dir}/"));
    ((name.starts_with("tsconfig") || name.starts_with("jsconfig")) && name.ends_with(".json"))
        || in_dir(".vscode")
        || in_dir(".devcontainer")
        || matches!(
            name,
            "devcontainer.json" | ".devcontainer.json" | ".eslintrc.json" | "deno.json"
        )
}

/// Replace `//` and `/* */` comments and trailing commas with spaces (newlines kept, so error
/// lines stay the same). Returns the cleaned text and whether any comment was found.
pub(crate) fn strip_jsonc(source: &str) -> (String, bool) {
    let chars: Vec<char> = source.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut had_comments = false;
    let mut in_string = false;
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(&next) = chars.get(i + 1) {
                    out.push(next);
                    i += 2;
                    continue;
                }
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match (c, chars.get(i + 1).copied()) {
            ('"', _) => {
                in_string = true;
                out.push(c);
                i += 1;
            }
            ('/', Some('/')) => {
                had_comments = true;
                while i < chars.len() && chars[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            }
            ('/', Some('*')) => {
                had_comments = true;
                out.extend([' ', ' ']);
                i += 2;
                while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                    out.push(if chars[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
                if i < chars.len() {
                    out.extend([' ', ' ']);
                    i += 2;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }

    // Trailing commas: `,` followed (after whitespace) by `}` or `]`, outside strings.
    let mut in_string = false;
    let mut escaped = false;
    for idx in 0..out.len() {
        let c = out[idx];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
        } else if c == ',' {
            let next = out[idx + 1..].iter().find(|ch| !ch.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                out[idx] = ' ';
            }
        }
    }

    (out.into_iter().collect(), had_comments)
}

/// `true` when a C/C++ syntax problem touches a preprocessor conditional: a missing `#endif`,
/// or an error region that contains `#if` / `#ifdef` / `#else` / `#elif` / `#endif`.
pub(crate) fn near_preprocessor_conditional(node: Node<'_>) -> bool {
    if node.is_missing() {
        return node.kind().starts_with('#');
    }
    let mut stack = vec![node];
    let mut visited = 0usize;
    while let Some(current) = stack.pop() {
        visited += 1;
        if visited > MAX_ERROR_SUBTREE_NODES {
            return true;
        }
        let kind = current.kind();
        if kind.starts_with("preproc_if")
            || kind.starts_with("preproc_else")
            || kind.starts_with("preproc_elif")
            || matches!(
                kind,
                "#if"
                    | "#ifdef"
                    | "#ifndef"
                    | "#else"
                    | "#elif"
                    | "#elifdef"
                    | "#elifndef"
                    | "#endif"
            )
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_jsonc_keeps_strings_and_lines() {
        let src = "{\n  // c\n  \"url\": \"http://x/*y*/\", /* z */\n  \"a\": [1, 2,],\n}\n";
        let (out, had) = strip_jsonc(src);
        assert!(had);
        assert_eq!(out.lines().count(), src.lines().count());
        assert!(out.contains("\"http://x/*y*/\""));
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["a"][1], 2);
    }

    #[test]
    fn jsonc_config_names() {
        assert!(is_jsonc_config_path("tsconfig.json"));
        assert!(is_jsonc_config_path("web/tsconfig.app.json"));
        assert!(is_jsonc_config_path(".vscode/settings.json"));
        assert!(!is_jsonc_config_path("package.json"));
    }
}
