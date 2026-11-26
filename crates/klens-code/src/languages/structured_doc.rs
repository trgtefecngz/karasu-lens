use klens_core::{
    CodeEdge, FileSymbols, LanguageAnalyzer, ParseOutcome, RelPath, SymbolInfo, SymbolKind,
};

/// Zero-C, pure-Rust structural document analyzer for Markdown, JSON, TOML, and YAML.
pub struct StructuredDocAnalyzer;

impl LanguageAnalyzer for StructuredDocAnalyzer {
    fn language_id(&self) -> &'static str {
        "structured_doc"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["md", "markdown", "json", "toml", "yaml", "yml"]
    }

    fn parse_symbols(&self, source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
        let ext = path
            .as_str()
            .rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase())
            .unwrap_or_default();

        match ext.as_str() {
            "md" | "markdown" => ParseOutcome::Parsed(FileSymbols {
                path: path.clone(),
                language_id: "markdown".to_string(),
                symbols: parse_markdown_headings(source),
            }),
            "json" => parse_json_top_level(source, path),
            "toml" => parse_toml_top_level(source, path),
            "yaml" | "yml" => parse_yaml_top_level(source, path),
            _ => ParseOutcome::Fallback {
                reason: format!("unsupported structured document extension `.{ext}`"),
            },
        }
    }

    fn extract_edges(&self, _source: &str, _symbols: &FileSymbols) -> Vec<CodeEdge> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Markdown (`#` .. `####` headings, fence-aware)
// ---------------------------------------------------------------------------

struct RawHeading {
    level: usize,
    title: String,
    line: usize,
}

fn parse_markdown_headings(source: &str) -> Vec<SymbolInfo> {
    let lines: Vec<&str> = source.lines().collect();
    let total_lines = lines.len().max(1);
    let mut headings: Vec<RawHeading> = Vec::new();
    let mut active_fence: Option<(char, usize)> = None;

    for (idx, raw_line) in lines.iter().enumerate() {
        let trimmed = raw_line.trim_start();
        if let Some((fence_ch, fence_len)) = active_fence {
            let run = trimmed.chars().take_while(|&c| c == fence_ch).count();
            if run >= fence_len && trimmed[run..].trim().is_empty() {
                active_fence = None;
            }
            continue;
        }
        if let Some(fence) = detect_fence_open(trimmed) {
            active_fence = Some(fence);
            continue;
        }

        let hashes = trimmed.chars().take_while(|&c| c == '#').count();
        if (1..=4).contains(&hashes) {
            let rest = &trimmed[hashes..];
            if rest.starts_with(' ') || rest.starts_with('\t') {
                let title = rest.trim().trim_end_matches('#').trim().to_string();
                if !title.is_empty() {
                    headings.push(RawHeading {
                        level: hashes,
                        title,
                        line: idx + 1,
                    });
                }
            }
        }
    }

    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut symbols = Vec::with_capacity(headings.len());

    for (i, h) in headings.iter().enumerate() {
        while stack.last().is_some_and(|(lvl, _)| *lvl >= h.level) {
            stack.pop();
        }
        let parent = stack.last().map(|(_, title)| title.clone());
        let hashes = "#".repeat(h.level);
        let signature = format!("{hashes} {}", h.title);
        let qualified_name = match &parent {
            Some(p) => format!("{p} > {}", h.title),
            None => signature.clone(),
        };

        let end_line = headings[i + 1..]
            .iter()
            .find(|next| next.level <= h.level)
            .map(|next| next.line.saturating_sub(1).max(h.line))
            .unwrap_or(total_lines);

        symbols.push(SymbolInfo {
            name: h.title.clone(),
            qualified_name,
            kind: SymbolKind::Other,
            signature,
            start_line: h.line,
            end_line,
            parent,
        });

        stack.push((h.level, h.title.clone()));
    }

    symbols
}

fn detect_fence_open(trimmed: &str) -> Option<(char, usize)> {
    let first = trimmed.chars().next()?;
    if first != '`' && first != '~' {
        return None;
    }
    let run = trimmed.chars().take_while(|&c| c == first).count();
    if run >= 3 { Some((first, run)) } else { None }
}

// ---------------------------------------------------------------------------
// JSON (validated by `serde_json`, top-level keys extracted with exact lines)
// ---------------------------------------------------------------------------

fn parse_json_top_level(source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
    let parsed: serde_json::Value = match serde_json::from_str(source) {
        Ok(v) => v,
        Err(err) => {
            return ParseOutcome::Fallback {
                reason: format!("invalid JSON syntax: {err}"),
            };
        }
    };

    let symbols = if parsed.is_object() {
        scan_json_top_level_keys(source)
    } else {
        Vec::new()
    };

    ParseOutcome::Parsed(FileSymbols {
        path: path.clone(),
        language_id: "json".to_string(),
        symbols,
    })
}

fn scan_json_top_level_keys(source: &str) -> Vec<SymbolInfo> {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut depth = 0usize;
    let mut keys: Vec<(String, usize, usize)> = Vec::new(); // (key, start_line, end_line)
    let mut expecting_key_at_depth1 = false;
    let mut current_key: Option<(String, usize)> = None;

    while i < len {
        let b = bytes[i];
        match b {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => {
                i += 1;
            }
            b'"' => {
                let start_line = line;
                let (decoded, next_i, next_line) = read_json_string(source, i, line);
                i = next_i;
                line = next_line;
                if depth == 1 && expecting_key_at_depth1 {
                    current_key = Some((decoded, start_line));
                    expecting_key_at_depth1 = false;
                }
            }
            b'{' | b'[' => {
                depth += 1;
                if depth == 1 && b == b'{' {
                    expecting_key_at_depth1 = true;
                }
                i += 1;
            }
            b'}' | b']' => {
                if depth == 1 && b == b'}' {
                    if let Some((key, start_line)) = current_key.take() {
                        keys.push((key, start_line, line));
                    }
                    expecting_key_at_depth1 = false;
                }
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b',' => {
                if depth == 1 {
                    if let Some((key, start_line)) = current_key.take() {
                        keys.push((key, start_line, line));
                    }
                    expecting_key_at_depth1 = true;
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    keys.into_iter()
        .map(|(key, start_line, end_line)| SymbolInfo {
            qualified_name: format!("key {key}"),
            signature: format!("\"{key}\""),
            name: key,
            kind: SymbolKind::Variable,
            start_line,
            end_line: end_line.max(start_line),
            parent: None,
        })
        .collect()
}

fn read_json_string(source: &str, start: usize, mut line: usize) -> (String, usize, usize) {
    let bytes = source.as_bytes();
    let mut i = start + 1;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            line += 1;
        }
        if escaped {
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            let raw = &source[start..=i];
            let decoded = serde_json::from_str::<String>(raw)
                .unwrap_or_else(|_| source[start + 1..i].to_string());
            return (decoded, i + 1, line);
        }
        i += 1;
    }
    (source[start + 1..].to_string(), bytes.len(), line)
}

// ---------------------------------------------------------------------------
// TOML (validated by `toml`, top-level keys + [table] sections)
// ---------------------------------------------------------------------------

fn parse_toml_top_level(source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
    if let Err(err) = toml::from_str::<toml::Value>(source) {
        return ParseOutcome::Fallback {
            reason: format!("invalid TOML syntax: {err}"),
        };
    }

    let lines: Vec<&str> = source.lines().collect();
    let total_lines = lines.len().max(1);
    let mut in_multiline: Option<&'static str> = None;
    let mut in_root_section = true;

    struct TomlEntry {
        name: String,
        qualified_name: String,
        kind: SymbolKind,
        signature: String,
        start_line: usize,
        is_section: bool,
    }

    let mut entries: Vec<TomlEntry> = Vec::new();

    for (idx, raw_line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();

        if in_multiline.is_some() {
            update_toml_multiline_state(raw_line, &mut in_multiline);
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with('[') {
            let header = strip_toml_comment(trimmed).trim();
            let is_array = header.starts_with("[[") && header.ends_with("]]");
            let name = header
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_string();
            if !name.is_empty() {
                in_root_section = false;
                let sig = if is_array {
                    format!("[[{name}]]")
                } else {
                    format!("[{name}]")
                };
                entries.push(TomlEntry {
                    qualified_name: sig.clone(),
                    signature: sig,
                    name,
                    kind: SymbolKind::Module,
                    start_line: line_no,
                    is_section: true,
                });
            }
            continue;
        }

        if in_root_section && let Some((lhs, _)) = trimmed.split_once('=') {
            let key = lhs.trim().trim_matches(['"', '\'']).to_string();
            if !key.is_empty() {
                entries.push(TomlEntry {
                    qualified_name: format!("key {key}"),
                    signature: format!("{key} = ..."),
                    name: key,
                    kind: SymbolKind::Variable,
                    start_line: line_no,
                    is_section: false,
                });
            }
        }

        // Track `"""` and `'''` multiline string boundaries across ALL sections
        // (both root and `[table]` sections) so lines inside multiline values
        // like `[fake_section]` are never misparsed as TOML table headers.
        update_toml_multiline_state(raw_line, &mut in_multiline);
    }

    let mut symbols = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let end_line = if entry.is_section {
            entries[i + 1..]
                .iter()
                .find(|next| next.is_section)
                .map(|next| next.start_line.saturating_sub(1).max(entry.start_line))
                .unwrap_or(total_lines)
        } else {
            entry.start_line
        };
        symbols.push(SymbolInfo {
            name: entry.name.clone(),
            qualified_name: entry.qualified_name.clone(),
            kind: entry.kind,
            signature: entry.signature.clone(),
            start_line: entry.start_line,
            end_line,
            parent: None,
        });
    }

    ParseOutcome::Parsed(FileSymbols {
        path: path.clone(),
        language_id: "toml".to_string(),
        symbols,
    })
}

fn update_toml_multiline_state(line: &str, state: &mut Option<&'static str>) {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        match *state {
            Some("\"\"\"") => {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if i + 3 <= len && &bytes[i..i + 3] == b"\"\"\"" {
                    // TOML allows up to 2 extra quotes at the end of a multiline basic string (e.g. `""""""`).
                    i += 3;
                    while i < len && bytes[i] == b'"' {
                        i += 1;
                    }
                    *state = None;
                    continue;
                }
                i += 1;
            }
            Some("'''") => {
                if i + 3 <= len && &bytes[i..i + 3] == b"'''" {
                    i += 3;
                    while i < len && bytes[i] == b'\'' {
                        i += 1;
                    }
                    *state = None;
                    continue;
                }
                i += 1;
            }
            _ => match bytes[i] {
                b'#' => break,
                b'"' => {
                    if i + 3 <= len && &bytes[i..i + 3] == b"\"\"\"" {
                        *state = Some("\"\"\"");
                        i += 3;
                    } else {
                        // Advance through regular single-line basic string.
                        i += 1;
                        while i < len {
                            if bytes[i] == b'\\' {
                                i += 2;
                                continue;
                            }
                            if bytes[i] == b'"' {
                                i += 1;
                                break;
                            }
                            i += 1;
                        }
                    }
                }
                b'\'' => {
                    if i + 3 <= len && &bytes[i..i + 3] == b"'''" {
                        *state = Some("'''");
                        i += 3;
                    } else {
                        // Advance through regular single-line literal string.
                        i += 1;
                        while i < len {
                            if bytes[i] == b'\'' {
                                i += 1;
                                break;
                            }
                            i += 1;
                        }
                    }
                }
                _ => i += 1,
            },
        }
    }
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (i, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '#' if !in_double && !in_single => return &line[..i],
            _ => {}
        }
    }
    line
}

// ---------------------------------------------------------------------------
// YAML (zero-dependency pure-Rust top-level key skeleton + syntax validation)
// ---------------------------------------------------------------------------

fn parse_yaml_top_level(source: &str, path: &RelPath) -> ParseOutcome<FileSymbols> {
    let lines: Vec<&str> = source.lines().collect();
    let total_lines = lines.len().max(1);
    let mut keys: Vec<(String, usize)> = Vec::new();
    let mut block_scalar_indent: Option<usize> = None;

    for (idx, raw_line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" || trimmed == "..." {
            continue;
        }

        let leading_tabs = raw_line.starts_with('\t');
        if leading_tabs {
            return ParseOutcome::Fallback {
                reason: format!("invalid YAML indentation (tab character) at L{line_no}"),
            };
        }

        let indent = raw_line.bytes().take_while(|&b| b == b' ').count();
        if let Some(min_indent) = block_scalar_indent {
            if indent > min_indent {
                continue;
            }
            block_scalar_indent = None;
        }

        if indent == 0 {
            if trimmed.starts_with('-') && (trimmed.len() == 1 || trimmed.as_bytes()[1] == b' ') {
                continue;
            }
            let Some((raw_key, rest)) = split_yaml_mapping_key(trimmed) else {
                return ParseOutcome::Fallback {
                    reason: format!("invalid YAML top-level mapping entry at L{line_no}"),
                };
            };
            let key = raw_key.trim().trim_matches(['"', '\'']).to_string();
            if key.is_empty() {
                return ParseOutcome::Fallback {
                    reason: format!("empty YAML key at L{line_no}"),
                };
            }
            keys.push((key, line_no));
            let val = rest.trim();
            if val == "|" || val == "|-" || val == "|+" || val == ">" || val == ">-" || val == ">+"
            {
                block_scalar_indent = Some(0);
            }
        }
    }

    let mut symbols = Vec::with_capacity(keys.len());
    for (i, (key, start_line)) in keys.iter().enumerate() {
        let end_line = keys
            .get(i + 1)
            .map(|(_, next_line)| next_line.saturating_sub(1).max(*start_line))
            .unwrap_or(total_lines);
        symbols.push(SymbolInfo {
            name: key.clone(),
            qualified_name: format!("key {key}"),
            kind: SymbolKind::Variable,
            signature: format!("{key}:"),
            start_line: *start_line,
            end_line,
            parent: None,
        });
    }

    ParseOutcome::Parsed(FileSymbols {
        path: path.clone(),
        language_id: "yaml".to_string(),
        symbols,
    })
}

fn split_yaml_mapping_key(line: &str) -> Option<(&str, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let bytes = line.as_bytes();

    for (i, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            ':' if !in_single && !in_double => {
                let next = bytes.get(i + 1).copied();
                if next.is_none() || matches!(next, Some(b' ' | b'\t')) {
                    return Some((&line[..i], &line[i + 1..]));
                }
            }
            _ => {}
        }
    }

    None
}
