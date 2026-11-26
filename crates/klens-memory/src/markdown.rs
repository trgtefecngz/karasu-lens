//! Pure-Rust Obsidian-compatible YAML frontmatter and `[[wikilink]]` parser/serializer.
//!
//! Zero external YAML dependencies; 100% UTF-8 char-boundary safe across Turkish
//! characters (`ğüşiöçĞÜŞİÖÇ`), emoji, and arbitrary multi-byte Unicode sequences.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use klens_core::{RelPath, SCHEMA_VERSION, normalize_line_endings};

use crate::error::MemoryError;
use crate::types::{
    MemoryAnchor, MemoryFrontmatter, MemoryKind, MemoryNote, MemoryStatus, normalize_tags,
};

/// Parse an Obsidian-compatible `.md` file into a [`MemoryNote`], preserving the exact
/// LF-normalized Markdown body verbatim.
pub fn parse_markdown_note(rel_path: &str, raw_content: &str) -> Result<MemoryNote, MemoryError> {
    let stripped_bom = raw_content.strip_prefix('\u{FEFF}').unwrap_or(raw_content);
    let normalized = normalize_line_endings(stripped_bom);
    let text = normalized.as_ref();

    let (frontmatter_src, body) = split_frontmatter_and_body(rel_path, text)?;
    let frontmatter = parse_frontmatter(rel_path, frontmatter_src)?;
    frontmatter.validate()?;

    let wikilinks = extract_wikilinks(body);

    Ok(MemoryNote {
        frontmatter,
        body: body.to_string(),
        wikilinks,
        rel_path: rel_path.to_string(),
    })
}

/// Render a [`MemoryFrontmatter`] and verbatim Markdown `body` into an Obsidian-compatible
/// UTF-8 `.md` document with LF line endings.
pub fn serialize_markdown_note(frontmatter: &MemoryFrontmatter, body: &str) -> String {
    let mut out = String::new();
    out.push_str("---\n");
    let _ = writeln!(out, "schema_version: {}", frontmatter.schema_version);
    let _ = writeln!(out, "id: {}", format_yaml_scalar(&frontmatter.id));
    let _ = writeln!(out, "title: {}", format_yaml_scalar(&frontmatter.title));
    let _ = writeln!(out, "kind: {}", frontmatter.kind.as_str());
    let _ = writeln!(out, "created_at: {}", frontmatter.created_at);
    let _ = writeln!(out, "updated_at: {}", frontmatter.updated_at);
    let _ = writeln!(out, "status: {}", frontmatter.status.as_str());

    if frontmatter.anchors.is_empty() {
        out.push_str("anchors: []\n");
    } else {
        out.push_str("anchors:\n");
        for anchor in &frontmatter.anchors {
            let _ = writeln!(out, "  - path: {}", format_yaml_scalar(&anchor.path));
            if let Some(ref sym) = anchor.symbol {
                let _ = writeln!(out, "    symbol: {}", format_yaml_scalar(sym));
            }
            let _ = writeln!(
                out,
                "    blake3: \"{}\"",
                escape_yaml_double_quoted(&anchor.blake3)
            );
        }
    }

    let clean_tags = normalize_tags(&frontmatter.tags);
    if clean_tags.is_empty() {
        out.push_str("tags: []\n");
    } else {
        let rendered: Vec<String> = clean_tags
            .iter()
            .map(|t| format_yaml_inline_item(t))
            .collect();
        let _ = writeln!(out, "tags: [{}]", rendered.join(", "));
    }

    out.push_str("---\n");

    let norm_body = normalize_line_endings(body);
    if !norm_body.is_empty() {
        out.push('\n');
        out.push_str(&norm_body);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }

    out
}

/// Extract all Obsidian `[[wikilink]]` targets from Markdown text in deterministic sorted order.
///
/// - Handles `[[Target]]`, `[[Target|Display Alias]]`, `[[Target#Heading]]`, `[[Target#Heading|Alias]]`.
/// - Skips fenced code blocks (` ``` ` / `~~~`) and inline code spans (`` `...` ``).
/// - 100% UTF-8 char-boundary safe across multi-byte Turkish characters and emoji.
pub fn extract_wikilinks(markdown: &str) -> Vec<String> {
    let mut links = BTreeSet::new();
    let mut in_fence = false;
    let mut fence_marker: Option<&str> = None;

    for raw_line in markdown.lines() {
        let trimmed = raw_line.trim_start();
        if let Some(marker) = fence_marker {
            if trimmed.starts_with(marker) {
                in_fence = false;
                fence_marker = None;
            }
            continue;
        }
        if trimmed.starts_with("```") {
            in_fence = true;
            fence_marker = Some("```");
            continue;
        }
        if trimmed.starts_with("~~~") {
            in_fence = true;
            fence_marker = Some("~~~");
            continue;
        }
        if in_fence {
            continue;
        }

        extract_wikilinks_from_line(raw_line, &mut links);
    }

    links.into_iter().collect()
}

fn extract_wikilinks_from_line(line: &str, out: &mut BTreeSet<String>) {
    let mut iter = line.char_indices().peekable();
    let mut in_inline_code = false;

    while let Some((idx, ch)) = iter.next() {
        if ch == '`' {
            in_inline_code = !in_inline_code;
            continue;
        }
        if in_inline_code {
            continue;
        }
        if ch == '['
            && let Some(&(_, '[')) = iter.peek()
        {
            iter.next(); // consume second '['
            let content_start = idx + 2; // safe: both '[' are 1-byte ASCII
            if let Some(rel_end) = line[content_start..].find("]]") {
                let inner = &line[content_start..content_start + rel_end];
                if !inner.contains('[') && !inner.contains('\n') {
                    let target = normalize_wikilink_target(inner);
                    if !target.is_empty() {
                        out.insert(target);
                    }
                }
                let resume_at = content_start + rel_end + 2;
                while let Some(&(next_idx, _)) = iter.peek() {
                    if next_idx < resume_at {
                        iter.next();
                    } else {
                        break;
                    }
                }
            }
        }
    }
}

fn normalize_wikilink_target(inner: &str) -> String {
    // Strip optional alias (`|alias`) and heading anchor (`#heading`).
    let without_alias = inner.split('|').next().unwrap_or(inner);
    let without_heading = without_alias.split('#').next().unwrap_or(without_alias);
    without_heading.trim().to_string()
}

fn split_frontmatter_and_body<'a>(
    rel_path: &str,
    text: &'a str,
) -> Result<(&'a str, &'a str), MemoryError> {
    let first_nl = text.find('\n');
    let first_line = match first_nl {
        Some(pos) => &text[..pos],
        None => text,
    };
    if first_line.trim() != "---" {
        return Err(MemoryError::FrontmatterParse {
            path: rel_path.to_string(),
            reason: "file must begin with `---` YAML frontmatter delimiter".to_string(),
        });
    }

    let fm_start = match first_nl {
        Some(pos) => pos + 1,
        None => {
            return Err(MemoryError::FrontmatterParse {
                path: rel_path.to_string(),
                reason: "unterminated YAML frontmatter block".to_string(),
            });
        }
    };

    let mut offset = fm_start;
    while offset <= text.len() {
        let rest = &text[offset..];
        let (line, next_offset) = match rest.find('\n') {
            Some(nl) => (&rest[..nl], offset + nl + 1),
            None => (rest, text.len()),
        };
        if line.trim() == "---" {
            let fm_src = &text[fm_start..offset];
            let raw_body = &text[next_offset..];
            // Strip a single separating blank line right after `---\n` so round-trips stay exact,
            // while preserving all subsequent blank lines and exact Markdown body formatting.
            let body = raw_body.strip_prefix('\n').unwrap_or(raw_body);
            return Ok((fm_src, body));
        }
        if next_offset == text.len() {
            break;
        }
        offset = next_offset;
    }

    Err(MemoryError::FrontmatterParse {
        path: rel_path.to_string(),
        reason: "missing closing `---` YAML frontmatter delimiter".to_string(),
    })
}

#[derive(Debug, Default)]
struct PendingAnchor {
    path: Option<String>,
    symbol: Option<String>,
    blake3: Option<String>,
}

impl PendingAnchor {
    fn is_empty(&self) -> bool {
        self.path.is_none() && self.symbol.is_none() && self.blake3.is_none()
    }

    fn finish(self, rel_path: &str) -> Result<MemoryAnchor, MemoryError> {
        let raw_path = self.path.ok_or_else(|| MemoryError::FrontmatterParse {
            path: rel_path.to_string(),
            reason: "anchor item is missing `path`".to_string(),
        })?;
        let norm_path = RelPath::normalize(&raw_path)
            .map(|p| p.as_str().to_string())
            .unwrap_or(raw_path);
        let blake3 = self.blake3.ok_or_else(|| MemoryError::FrontmatterParse {
            path: rel_path.to_string(),
            reason: format!("anchor `{norm_path}` is missing `blake3`"),
        })?;
        let clean_hash = blake3
            .strip_prefix("blake3:")
            .unwrap_or(&blake3)
            .trim()
            .to_string();
        Ok(MemoryAnchor {
            path: norm_path,
            symbol: self.symbol.filter(|s| !s.trim().is_empty()),
            blake3: clean_hash,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Root,
    Anchors,
    Tags,
}

fn parse_frontmatter(rel_path: &str, src: &str) -> Result<MemoryFrontmatter, MemoryError> {
    let mut schema_version: Option<u32> = None;
    let mut id: Option<String> = None;
    let mut title: Option<String> = None;
    let mut kind: Option<MemoryKind> = None;
    let mut created_at: Option<String> = None;
    let mut updated_at: Option<String> = None;
    let mut status = MemoryStatus::Active;
    let mut anchors: Vec<MemoryAnchor> = Vec::new();
    let mut tags: Vec<String> = Vec::new();

    let mut section = Section::Root;
    let mut current_anchor = PendingAnchor::default();

    for raw_line in src.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let is_indented = raw_line.starts_with(' ') || raw_line.starts_with('\t');

        if section == Section::Anchors && (is_indented || trimmed.starts_with('-')) {
            if let Some(after_dash) = trimmed.strip_prefix('-') {
                if !current_anchor.is_empty() {
                    anchors.push(current_anchor.finish(rel_path)?);
                    current_anchor = PendingAnchor::default();
                }
                let item_rest = after_dash.trim();
                if !item_rest.is_empty() {
                    apply_anchor_kv(rel_path, item_rest, &mut current_anchor)?;
                }
            } else {
                apply_anchor_kv(rel_path, trimmed, &mut current_anchor)?;
            }
            continue;
        }

        if section == Section::Tags && (is_indented || trimmed.starts_with('-')) {
            if let Some(after_dash) = trimmed.strip_prefix('-') {
                let val = parse_yaml_scalar(after_dash);
                if !val.is_empty() {
                    tags.push(val);
                }
            }
            continue;
        }

        // Flush any open anchor when returning to root keys.
        if section == Section::Anchors && !current_anchor.is_empty() {
            anchors.push(current_anchor.finish(rel_path)?);
            current_anchor = PendingAnchor::default();
        }
        section = Section::Root;

        let Some((key_raw, val_raw)) = trimmed.split_once(':') else {
            return Err(MemoryError::FrontmatterParse {
                path: rel_path.to_string(),
                reason: format!("expected `key: value`, found `{trimmed}`"),
            });
        };

        let key = key_raw.trim();
        let val_trimmed = strip_unquoted_comment(val_raw).trim();

        match key {
            "schema_version" => {
                let parsed = parse_yaml_scalar(val_raw).parse::<u32>().map_err(|_| {
                    MemoryError::FrontmatterParse {
                        path: rel_path.to_string(),
                        reason: format!("invalid `schema_version`: `{val_trimmed}`"),
                    }
                })?;
                schema_version = Some(parsed);
            }
            "id" => id = Some(parse_yaml_scalar(val_raw)),
            "title" => title = Some(parse_yaml_scalar(val_raw)),
            "kind" => kind = Some(MemoryKind::parse(&parse_yaml_scalar(val_raw))?),
            "created_at" => created_at = Some(parse_yaml_scalar(val_raw)),
            "updated_at" => updated_at = Some(parse_yaml_scalar(val_raw)),
            "status" => status = MemoryStatus::parse(&parse_yaml_scalar(val_raw))?,
            "anchors" => {
                if val_trimmed == "[]" {
                    section = Section::Root;
                } else if val_trimmed.is_empty() {
                    section = Section::Anchors;
                } else {
                    return Err(MemoryError::FrontmatterParse {
                        path: rel_path.to_string(),
                        reason: format!("unsupported inline `anchors` value: `{val_trimmed}`"),
                    });
                }
            }
            "tags" => {
                if val_trimmed.is_empty() {
                    section = Section::Tags;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let inner = &val_trimmed[1..val_trimmed.len() - 1];
                    tags.extend(parse_inline_yaml_list(inner));
                } else {
                    let single = parse_yaml_scalar(val_raw);
                    if !single.is_empty() {
                        tags.push(single);
                    }
                }
            }
            _ => {
                // Tolerate unknown extension keys added manually in Obsidian.
            }
        }
    }

    if !current_anchor.is_empty() {
        anchors.push(current_anchor.finish(rel_path)?);
    }

    let id = id.ok_or_else(|| MemoryError::FrontmatterParse {
        path: rel_path.to_string(),
        reason: "missing required `id` field".to_string(),
    })?;
    let title = title.ok_or_else(|| MemoryError::FrontmatterParse {
        path: rel_path.to_string(),
        reason: "missing required `title` field".to_string(),
    })?;
    let kind = kind.ok_or_else(|| MemoryError::FrontmatterParse {
        path: rel_path.to_string(),
        reason: "missing required `kind` field".to_string(),
    })?;

    Ok(MemoryFrontmatter {
        schema_version: schema_version.unwrap_or(SCHEMA_VERSION),
        id,
        title,
        kind,
        created_at: created_at.unwrap_or_default(),
        updated_at: updated_at.unwrap_or_default(),
        status,
        anchors,
        tags: normalize_tags(&tags),
    })
}

fn apply_anchor_kv(
    rel_path: &str,
    kv: &str,
    anchor: &mut PendingAnchor,
) -> Result<(), MemoryError> {
    let Some((k, v)) = kv.split_once(':') else {
        return Err(MemoryError::FrontmatterParse {
            path: rel_path.to_string(),
            reason: format!("invalid anchor property `{kv}`"),
        });
    };
    let val = parse_yaml_scalar(v);
    match k.trim() {
        "path" => anchor.path = Some(val),
        "symbol" => anchor.symbol = Some(val),
        "blake3" => anchor.blake3 = Some(val),
        _ => {}
    }
    Ok(())
}

/// Strip an unquoted YAML `# comment` safely using `char_indices` (100% UTF-8 safe).
fn strip_unquoted_comment(raw: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut prev_space = true;

    for (idx, ch) in raw.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            prev_space = false;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            prev_space = false;
            continue;
        }

        match ch {
            '"' => {
                in_double = true;
                prev_space = false;
            }
            '\'' => {
                in_single = true;
                prev_space = false;
            }
            '#' if prev_space => {
                return &raw[..idx];
            }
            c if c.is_whitespace() => {
                prev_space = true;
            }
            _ => {
                prev_space = false;
            }
        }
    }

    raw
}

/// Parse a YAML scalar (double-quoted, single-quoted, or plain) safely across all UTF-8 text.
fn parse_yaml_scalar(raw: &str) -> String {
    let stripped = strip_unquoted_comment(raw).trim();
    if stripped.len() >= 2 && stripped.starts_with('"') && stripped.ends_with('"') {
        let inner = &stripped[1..stripped.len() - 1];
        return unescape_yaml_double_quoted(inner);
    }
    if stripped.len() >= 2 && stripped.starts_with('\'') && stripped.ends_with('\'') {
        let inner = &stripped[1..stripped.len() - 1];
        return inner.replace("''", "'");
    }
    stripped.to_string()
}

fn unescape_yaml_double_quoted(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn parse_inline_yaml_list(inner: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;

    for ch in inner.chars() {
        if in_double {
            if escaped {
                cur.push('\\');
                cur.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
                cur.push(ch);
            } else {
                cur.push(ch);
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            cur.push(ch);
            continue;
        }

        match ch {
            '"' => {
                in_double = true;
                cur.push(ch);
            }
            '\'' => {
                in_single = true;
                cur.push(ch);
            }
            ',' => {
                let parsed = parse_yaml_scalar(&cur);
                if !parsed.is_empty() {
                    items.push(parsed);
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }

    let tail = parse_yaml_scalar(&cur);
    if !tail.is_empty() {
        items.push(tail);
    }
    items
}

fn needs_yaml_quotes(s: &str) -> bool {
    if s.is_empty() || s.starts_with(' ') || s.ends_with(' ') {
        return true;
    }
    if s.starts_with([
        '-', '?', ':', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`',
    ]) {
        return true;
    }
    s.contains(": ")
        || s.contains(" #")
        || s.contains('\n')
        || s.contains('\r')
        || s.contains('\t')
        || s.contains('"')
}

fn escape_yaml_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn format_yaml_scalar(s: &str) -> String {
    if needs_yaml_quotes(s) {
        format!("\"{}\"", escape_yaml_double_quoted(s))
    } else {
        s.to_string()
    }
}

fn format_yaml_inline_item(s: &str) -> String {
    if needs_yaml_quotes(s) || s.contains(',') || s.contains('[') || s.contains(']') {
        format!("\"{}\"", escape_yaml_double_quoted(s))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_obsidian_markdown_with_turkish_utf8_and_wikilinks() {
        let doc = concat!(
            "---\n",
            "schema_version: 1\n",
            "id: adr-001-chunk-save\n",
            "title: \"Dünya kayıt sistemi: 16x16 parçalı #1 formatı (ğüşiöçĞÜŞİÖÇ 🚀)\"\n",
            "kind: decision # inline comment ignored\n",
            "created_at: 2026-11-22T18:40:00Z\n",
            "updated_at: 2026-11-22T18:40:00Z\n",
            "status: active # active | stale | archived\n",
            "anchors:\n",
            "  - path: src/world/save.rs\n",
            "    symbol: impl World::save_chunk\n",
            "    blake3: \"9f86d081884c7d65\"\n",
            "tags: [world, \"türkçe-etiket\", performance]\n",
            "---\n",
            "\n",
            "## Karar\n",
            "Şişli'deki geliştiriciler için ğüşiöçĞÜŞİÖÇ metni ve 🚀 emojisi.\n",
            "\n",
            "## Bağlantılar\n",
            "- İlgili kontrat: [[PROJECT_CONTRACT]]\n",
            "- İlgili düğüm: [[save.rs|Kayıt Modülü]]\n",
            "- Türkçe bağlantı: [[Mimari Özet#Bölüm 2|Özet]]\n",
            "- Kod bloğundaki sahte link: `[[ignored_inline]]`\n",
            "```rust\n",
            "// [[ignored_fenced]]\n",
            "```\n",
        );

        let parsed = parse_markdown_note(".klens/memory/adr-001-chunk-save.md", doc).unwrap();
        assert_eq!(parsed.frontmatter.id, "adr-001-chunk-save");
        assert_eq!(
            parsed.frontmatter.title,
            "Dünya kayıt sistemi: 16x16 parçalı #1 formatı (ğüşiöçĞÜŞİÖÇ 🚀)"
        );
        assert_eq!(parsed.frontmatter.kind, MemoryKind::Decision);
        assert_eq!(parsed.frontmatter.status, MemoryStatus::Active);
        assert_eq!(parsed.frontmatter.anchors.len(), 1);
        assert_eq!(parsed.frontmatter.anchors[0].path, "src/world/save.rs");
        assert_eq!(
            parsed.frontmatter.anchors[0].symbol.as_deref(),
            Some("impl World::save_chunk")
        );
        assert_eq!(parsed.frontmatter.anchors[0].blake3, "9f86d081884c7d65");
        assert_eq!(
            parsed.frontmatter.tags,
            vec!["performance", "türkçe-etiket", "world"]
        );
        assert_eq!(
            parsed.wikilinks,
            vec!["Mimari Özet", "PROJECT_CONTRACT", "save.rs"]
        );

        let serialized = serialize_markdown_note(&parsed.frontmatter, &parsed.body);
        let reparsed =
            parse_markdown_note(".klens/memory/adr-001-chunk-save.md", &serialized).unwrap();
        assert_eq!(reparsed.frontmatter, parsed.frontmatter);
        assert_eq!(reparsed.body, parsed.body);
        assert_eq!(reparsed.wikilinks, parsed.wikilinks);
    }

    #[test]
    fn multibyte_turkish_and_malformed_wikilinks_never_panic_on_char_boundaries() {
        let samples = [
            "ğüşiöç[[bağlantı]]ğüşiöç",
            "🚀[[unclosed-ğüşiöç",
            "öçşğü[[[[nested]]]]çöğ",
            "ş[[a|ğüşiöç]]ı[[b#🚀]]ö",
            "title: \"ğüşiöç # içeride\" # dışarıda yorum 🚀",
        ];
        for s in samples {
            let _ = extract_wikilinks(s);
            let _ = parse_yaml_scalar(s);
        }
        assert_eq!(
            extract_wikilinks("ğüşiöç[[bağlantı]]ğüşiöç"),
            vec!["bağlantı"]
        );
        assert_eq!(
            parse_yaml_scalar(" \"ğüşiöç # içeride\" # dışarıda yorum 🚀 "),
            "ğüşiöç # içeride"
        );
    }
}
