//! Unified-diff parsing for `diff_check`: added lines and changed line numbers per file.

use std::collections::{BTreeMap, BTreeSet};

use klens_core::RelPath;

#[derive(Debug, Default)]
pub(crate) struct ParsedFileDiff {
    pub(crate) changed_lines: BTreeSet<usize>,
    pub(crate) added_lines: Vec<(usize, String)>,
}

pub(crate) fn parse_unified_diff(diff_text: &str, out: &mut BTreeMap<String, ParsedFileDiff>) {
    let mut current_file: Option<String> = None;
    let mut current_new_line: usize = 0;
    // Lines still expected in the current hunk (from its `@@ -a,b +c,d @@` header). While any
    // remain, every line is hunk data — an added line may itself start with `++` or `@@`.
    let mut old_left: usize = 0;
    let mut new_left: usize = 0;

    for raw_line in diff_text.lines() {
        let line = raw_line.trim_end_matches('\r');

        if old_left > 0 || new_left > 0 {
            if let Some(added) = line.strip_prefix('+') {
                new_left = new_left.saturating_sub(1);
                if let Some(path) = &current_file
                    && let Some(entry) = out.get_mut(path)
                {
                    let ln = current_new_line.max(1);
                    entry.changed_lines.insert(ln);
                    entry.added_lines.push((ln, added.to_string()));
                }
                current_new_line = current_new_line.saturating_add(1);
            } else if line.starts_with('-') {
                old_left = old_left.saturating_sub(1);
            } else if !line.starts_with('\\') {
                old_left = old_left.saturating_sub(1);
                new_left = new_left.saturating_sub(1);
                current_new_line = current_new_line.saturating_add(1);
            }
            continue;
        }

        if line.starts_with("diff --git ") {
            current_file = None;
            current_new_line = 0;
            continue;
        }

        if let Some(rest) = line.strip_prefix("+++ ") {
            let trimmed = rest.trim();
            if trimmed == "/dev/null" {
                current_file = None;
                continue;
            }
            let unquoted = trimmed.trim_matches('"');
            let path = unquoted.strip_prefix("b/").unwrap_or(unquoted);
            if let Ok(rel) = RelPath::normalize(path)
                && !is_internal_klens_path(rel.as_str())
            {
                current_file = Some(rel.as_str().to_string());
                out.entry(rel.as_str().to_string()).or_default();
            } else {
                current_file = None;
            }
            continue;
        }

        if let Some(hunk_rest) = line.strip_prefix("@@ ") {
            if let Some((start, count)) = parse_hunk_new_range(hunk_rest) {
                current_new_line = start;
                new_left = count;
                old_left = parse_hunk_old_count(hunk_rest).unwrap_or(0);
                if let Some(path) = &current_file
                    && let Some(entry) = out.get_mut(path)
                {
                    if count == 0 {
                        // Pure deletion hunk: anchor to surrounding line so symbol mapping sees it.
                        entry.changed_lines.insert(start.max(1));
                    } else {
                        for ln in start..start.saturating_add(count) {
                            entry.changed_lines.insert(ln);
                        }
                    }
                }
            }
            continue;
        }
    }
}

/// Old-side line count of a hunk header (`-a,b` → `b`, `-a` → 1).
fn parse_hunk_old_count(hunk_after_at: &str) -> Option<usize> {
    let token = hunk_after_at.split_whitespace().next()?.strip_prefix('-')?;
    match token.split_once(',') {
        Some((_, count)) => count.parse().ok(),
        None => Some(1),
    }
}

fn parse_hunk_new_range(hunk_after_at: &str) -> Option<(usize, usize)> {
    // Format: `-old_start[,old_count] +new_start[,new_count] @@ ...`
    let plus_pos = hunk_after_at.find('+')?;
    let after_plus = &hunk_after_at[plus_pos + 1..];
    let range_token = after_plus.split_whitespace().next()?;
    if let Some((start_s, count_s)) = range_token.split_once(',') {
        let start = start_s.parse::<usize>().ok()?;
        let count = count_s.parse::<usize>().ok()?;
        Some((start, count))
    } else {
        let start = range_token.parse::<usize>().ok()?;
        Some((start, 1))
    }
}

pub(crate) fn is_internal_klens_path(rel: &str) -> bool {
    rel == ".klens" || rel.starts_with(".klens/")
}

#[cfg(test)]
#[path = "diff_parse_tests.rs"]
mod tests;
