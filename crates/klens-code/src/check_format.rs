//! Compact text rendering of `klens check` results: one line per problem, grouped
//! not-checked / skipped lines, then one summary line.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use klens_core::ProvenanceEnvelope;

use crate::check::{CheckFileStatus, CheckPayload};

/// Compact text: one line per problem, grouped not-checked lines, then one summary line.
/// A fully clean run is a single line: `OK n files [VERIFIED_AST]`.
pub fn format_check_text(envelope: &ProvenanceEnvelope<CheckPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    for file in &data.files {
        if file.status != CheckFileStatus::SyntaxErrors {
            continue;
        }
        for p in &file.problems {
            let scope = p
                .symbol
                .as_deref()
                .map(|s| format!(" [in {s}]"))
                .unwrap_or_default();
            let snippet = if p.snippet.is_empty() {
                String::new()
            } else {
                format!(" | {}", p.snippet)
            };
            let _ = writeln!(
                out,
                "{}:{}:{} {}{scope}{snippet}",
                file.path, p.line, p.column, p.message
            );
        }
        let hidden = file.problems_total.saturating_sub(file.problems.len());
        if hidden > 0 {
            let _ = writeln!(out, "{}: +{hidden} more problems not listed", file.path);
        }
        if let Some(reason) = &file.reason {
            let _ = writeln!(out, "{}: {reason}", file.path);
        }
    }

    // Group not-checked / skipped files by (status, trust, reason) to keep diff mode quiet.
    let mut groups: BTreeMap<(CheckFileStatus, &'static str, &str), Vec<&str>> = BTreeMap::new();
    for file in &data.files {
        if matches!(
            file.status,
            CheckFileStatus::NotChecked | CheckFileStatus::Skipped
        ) {
            groups
                .entry((
                    file.status,
                    crate::trust_label(file.trust),
                    file.reason.as_deref().unwrap_or(""),
                ))
                .or_default()
                .push(file.path.as_str());
        }
    }
    for ((status, trust, reason), paths) in groups {
        let label = if status == CheckFileStatus::Skipped {
            "skipped"
        } else {
            "not checked"
        };
        let _ = writeln!(out, "{label} ({trust}, {reason}): {}", paths.join(", "));
    }

    let trust = crate::trust_label(envelope.trust);
    let mut summary = if data.files.is_empty() {
        "NOTHING CHECKED".to_string()
    } else if data.error_files > 0 {
        format!(
            "FAIL {} in {}; OK {}",
            plural(data.problems_total, "problem", "problems"),
            plural(data.error_files, "file", "files"),
            plural(data.ok_files, "file", "files")
        )
    } else {
        format!("OK {}", plural(data.ok_files, "file", "files"))
    };
    if data.not_checked_files > 0 {
        let _ = write!(summary, "; {} not checked", data.not_checked_files);
    }
    let _ = write!(out, "{summary} [{trust}]");
    out
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}
