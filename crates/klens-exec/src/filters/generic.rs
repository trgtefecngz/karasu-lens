//! Safe fallback filter (`GenericSafeFilter`) for unknown commands.
//!
//! Exact Phase 2 contract (`docs/phases/phase-2.md` §4):
//! - `exit_code == 0`: head + tail summary with explicit `omissions` when long.
//! - `exit_code != 0`: ±4 context lines around EVERY error keyword line + last 40 lines
//!   + `truncated_errors == false` + `raw_log_path` guaranteed.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::build_filtered_run;
use crate::output::combine_raw_output;

const SUCCESS_MAX_VERBATIM_LINES: usize = 40;
const SUCCESS_HEAD_LINES: usize = 15;
const SUCCESS_TAIL_LINES: usize = 15;
const ERROR_CONTEXT_RADIUS: usize = 4;
const ERROR_TAIL_LINES: usize = 40;

const ERROR_KEYWORDS: &[&str] = &[
    "error",
    "fail",
    "failed",
    "failure",
    "fatal",
    "panic",
    "panicked",
    "exception",
    "traceback",
    "segmentation fault",
    "segfault",
    "abort",
    "aborted",
    "denied",
    "cannot ",
    "undefined",
    "unresolved",
    "syntax",
    "errno",
    "caused by",
    "stack backtrace",
    "exit code",
];

pub struct GenericSafeFilter;

impl CommandFilter for GenericSafeFilter {
    fn id(&self) -> &'static str {
        "generic"
    }

    fn matches(&self, _program: &str, _args: &[String]) -> bool {
        true
    }

    fn filter(
        &self,
        raw_clean_stdout: &str,
        raw_clean_stderr: &str,
        exit_code: i32,
    ) -> FilteredRun {
        let combined = combine_raw_output(raw_clean_stdout, raw_clean_stderr);
        let lines: Vec<&str> = combined.lines().collect();

        let mut omissions: Vec<Omission> = Vec::new();
        let summary = if exit_code == 0 {
            filter_success_lines(&lines, &mut omissions)
        } else {
            filter_error_lines(&lines, &mut omissions)
        };

        build_filtered_run(
            self.id(),
            raw_clean_stdout,
            raw_clean_stderr,
            exit_code,
            summary,
            omissions,
        )
    }
}

fn filter_success_lines(lines: &[&str], omissions: &mut Vec<Omission>) -> String {
    let total = lines.len();
    if total <= SUCCESS_MAX_VERBATIM_LINES {
        return lines.join("\n");
    }

    let head = &lines[..SUCCESS_HEAD_LINES];
    let tail_start = total - SUCCESS_TAIL_LINES;
    let tail = &lines[tail_start..];
    let start_line = SUCCESS_HEAD_LINES + 1; // 1-based inclusive
    let end_line = tail_start; // 1-based inclusive
    let omitted_count = end_line.saturating_sub(start_line) + 1;

    omissions.push(Omission::lines(
        "<output>",
        start_line,
        end_line,
        "generic_middle_omitted",
    ));

    let mut out: Vec<String> = Vec::with_capacity(head.len() + tail.len() + 1);
    out.extend(head.iter().map(|s| (*s).to_string()));
    out.push(format!(
        "... [omitted {omitted_count} lines: L{start_line}-L{end_line}] ..."
    ));
    out.extend(tail.iter().map(|s| (*s).to_string()));
    out.join("\n")
}

fn filter_error_lines(lines: &[&str], omissions: &mut Vec<Omission>) -> String {
    let total = lines.len();
    if total <= ERROR_TAIL_LINES {
        return lines.join("\n");
    }

    let mut keep = vec![false; total];

    // 1. Mark ±4 context lines around EVERY line containing an error keyword.
    for (idx, line) in lines.iter().enumerate() {
        if contains_error_keyword(line) {
            let start = idx.saturating_sub(ERROR_CONTEXT_RADIUS);
            let end = (idx + ERROR_CONTEXT_RADIUS).min(total - 1);
            for flag in &mut keep[start..=end] {
                *flag = true;
            }
        }
    }

    // 2. Always keep the last 40 lines verbatim.
    let tail_start = total.saturating_sub(ERROR_TAIL_LINES);
    for flag in &mut keep[tail_start..total] {
        *flag = true;
    }

    // 3. Emit kept ranges in exact original order with explicit omission markers for gaps.
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < total {
        if keep[i] {
            out.push(lines[i].to_string());
            i += 1;
        } else {
            let gap_start = i;
            while i < total && !keep[i] {
                i += 1;
            }
            let gap_end = i - 1;
            let start_line = gap_start + 1;
            let end_line = gap_end + 1;
            let count = end_line - start_line + 1;
            omissions.push(Omission::lines(
                "<output>",
                start_line,
                end_line,
                "generic_non_error_context_omitted",
            ));
            out.push(format!(
                "... [omitted {count} lines: L{start_line}-L{end_line}] ..."
            ));
        }
    }

    out.join("\n")
}

fn contains_error_keyword(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ERROR_KEYWORDS.iter().any(|kw| lower.contains(kw))
}
