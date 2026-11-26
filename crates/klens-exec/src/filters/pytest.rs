//! Block-aware filter for `pytest` (including `python -m pytest` / `uv run pytest`).
//!
//! Summarizes passing tests into counts while keeping 100% of `FAILURES`, `ERRORS`,
//! tracebacks, assertion diffs, and short test summary sections verbatim.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct PytestFilter;

impl CommandFilter for PytestFilter {
    fn id(&self) -> &'static str {
        "pytest"
    }

    fn matches(&self, program: &str, args: &[String]) -> bool {
        let stem = program_stem(program);
        if matches!(stem.as_str(), "pytest" | "py.test") {
            return true;
        }
        if matches!(stem.as_str(), "python" | "python3" | "py" | "uv" | "poetry") {
            return args
                .iter()
                .any(|a| a == "pytest" || a.ends_with("/pytest") || a.ends_with("\\pytest"));
        }
        false
    }

    fn filter(
        &self,
        raw_clean_stdout: &str,
        raw_clean_stderr: &str,
        exit_code: i32,
    ) -> FilteredRun {
        let mut lines: Vec<&str> = Vec::new();
        if !raw_clean_stdout.is_empty() {
            lines.extend(raw_clean_stdout.lines());
        }
        if !raw_clean_stderr.is_empty() {
            lines.extend(raw_clean_stderr.lines());
        }

        let mut kept: Vec<String> = Vec::new();
        let mut omissions: Vec<Omission> = Vec::new();
        let mut passed_tests = 0usize;
        let mut skipped_tests = 0usize;
        let mut in_verbatim_failure = false;

        for line in lines {
            let trimmed = line.trim();

            if in_verbatim_failure {
                kept.push(line.to_string());
                continue;
            }

            if is_pytest_failure_section_start(trimmed) {
                in_verbatim_failure = true;
                kept.push(line.to_string());
                continue;
            }

            if is_pytest_passed_line(trimmed) {
                passed_tests += 1;
                continue;
            }

            if is_pytest_skipped_line(trimmed) {
                skipped_tests += 1;
                continue;
            }

            // Compact dot-only progress lines like `tests/test_a.py ..... [ 50%]`
            if let Some(dot_passes) = count_dot_only_progress(trimmed) {
                passed_tests += dot_passes;
                continue;
            }

            if trimmed.is_empty() {
                if kept.last().is_some_and(|l| !l.is_empty()) {
                    kept.push(String::new());
                }
            } else {
                kept.push(line.to_string());
            }
        }

        while kept.last().is_some_and(|l| l.is_empty()) {
            kept.pop();
        }

        let mut preamble: Vec<String> = Vec::new();
        if passed_tests > 0 {
            preamble.push(format!("{passed_tests} passed (omitted)"));
            omissions.push(Omission::items(passed_tests, "pytest_passed_tests_omitted"));
        }
        if skipped_tests > 0 {
            preamble.push(format!("{skipped_tests} skipped (omitted)"));
            omissions.push(Omission::items(
                skipped_tests,
                "pytest_skipped_tests_omitted",
            ));
        }

        let mut final_lines = Vec::with_capacity(kept.len() + preamble.len());
        if exit_code == 0 {
            final_lines.extend(preamble);
            final_lines.extend(kept);
        } else {
            final_lines.extend(kept);
            final_lines.extend(preamble);
        }

        build_filtered_run(
            self.id(),
            raw_clean_stdout,
            raw_clean_stderr,
            exit_code,
            final_lines.join("\n"),
            omissions,
        )
    }
}

fn is_pytest_failure_section_start(trimmed: &str) -> bool {
    (trimmed.starts_with('=') && (trimmed.contains("FAILURES") || trimmed.contains("ERRORS")))
        || trimmed.starts_with("Traceback (most recent call last):")
        || trimmed.starts_with("FAILED ")
        || trimmed.starts_with("ERROR ")
        || trimmed.contains(" FAILED")
        || trimmed.contains(" ERROR")
}

fn is_pytest_passed_line(trimmed: &str) -> bool {
    trimmed.ends_with(" PASSED")
        || (trimmed.contains("::") && trimmed.contains(" PASSED [") && trimmed.ends_with(']'))
}

fn is_pytest_skipped_line(trimmed: &str) -> bool {
    trimmed.ends_with(" SKIPPED")
        || (trimmed.contains("::") && trimmed.contains(" SKIPPED [") && trimmed.ends_with(']'))
}

fn count_dot_only_progress(trimmed: &str) -> Option<usize> {
    let mut tokens = trimmed.split_whitespace();
    let first = tokens.next()?;
    let rest: Vec<&str> = tokens.collect();

    // Case 1: pure dot progress line (e.g. `.....` or `..... [ 50%]`).
    if !first.is_empty() && first.bytes().all(|b| b == b'.') {
        if rest.is_empty() || is_pytest_percent_tail(&rest) {
            return Some(first.len());
        }
        return None;
    }

    // Case 2: `<path>.py ..... [100%]` (strictly requires `.py` path + dot-only 2nd token).
    if first.ends_with(".py") {
        let second = *rest.first()?;
        if !second.is_empty() && second.bytes().all(|b| b == b'.') {
            let tail = &rest[1..];
            if tail.is_empty() || is_pytest_percent_tail(tail) {
                return Some(second.len());
            }
        }
    }

    None
}

fn is_pytest_percent_tail(tokens: &[&str]) -> bool {
    let joined = tokens.join(" ");
    joined.starts_with('[') && joined.ends_with("%]")
}
