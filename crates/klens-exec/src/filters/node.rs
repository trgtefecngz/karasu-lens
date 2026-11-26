//! Block-aware filter for Node/TypeScript tooling (`npm`, `pnpm`, `yarn`, `npx`,
//! `tsc`, `vitest`, `jest`, `bun`, `tsx`, `node`).
//!
//! - `tsc`: keeps error line + all indented type-mismatch continuation & code-frame lines verbatim.
//! - `vitest`/`jest`: summarizes passing tests (`N passed (omitted)`) and keeps all failed blocks
//!   + stack traces verbatim.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct NodePkgFilter;

impl CommandFilter for NodePkgFilter {
    fn id(&self) -> &'static str {
        "node"
    }

    fn matches(&self, program: &str, _args: &[String]) -> bool {
        matches!(
            program_stem(program).as_str(),
            "npm" | "pnpm" | "yarn" | "npx" | "tsc" | "vitest" | "jest" | "bun" | "tsx" | "node"
        )
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
        let mut install_noise = 0usize;

        let mut in_tsc_error = false;
        let mut in_failure_block = false;

        let len = lines.len();
        let mut i = 0usize;
        while i < len {
            let line = lines[i];
            let trimmed = line.trim();

            // 1. Active TypeScript (`tsc`) diagnostic block: keep ALL indented / code-frame lines.
            if in_tsc_error {
                if is_tsc_error_start(trimmed) {
                    kept.push(line.to_string());
                    i += 1;
                    continue;
                }
                if trimmed.is_empty() {
                    if next_non_blank_continues_tsc(&lines, i + 1) {
                        kept.push(String::new());
                        i += 1;
                        continue;
                    }
                    in_tsc_error = false;
                    kept.push(String::new());
                    i += 1;
                    continue;
                }
                if is_tsc_continuation(line, trimmed) {
                    kept.push(line.to_string());
                    i += 1;
                    continue;
                }
                in_tsc_error = false;
                // Fall through to handle current line normally.
            }

            // 2. Active test failure / stack trace block: preserve verbatim until passing marker or summary boundary.
            if in_failure_block {
                if is_passing_test_line(line, trimmed) {
                    in_failure_block = false;
                    passed_tests += 1;
                    i += 1;
                    continue;
                }
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 3. Detect TypeScript (`tsc`) error start.
            if is_tsc_error_start(trimmed) {
                in_tsc_error = true;
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 4. Detect test failure / runtime error / npm ERR! start.
            if is_failure_block_start(trimmed) {
                in_failure_block = true;
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 5. Compress individual passing test lines (`✓`, `√`, `✔`, `PASS `, TAP `ok <N>`).
            if is_passing_test_line(line, trimmed) {
                passed_tests += 1;
                i += 1;
                continue;
            }

            // 6. Compress package-manager progress noise (only when exit_code == 0).
            if exit_code == 0 && is_pkg_progress_noise(trimmed) {
                install_noise += 1;
                i += 1;
                continue;
            }

            // 7. Keep all other lines (summaries, warnings, unmatched errors).
            if trimmed.is_empty() {
                if kept.last().is_some_and(|l| !l.is_empty()) {
                    kept.push(String::new());
                }
            } else {
                kept.push(line.to_string());
            }

            i += 1;
        }

        while kept.last().is_some_and(|l| l.is_empty()) {
            kept.pop();
        }

        let mut preamble: Vec<String> = Vec::new();
        if passed_tests > 0 {
            preamble.push(format!("{passed_tests} passed (omitted)"));
            omissions.push(Omission::items(passed_tests, "node_passed_tests_omitted"));
        }
        if install_noise > 0 {
            omissions.push(Omission::items(install_noise, "node_pkg_progress_omitted"));
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

fn is_tsc_error_start(trimmed: &str) -> bool {
    trimmed.contains("): error TS")
        || trimmed.contains(" - error TS")
        || trimmed.starts_with("error TS")
}

fn is_tsc_continuation(raw: &str, trimmed: &str) -> bool {
    raw.starts_with(' ')
        || raw.starts_with('\t')
        || trimmed.starts_with('~')
        || trimmed.starts_with("Found ")
        || has_code_frame_prefix(trimmed)
}

fn has_code_frame_prefix(trimmed: &str) -> bool {
    let digits = trimmed.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && trimmed[digits..].starts_with(' ')
}

fn next_non_blank_continues_tsc(lines: &[&str], start: usize) -> bool {
    for &line in &lines[start..] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return is_tsc_continuation(line, trimmed) && !is_tsc_error_start(trimmed);
    }
    false
}

fn is_passing_test_line(raw: &str, trimmed: &str) -> bool {
    let is_unindented = !raw.starts_with(' ') && !raw.starts_with('\t');
    let is_tap_ok = is_unindented
        && raw
            .strip_prefix("ok ")
            .is_some_and(|rest| rest.bytes().next().is_some_and(|b| b.is_ascii_digit()));
    trimmed.starts_with("✓ ")
        || trimmed.starts_with("✔ ")
        || trimmed.starts_with("√ ")
        || (is_unindented && trimmed.starts_with("PASS "))
        || is_tap_ok
}

fn is_failure_block_start(trimmed: &str) -> bool {
    trimmed.starts_with("FAIL ")
        || trimmed.starts_with("× ")
        || trimmed.starts_with("✕ ")
        || trimmed.starts_with("● ")
        || trimmed.starts_with("⎯⎯⎯ Failed Tests")
        || trimmed.starts_with("npm ERR!")
        || trimmed.starts_with("ERR_PNPM_")
        || trimmed.starts_with("AssertionError")
        || trimmed.starts_with("TypeError:")
        || trimmed.starts_with("ReferenceError:")
        || trimmed.starts_with("SyntaxError:")
        || trimmed.starts_with("Error:")
}

fn is_pkg_progress_noise(trimmed: &str) -> bool {
    trimmed.starts_with("Progress: resolved ")
        || trimmed.starts_with("Packages: +")
        || trimmed.starts_with("Downloading ")
        || trimmed.starts_with("Resolving ")
        || trimmed.starts_with("Fetching ")
        || trimmed.starts_with("Linking ")
        || trimmed.starts_with("idealTree:")
        || trimmed.starts_with("reify:")
}
