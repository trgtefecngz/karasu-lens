//! Block-aware filter for `go test` (and `go build`/`go vet`).
//!
//! Buffers verbose `=== RUN` blocks so passing tests are omitted into a count while
//! EVERY `--- FAIL:` block, panic, goroutine stack trace, and compiler error is kept verbatim.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct GoTestFilter;

impl CommandFilter for GoTestFilter {
    fn id(&self) -> &'static str {
        "go_test"
    }

    fn matches(&self, program: &str, _args: &[String]) -> bool {
        program_stem(program) == "go"
    }

    fn filter(
        &self,
        raw_clean_stdout: &str,
        raw_clean_stderr: &str,
        exit_code: i32,
    ) -> FilteredRun {
        let mut lines: Vec<&str> = Vec::new();
        if !raw_clean_stderr.is_empty() {
            lines.extend(raw_clean_stderr.lines());
        }
        if !raw_clean_stdout.is_empty() {
            lines.extend(raw_clean_stdout.lines());
        }

        let mut kept: Vec<String> = Vec::new();
        let mut omissions: Vec<Omission> = Vec::new();
        let mut passed_tests = 0usize;
        let mut skipped_tests = 0usize;

        let mut active_run_buf: Vec<String> = Vec::new();
        let mut in_active_run = false;
        let mut in_panic_or_fail = false;

        for line in lines {
            let trimmed = line.trim();

            if in_panic_or_fail {
                if trimmed.starts_with("=== RUN") {
                    in_panic_or_fail = false;
                    active_run_buf.clear();
                    active_run_buf.push(line.to_string());
                    in_active_run = true;
                    continue;
                }
                kept.push(line.to_string());
                continue;
            }

            if trimmed.starts_with("panic:") || trimmed.starts_with("goroutine ") {
                if in_active_run {
                    kept.append(&mut active_run_buf);
                    in_active_run = false;
                }
                in_panic_or_fail = true;
                kept.push(line.to_string());
                continue;
            }

            if trimmed.starts_with("=== RUN") {
                if in_active_run {
                    // Previous `=== RUN` didn't finish with PASS before a new one started:
                    // keep it if exit_code != 0 so parallel/interrupted test logs are never lost.
                    if exit_code != 0 {
                        kept.append(&mut active_run_buf);
                    } else {
                        active_run_buf.clear();
                    }
                }
                active_run_buf.push(line.to_string());
                in_active_run = true;
                continue;
            }

            if trimmed.starts_with("--- PASS:") {
                passed_tests += 1;
                active_run_buf.clear();
                in_active_run = false;
                continue;
            }

            if trimmed.starts_with("--- SKIP:") {
                skipped_tests += 1;
                active_run_buf.clear();
                in_active_run = false;
                continue;
            }

            if trimmed.starts_with("--- FAIL:") {
                if in_active_run {
                    kept.append(&mut active_run_buf);
                    in_active_run = false;
                }
                kept.push(line.to_string());
                in_panic_or_fail = true;
                continue;
            }

            if in_active_run {
                if trimmed == "PASS"
                    || trimmed == "FAIL"
                    || trimmed.starts_with("ok\t")
                    || trimmed.starts_with("ok  ")
                    || trimmed.starts_with("FAIL\t")
                {
                    // Flush buffered lines on failure; discard on clean PASS.
                    if exit_code != 0 || trimmed.starts_with("FAIL") {
                        kept.append(&mut active_run_buf);
                    } else {
                        active_run_buf.clear();
                    }
                    in_active_run = false;
                } else {
                    active_run_buf.push(line.to_string());
                    continue;
                }
            }

            // Package-level summaries.
            if exit_code == 0
                && (trimmed.starts_with("ok\t")
                    || trimmed.starts_with("ok  ")
                    || trimmed.starts_with("?\t")
                    || trimmed.starts_with("?   "))
            {
                kept.push(line.to_string());
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

        if in_active_run && exit_code != 0 {
            kept.append(&mut active_run_buf);
        }

        while kept.last().is_some_and(|l| l.is_empty()) {
            kept.pop();
        }

        let mut preamble: Vec<String> = Vec::new();
        if passed_tests > 0 {
            preamble.push(format!("{passed_tests} passed (omitted)"));
            omissions.push(Omission::items(passed_tests, "go_passed_tests_omitted"));
        }
        if skipped_tests > 0 {
            preamble.push(format!("{skipped_tests} skipped (omitted)"));
            omissions.push(Omission::items(skipped_tests, "go_skipped_tests_omitted"));
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
