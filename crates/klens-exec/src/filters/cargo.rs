//! Block-aware filter for `cargo` (`test`, `build`, `check`, `clippy`, etc.) and `rustc`.
//!
//! Compresses repetitive `Compiling ...` / `Downloading ...` / `test ... ok` lines while
//! preserving 100% of compiler diagnostic blocks (`error[E....]:`, `warning:`, `-->`,
//! line-numbered source snippets, `^^^`, `note:`, `help:`) and failed test / panic blocks.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct CargoFilter;

impl CommandFilter for CargoFilter {
    fn id(&self) -> &'static str {
        "cargo"
    }

    fn matches(&self, program: &str, _args: &[String]) -> bool {
        matches!(program_stem(program).as_str(), "cargo" | "rustc")
    }

    fn filter(
        &self,
        raw_clean_stdout: &str,
        raw_clean_stderr: &str,
        exit_code: i32,
    ) -> FilteredRun {
        // Process stderr (compiler diagnostics, build progress) and stdout (test runner)
        // using the same block-aware state machine so both live runs and combined `.raw.log`
        // re-filtering produce consistent, zero-loss output.
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
        let mut ignored_tests = 0usize;
        let mut build_noise_lines = 0usize;
        let mut skipped_suite_headers = 0usize;

        let mut in_diagnostic = false;
        let mut in_failure_section = false;
        let mut in_panic_block = false;

        let len = lines.len();
        let mut i = 0usize;
        while i < len {
            let line = lines[i];
            let trimmed = line.trim();

            // 1. Inside an active rustc/clippy diagnostic block: preserve EVERY line verbatim.
            if in_diagnostic {
                if trimmed.is_empty() {
                    if next_non_blank_continues_diagnostic(&lines, i + 1) {
                        kept.push(line.to_string());
                        i += 1;
                        continue;
                    }
                    in_diagnostic = false;
                    kept.push(String::new());
                    i += 1;
                    continue;
                }
                if is_build_progress_noise(trimmed)
                    || trimmed.starts_with("Finished ")
                    || trimmed.starts_with("Running ")
                    || trimmed.starts_with("Doc-tests ")
                    || trimmed.starts_with("test result:")
                {
                    in_diagnostic = false;
                    // Fall through to process this line normally.
                } else {
                    kept.push(line.to_string());
                    i += 1;
                    continue;
                }
            }

            // 2. Inside a `failures:` section of `cargo test`: preserve EVERY line until `test result:`.
            if in_failure_section {
                kept.push(line.to_string());
                if trimmed.starts_with("test result:") {
                    in_failure_section = false;
                }
                i += 1;
                continue;
            }

            // 3. Inside a standalone panic / backtrace block.
            if in_panic_block {
                if trimmed.is_empty() && !next_non_blank_continues_panic(&lines, i + 1) {
                    in_panic_block = false;
                    kept.push(String::new());
                    i += 1;
                    continue;
                }
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 4. Detect start of a compiler diagnostic block (`error[E0308]:`, `error:`, `warning:`).
            if is_diagnostic_start(trimmed) {
                in_diagnostic = true;
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 5. Detect `failures:` section or panic start.
            if trimmed == "failures:" || trimmed.starts_with("---- ") && trimmed.ends_with(" ----")
            {
                in_failure_section = true;
                kept.push(line.to_string());
                i += 1;
                continue;
            }
            if is_panic_start(trimmed) {
                in_panic_block = true;
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 6. Failed test lines MUST always be preserved verbatim.
            if trimmed.starts_with("test ") && trimmed.ends_with("... FAILED") {
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 7. Compress passing & ignored individual test lines into counts.
            if trimmed.starts_with("test ") && trimmed.ends_with("... ok") {
                passed_tests += 1;
                i += 1;
                continue;
            }
            if trimmed.starts_with("test ") && trimmed.ends_with("... ignored") {
                ignored_tests += 1;
                i += 1;
                continue;
            }

            // 8. Compress repetitive build progress noise (`Compiling`, `Downloading`, etc.).
            if is_build_progress_noise(trimmed) {
                build_noise_lines += 1;
                i += 1;
                continue;
            }

            // 9. Suppress empty suite headers (`Running ...`, `running 0 tests`, `Doc-tests ...`)
            //    and empty `test result: ok. 0 passed; 0 failed...` on clean runs to maximize signal.
            if exit_code == 0 {
                if is_suite_banner(trimmed) || trimmed == "running 0 tests" {
                    skipped_suite_headers += 1;
                    i += 1;
                    continue;
                }
                if trimmed.starts_with("running ") && trimmed.ends_with(" tests")
                    || trimmed == "running 1 test"
                {
                    skipped_suite_headers += 1;
                    i += 1;
                    continue;
                }
                if trimmed.starts_with("test result: ok. 0 passed; 0 failed;") {
                    skipped_suite_headers += 1;
                    i += 1;
                    continue;
                }
            }

            // 10. Keep summary lines and ANY unrecognized line (whitelist-only omission!).
            if trimmed.is_empty() {
                if kept.last().is_some_and(|l| !l.is_empty()) {
                    kept.push(String::new());
                }
            } else {
                kept.push(line.to_string());
            }

            i += 1;
        }

        // Trim trailing blank lines.
        while kept.last().is_some_and(|l| l.is_empty()) {
            kept.pop();
        }

        // Insert concise omission summary lines right before the final `test result:` or at top.
        let mut summary_lines: Vec<String> = Vec::new();
        if build_noise_lines > 0 {
            omissions.push(Omission::items(
                build_noise_lines,
                "cargo_build_progress_omitted",
            ));
        }
        if skipped_suite_headers > 0 {
            omissions.push(Omission::items(
                skipped_suite_headers,
                "cargo_suite_headers_omitted",
            ));
        }
        if passed_tests > 0 {
            summary_lines.push(format!("{passed_tests} passed (omitted)"));
            omissions.push(Omission::items(passed_tests, "cargo_passed_tests_omitted"));
        }
        if ignored_tests > 0 {
            summary_lines.push(format!("{ignored_tests} ignored (omitted)"));
            omissions.push(Omission::items(
                ignored_tests,
                "cargo_ignored_tests_omitted",
            ));
        }

        // Place omitted test counts ahead of final summary lines while keeping errors prominent.
        let mut final_lines: Vec<String> = Vec::with_capacity(kept.len() + summary_lines.len());
        if exit_code == 0 {
            final_lines.extend(summary_lines);
            final_lines.extend(kept);
        } else {
            final_lines.extend(kept);
            final_lines.extend(summary_lines);
        }

        let summary = final_lines.join("\n");
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

fn is_diagnostic_start(trimmed: &str) -> bool {
    trimmed.starts_with("error:")
        || trimmed.starts_with("error[")
        || trimmed.starts_with("warning:")
        || trimmed.starts_with("warning[")
        || trimmed.starts_with("error(internal):")
}

fn is_panic_start(trimmed: &str) -> bool {
    trimmed.starts_with("thread '") && trimmed.contains("panicked at")
        || trimmed.starts_with("fatal runtime error:")
}

fn is_build_progress_noise(trimmed: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "Compiling ",
        "Checking ",
        "Downloading ",
        "Downloaded ",
        "Updating ",
        "Locking ",
        "Fresh ",
        "Dirty ",
        "Documenting ",
        "Packaging ",
        "Archiving ",
        "Fetching ",
        "Blocking waiting for file lock ",
        "Adding ",
        "Removing ",
        "Unpacking ",
    ];
    PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

fn is_suite_banner(trimmed: &str) -> bool {
    trimmed.starts_with("Running unittests ")
        || trimmed.starts_with("Running tests/")
        || trimmed.starts_with("Running tests\\")
        || trimmed.starts_with("Running bin ")
        || trimmed.starts_with("Doc-tests ")
        || (trimmed.starts_with("Running ")
            && (trimmed.contains("(target/") || trimmed.contains("(target\\")))
}

fn next_non_blank_continues_diagnostic(lines: &[&str], start: usize) -> bool {
    for &line in &lines[start..] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return is_diagnostic_continuation(line, trimmed);
    }
    false
}

fn is_diagnostic_continuation(raw: &str, trimmed: &str) -> bool {
    trimmed.starts_with("-->")
        || trimmed.starts_with(":::")
        || trimmed.starts_with('|')
        || trimmed.starts_with("= note:")
        || trimmed.starts_with("= help:")
        || trimmed.starts_with("note:")
        || trimmed.starts_with("help:")
        || has_rustc_line_gutter(trimmed)
        || (raw.starts_with("   ")
            && !is_build_progress_noise(trimmed)
            && !trimmed.starts_with("Finished ")
            && !trimmed.starts_with("Running "))
}

fn has_rustc_line_gutter(trimmed: &str) -> bool {
    let digits = trimmed.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return false;
    }
    trimmed[digits..].trim_start().starts_with('|')
}

fn next_non_blank_continues_panic(lines: &[&str], start: usize) -> bool {
    for &line in &lines[start..] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return trimmed.starts_with("stack backtrace:")
            || trimmed.starts_with("note: run with `RUST_BACKTRACE")
            || trimmed.starts_with("at ")
            || line.starts_with("  ")
            || trimmed
                .split_once(':')
                .is_some_and(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    }
    false
}
