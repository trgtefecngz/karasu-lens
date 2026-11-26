//! Block-aware filter for `gradle` and `gradlew` (`.bat`/`.cmd` normalized by `program_stem`).
//!
//! Compresses `UP-TO-DATE`, `FROM-CACHE`, `NO-SOURCE`, `SKIPPED` task lines and `Downloading ...`
//! progress lines with explicit `Omission` records while preserving 100% of `FAILURE:` sections,
//! `* What went wrong:`, `* Where:`, `* Try:`, Kotlin/Java compiler errors, test failure stack
//! traces, and `BUILD SUCCESSFUL` / `BUILD FAILED` summaries.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct GradleFilter;

impl CommandFilter for GradleFilter {
    fn id(&self) -> &'static str {
        "gradle"
    }

    fn matches(&self, program: &str, _args: &[String]) -> bool {
        matches!(program_stem(program).as_str(), "gradle" | "gradlew")
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
        let mut cached_tasks = 0usize;
        let mut download_noise = 0usize;
        let mut in_failure_section = false;
        let mut in_diagnostic_block = false;

        let len = lines.len();
        let mut i = 0usize;
        while i < len {
            let line = lines[i];
            let trimmed = line.trim();

            // 1. Inside `FAILURE: Build failed with an exception.` — keep everything verbatim.
            if in_failure_section {
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            if is_gradle_failure_section_start(trimmed) {
                in_failure_section = true;
                in_diagnostic_block = false;
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 2. Inside a Kotlin/Java compiler error or test failure stack trace block.
            if in_diagnostic_block {
                if is_cached_task_line(trimmed) {
                    in_diagnostic_block = false;
                    cached_tasks += 1;
                    i += 1;
                    continue;
                }
                if is_download_line(trimmed) {
                    in_diagnostic_block = false;
                    download_noise += 1;
                    i += 1;
                    continue;
                }
                if trimmed.is_empty() && !next_non_blank_continues_diagnostic(&lines, i + 1) {
                    in_diagnostic_block = false;
                    kept.push(String::new());
                    i += 1;
                    continue;
                }
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 3. Detect compiler errors, failed tasks, or test failure stack traces.
            if is_gradle_diagnostic_start(trimmed) {
                in_diagnostic_block = true;
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            // 4. Compress cached/up-to-date/no-source/skipped task lines and downloads.
            if is_cached_task_line(trimmed) {
                cached_tasks += 1;
                i += 1;
                continue;
            }

            if is_download_line(trimmed) {
                download_noise += 1;
                i += 1;
                continue;
            }

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

        let mut summary_notes: Vec<String> = Vec::new();
        if cached_tasks > 0 {
            omissions.push(Omission::items(cached_tasks, "gradle_cached_tasks_omitted"));
            summary_notes.push(format!("{cached_tasks} up-to-date/cached tasks omitted"));
        }
        if download_noise > 0 {
            omissions.push(Omission::items(
                download_noise,
                "gradle_download_progress_omitted",
            ));
        }

        let mut final_lines = Vec::with_capacity(kept.len() + summary_notes.len());
        if exit_code == 0 {
            final_lines.extend(summary_notes);
            final_lines.extend(kept);
        } else {
            final_lines.extend(kept);
            final_lines.extend(summary_notes);
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

fn is_gradle_failure_section_start(trimmed: &str) -> bool {
    trimmed.starts_with("FAILURE:")
        || trimmed == "* What went wrong:"
        || trimmed == "* Where:"
        || trimmed == "* Try:"
        || trimmed == "* Exception is:"
}

fn is_gradle_diagnostic_start(trimmed: &str) -> bool {
    (trimmed.starts_with("> Task ") && trimmed.ends_with(" FAILED"))
        || trimmed.starts_with("e: ")
        || trimmed.starts_with("w: ")
        || trimmed.contains(": error:")
        || trimmed.ends_with(" FAILED")
        || trimmed.starts_with("Caused by:")
        || trimmed.contains("AssertionError")
        || trimmed.contains("AssertionFailedError")
        || trimmed.contains("Exception:")
}

fn is_cached_task_line(trimmed: &str) -> bool {
    trimmed.starts_with("> Task ")
        && (trimmed.ends_with(" UP-TO-DATE")
            || trimmed.ends_with(" FROM-CACHE")
            || trimmed.ends_with(" NO-SOURCE")
            || trimmed.ends_with(" SKIPPED"))
}

fn is_download_line(trimmed: &str) -> bool {
    trimmed.starts_with("Downloading ") || trimmed.starts_with("Download ")
}

fn next_non_blank_continues_diagnostic(lines: &[&str], start: usize) -> bool {
    for &line in &lines[start..] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_cached_task_line(trimmed)
            || is_download_line(trimmed)
            || trimmed.starts_with("BUILD ")
            || is_gradle_failure_section_start(trimmed)
        {
            return false;
        }
        return line.starts_with(' ')
            || line.starts_with('\t')
            || trimmed.starts_with("at ")
            || trimmed.starts_with("Caused by:")
            || trimmed.starts_with("e: ")
            || trimmed.starts_with("w: ")
            || trimmed.starts_with("symbol:")
            || trimmed.starts_with("location:")
            || trimmed.starts_with('^')
            || trimmed.contains(": error:");
    }
    false
}
