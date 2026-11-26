//! Block-aware filter for `dotnet` (`build`, `test`, `publish`, `restore`, etc.).
//!
//! Compresses project restore noise and passing `Passed ...` test lines with explicit
//! `Omission` records while preserving 100% of `error CSxxxx` / `error MSBxxxx` /
//! `warning CSxxxx` diagnostics, `Failed ...` test blocks (`Error Message:`, `Stack Trace:`),
//! and `Build succeeded` / `Build FAILED` / `Failed! - Failed: ...` summaries verbatim.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct DotnetFilter;

impl CommandFilter for DotnetFilter {
    fn id(&self) -> &'static str {
        "dotnet"
    }

    fn matches(&self, program: &str, _args: &[String]) -> bool {
        program_stem(program) == "dotnet"
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
        let mut restore_noise = 0usize;
        let mut passed_tests = 0usize;
        let mut skipped_tests = 0usize;
        let mut in_failed_test = false;

        for line in lines {
            let trimmed = line.trim();

            // 1. Active failed test block (`Failed ...` + `Error Message:` + `Stack Trace:`):
            //    preserve EVERY line verbatim until the next test status or summary boundary.
            if in_failed_test {
                if is_passed_test_line(trimmed) {
                    in_failed_test = false;
                    passed_tests += 1;
                    continue;
                }
                if is_skipped_test_line(trimmed) {
                    in_failed_test = false;
                    skipped_tests += 1;
                    continue;
                }
                if is_dotnet_summary_line(trimmed) {
                    in_failed_test = false;
                    kept.push(line.to_string());
                    continue;
                }
                kept.push(line.to_string());
                continue;
            }

            // 2. Detect failed test start.
            if is_failed_test_line(trimmed) {
                in_failed_test = true;
                kept.push(line.to_string());
                continue;
            }

            // 3. Always preserve C# / MSBuild compiler diagnostics and error headers verbatim.
            if is_dotnet_diagnostic(trimmed) {
                kept.push(line.to_string());
                continue;
            }

            // 4. Compress individual passing/skipped test lines into counts.
            if is_passed_test_line(trimmed) {
                passed_tests += 1;
                continue;
            }
            if is_skipped_test_line(trimmed) {
                skipped_tests += 1;
                continue;
            }

            // 5. Compress restore noise.
            if is_restore_noise(trimmed) {
                restore_noise += 1;
                continue;
            }

            // 6. Keep summaries and any unrecognized lines verbatim.
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

        let mut summary_notes: Vec<String> = Vec::new();
        if restore_noise > 0 {
            omissions.push(Omission::items(
                restore_noise,
                "dotnet_restore_noise_omitted",
            ));
        }
        if passed_tests > 0 {
            summary_notes.push(format!("{passed_tests} passed (omitted)"));
            omissions.push(Omission::items(passed_tests, "dotnet_passed_tests_omitted"));
        }
        if skipped_tests > 0 {
            summary_notes.push(format!("{skipped_tests} skipped (omitted)"));
            omissions.push(Omission::items(
                skipped_tests,
                "dotnet_skipped_tests_omitted",
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

fn is_restore_noise(trimmed: &str) -> bool {
    trimmed == "Determining projects to restore..."
        || trimmed == "All projects are up-to-date for restore."
        || trimmed.starts_with("Restored ")
        || trimmed.starts_with("Nothing to do. None of the projects specified")
}

fn is_passed_test_line(trimmed: &str) -> bool {
    trimmed.starts_with("Passed ") && !trimmed.starts_with("Passed!")
}

fn is_skipped_test_line(trimmed: &str) -> bool {
    trimmed.starts_with("Skipped ") && !trimmed.starts_with("Skipped!")
}

fn is_failed_test_line(trimmed: &str) -> bool {
    (trimmed.starts_with("Failed ") && !trimmed.starts_with("Failed!"))
        || (trimmed.starts_with("X ") && trimmed.contains(" ["))
}

fn is_dotnet_diagnostic(trimmed: &str) -> bool {
    trimmed.contains(": error ")
        || trimmed.contains(": warning ")
        || trimmed.contains("error CS")
        || trimmed.contains("error MSB")
        || trimmed.contains("error NU")
        || trimmed.contains("error NETSDK")
        || trimmed.contains("warning CS")
        || trimmed.contains("warning MSB")
        || trimmed.contains("warning NU")
        || trimmed.starts_with("Error Message:")
        || trimmed.starts_with("Stack Trace:")
}

fn is_dotnet_summary_line(trimmed: &str) -> bool {
    trimmed.starts_with("Failed!")
        || trimmed.starts_with("Passed!")
        || trimmed.starts_with("Total tests:")
        || trimmed == "Build succeeded."
        || trimmed == "Build FAILED."
        || trimmed.starts_with("Time Elapsed ")
}
