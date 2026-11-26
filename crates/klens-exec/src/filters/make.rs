//! Block-aware filter for `make`, `gmake`, `mingw32-make`, and `nmake`.
//!
//! Summarizes `Entering directory` / `Leaving directory` banners and successful single-line
//! compiler/build echoes outside error blocks while preserving 100% of compiler/linker
//! diagnostics (`error:`, `fatal error:`, `undefined reference`, `ld returned`, `note:`,
//! code/caret lines) and `make: *** [...] Error N` / `Stop.` lines verbatim.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct MakeFilter;

impl CommandFilter for MakeFilter {
    fn id(&self) -> &'static str {
        "make"
    }

    fn matches(&self, program: &str, _args: &[String]) -> bool {
        matches!(
            program_stem(program).as_str(),
            "make" | "gmake" | "mingw32-make" | "nmake"
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
        let mut dir_noise = 0usize;
        let mut compile_noise = 0usize;
        let mut in_error_block = false;

        let len = lines.len();
        let mut i = 0usize;
        while i < len {
            let line = lines[i];
            let trimmed = line.trim();

            if in_error_block {
                if is_directory_banner(trimmed) {
                    in_error_block = false;
                    dir_noise += 1;
                    i += 1;
                    continue;
                }
                if is_compile_echo(trimmed) && !next_non_blank_starts_error(&lines, i + 1) {
                    in_error_block = false;
                    compile_noise += 1;
                    i += 1;
                    continue;
                }
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            if is_diagnostic_or_make_error_start(trimmed) {
                in_error_block = true;
                kept.push(line.to_string());
                i += 1;
                continue;
            }

            if is_directory_banner(trimmed) {
                dir_noise += 1;
                i += 1;
                continue;
            }

            if is_compile_echo(trimmed) {
                // Keep a compile invocation verbatim if the immediately following non-blank
                // line begins a compiler/linker/make error block.
                if next_non_blank_starts_error(&lines, i + 1) {
                    kept.push(line.to_string());
                } else {
                    compile_noise += 1;
                }
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
        if dir_noise > 0 {
            omissions.push(Omission::items(dir_noise, "make_directory_noise_omitted"));
        }
        if compile_noise > 0 {
            omissions.push(Omission::items(
                compile_noise,
                "make_compile_commands_omitted",
            ));
            summary_notes.push(format!("{compile_noise} compile commands omitted"));
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

fn is_directory_banner(trimmed: &str) -> bool {
    (trimmed.contains("Entering directory ") || trimmed.contains("Leaving directory "))
        && (trimmed.starts_with("make")
            || trimmed.starts_with("gmake")
            || trimmed.starts_with("mingw32-make"))
}

fn is_diagnostic_or_make_error_start(trimmed: &str) -> bool {
    trimmed.starts_with("error:")
        || trimmed.starts_with("fatal error:")
        || trimmed.starts_with("warning:")
        || trimmed.starts_with("note:")
        || trimmed.starts_with("In file included from ")
        || trimmed.starts_with("In function ")
        || trimmed.starts_with("In member function ")
        || trimmed.starts_with("collect2: error:")
        || trimmed.starts_with("NMAKE : fatal error")
        || trimmed.contains(": error:")
        || trimmed.contains(": fatal error:")
        || trimmed.contains(": warning:")
        || trimmed.contains(": note:")
        || trimmed.contains("undefined reference to")
        || trimmed.contains("multiple definition of")
        || trimmed.contains("cannot find -l")
        || trimmed.contains("ld returned ")
        || trimmed.contains("error LNK")
        || trimmed.contains("fatal error LNK")
        || trimmed.contains("error C")
        || trimmed.contains("fatal error C")
        || is_make_failure_line(trimmed)
}

fn is_make_failure_line(trimmed: &str) -> bool {
    trimmed.contains(": *** ")
        || trimmed.starts_with("*** [")
        || trimmed.ends_with(" Stop.")
        || trimmed == "Stop."
}

fn is_compile_echo(trimmed: &str) -> bool {
    if trimmed.is_empty() || trimmed.ends_with('\\') {
        return false;
    }
    if is_diagnostic_or_make_error_start(trimmed) {
        return false;
    }
    let Some(first) = trimmed.split_whitespace().next() else {
        return false;
    };
    let stem = program_stem(first);
    matches!(
        stem.as_str(),
        "cc" | "gcc"
            | "g++"
            | "c++"
            | "clang"
            | "clang++"
            | "cl"
            | "ar"
            | "ranlib"
            | "mkdir"
            | "rm"
            | "cp"
            | "mv"
            | "install"
            | "ld"
            | "libtool"
            | "nasm"
            | "as"
    )
}

fn next_non_blank_starts_error(lines: &[&str], start: usize) -> bool {
    for &line in &lines[start..] {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return is_diagnostic_or_make_error_start(trimmed);
    }
    false
}
