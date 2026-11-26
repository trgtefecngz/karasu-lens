//! Block-aware filter for `eslint` (including `npx`/`bunx`/`pnpm`/`yarn`/`npm exec` invocations).
//!
//! Preserves 100% of file path headers, `line:col error/warning ... rule-id` diagnostic lines,
//! `✖ N problems (...)` summaries, and fatal/config/parser error blocks while compressing
//! clean-file/progress/wrapper noise with explicit `Omission` records.

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct EslintFilter;

impl CommandFilter for EslintFilter {
    fn id(&self) -> &'static str {
        "eslint"
    }

    fn matches(&self, program: &str, args: &[String]) -> bool {
        let stem = program_stem(program);
        if stem == "eslint" {
            return true;
        }
        if matches!(stem.as_str(), "npx" | "bunx") {
            return first_exec_subcommand(args).is_some_and(is_eslint_token);
        }
        if matches!(stem.as_str(), "pnpm" | "yarn" | "npm") {
            return matches_pkg_manager_eslint(args);
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
        let mut omitted_noise = 0usize;
        let mut in_fatal_block = false;

        for line in lines {
            let trimmed = line.trim();

            if in_fatal_block {
                kept.push(line.to_string());
                continue;
            }

            if is_fatal_or_config_error_start(trimmed) {
                in_fatal_block = true;
                kept.push(line.to_string());
                continue;
            }

            // Always preserve ESLint diagnostic lines and problem summaries verbatim.
            if is_eslint_diagnostic_line(trimmed) || is_eslint_summary_line(trimmed) {
                kept.push(line.to_string());
                continue;
            }

            if is_eslint_noise(trimmed, exit_code) {
                omitted_noise += 1;
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

        let mut summary_notes: Vec<String> = Vec::new();
        if omitted_noise > 0 {
            omissions.push(Omission::items(omitted_noise, "eslint_noise_omitted"));
            summary_notes.push(format!("{omitted_noise} clean/progress lines omitted"));
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

fn is_eslint_token(arg: &str) -> bool {
    let stem = program_stem(arg);
    stem == "eslint" || stem.starts_with("eslint@")
}

fn takes_following_value_flag(flag: &str) -> bool {
    matches!(
        flag,
        "-p" | "--package"
            | "-c"
            | "--call"
            | "-F"
            | "--filter"
            | "-C"
            | "--dir"
            | "--prefix"
            | "--cwd"
            | "-w"
            | "--workspace"
    )
}

fn first_exec_subcommand(args: &[String]) -> Option<&str> {
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            return args.get(i + 1).map(String::as_str);
        }
        if takes_following_value_flag(arg) {
            i += 2;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        return Some(arg);
    }
    None
}

fn matches_pkg_manager_eslint(args: &[String]) -> bool {
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            return args
                .get(i + 1)
                .map(String::as_str)
                .is_some_and(is_eslint_token);
        }
        if takes_following_value_flag(arg) {
            i += 2;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        if is_eslint_token(arg) {
            return true;
        }
        if matches!(arg, "exec" | "dlx" | "x") {
            return first_exec_subcommand(&args[i + 1..]).is_some_and(is_eslint_token);
        }
        return false;
    }
    false
}

fn is_fatal_or_config_error_start(trimmed: &str) -> bool {
    trimmed.starts_with("Oops! Something went wrong!")
        || trimmed.starts_with("ESLint:")
        || trimmed.starts_with("ESLint couldn't ")
        || trimmed.starts_with("Error:")
        || trimmed.starts_with("SyntaxError:")
        || trimmed.starts_with("TypeError:")
        || trimmed.starts_with("ReferenceError:")
        || trimmed.starts_with("RangeError:")
        || trimmed.starts_with("Fatal:")
        || trimmed.starts_with("Failed to load config")
        || trimmed.starts_with("Cannot find module")
        || trimmed.starts_with("Cannot find package")
        || trimmed.contains("Parsing error:")
}

fn is_eslint_diagnostic_line(trimmed: &str) -> bool {
    let mut parts = trimmed.split_whitespace();
    let Some(first) = parts.next() else {
        return false;
    };
    if let Some((line_no, col_no)) = first.split_once(':')
        && !line_no.is_empty()
        && !col_no.is_empty()
        && line_no.bytes().all(|b| b.is_ascii_digit())
        && col_no.bytes().all(|b| b.is_ascii_digit())
        && let Some(level) = parts.next()
        && matches!(level, "error" | "warning" | "fatal")
    {
        return true;
    }
    trimmed.contains(": line ")
        && trimmed.contains(", col ")
        && (trimmed.contains("Error -") || trimmed.contains("Warning -"))
}

fn is_eslint_summary_line(trimmed: &str) -> bool {
    trimmed.starts_with('✖')
        || trimmed.starts_with('×')
        || trimmed.contains(" potentially fixable with the `--fix` option")
        || trimmed.contains(" potentially fixable with the --fix option")
        || (trimmed.contains(" problem")
            && (trimmed.contains("error") || trimmed.contains("warning")))
}

fn is_eslint_noise(trimmed: &str, exit_code: i32) -> bool {
    // Verbose debug/progress lines and explicit 0-problem clean-file lines.
    if trimmed.starts_with("eslint:cli ")
        || trimmed.starts_with("eslint:linter ")
        || trimmed.starts_with("eslint:config ")
        || trimmed.starts_with("eslint:file-enumerator ")
        || trimmed.starts_with("eslint:ignored-paths ")
        || trimmed.starts_with("Linting ")
        || trimmed.starts_with("Scanning ")
        || trimmed.starts_with("Checking ")
        || trimmed.starts_with("Processing ")
        || trimmed.starts_with("Loading config")
        || trimmed.ends_with(" (0 problems)")
        || trimmed.ends_with(": 0 problems")
        || trimmed.ends_with(": 0 errors, 0 warnings")
        || trimmed.starts_with("✓ ")
        || trimmed.starts_with("✔ ")
        || trimmed.starts_with("OK ")
    {
        return true;
    }

    if exit_code == 0 {
        return trimmed.starts_with("> ")
            || trimmed.starts_with("Done in ")
            || trimmed.starts_with("✨ Done in ")
            || trimmed.starts_with("Finished in ")
            || trimmed == "No ESLint warnings or errors";
    }

    false
}
