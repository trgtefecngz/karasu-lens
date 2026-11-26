//! Shared leaf helpers for command filter implementations (zero cycles with `filters/mod.rs`).

use klens_core::{FilteredRun, Omission, estimate_tokens};

use crate::output::combine_raw_output;

/// Normalize a program path or command name to a lowercase executable stem
/// (e.g. `C:\Users\dev\.cargo\bin\cargo.exe` -> `cargo`, `npm.cmd` -> `npm`).
pub(crate) fn program_stem(program: &str) -> String {
    let trimmed = program.trim();
    let file_name = trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();

    for ext in [".exe", ".cmd", ".bat", ".ps1", ".com"] {
        if let Some(stem) = file_name.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    file_name
}

/// Construct a `FilteredRun` with real token/byte measurements from ANSI-cleaned text.
pub(crate) fn build_filtered_run(
    filter_id: &'static str,
    raw_clean_stdout: &str,
    raw_clean_stderr: &str,
    exit_code: i32,
    summary: String,
    omissions: Vec<Omission>,
) -> FilteredRun {
    let clean_combined = combine_raw_output(raw_clean_stdout, raw_clean_stderr);
    let raw_bytes = clean_combined.len();
    let est_raw_tokens = estimate_tokens(&clean_combined);
    let filtered_bytes = summary.len();
    let est_filtered_tokens = estimate_tokens(&summary);

    FilteredRun {
        filter_id: filter_id.to_string(),
        summary,
        exit_code,
        raw_bytes,
        filtered_bytes,
        est_raw_tokens,
        est_filtered_tokens,
        omissions,
        truncated_errors: false,
    }
}
