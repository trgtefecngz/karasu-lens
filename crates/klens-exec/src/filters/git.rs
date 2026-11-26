//! Block-aware filter for `git status`, `git diff`, and `git log`.
//!
//! - `status`: compact grouped summary without repetitive `(use "git ...")` hints.
//! - `diff`: omits lockfiles & generated files into `omissions`, keeps 100% of code diffs verbatim.
//! - `log`: condenses multi-line commit headers into a dense one-line format.

use klens_core::{CommandFilter, FilteredRun, Omission, OmissionKind};

use super::common::{build_filtered_run, program_stem};

const LOCKFILE_NAMES: &[&str] = &[
    "cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "pipfile.lock",
    "go.sum",
    "composer.lock",
    "gemfile.lock",
    "uv.lock",
    "flake.lock",
    "pdm.lock",
    "shrinkwrap.json",
];

const GENERATED_SUFFIXES: &[&str] = &[
    ".min.js",
    ".min.css",
    ".map",
    ".pb.go",
    "_pb2.py",
    ".snap",
    ".generated.ts",
    ".generated.js",
    ".generated.rs",
    ".generated.go",
    ".g.dart",
];

pub struct GitFilter;

impl CommandFilter for GitFilter {
    fn id(&self) -> &'static str {
        "git"
    }

    fn matches(&self, program: &str, _args: &[String]) -> bool {
        program_stem(program) == "git"
    }

    fn filter(
        &self,
        raw_clean_stdout: &str,
        raw_clean_stderr: &str,
        exit_code: i32,
    ) -> FilteredRun {
        let mut omissions = Vec::new();
        let mut out_parts: Vec<String> = Vec::new();

        // On errors, always keep stderr completely verbatim.
        if exit_code != 0 && !raw_clean_stderr.trim().is_empty() {
            out_parts.push(raw_clean_stderr.trim_end().to_string());
        }

        let stdout_filtered = if looks_like_git_diff(raw_clean_stdout) {
            filter_git_diff(raw_clean_stdout, &mut omissions)
        } else if looks_like_git_status(raw_clean_stdout) {
            filter_git_status(raw_clean_stdout, &mut omissions)
        } else if looks_like_git_log(raw_clean_stdout) {
            filter_git_log(raw_clean_stdout, exit_code, &mut omissions)
        } else {
            filter_git_generic(
                raw_clean_stdout,
                raw_clean_stderr,
                exit_code,
                &mut omissions,
            )
        };

        if !stdout_filtered.trim().is_empty() {
            out_parts.push(stdout_filtered.trim_end().to_string());
        } else if exit_code == 0 && !raw_clean_stderr.trim().is_empty() {
            // Commands like `git checkout` / `git fetch` report status on stderr even when exit=0.
            let stderr_cleaned = strip_git_progress(raw_clean_stderr, &mut omissions);
            if !stderr_cleaned.trim().is_empty() {
                out_parts.push(stderr_cleaned.trim_end().to_string());
            }
        }

        let summary = out_parts.join("\n");
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

fn looks_like_git_diff(text: &str) -> bool {
    text.lines().any(|l| l.starts_with("diff --git "))
}

fn looks_like_git_status(text: &str) -> bool {
    let mut non_empty = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let Some(first) = non_empty.next() else {
        return false;
    };
    first.starts_with("On branch ")
        || first.starts_with("HEAD detached ")
        || first.starts_with("Not currently on any branch")
        || first.starts_with("## ")
        || text.contains("Changes to be committed:")
        || text.contains("Changes not staged for commit:")
        || text.contains("Untracked files:")
}

fn parse_git_commit_hash(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("commit ")?;
    let hash = rest.split_whitespace().next()?;
    if hash.len() >= 7 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hash)
    } else {
        None
    }
}

fn is_git_diagnostic_line(line: &str) -> bool {
    line.starts_with("fatal:")
        || line.starts_with("error:")
        || line.starts_with("warning:")
        || line.starts_with("hint:")
}

fn looks_like_git_log(text: &str) -> bool {
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return false;
    };
    if parse_git_commit_hash(first).is_none() {
        return false;
    }
    lines
        .take(4)
        .any(|l| l.starts_with("Author:") || l.starts_with("Merge:"))
}

fn filter_git_diff(stdout: &str, omissions: &mut Vec<Omission>) -> String {
    let mut output: Vec<String> = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_lines: Vec<&str> = Vec::new();

    let flush_section = |path_opt: &Option<String>,
                         section: &[&str],
                         out: &mut Vec<String>,
                         omissions: &mut Vec<Omission>| {
        if section.is_empty() {
            return;
        }
        if let Some(path) = path_opt
            && is_lockfile_or_generated(path)
        {
            let count = section.len();
            omissions.push(Omission {
                kind: OmissionKind::Lines,
                path: Some(path.clone()),
                start_line: None,
                end_line: None,
                count,
                reason: "git_diff_lockfile_or_generated_omitted".to_string(),
            });
            out.push(format!(
                "[omitted lockfile/generated diff: {path} ({count} lines)]"
            ));
            return;
        }
        for line in section {
            out.push((*line).to_string());
        }
    };

    for line in stdout.lines() {
        if line.starts_with("diff --git ") {
            flush_section(&current_path, &current_lines, &mut output, omissions);
            current_lines.clear();
            current_path = extract_diff_path(line);
            current_lines.push(line);
        } else if line.starts_with("fatal:") || line.starts_with("error:") {
            // Flush active section (even if lockfile) before preserving error line verbatim.
            flush_section(&current_path, &current_lines, &mut output, omissions);
            current_lines.clear();
            current_path = None;
            output.push(line.to_string());
        } else {
            current_lines.push(line);
        }
    }
    flush_section(&current_path, &current_lines, &mut output, omissions);

    output.join("\n")
}

fn extract_diff_path(header: &str) -> Option<String> {
    // Format: `diff --git a/path/to/file b/path/to/file` (or quoted paths).
    let rest = header.strip_prefix("diff --git ")?;
    if let Some((_, b_part)) = rest.rsplit_once(" b/") {
        return Some(b_part.trim_matches('"').to_string());
    }
    rest.split_whitespace()
        .last()
        .map(|s| s.trim_matches('"').trim_start_matches("b/").to_string())
}

fn is_lockfile_or_generated(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);
    if LOCKFILE_NAMES.contains(&file_name) {
        return true;
    }
    if GENERATED_SUFFIXES.iter().any(|s| file_name.ends_with(s)) {
        return true;
    }
    lower.contains("/generated/") || lower.starts_with("generated/")
}

fn filter_git_status(stdout: &str, omissions: &mut Vec<Omission>) -> String {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        None,
        Staged,
        Unstaged,
        Untracked,
        Unmerged,
    }

    let mut branch_info: Vec<String> = Vec::new();
    let mut staged: Vec<String> = Vec::new();
    let mut unstaged: Vec<String> = Vec::new();
    let mut untracked: Vec<String> = Vec::new();
    let mut unmerged: Vec<String> = Vec::new();
    let mut other: Vec<String> = Vec::new();
    let mut omitted_hints = 0usize;
    let mut section = Section::None;

    for raw_line in stdout.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("(use \"git ") || trimmed.starts_with("(fix conflicts") {
            omitted_hints += 1;
            continue;
        }
        if trimmed.starts_with("On branch ")
            || trimmed.starts_with("HEAD detached ")
            || trimmed.starts_with("Your branch ")
            || trimmed.starts_with("## ")
        {
            branch_info.push(trimmed.to_string());
            continue;
        }
        match trimmed {
            "Changes to be committed:" => {
                section = Section::Staged;
                continue;
            }
            "Changes not staged for commit:" => {
                section = Section::Unstaged;
                continue;
            }
            "Untracked files:" => {
                section = Section::Untracked;
                continue;
            }
            "Unmerged paths:" => {
                section = Section::Unmerged;
                continue;
            }
            _ => {}
        }

        if raw_line.starts_with('\t') || raw_line.starts_with("        ") {
            let entry = trimmed.to_string();
            match section {
                Section::Staged => staged.push(entry),
                Section::Unstaged => unstaged.push(entry),
                Section::Untracked => untracked.push(entry),
                Section::Unmerged => unmerged.push(entry),
                Section::None => other.push(entry),
            }
        } else {
            other.push(trimmed.to_string());
        }
    }

    if omitted_hints > 0 {
        omissions.push(Omission::items(omitted_hints, "git_status_hints_omitted"));
    }

    let mut out = Vec::new();
    out.extend(branch_info);
    if !unmerged.is_empty() {
        out.push(format!(
            "Unmerged ({}): {}",
            unmerged.len(),
            unmerged.join(", ")
        ));
    }
    if !staged.is_empty() {
        out.push(format!("Staged ({}): {}", staged.len(), staged.join(", ")));
    }
    if !unstaged.is_empty() {
        out.push(format!(
            "Modified ({}): {}",
            unstaged.len(),
            unstaged.join(", ")
        ));
    }
    if !untracked.is_empty() {
        out.push(format!(
            "Untracked ({}): {}",
            untracked.len(),
            untracked.join(", ")
        ));
    }
    out.extend(other);
    out.join("\n")
}

fn filter_git_log(stdout: &str, exit_code: i32, omissions: &mut Vec<Omission>) -> String {
    let mut entries: Vec<String> = Vec::new();
    let mut omitted_meta_lines = 0usize;

    let mut cur_hash = String::new();
    let mut cur_author = String::new();
    let mut cur_date = String::new();
    let mut cur_subject = String::new();

    let flush = |hash: &mut String,
                 author: &mut String,
                 date: &mut String,
                 subject: &mut String,
                 out: &mut Vec<String>| {
        if hash.is_empty() {
            return;
        }
        let short = &hash[..hash.len().min(7)];
        let mut line = short.to_string();
        if !date.is_empty() {
            line.push(' ');
            line.push_str(date);
        }
        if !author.is_empty() {
            line.push(' ');
            line.push_str(author);
        }
        if !subject.is_empty() {
            line.push_str(" | ");
            line.push_str(subject);
        }
        out.push(line);
        hash.clear();
        author.clear();
        date.clear();
        subject.clear();
    };

    for line in stdout.lines() {
        if let Some(hash) = parse_git_commit_hash(line) {
            flush(
                &mut cur_hash,
                &mut cur_author,
                &mut cur_date,
                &mut cur_subject,
                &mut entries,
            );
            cur_hash = hash.to_string();
        } else if is_git_diagnostic_line(line) {
            // Never drop diagnostic/error lines (also preserves combined stderr on `klens runs show`).
            flush(
                &mut cur_hash,
                &mut cur_author,
                &mut cur_date,
                &mut cur_subject,
                &mut entries,
            );
            entries.push(line.to_string());
        } else if !cur_hash.is_empty()
            && let Some(rest) = line.strip_prefix("Author:")
        {
            let trimmed = rest.trim();
            // Keep author name without full `<email>` noise.
            cur_author = trimmed
                .split('<')
                .next()
                .unwrap_or(trimmed)
                .trim()
                .to_string();
            omitted_meta_lines += 1;
        } else if !cur_hash.is_empty()
            && let Some(rest) = line.strip_prefix("Date:")
        {
            cur_date = compact_git_date(rest.trim());
            omitted_meta_lines += 1;
        } else if !cur_hash.is_empty() && line.starts_with("Merge:") {
            omitted_meta_lines += 1;
        } else if !cur_hash.is_empty() && line.starts_with("    ") {
            let msg = line.trim();
            if !msg.is_empty() {
                if cur_subject.is_empty() {
                    cur_subject = msg.to_string();
                } else {
                    omitted_meta_lines += 1;
                }
            }
        } else if !line.trim().is_empty() && (exit_code != 0 || cur_hash.is_empty()) {
            flush(
                &mut cur_hash,
                &mut cur_author,
                &mut cur_date,
                &mut cur_subject,
                &mut entries,
            );
            entries.push(line.to_string());
        }
    }

    flush(
        &mut cur_hash,
        &mut cur_author,
        &mut cur_date,
        &mut cur_subject,
        &mut entries,
    );

    if omitted_meta_lines > 0 {
        omissions.push(Omission::items(
            omitted_meta_lines,
            "git_log_verbose_headers_omitted",
        ));
    }

    entries.join("\n")
}

fn compact_git_date(raw: &str) -> String {
    // Handles ISO dates (`2026-11-22 ...`) or default git dates (`Sun Nov 22 18:30:00 2026 +0300`).
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() >= 5 && parts[4].len() == 4 && parts[4].bytes().all(|b| b.is_ascii_digit()) {
        // e.g. `Sun Nov 22 18:30:00 2026 +0300` -> `2026-Nov-22`
        return format!("{}-{}-{}", parts[4], parts[1], parts[2]);
    }
    if let Some(first) = parts.first() {
        return (*first).to_string();
    }
    raw.to_string()
}

fn filter_git_generic(
    stdout: &str,
    _stderr: &str,
    _exit_code: i32,
    omissions: &mut Vec<Omission>,
) -> String {
    strip_git_progress(stdout, omissions)
}

fn strip_git_progress(text: &str, omissions: &mut Vec<Omission>) -> String {
    let mut kept = Vec::new();
    let mut dropped = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if (trimmed.starts_with("Counting objects:")
            || trimmed.starts_with("Compressing objects:")
            || trimmed.starts_with("Receiving objects:")
            || trimmed.starts_with("Resolving deltas:")
            || trimmed.starts_with("Writing objects:"))
            && trimmed.contains('%')
            && !trimmed.ends_with(", done.")
        {
            dropped += 1;
            continue;
        }
        kept.push(line);
    }
    if dropped > 0 {
        omissions.push(Omission::items(dropped, "git_progress_omitted"));
    }
    kept.join("\n")
}
