//! Block-aware filter for `docker` and `docker-compose`.
//!
//! Compresses BuildKit/classic build cache and layer pull/push progress lines with explicit
//! `Omission` records while preserving 100% of failed `#N` `RUN` step outputs, `ERROR:`,
//! `failed to solve`, `exit code: N`, container/compose errors, and final image/tag summaries.

use std::collections::BTreeSet;

use klens_core::{CommandFilter, FilteredRun, Omission};

use super::common::{build_filtered_run, program_stem};

pub struct DockerFilter;

impl CommandFilter for DockerFilter {
    fn id(&self) -> &'static str {
        "docker"
    }

    fn matches(&self, program: &str, _args: &[String]) -> bool {
        matches!(program_stem(program).as_str(), "docker" | "docker-compose")
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

        // Pass 1: Identify every BuildKit step ID (`#N`) that errored so its entire output
        // block (including build/compiler errors inside `RUN`) is kept 100% verbatim.
        let mut failed_steps: BTreeSet<u64> = BTreeSet::new();
        for &line in &lines {
            let trimmed = line.trim();
            if let Some((step_id, rest)) = parse_buildkit_step(trimmed)
                && is_buildkit_step_error(rest)
            {
                failed_steps.insert(step_id);
            }
        }

        let mut kept: Vec<String> = Vec::new();
        let mut omissions: Vec<Omission> = Vec::new();
        let mut build_noise = 0usize;
        let mut layer_noise = 0usize;
        let mut in_error_block = false;

        for line in lines {
            let trimmed = line.trim();

            if in_error_block {
                kept.push(line.to_string());
                continue;
            }

            if is_docker_error_block_start(trimmed) {
                in_error_block = true;
                kept.push(line.to_string());
                continue;
            }

            if let Some((step_id, rest)) = parse_buildkit_step(trimmed) {
                if failed_steps.contains(&step_id) {
                    kept.push(line.to_string());
                    continue;
                }
                if is_buildkit_success_summary(rest) {
                    kept.push(line.to_string());
                    continue;
                }
                if is_buildkit_progress_noise(step_id, rest, exit_code) {
                    build_noise += 1;
                    continue;
                }
            }

            if is_classic_build_noise(trimmed, exit_code) {
                build_noise += 1;
                continue;
            }

            if is_layer_progress_noise(trimmed) {
                layer_noise += 1;
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
        if build_noise > 0 {
            omissions.push(Omission::items(
                build_noise,
                "docker_build_progress_omitted",
            ));
            summary_notes.push(format!("{build_noise} build step progress lines omitted"));
        }
        if layer_noise > 0 {
            omissions.push(Omission::items(
                layer_noise,
                "docker_layer_progress_omitted",
            ));
            summary_notes.push(format!("{layer_noise} layer progress lines omitted"));
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

fn parse_buildkit_step(trimmed: &str) -> Option<(u64, &str)> {
    let rest = trimmed.strip_prefix('#')?;
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let after_digits = &rest[digits..];
    let body = after_digits.strip_prefix(' ')?;
    let step_id = rest[..digits].parse::<u64>().ok()?;
    Some((step_id, body.trim_start()))
}

fn is_buildkit_step_error(rest: &str) -> bool {
    rest.starts_with("ERROR:")
        || rest.starts_with("ERROR ")
        || rest.contains("did not complete successfully")
        || rest.contains("exit code:")
        || rest.starts_with("error:")
}

fn is_docker_error_block_start(trimmed: &str) -> bool {
    trimmed.starts_with("------")
        || trimmed.starts_with("ERROR:")
        || trimmed.starts_with("ERROR ")
        || trimmed.contains("failed to solve")
        || trimmed.starts_with("Error response from daemon:")
        || trimmed.starts_with("Error:")
        || trimmed.starts_with("error:")
        || trimmed.starts_with("Dockerfile:")
        || trimmed.starts_with("failed to ")
        || trimmed.contains("exit code:")
        || trimmed.starts_with("unable to ")
        || trimmed.starts_with("manifest for ")
}

fn is_buildkit_success_summary(rest: &str) -> bool {
    rest.starts_with("naming to ") || rest.starts_with("writing image ")
}

fn is_buildkit_progress_noise(step_id: u64, rest: &str, exit_code: i32) -> bool {
    if rest == "CACHED"
        || rest == "DONE"
        || rest.starts_with("DONE ")
        || rest.starts_with("[internal] ")
        || rest.starts_with("sha256:")
        || rest.starts_with("transferring ")
        || rest.starts_with("resolving provenance")
        || rest.starts_with("extracting sha256:")
        || rest.starts_with("loading ")
        || rest.starts_with("exporting layers")
        || rest.starts_with("exporting manifest")
        || rest.starts_with("exporting config")
        || rest.starts_with("exporting attestation")
        || rest.starts_with("exporting to image")
    {
        return true;
    }

    if step_id == 0 && rest.starts_with("building with ") {
        return true;
    }

    // Non-failed stage headers (`#5 [builder 2/6] COPY ...`) and timestamped step output
    // on clean builds are progress noise.
    if rest.starts_with('[') && rest.contains(']') {
        return true;
    }

    exit_code == 0 && has_leading_seconds_timestamp(rest)
}

fn has_leading_seconds_timestamp(rest: &str) -> bool {
    let Some((first, _)) = rest.split_once(' ') else {
        return false;
    };
    let Some((secs, frac)) = first.split_once('.') else {
        return false;
    };
    !secs.is_empty()
        && !frac.is_empty()
        && secs.bytes().all(|b| b.is_ascii_digit())
        && frac.bytes().all(|b| b.is_ascii_digit())
}

fn is_classic_build_noise(trimmed: &str, exit_code: i32) -> bool {
    if trimmed == "---> Using cache"
        || trimmed.starts_with("Removing intermediate container ")
        || trimmed.starts_with("Sending build context to Docker daemon")
    {
        return true;
    }
    if let Some(hash) = trimmed.strip_prefix("---> ")
        && hash.len() >= 12
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return true;
    }
    exit_code == 0
        && trimmed.starts_with("Step ")
        && trimmed.contains('/')
        && trimmed.contains(" : ")
}

fn is_layer_progress_noise(trimmed: &str) -> bool {
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("error")
        || lower.contains("failed")
        || lower.contains("denied")
        || lower.contains("unauthorized")
        || lower.contains("not found")
        || lower.contains("unknown")
    {
        return false;
    }

    const LAYER_STATUSES: &[&str] = &[
        "Pulling fs layer",
        "Waiting",
        "Downloading",
        "Verifying Checksum",
        "Download complete",
        "Extracting",
        "Pull complete",
        "Already exists",
        "Preparing",
        "Pushing",
        "Pushed",
        "Layer already exists",
        "Mounted from",
    ];

    if let Some((_prefix, status)) = trimmed.split_once(": ") {
        let s = status.trim();
        if LAYER_STATUSES.iter().any(|p| s.starts_with(p)) {
            return true;
        }
    }

    // Docker Compose progress lines (`app Pulling`, `3f9582a2cbe7 Downloading ...`).
    for status in [
        " Pulling",
        " Waiting",
        " Downloading",
        " Verifying Checksum",
        " Download complete",
        " Extracting",
        " Pull complete",
        " Already exists",
        " Pulling fs layer",
    ] {
        if trimmed.contains(status) {
            return true;
        }
    }

    false
}
