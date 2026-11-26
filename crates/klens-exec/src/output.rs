//! Lossless stdout + stderr combination helper (leaf module — zero internal deps).

/// Deterministically combine stdout and stderr into a single lossless raw log string.
pub fn combine_raw_output(stdout: &str, stderr: &str) -> String {
    if stderr.is_empty() {
        return stdout.to_string();
    }
    if stdout.is_empty() {
        return stderr.to_string();
    }
    let mut combined = String::with_capacity(stdout.len() + stderr.len() + 1);
    combined.push_str(stdout);
    if !stdout.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(stderr);
    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_raw_output_is_lossless() {
        assert_eq!(combine_raw_output("out\n", ""), "out\n");
        assert_eq!(combine_raw_output("", "err\n"), "err\n");
        assert_eq!(combine_raw_output("out\n", "err\n"), "out\nerr\n");
        assert_eq!(combine_raw_output("out", "err"), "out\nerr");
    }
}
