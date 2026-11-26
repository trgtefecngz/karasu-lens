//! B1 regression tests (v0.3.3+): `klens run` / `klens_run` must never hang forever or
//! exhaust memory.
//!
//! 1. Output larger than the capture limit keeps the head and (most importantly, for error
//!    context) the tail, and reports the omitted middle explicitly (Constitution Art. 2).
//! 2. A background process that inherits and keeps the output pipe open must not block the
//!    run after the command itself has exited.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use klens_core::ProjectRoot;
use klens_exec::{RunOptions, execute_command};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "klens-run-limits-{label}-{}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn huge_output_is_capped_but_keeps_tail_and_reports_omission() {
    let sb = Sandbox::new("cap");
    let root = ProjectRoot::new(sb.path()).unwrap();

    // ~2 MB of noise followed by the line that matters (like a final test failure).
    #[cfg(windows)]
    let cmd: Vec<String> = [
        "powershell",
        "-NoProfile",
        "-Command",
        "[Console]::Out.Write(('x' * 2000000)); [Console]::Out.WriteLine(''); [Console]::Out.WriteLine('TAIL_MARKER_OK')",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    #[cfg(not(windows))]
    let cmd: Vec<String> = [
        "sh",
        "-c",
        "head -c 2000000 /dev/zero | tr '\\000' x; echo; echo TAIL_MARKER_OK",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();

    let limit = 256 * 1024;
    let opts = RunOptions {
        raw: true,
        max_capture_bytes: limit,
        ..RunOptions::default()
    };
    let env = execute_command(&root, &cmd, &opts).unwrap();

    assert!(
        env.data.output.contains("TAIL_MARKER_OK"),
        "tail of the output (where errors usually are) must be kept"
    );
    assert!(
        env.data.output.contains("[klens] ... omitted"),
        "omitted middle must be reported explicitly"
    );
    assert!(
        env.warnings.iter().any(|w| w.contains("omitted")),
        "envelope must warn about the capped output: {:?}",
        env.warnings
    );

    // Honesty: errors may have been in the omitted middle, and the raw log is not complete.
    assert!(
        env.data.meta.truncated_errors,
        "capped output must never claim zero error loss"
    );
    let fallback = env.raw_fallback.as_ref().expect("raw fallback pointer");
    assert!(
        fallback.reason.contains("middle omitted"),
        "raw log must not be described as complete: {}",
        fallback.reason
    );

    let raw_log = fs::read(sb.path().join(&env.data.meta.raw_log_path)).unwrap();
    assert!(
        raw_log.len() < limit + 4096,
        "raw capture must stay within the limit, got {} bytes",
        raw_log.len()
    );
}

#[test]
fn background_process_holding_the_pipe_does_not_hang_the_run() {
    let sb = Sandbox::new("bgpipe");
    let root = ProjectRoot::new(sb.path()).unwrap();

    // The command itself finishes immediately, but leaves a 20 s background process that
    // inherits stdout (e.g. a dev server or build daemon).
    #[cfg(windows)]
    let cmd: Vec<String> = [
        "cmd",
        "/C",
        "start /B powershell -NoProfile -Command Start-Sleep -Seconds 20 & echo FOREGROUND_DONE",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    #[cfg(not(windows))]
    let cmd: Vec<String> = ["sh", "-c", "sleep 20 & echo FOREGROUND_DONE"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let started = Instant::now();
    let env = execute_command(
        &root,
        &cmd,
        &RunOptions {
            raw: true,
            ..RunOptions::default()
        },
    )
    .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(12),
        "run blocked on a pipe held open by a background process: {elapsed:?}"
    );
    assert!(env.data.output.contains("FOREGROUND_DONE"));
    assert!(
        env.warnings
            .iter()
            .any(|w| w.contains("background process")),
        "envelope must explain why capture stopped early: {:?}",
        env.warnings
    );
}
