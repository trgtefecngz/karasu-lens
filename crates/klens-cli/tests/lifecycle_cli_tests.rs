use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static CLI_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct CliSandbox {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl CliSandbox {
    fn new(label: &str) -> Self {
        let seq = CLI_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "klens-cli-p3b-{label}-{}-{seq}",
            std::process::id()
        ));
        let home = root.join("home");
        let project = root.join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        Self {
            root,
            home,
            project,
        }
    }

    fn run_klens(&self, args: &[&str]) -> std::process::Output {
        let bin = env!("CARGO_BIN_EXE_klens");
        Command::new(bin)
            .args(args)
            .current_dir(&self.project)
            .env("USERPROFILE", &self.home)
            .env("HOME", &self.home)
            .output()
            .expect("failed to run klens binary")
    }
}

impl Drop for CliSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_ok_stdout(output: &std::process::Output) -> String {
    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn cli_full_phase3b_lifecycle_end_to_end() {
    let sb = CliSandbox::new("e2e");
    fs::write(
        sb.project.join("Cargo.toml"),
        "[package]\nname = \"demo\"\n",
    )
    .unwrap();
    fs::write(sb.project.join(".gitignore"), "target/\r\n").unwrap();

    // 1. `klens init --print-mcp-json` (read-only snippet)
    let snippet_out = assert_ok_stdout(&sb.run_klens(&[
        "init",
        "--print-mcp-json",
        "--binary",
        r"C:\tools\klens.exe",
    ]));
    let snippet_json: serde_json::Value = serde_json::from_str(&snippet_out).unwrap();
    assert_eq!(
        snippet_json["mcpServers"]["klens"]["command"],
        r"C:\tools\klens.exe"
    );
    assert!(!sb.project.join("KLENS.md").exists());

    // 2. `klens scan <parent> --json` (read-only)
    let parent_str = sb.root.to_string_lossy().into_owned();
    let scan_out = assert_ok_stdout(&sb.run_klens(&["scan", &parent_str, "--json"]));
    let scan_json: serde_json::Value = serde_json::from_str(&scan_out).unwrap();
    assert_eq!(scan_json["projects"].as_array().unwrap().len(), 1);
    assert_eq!(scan_json["projects"][0]["name"], "project");

    // 3. `klens attach --dry-run` writes nothing, then real `klens attach` registers in config.toml
    let attach_dry = assert_ok_stdout(&sb.run_klens(&["attach", "--dry-run", "--json"]));
    let attach_dry_val: serde_json::Value = serde_json::from_str(&attach_dry).unwrap();
    assert_eq!(attach_dry_val["dry_run"], true);
    assert_eq!(attach_dry_val["changed"], false);
    assert!(!sb.home.join(".klens/config.toml").exists());

    let attach_real = assert_ok_stdout(&sb.run_klens(&["attach", "--json"]));
    let attach_real_val: serde_json::Value = serde_json::from_str(&attach_real).unwrap();
    assert_eq!(attach_real_val["changed"], true);
    assert!(sb.home.join(".klens/config.toml").is_file());
    assert!(!sb.home.join(".klens/projects.json").exists());

    // 4. `klens init --host all` with binary A then moved binary B
    assert_ok_stdout(&sb.run_klens(&[
        "init",
        "--host",
        "all",
        "--binary",
        r"C:\a\klens.exe",
        "--json",
    ]));
    let init_b = assert_ok_stdout(&sb.run_klens(&[
        "init",
        "--host",
        "all",
        "--binary",
        r"C:\b\klens.exe",
        "--json",
    ]));
    assert!(init_b.contains("Updated binary path"));

    // 5. `klens detect --json` and `klens doctor --json`
    let detect_out =
        assert_ok_stdout(&sb.run_klens(&["detect", "--binary", r"C:\b\klens.exe", "--json"]));
    let detect_val: serde_json::Value = serde_json::from_str(&detect_out).unwrap();
    assert_eq!(detect_val["project_registered"], true);
    assert!(
        !detect_val["configured_access"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let doctor_out =
        assert_ok_stdout(&sb.run_klens(&["doctor", "--binary", r"C:\b\klens.exe", "--json"]));
    let doctor_val: serde_json::Value = serde_json::from_str(&doctor_out).unwrap();
    assert_eq!(doctor_val["overall"], "ok");

    // 6. `klens detach --purge` restores `.gitignore` byte-for-byte and removes `.klens/`
    assert_ok_stdout(&sb.run_klens(&["detach", "--purge", "--json"]));
    assert!(!sb.project.join(".klens").exists());
    assert_eq!(
        fs::read(sb.project.join(".gitignore")).unwrap(),
        b"target/\r\n"
    );

    // 7. `klens uninstall` fails without `--all`, succeeds with `--all`
    let fail_uninstall = sb.run_klens(&["uninstall"]);
    assert!(!fail_uninstall.status.success());

    assert_ok_stdout(&sb.run_klens(&["uninstall", "--all", "--json"]));
    assert!(!Path::new(&sb.home.join(".klens")).exists());
}

#[test]
fn cli_ui_help_exposes_background_foreground_and_hides_internal_worker_flag() {
    let sb = CliSandbox::new("ui-help");
    let help = assert_ok_stdout(&sb.run_klens(&["ui", "--help"]));
    for expected in ["--print-url", "--no-open", "--background", "--foreground"] {
        assert!(
            help.contains(expected),
            "expected `klens ui --help` to document `{expected}`, got:\n{help}"
        );
    }
    assert!(
        !help.contains("--background-worker"),
        "expected internal `--background-worker` flag to be hidden from `klens ui --help`, got:\n{help}"
    );

    // `--background` and `--foreground` are mutually exclusive.
    let conflict = sb.run_klens(&["ui", "--background", "--foreground"]);
    assert!(
        !conflict.status.success(),
        "expected `--background --foreground` to fail clap conflict check"
    );
}

fn probe_loopback_tcp_available() -> bool {
    let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", 0)) else {
        return false;
    };
    let Ok(addr) = listener.local_addr() else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)).is_ok()
}

fn parse_loopback_port_and_token(url: &str) -> Option<(u16, String)> {
    let rest = url.strip_prefix("http://127.0.0.1:")?;
    let (port_str, query) = rest.split_once("/?token=")?;
    let port = port_str.parse::<u16>().ok()?;
    if query.is_empty() {
        return None;
    }
    Some((port, query.to_string()))
}

fn send_authenticated_shutdown(port: u16, token: &str) -> std::io::Result<String> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(3)))?;
    let req = format!(
        "POST /api/shutdown HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Origin: http://127.0.0.1:{port}\r\n\
         Cookie: klens_session={token}\r\n\
         X-Klens-Request: 1\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp);
    Ok(resp)
}

struct BackgroundUiGuard {
    port: u16,
    token: String,
    shut_down: bool,
}

impl Drop for BackgroundUiGuard {
    fn drop(&mut self) {
        if !self.shut_down {
            let _ = send_authenticated_shutdown(self.port, &self.token);
        }
    }
}

#[test]
fn cli_ui_background_print_url_launches_detached_and_shuts_down_cleanly() {
    if !probe_loopback_tcp_available() {
        // Windows sandbox environments may deny loopback TCP connect (`Os 10013`).
        // Avoid spawning an unreachable background worker when loopback is restricted.
        return;
    }

    let sb = CliSandbox::new("ui-bg");
    let root_str = sb.project.to_string_lossy().into_owned();
    let output = sb.run_klens(&[
        "ui",
        "--background",
        "--print-url",
        "--port",
        "0",
        "--root",
        &root_str,
    ]);
    let stdout = assert_ok_stdout(&output);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one loopback URL line from `--background --print-url`, got:\n{stdout}"
    );
    let url = lines[0].trim();
    assert!(
        klens_ui::is_safe_loopback_launch_url(url),
        "expected safe loopback URL, got: {url}"
    );

    let (port, token) = parse_loopback_port_and_token(url)
        .unwrap_or_else(|| panic!("failed to parse loopback port/token from URL: {url}"));
    let mut guard = BackgroundUiGuard {
        port,
        token: token.clone(),
        shut_down: false,
    };

    let resp = send_authenticated_shutdown(port, &token)
        .expect("failed to send authenticated POST /api/shutdown to background UI worker");
    assert!(
        resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200"),
        "expected 200 OK from /api/shutdown, got:\n{resp}"
    );
    guard.shut_down = true;

    // Wait briefly and verify the detached worker actually closed its listening socket.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut closed = false;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            std::time::Duration::from_millis(100),
        )
        .is_err()
        {
            closed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        closed,
        "background UI worker on 127.0.0.1:{port} did not exit after /api/shutdown"
    );
}

fn run_git_in(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().expect("failed to spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_diff_check_staged_fail_on_and_hook_lifecycle_end_to_end() {
    let sb = CliSandbox::new("phase4-hook-diff");
    fs::create_dir_all(sb.project.join("src")).unwrap();
    fs::write(
        sb.project.join("src/lib.rs"),
        "pub fn clean() -> i32 { 1 }\n",
    )
    .unwrap();
    fs::write(
        sb.project.join("src/unstaged.rs"),
        "pub fn other() -> i32 { 2 }\n",
    )
    .unwrap();

    run_git_in(&sb.project, &["init"]);
    run_git_in(&sb.project, &["config", "user.email", "cli@klens.local"]);
    run_git_in(&sb.project, &["config", "user.name", "Klens CLI"]);
    run_git_in(&sb.project, &["add", "."]);
    run_git_in(&sb.project, &["commit", "-m", "initial"]);

    // 1. Clean staged change + unstaged secret -> `--staged --fail-on error` exits 0!
    let synthetic_token = format!("ghp_{}", "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2");
    fs::write(
        sb.project.join("src/lib.rs"),
        "pub fn clean() -> i32 { 42 }\n",
    )
    .unwrap();
    run_git_in(&sb.project, &["add", "src/lib.rs"]);
    fs::write(
        sb.project.join("src/unstaged.rs"),
        format!("pub fn other() -> &'static str {{ \"{synthetic_token}\" }}\n"),
    )
    .unwrap();

    let clean_out = sb.run_klens(&[
        "diff-check",
        "--staged",
        "--fail-on",
        "error",
        "--read-only",
        "--json",
    ]);
    let clean_stdout = assert_ok_stdout(&clean_out);
    let clean_val: serde_json::Value = serde_json::from_str(&clean_stdout).unwrap();
    assert_eq!(clean_val["data"]["overall_severity"], "ok");

    // 2. Stage the synthetic secret -> `--staged --fail-on error` MUST exit non-zero!
    run_git_in(&sb.project, &["add", "src/unstaged.rs"]);
    let fail_out = sb.run_klens(&[
        "diff-check",
        "--staged",
        "--fail-on",
        "error",
        "--read-only",
        "--json",
    ]);
    assert!(
        !fail_out.status.success(),
        "expected non-zero exit status on staged secret leak, got: {:?}\nstdout:\n{}",
        fail_out.status,
        String::from_utf8_lossy(&fail_out.stdout)
    );
    let fail_val: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&fail_out.stdout)).unwrap();
    assert_eq!(fail_val["data"]["overall_severity"], "error");
    assert_eq!(
        fail_val["data"]["secret_leaks"].as_array().unwrap().len(),
        1
    );

    // 3. `klens hook install --dry-run --json` -> `install --json` -> `status --json` -> `uninstall --json`
    let hook_file = sb.project.join(".git").join("hooks").join("pre-commit");
    let dry_out = assert_ok_stdout(&sb.run_klens(&["hook", "install", "--dry-run", "--json"]));
    let dry_val: serde_json::Value = serde_json::from_str(&dry_out).unwrap();
    assert_eq!(dry_val["dry_run"], true);
    assert_eq!(dry_val["changed"], false);
    assert!(!hook_file.exists());

    let inst_out = assert_ok_stdout(&sb.run_klens(&["hook", "install", "--json"]));
    let inst_val: serde_json::Value = serde_json::from_str(&inst_out).unwrap();
    assert_eq!(inst_val["changed"], true);
    assert!(hook_file.is_file());

    let status_out = assert_ok_stdout(&sb.run_klens(&["hook", "status", "--json"]));
    let status_val: serde_json::Value = serde_json::from_str(&status_out).unwrap();
    assert_eq!(status_val["is_git_repo"], true);
    assert_eq!(status_val["installed"], true);
    assert_eq!(status_val["binary_matches_current"], true);

    let un_out = assert_ok_stdout(&sb.run_klens(&["hook", "uninstall", "--json"]));
    let un_val: serde_json::Value = serde_json::from_str(&un_out).unwrap();
    assert_eq!(un_val["changed"], true);
    assert_eq!(un_val["removed_file"], true);
    assert!(!hook_file.exists());
}
