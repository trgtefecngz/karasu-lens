//! CLI handler for `klens ui` and no-argument Windows double-click launch.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;
use klens_ui::{
    UiConfig, UiError, UiServer, directory_looks_like_project, is_safe_loopback_launch_url,
    open_browser,
};

use super::common::{CliError, CliOutcome};

static BG_LAUNCH_SEQ: AtomicU64 = AtomicU64::new(0);
const BG_LAUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const BG_LAUNCH_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Default, Args)]
pub(crate) struct UiArgs {
    /// Local loopback port to bind on `127.0.0.1` (defaults to `GlobalConfig::ui_port`, 4729, or a free port).
    #[arg(long)]
    pub port: Option<u16>,

    /// Do not automatically open the default web browser on startup.
    #[arg(long)]
    pub no_open: bool,

    /// Print only the tokenized loopback URL to stdout (implies --no-open).
    #[arg(long)]
    pub print_url: bool,

    /// Zero-footprint inspection mode: forbids writing any file into the selected project directory.
    #[arg(long)]
    pub read_only: bool,

    /// Optional explicit initial project root directory.
    #[arg(long, value_name = "PATH")]
    pub root: Option<PathBuf>,

    /// Launch the local Web UI server detached in the background (closes the console window immediately on Windows).
    #[arg(long)]
    pub background: bool,

    /// Keep the local Web UI server attached to the current console window.
    #[arg(long, conflicts_with = "background")]
    pub foreground: bool,

    /// Internal hidden flag used exclusively by the detached background Web UI worker process.
    #[arg(long, hide = true)]
    pub background_worker: bool,

    /// Internal hidden flag carrying the atomic rendezvous file path for background worker startup.
    #[arg(long, hide = true)]
    pub background_url_file: Option<PathBuf>,
}

pub(crate) fn run_ui_cmd(args: UiArgs) -> Result<CliOutcome, CliError> {
    if args.background_worker {
        return run_ui_background_worker(args);
    }

    if args.background && !args.foreground {
        return spawn_ui_background(&args);
    }

    run_ui_foreground(args)
}

fn resolve_initial_root(explicit_root: Option<PathBuf>) -> Option<PathBuf> {
    match explicit_root {
        Some(path) => Some(path),
        None => std::env::current_dir()
            .ok()
            .filter(|dir| directory_looks_like_project(dir)),
    }
}

fn build_background_worker_args(args: &UiArgs, url_file: Option<&Path>) -> Vec<OsString> {
    let mut worker_args = vec![
        OsString::from("ui"),
        OsString::from("--background-worker"),
        OsString::from("--no-open"),
    ];
    if let Some(port) = args.port {
        worker_args.push(OsString::from("--port"));
        worker_args.push(OsString::from(port.to_string()));
    }
    if let Some(root) = &args.root {
        worker_args.push(OsString::from("--root"));
        worker_args.push(root.as_os_str().to_os_string());
    }
    if args.read_only {
        worker_args.push(OsString::from("--read-only"));
    }
    if let Some(path) = url_file {
        worker_args.push(OsString::from("--background-url-file"));
        worker_args.push(path.as_os_str().to_os_string());
    }
    worker_args
}

fn write_atomic_rendezvous(path: &Path, content: &str) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    fs::write(&tmp_path, content.as_bytes())?;
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

struct RendezvousFileGuard {
    path: PathBuf,
}

impl RendezvousFileGuard {
    fn new() -> Self {
        let seq = BG_LAUNCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("klens-ui-launch-{}-{seq}.url", std::process::id()));
        let _ = fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RendezvousFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let mut tmp = self.path.as_os_str().to_os_string();
        tmp.push(".tmp");
        let _ = fs::remove_file(PathBuf::from(tmp));
    }
}

/// Quote a single argument according to Windows `CommandLineToArgvW` rules so paths with spaces,
/// quotes, trailing backslashes, or Unicode characters round-trip losslessly.
#[cfg(any(windows, test))]
fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.bytes().any(|b| matches!(b, b' ' | b'\t' | b'"')) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(ch);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

#[cfg(any(windows, test))]
fn format_windows_argument_list(args: &[OsString]) -> String {
    args.iter()
        .map(|arg| quote_windows_arg(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_ui_background_worker(args: UiArgs) -> Result<CliOutcome, CliError> {
    let url_file = args.background_url_file.clone();
    let initial_root = resolve_initial_root(args.root);
    let config = UiConfig {
        port: args.port,
        initial_root,
        read_only: args.read_only,
        no_open: true,
        ..UiConfig::default()
    };

    let server = match UiServer::bind(config) {
        Ok(srv) => srv,
        Err(err) => {
            if let Some(ref path) = url_file {
                let _ = write_atomic_rendezvous(path, &format!("ERR:{err}\n"));
            }
            return Err(err.into());
        }
    };
    let url = server.launch_url();

    if let Some(ref path) = url_file {
        write_atomic_rendezvous(path, &format!("{url}\n")).map_err(UiError::Io)?;
    } else {
        let mut stdout = io::stdout().lock();
        let _ = writeln!(stdout, "{url}");
        let _ = stdout.flush();
    }

    server.serve_until_shutdown()?;
    Ok(CliOutcome::silent_ok())
}

#[cfg(windows)]
fn spawn_detached_worker_process(exe: &Path, worker_args: &[OsString]) -> io::Result<()> {
    use std::os::windows::process::CommandExt;

    // On Windows, `std::process::Command::spawn` inherits the parent's inheritable stdout/stderr
    // pipe handles into long-lived children, causing callers capturing stdout (`Command::output()`,
    // PowerShell `$u = klens ui --background --print-url`) to block forever waiting for EOF.
    // Launching via `Start-Process -WindowStyle Hidden` uses `ShellExecuteExW` (`bInheritHandles = FALSE`)
    // so the detached worker holds zero caller pipe handles, with zero `unsafe` code and zero console flash.
    const LAUNCH_SCRIPT: &str = "Start-Process -FilePath $env:KLENS_BG_EXE -ArgumentList $env:KLENS_BG_ARGS -WindowStyle Hidden";
    let arg_string = format_windows_argument_list(worker_args);

    let mut ps = Command::new("powershell.exe");
    ps.args(["-NoProfile", "-NonInteractive", "-Command", LAUNCH_SCRIPT])
        .env("KLENS_BG_EXE", exe)
        .env("KLENS_BG_ARGS", &arg_string)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(klens_exec::WINDOWS_CREATE_NO_WINDOW);

    if let Ok(status) = ps.status()
        && status.success()
    {
        return Ok(());
    }

    // Fallback for minimal Windows environments without PowerShell.
    let mut fallback = Command::new(exe);
    fallback
        .args(worker_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(klens_exec::WINDOWS_CREATE_NO_WINDOW);
    let _child = fallback.spawn()?;
    Ok(())
}

#[cfg(not(windows))]
fn spawn_detached_worker_process(exe: &Path, worker_args: &[OsString]) -> io::Result<()> {
    let mut cmd = Command::new(exe);
    cmd.args(worker_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _child = cmd.spawn()?;
    Ok(())
}

fn spawn_ui_background(args: &UiArgs) -> Result<CliOutcome, CliError> {
    let exe = std::env::current_exe().map_err(UiError::Io)?;
    let effective_args = UiArgs {
        port: args.port,
        no_open: args.no_open,
        print_url: args.print_url,
        read_only: args.read_only,
        root: resolve_initial_root(args.root.clone()),
        background: args.background,
        foreground: args.foreground,
        background_worker: false,
        background_url_file: None,
    };

    let rendezvous = RendezvousFileGuard::new();
    let worker_args = build_background_worker_args(&effective_args, Some(rendezvous.path()));
    spawn_detached_worker_process(&exe, &worker_args).map_err(UiError::Io)?;

    let deadline = Instant::now() + BG_LAUNCH_TIMEOUT;
    let mut published: Option<String> = None;
    while Instant::now() < deadline {
        if let Ok(raw) = fs::read_to_string(rendezvous.path()) {
            let trimmed = raw.trim().to_string();
            if !trimmed.is_empty() {
                published = Some(trimmed);
                break;
            }
        }
        thread::sleep(BG_LAUNCH_POLL_INTERVAL);
    }

    let Some(payload) = published else {
        return Err(UiError::Io(io::Error::other(
            "timed out waiting for background UI worker to publish its loopback URL",
        ))
        .into());
    };

    if let Some(err_detail) = payload.strip_prefix("ERR:") {
        return Err(UiError::Io(io::Error::other(format!(
            "background UI worker failed to start: {}",
            err_detail.trim()
        )))
        .into());
    }

    let url = payload;
    if !is_safe_loopback_launch_url(&url) {
        return Err(UiError::Io(io::Error::other(format!(
            "background UI worker printed an unsafe or non-loopback URL: {url}"
        )))
        .into());
    }

    if !args.no_open
        && !args.print_url
        && let Err(err) = open_browser(&url)
    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: could not launch browser automatically ({err}); open {url} manually"
        );
    }

    {
        let mut stdout = io::stdout().lock();
        if args.print_url {
            let _ = writeln!(stdout, "{url}");
        } else {
            let _ = writeln!(stdout, "Karasu Lens arka planda başlatıldı: {url}");
            let _ = writeln!(
                stdout,
                "Durdurmak için Web UI içindeki 'Sunucuyu Kapat' (Shutdown) düğmesini kullanabilirsiniz."
            );
            if args.read_only {
                let _ = writeln!(
                    stdout,
                    "Mod: Salt-Okunur (--read-only) — hedef proje klasörüne hiçbir dosya yazılmayacaktır."
                );
            }
        }
        let _ = stdout.flush();
    }

    Ok(CliOutcome::silent_ok())
}

fn run_ui_foreground(args: UiArgs) -> Result<CliOutcome, CliError> {
    let initial_root = resolve_initial_root(args.root);

    let no_open = args.no_open || args.print_url;
    let config = UiConfig {
        port: args.port,
        initial_root,
        read_only: args.read_only,
        no_open,
        ..UiConfig::default()
    };

    let server = UiServer::bind(config)?;
    let url = server.launch_url();

    {
        let mut stdout = io::stdout().lock();
        if args.print_url {
            let _ = writeln!(stdout, "{url}");
        } else {
            let _ = writeln!(stdout, "Karasu Lens paneli açıldı: {url}");
            let _ = writeln!(
                stdout,
                "Durdurmak için bu pencereyi kapatabilir veya arayüzdeki 'Sunucuyu Kapat' (Shutdown) düğmesini kullanabilirsiniz."
            );
            if args.read_only {
                let _ = writeln!(
                    stdout,
                    "Mod: Salt-Okunur (--read-only) — hedef proje klasörüne hiçbir dosya yazılmayacaktır."
                );
            }
        }
        let _ = stdout.flush();
    }

    if !no_open && let Err(err) = open_browser(&url) {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: could not launch browser automatically ({err}); open {url} manually"
        );
    }

    server.serve_until_shutdown()?;
    Ok(CliOutcome::silent_ok())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use klens_ui::is_safe_loopback_launch_url;

    use super::{UiArgs, build_background_worker_args, format_windows_argument_list};

    #[test]
    fn worker_args_forward_port_root_and_read_only_without_recursing_background() {
        let args = UiArgs {
            port: Some(4799),
            no_open: false,
            print_url: true,
            read_only: true,
            root: Some(PathBuf::from("C:/proj/demo")),
            background: true,
            foreground: false,
            background_worker: false,
            background_url_file: None,
        };

        let url_file = Path::new("C:/tmp/launch.url");
        let forwarded = build_background_worker_args(&args, Some(url_file));
        assert_eq!(
            forwarded,
            vec![
                OsString::from("ui"),
                OsString::from("--background-worker"),
                OsString::from("--no-open"),
                OsString::from("--port"),
                OsString::from("4799"),
                OsString::from("--root"),
                OsString::from("C:/proj/demo"),
                OsString::from("--read-only"),
                OsString::from("--background-url-file"),
                OsString::from("C:/tmp/launch.url"),
            ]
        );
    }

    #[test]
    fn worker_args_default_omits_optional_flags() {
        let forwarded = build_background_worker_args(&UiArgs::default(), None);
        assert_eq!(
            forwarded,
            vec![
                OsString::from("ui"),
                OsString::from("--background-worker"),
                OsString::from("--no-open"),
            ]
        );
    }

    #[test]
    fn windows_argument_quoting_preserves_spaces_quotes_and_trailing_backslashes() {
        let args = vec![
            OsString::from("ui"),
            OsString::from("--root"),
            OsString::from(r"C:\Users\Örnek Proje\dir\"),
            OsString::from("--port"),
            OsString::from("4729"),
        ];
        assert_eq!(
            format_windows_argument_list(&args),
            r#"ui --root "C:\Users\Örnek Proje\dir\\" --port 4729"#
        );
    }

    #[test]
    fn background_launch_url_gate_rejects_non_loopback_worker_output() {
        assert!(is_safe_loopback_launch_url(
            "http://127.0.0.1:4729/?token=abcdef0123456789"
        ));
        assert!(!is_safe_loopback_launch_url(""));
        assert!(!is_safe_loopback_launch_url("http://0.0.0.0:4729/?token=x"));
        assert!(!is_safe_loopback_launch_url(
            "http://127.0.0.1:4729/?token=abc&cmd=whoami;calc"
        ));
    }
}
