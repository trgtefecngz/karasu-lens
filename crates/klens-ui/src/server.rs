//! Synchronous loopback-only HTTP server (`tiny_http`) and safe OS browser launcher.

use std::io::Cursor;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use klens_adapters::{global_config_path_in, resolve_home_dir};
use klens_core::GlobalConfig;
use tiny_http::{Header, Request, Response, Server, StatusCode};

use crate::error::UiError;
use crate::routes::common::HttpResponse;
use crate::routes::dispatch;
use crate::security::{GuardOutcome, security_guard, session_cookie_header_value};
use crate::state::{UiConfig, UiState};

const RECV_POLL_INTERVAL: Duration = Duration::from_millis(80);

/// Bound synchronous local HTTP server ready to serve requests on `127.0.0.1:<port>`.
pub struct UiServer {
    server: Server,
    state: Arc<UiState>,
}

impl UiServer {
    /// Bind strictly to `127.0.0.1:<port>` (never `0.0.0.0`) and initialize [`UiState`].
    pub fn bind(config: UiConfig) -> Result<Self, UiError> {
        let home_for_port = match &config.home_dir {
            Some(h) => h.clone(),
            None => resolve_home_dir().unwrap_or_default(),
        };
        let preferred_port = config.port.unwrap_or_else(|| {
            GlobalConfig::load_or_default(&global_config_path_in(&home_for_port))
                .map(|c| c.ui_port)
                .unwrap_or(4729)
        });

        let server = match config.port {
            Some(explicit) => {
                Server::http(("127.0.0.1", explicit)).map_err(|e| UiError::BindFailed {
                    port: explicit,
                    reason: e.to_string(),
                })?
            }
            None => match Server::http(("127.0.0.1", preferred_port)) {
                Ok(srv) => srv,
                Err(_) => Server::http(("127.0.0.1", 0)).map_err(|e| UiError::BindFailed {
                    port: 0,
                    reason: e.to_string(),
                })?,
            },
        };

        let bound_port = server
            .server_addr()
            .to_ip()
            .map(|addr| addr.port())
            .ok_or_else(|| UiError::BindFailed {
                port: preferred_port,
                reason: "unable to determine bound IPv4 loopback port".to_string(),
            })?;

        let state = Arc::new(UiState::new(&config, bound_port)?);
        Ok(Self { server, state })
    }

    /// Actual loopback port bound by this server.
    pub fn bound_port(&self) -> u16 {
        self.state.bound_port
    }

    /// Cryptographic session token generated for this server instance.
    pub fn session_token(&self) -> &str {
        &self.state.session_token
    }

    /// Tokenized local URL (`http://127.0.0.1:<port>/?token=<token>`).
    pub fn launch_url(&self) -> String {
        self.state.launch_url()
    }

    /// Shared shutdown signal flag (can be set externally or via `POST /api/shutdown`).
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.state.shutdown_requested)
    }

    /// Run the synchronous HTTP request loop until graceful shutdown is requested.
    pub fn serve_until_shutdown(self) -> Result<(), UiError> {
        while !self.state.is_shutdown_requested() {
            match self.server.recv_timeout(RECV_POLL_INTERVAL) {
                Ok(Some(mut request)) => {
                    let response = handle_single_request(&self.state, &mut request);
                    send_response(request, response);
                }
                Ok(None) => {}
                Err(err) => {
                    if self.state.is_shutdown_requested() {
                        break;
                    }
                    return Err(UiError::Io(err));
                }
            }
        }
        Ok(())
    }
}

fn handle_single_request(state: &UiState, request: &mut Request) -> HttpResponse {
    match security_guard(request, state.bound_port, &state.session_token) {
        Ok(GuardOutcome::SetSessionCookieAndRedirect) => HttpResponse::redirect_with_cookie(
            "/",
            session_cookie_header_value(&state.session_token),
        ),
        Ok(GuardOutcome::Allow { .. }) => match dispatch(state, request) {
            Ok(resp) => resp,
            Err(err) => HttpResponse::from_error(&err),
        },
        Err(err) => HttpResponse::from_error(&err),
    }
}

/// Defense in depth for the local dashboard: scripts and network calls only from the UI's
/// own origin, no plugins, frames, forms or `<base>` tricks. Inline `style="..."` attributes
/// are used by the views, so styles allow `'unsafe-inline'`; scripts never do.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
    font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

fn send_response(request: Request, resp: HttpResponse) {
    let len = resp.body.len();
    let mut http_resp = Response::new(
        StatusCode(resp.status),
        Vec::new(),
        Cursor::new(resp.body),
        Some(len),
        None,
    );

    if let Ok(ct) = Header::from_bytes("Content-Type", resp.content_type) {
        http_resp.add_header(ct);
    }
    if let Ok(h) = Header::from_bytes("X-Content-Type-Options", "nosniff") {
        http_resp.add_header(h);
    }
    if let Ok(h) = Header::from_bytes("X-Frame-Options", "DENY") {
        http_resp.add_header(h);
    }
    if let Ok(h) = Header::from_bytes("Referrer-Policy", "no-referrer") {
        http_resp.add_header(h);
    }
    if let Ok(h) = Header::from_bytes("Content-Security-Policy", CONTENT_SECURITY_POLICY) {
        http_resp.add_header(h);
    }
    for (k, v) in resp.extra_headers {
        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            http_resp.add_header(h);
        }
    }

    let _ = request.respond(http_resp);
}

/// Safely open a local loopback URL in the user's default web browser.
///
/// Security guarantee (Windows):
/// - NEVER invokes `cmd /C start` (avoids `&` command injection and black console window flash).
/// - Uses `rundll32.exe url.dll,FileProtocolHandler <url>` with `CREATE_NO_WINDOW` (`0x0800_0000`).
pub fn open_browser(url: &str) -> Result<(), UiError> {
    if !is_safe_loopback_launch_url(url) {
        return Err(UiError::BrowserLaunch(format!(
            "refused to launch non-loopback or unsafe URL: {url}"
        )));
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = Command::new("rundll32.exe");
        cmd.args(["url.dll,FileProtocolHandler", url])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(klens_exec::WINDOWS_CREATE_NO_WINDOW);
        cmd.spawn()
            .map_err(|e| UiError::BrowserLaunch(e.to_string()))?;
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| UiError::BrowserLaunch(e.to_string()))?;
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| UiError::BrowserLaunch(e.to_string()))?;
    }

    Ok(())
}

/// Validate that a browser launch URL is strictly `http://127.0.0.1:<port>/...` with safe ASCII chars.
pub fn is_safe_loopback_launch_url(url: &str) -> bool {
    if !url.starts_with("http://127.0.0.1:") {
        return false;
    }
    url.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b':' | b'/' | b'.' | b'?' | b'=' | b'-' | b'_' | b'&')
    })
}

#[cfg(test)]
mod tests {
    use super::is_safe_loopback_launch_url;

    #[test]
    fn browser_url_validator_accepts_loopback_and_rejects_injection() {
        assert!(is_safe_loopback_launch_url(
            "http://127.0.0.1:4729/?token=0123456789abcdef"
        ));
        assert!(!is_safe_loopback_launch_url("https://evil.com/?token=123"));
        assert!(!is_safe_loopback_launch_url(
            "http://127.0.0.1:4729/?token=abc;calc.exe"
        ));
        assert!(!is_safe_loopback_launch_url(
            "http://127.0.0.1:4729/?token=abc|whoami"
        ));
    }
}
