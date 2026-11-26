//! Bounded `stdio` JSON-RPC 2.0 client for out-of-core `ext-lang-*` sidecars.
//!
//! Enforces:
//! - Direct `Command::new(&manifest.command)` without shell interpolation
//! - Windows `CREATE_NO_WINDOW` (`0x0800_0000`) on spawn and `taskkill /T /F /PID`
//! - `env_clear()` + minimal OS baseline vars + `cwd = std::env::temp_dir()`
//! - Bounded 4 MiB line reader (zero OOM on malicious oversized frames)
//! - Wall-clock `mpsc::recv_timeout` per RPC call + process-tree termination
//! - Bounded 64 KiB stderr drain thread (zero pipe deadlock)

use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use klens_core::{
    LanguageExtensionManifest, MAX_ALLOWED_FILE_BYTES, RelPath, SUPPORTED_SIDECAR_PROTOCOL_VERSION,
    redact_secrets,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::sidecar::common::{
    CapabilitiesResult, DEFAULT_HANDSHAKE_TIMEOUT_MS, DEFAULT_SHUTDOWN_TIMEOUT_MS, EmptyParams,
    ExternalParseOutcome, InitializeParams, InitializeResult, JsonRpcRequest, JsonRpcResponse,
    MAX_STDERR_BYTES, ParseFileParams, ParseFileResult, ShutdownResult, apply_minimal_sidecar_env,
    configure_no_window, is_valid_language_id, kill_process_tree, truncate_utf8_bytes,
    validate_and_normalize_parse_result,
};

enum ReadLineEvent {
    Line(Vec<u8>),
    Oversized { limit: usize },
    Eof,
    IoError(String),
}

/// Active `stdio` JSON-RPC 2.0 session for a single enabled `ext-lang-*` sidecar.
pub(crate) struct RpcSidecarSession {
    manifest: LanguageExtensionManifest,
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    stdout_rx: mpsc::Receiver<ReadLineEvent>,
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    next_id: u64,
    capabilities: CapabilitiesResult,
    effective_max_file_bytes: u64,
    terminated: bool,
}

impl RpcSidecarSession {
    /// Spawn a language sidecar subprocess and complete the mandatory
    /// `ext/initialize` -> `ext/capabilities` fail-closed handshake.
    pub(crate) fn spawn(manifest: &LanguageExtensionManifest) -> Result<Self, String> {
        let mut cmd = Command::new(&manifest.command);
        cmd.args(&manifest.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        apply_minimal_sidecar_env(&mut cmd, &manifest.id);
        configure_no_window(&mut cmd);

        let mut child = cmd
            .spawn()
            .map_err(|err| format!("failed to spawn sidecar `{}`: {err}", manifest.command))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "sidecar stdin pipe unavailable".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "sidecar stdout pipe unavailable".to_string())?;
        let stderr = child.stderr.take();

        let (tx, rx) = mpsc::channel();
        let max_frame = manifest.max_frame_bytes;
        thread::spawn(move || {
            let mut reader = BufReader::with_capacity(64 * 1024, stdout);
            loop {
                let ev = read_line_bounded(&mut reader, max_frame);
                let stop = !matches!(ev, ReadLineEvent::Line(_));
                if tx.send(ev).is_err() || stop {
                    break;
                }
            }
        });

        let stderr_buf = Arc::new(Mutex::new(Vec::new()));
        if let Some(err_pipe) = stderr {
            let buf_ref = Arc::clone(&stderr_buf);
            thread::spawn(move || drain_stderr_bounded(err_pipe, buf_ref));
        }

        let placeholder_caps = CapabilitiesResult {
            protocol_version: SUPPORTED_SIDECAR_PROTOCOL_VERSION,
            extension_id: manifest.id.clone(),
            parser_id: manifest.id.clone(),
            parser_version: manifest.version.clone(),
            languages: Vec::new(),
            supports_byte_ranges: false,
            supports_imports: false,
            max_file_bytes: manifest.max_file_bytes,
        };

        let mut session = Self {
            manifest: manifest.clone(),
            child,
            stdin: Some(BufWriter::new(stdin)),
            stdout_rx: rx,
            stderr_buf,
            next_id: 1,
            capabilities: placeholder_caps,
            effective_max_file_bytes: manifest.max_file_bytes.min(MAX_ALLOWED_FILE_BYTES),
            terminated: false,
        };

        if let Err(err) = session.perform_handshake() {
            session.terminate_hard();
            return Err(err);
        }

        Ok(session)
    }

    pub(crate) fn capabilities(&self) -> &CapabilitiesResult {
        &self.capabilities
    }

    fn perform_handshake(&mut self) -> Result<(), String> {
        let init_params = InitializeParams {
            protocol_version: SUPPORTED_SIDECAR_PROTOCOL_VERSION,
            klens_version: env!("CARGO_PKG_VERSION"),
            project_root: None,
            read_only: true,
            capabilities_requested: vec!["parse_file"],
        };
        let init_resp: JsonRpcResponse<InitializeResult> =
            self.call_rpc("ext/initialize", &init_params, DEFAULT_HANDSHAKE_TIMEOUT_MS)?;
        if let Some(err) = init_resp.error {
            return Err(format!(
                "ext/initialize returned JSON-RPC error {}: {}",
                err.code,
                redact_secrets(&err.message).text
            ));
        }
        let init = init_resp
            .result
            .ok_or_else(|| "ext/initialize response missing `result`".to_string())?;
        if init.protocol_version != SUPPORTED_SIDECAR_PROTOCOL_VERSION {
            return Err(format!(
                "ext/initialize protocol_version mismatch: got {}, expected {SUPPORTED_SIDECAR_PROTOCOL_VERSION}",
                init.protocol_version
            ));
        }
        if init.extension_id != self.manifest.id {
            return Err(format!(
                "ext/initialize extension_id mismatch: got `{}`, expected `{}`",
                init.extension_id, self.manifest.id
            ));
        }
        if init.version != self.manifest.version {
            return Err(format!(
                "ext/initialize version mismatch: got `{}`, expected `{}`",
                init.version, self.manifest.version
            ));
        }
        if init.requires_network {
            return Err("ext/initialize violation: requires_network must be false".to_string());
        }
        if !init.supports_read_only {
            return Err("ext/initialize violation: supports_read_only must be true".to_string());
        }
        if !init.capabilities.iter().any(|c| c == "parse_file") {
            return Err(
                "ext/initialize violation: missing required `parse_file` capability".to_string(),
            );
        }

        let caps_resp: JsonRpcResponse<CapabilitiesResult> = self.call_rpc(
            "ext/capabilities",
            &EmptyParams {},
            DEFAULT_HANDSHAKE_TIMEOUT_MS,
        )?;
        if let Some(err) = caps_resp.error {
            return Err(format!(
                "ext/capabilities returned JSON-RPC error {}: {}",
                err.code,
                redact_secrets(&err.message).text
            ));
        }
        let caps = caps_resp
            .result
            .ok_or_else(|| "ext/capabilities response missing `result`".to_string())?;
        if caps.protocol_version != SUPPORTED_SIDECAR_PROTOCOL_VERSION {
            return Err(format!(
                "ext/capabilities protocol_version mismatch: got {}",
                caps.protocol_version
            ));
        }
        if caps.extension_id != self.manifest.id || caps.parser_id != self.manifest.id {
            return Err(format!(
                "ext/capabilities identity mismatch (extension_id=`{}`, parser_id=`{}`, expected `{}`)",
                caps.extension_id, caps.parser_id, self.manifest.id
            ));
        }
        if caps.parser_version != self.manifest.version {
            return Err(format!(
                "ext/capabilities parser_version mismatch: got `{}`, expected `{}`",
                caps.parser_version, self.manifest.version
            ));
        }
        if caps.languages.is_empty() {
            return Err("ext/capabilities violation: `languages` must not be empty".to_string());
        }
        for lang in &caps.languages {
            if !is_valid_language_id(&lang.language_id) {
                return Err(format!(
                    "ext/capabilities violation: invalid language_id `{}`",
                    lang.language_id
                ));
            }
        }

        let cap_max = if caps.max_file_bytes == 0 {
            self.manifest.max_file_bytes
        } else {
            caps.max_file_bytes
        };
        self.effective_max_file_bytes = self
            .manifest
            .max_file_bytes
            .min(cap_max)
            .min(MAX_ALLOWED_FILE_BYTES);
        self.capabilities = caps;
        Ok(())
    }

    /// Invoke `ext/parse_file` on CRLF-normalized inline UTF-8 content and pass the reply
    /// through the mandatory core validation/redaction/sorting gate.
    ///
    /// Returns `Err(reason)` on hard transport/timeout/framing failure (after killing the
    /// process tree) so the caller can drop this session and advance the circuit breaker.
    pub(crate) fn parse_file(
        &mut self,
        rel: &RelPath,
        language_hint: &str,
        normalized_content: &str,
        content_blake3: &str,
        file_line_count: usize,
    ) -> Result<ExternalParseOutcome, String> {
        let content_bytes = normalized_content.len() as u64;
        if content_bytes > self.effective_max_file_bytes {
            return Ok(ExternalParseOutcome::Fallback {
                language_id: Some(language_hint.to_string()),
                reason: format!(
                    "file size ({content_bytes} bytes) exceeds sidecar `{}` max_file_bytes ({})",
                    self.manifest.id, self.effective_max_file_bytes
                ),
                count_as_failure: false,
            });
        }

        let params = ParseFileParams {
            path: rel.as_str(),
            language_hint,
            content: normalized_content,
            content_blake3,
            line_ending: "lf",
        };

        // Pre-check serialized request frame size against `max_frame_bytes` (fail-closed before write).
        let id = self.next_id;
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: "ext/parse_file",
            params: &params,
        };
        let encoded =
            serde_json::to_string(&req).map_err(|e| format!("failed to encode request: {e}"))?;
        if encoded.len() + 1 > self.manifest.max_frame_bytes {
            return Ok(ExternalParseOutcome::Fallback {
                language_id: Some(language_hint.to_string()),
                reason: format!(
                    "serialized ext/parse_file request ({} bytes) exceeds max_frame_bytes ({})",
                    encoded.len() + 1,
                    self.manifest.max_frame_bytes
                ),
                count_as_failure: false,
            });
        }

        let resp: JsonRpcResponse<ParseFileResult> =
            self.call_rpc_encoded(id, &encoded, self.manifest.timeout_ms)?;

        if let Some(err) = resp.error {
            return Ok(ExternalParseOutcome::Fallback {
                language_id: Some(language_hint.to_string()),
                reason: format!(
                    "sidecar `{}` JSON-RPC error {}: {}",
                    self.manifest.id,
                    err.code,
                    redact_secrets(&err.message).text
                ),
                count_as_failure: false,
            });
        }

        let Some(result) = resp.result else {
            self.terminate_hard();
            return Err("protocol violation: ext/parse_file response missing `result`".to_string());
        };

        Ok(validate_and_normalize_parse_result(
            result,
            &self.manifest.id,
            &self.manifest.version,
            normalized_content,
            file_line_count,
        ))
    }

    /// Gracefully send `ext/shutdown` and wait for clean exit, or terminate process tree on timeout.
    pub(crate) fn shutdown(mut self) {
        self.shutdown_in_place();
    }

    fn shutdown_in_place(&mut self) {
        if self.terminated {
            return;
        }
        let _: Result<JsonRpcResponse<ShutdownResult>, String> =
            self.call_rpc("ext/shutdown", &EmptyParams {}, DEFAULT_SHUTDOWN_TIMEOUT_MS);
        self.stdin.take();

        let deadline = Instant::now() + Duration::from_millis(250);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                self.terminated = true;
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.terminate_hard();
    }

    fn call_rpc<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &'static str,
        params: &P,
        timeout_ms: u64,
    ) -> Result<JsonRpcResponse<R>, String> {
        let id = self.next_id;
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let encoded = serde_json::to_string(&req)
            .map_err(|e| format!("failed to serialize {method}: {e}"))?;
        if encoded.len() + 1 > self.manifest.max_frame_bytes {
            return Err(format!(
                "RPC request `{method}` exceeds max_frame_bytes ({})",
                self.manifest.max_frame_bytes
            ));
        }
        self.call_rpc_encoded(id, &encoded, timeout_ms)
    }

    fn call_rpc_encoded<R: DeserializeOwned>(
        &mut self,
        id: u64,
        encoded_json: &str,
        timeout_ms: u64,
    ) -> Result<JsonRpcResponse<R>, String> {
        self.next_id = id.saturating_add(1);
        let Some(stdin) = self.stdin.as_mut() else {
            self.terminate_hard();
            return Err("sidecar stdin is closed".to_string());
        };
        if let Err(err) = stdin
            .write_all(encoded_json.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
        {
            self.terminate_hard();
            return Err(format!(
                "failed writing request to sidecar `{}`: {err}{}",
                self.manifest.id,
                self.stderr_suffix()
            ));
        }

        let raw_bytes = match self
            .stdout_rx
            .recv_timeout(Duration::from_millis(timeout_ms))
        {
            Ok(ReadLineEvent::Line(bytes)) => bytes,
            Ok(ReadLineEvent::Oversized { limit }) => {
                self.terminate_hard();
                return Err(format!(
                    "sidecar `{}` exceeded max_frame_bytes ({limit} bytes); process terminated",
                    self.manifest.id
                ));
            }
            Ok(ReadLineEvent::Eof) => {
                self.terminate_hard();
                return Err(format!(
                    "sidecar `{}` closed stdout unexpectedly (EOF){}",
                    self.manifest.id,
                    self.stderr_suffix()
                ));
            }
            Ok(ReadLineEvent::IoError(err)) => {
                self.terminate_hard();
                return Err(format!(
                    "sidecar `{}` stdout read error: {err}{}",
                    self.manifest.id,
                    self.stderr_suffix()
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.terminate_hard();
                return Err(format!(
                    "sidecar `{}` timed out after {timeout_ms}ms; process tree terminated",
                    self.manifest.id
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.terminate_hard();
                return Err(format!(
                    "sidecar `{}` terminated prematurely{}",
                    self.manifest.id,
                    self.stderr_suffix()
                ));
            }
        };

        let parsed: JsonRpcResponse<R> = serde_json::from_slice(&raw_bytes).map_err(|err| {
            self.terminate_hard();
            format!(
                "sidecar `{}` emitted invalid JSON on stdout: {err}{}",
                self.manifest.id,
                self.stderr_suffix()
            )
        })?;

        if parsed.jsonrpc != "2.0" || parsed.id != Some(id) {
            self.terminate_hard();
            return Err(format!(
                "protocol violation: mismatched JSON-RPC envelope (jsonrpc=`{}`, id={:?}, expected {id})",
                parsed.jsonrpc, parsed.id
            ));
        }

        Ok(parsed)
    }

    fn stderr_suffix(&self) -> String {
        let Ok(guard) = self.stderr_buf.lock() else {
            return String::new();
        };
        if guard.is_empty() {
            return String::new();
        }
        let lossy = String::from_utf8_lossy(&guard);
        let trimmed = lossy.trim();
        if trimmed.is_empty() {
            return String::new();
        }
        let redacted = redact_secrets(trimmed).text;
        let (short, _) = truncate_utf8_bytes(&redacted, 240);
        format!(" [stderr: {short}]")
    }

    fn terminate_hard(&mut self) {
        if self.terminated {
            return;
        }
        self.terminated = true;
        self.stdin.take();
        let pid = self.child.id();
        kill_process_tree(pid);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for RpcSidecarSession {
    fn drop(&mut self) {
        self.shutdown_in_place();
    }
}

/// Spawn a custom `ext-lang-*` sidecar, verify `ext/initialize` + `ext/capabilities`,
/// and shut it down cleanly (used by `klens doctor` and Web UI health inspection).
pub fn probe_rpc_sidecar(
    manifest: &LanguageExtensionManifest,
) -> Result<CapabilitiesResult, String> {
    let session = RpcSidecarSession::spawn(manifest)?;
    let caps = session.capabilities().clone();
    session.shutdown();
    Ok(caps)
}

fn read_line_bounded<R: BufRead>(reader: &mut R, max_bytes: usize) -> ReadLineEvent {
    let mut buf = Vec::new();
    loop {
        let avail = match reader.fill_buf() {
            Ok(slice) => slice,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return ReadLineEvent::IoError(err.to_string()),
        };

        if avail.is_empty() {
            if buf.is_empty() {
                return ReadLineEvent::Eof;
            }
            trim_trailing_crlf(&mut buf);
            return ReadLineEvent::Line(buf);
        }

        if let Some(newline_pos) = avail.iter().position(|&b| b == b'\n') {
            let take = newline_pos + 1;
            if buf.len().saturating_add(take) > max_bytes {
                reader.consume(take);
                return ReadLineEvent::Oversized { limit: max_bytes };
            }
            buf.extend_from_slice(&avail[..take]);
            reader.consume(take);
            trim_trailing_crlf(&mut buf);
            return ReadLineEvent::Line(buf);
        }

        let len = avail.len();
        if buf.len().saturating_add(len) > max_bytes {
            return ReadLineEvent::Oversized { limit: max_bytes };
        }
        buf.extend_from_slice(avail);
        reader.consume(len);
    }
}

fn trim_trailing_crlf(buf: &mut Vec<u8>) {
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
}

fn drain_stderr_bounded<R: Read>(mut reader: R, out: Arc<Mutex<Vec<u8>>>) {
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(mut guard) = out.lock() {
                    let remaining = MAX_STDERR_BYTES.saturating_sub(guard.len());
                    if remaining > 0 {
                        let copy_len = n.min(remaining);
                        guard.extend_from_slice(&chunk[..copy_len]);
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}
