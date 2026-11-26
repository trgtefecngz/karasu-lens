//! Universal synchronous `stdio` MCP server (`McpServer`).
//!
//! Guarantees:
//! - JSON-RPC 2.0 compliance: echoes string, integer, or `null` `id` verbatim;
//!   NEVER emits any response to notifications lacking an `id` key.
//! - Windows `stdio` safety: strips incoming `\r\n`, writes strictly pure `\n` (LF),
//!   and calls `flush()` after every single frame.
//! - Enforces `.klens/config.toml` project access policy on every `tools/call`.
//! - Appends honest Layer 1 telemetry to `~/.klens/metrics.jsonl`.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use klens_core::ProjectRoot;
use klens_core::telemetry::{
    DEFAULT_MAX_LINE_BYTES, LineReadOutcome, MetricEvent, append_metric_event,
    default_metrics_path, read_bounded_line, utf8_safe_prefix,
};
use klens_core::time::now_iso8601_utc;
use serde_json::{Value, json};

use crate::error::McpError;
use crate::handlers::{ToolContext, execute_tool};
use crate::policy::check_tool_call_access;
use crate::protocol::{
    CallToolResult, DEFAULT_PROTOCOL_VERSION, ERR_INVALID_PARAMS, ERR_METHOD_NOT_FOUND,
    IncomingMessage, InitializeParams, JsonRpcErrorBody, JsonRpcResponse, ToolCallParams,
    trim_line_endings, write_lf_frame,
};
use crate::tools::tool_definitions;

/// Concise workflow instructions emitted in MCP `initialize` responses.
pub const MCP_INITIALIZE_INSTRUCTIONS: &str = "Use klens_map (optionally scoped with `path`) to orient, then klens_outline before surgical klens_read (prefer qualified symbols or batch `targets` over full-file reads). Check blast radius with klens_impact before edits and execute tests or builds via klens_run for ANSI-clean, zero-error-loss output.";

/// Configuration for [`McpServer`].
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    pub project_root: ProjectRoot,
    /// Path to Layer 1 universal telemetry log (`~/.klens/metrics.jsonl` by default).
    pub metrics_path: Option<PathBuf>,
    /// Optional explicit read-only SQLite cache directory (useful for isolated tests).
    pub readonly_cache_dir: Option<PathBuf>,
    /// Maximum incoming JSON-RPC line length in bytes.
    pub max_line_bytes: usize,
}

impl McpServerConfig {
    /// Construct a default server configuration targeting `project_root`.
    pub fn new(project_root: ProjectRoot) -> Self {
        Self {
            project_root,
            metrics_path: default_metrics_path(),
            readonly_cache_dir: None,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        }
    }
}

/// Stateful JSON-RPC 2.0 / MCP server over `stdio` or any `BufRead`/`Write` transport.
pub struct McpServer {
    config: McpServerConfig,
    client_name: Option<String>,
    client_version: Option<String>,
    initialized: bool,
}

impl McpServer {
    /// Create a new MCP server bound to the configured project root.
    pub fn new(config: McpServerConfig) -> Self {
        Self {
            config,
            client_name: None,
            client_version: None,
            initialized: false,
        }
    }

    /// Borrow the negotiated client name from `initialize` (`clientInfo.name`), if any.
    pub fn client_name(&self) -> Option<&str> {
        self.client_name.as_deref()
    }

    /// Serve MCP requests over process `stdin`/`stdout` until EOF.
    pub fn serve_stdio(&mut self) -> Result<(), McpError> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let reader = stdin.lock();
        let writer = stdout.lock();
        self.serve_io(reader, writer)
    }

    /// Serve MCP requests from `reader` and write pure-LF flushed responses to `writer`.
    pub fn serve_io<R: BufRead, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> Result<(), McpError> {
        let mut buf = Vec::new();
        loop {
            match read_bounded_line(&mut reader, &mut buf, self.config.max_line_bytes)? {
                LineReadOutcome::Eof => break,
                LineReadOutcome::Truncated { .. } => {
                    let err_resp = JsonRpcResponse::err(
                        Value::Null,
                        JsonRpcErrorBody {
                            code: crate::protocol::ERR_INVALID_REQUEST,
                            message: format!(
                                "JSON-RPC frame exceeds max limit of {} bytes",
                                self.config.max_line_bytes
                            ),
                            data: None,
                        },
                    );
                    write_lf_frame(&mut writer, &err_resp.to_json_line())?;
                }
                LineReadOutcome::Complete => {
                    let text = utf8_safe_prefix(&buf);
                    if let Some(reply) = self.handle_raw_line(text) {
                        write_lf_frame(&mut writer, &reply)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle a single raw line (tolerant of trailing `\r\n` or `\n`).
    ///
    /// Returns `None` for empty lines and for all JSON-RPC notifications (missing `id`).
    pub fn handle_raw_line(&mut self, raw_line: &str) -> Option<String> {
        let line = trim_line_endings(raw_line).trim();
        if line.is_empty() {
            return None;
        }

        let msg = match IncomingMessage::parse_line(line) {
            Ok(msg) => msg,
            Err(err_body) => {
                return Some(JsonRpcResponse::err(Value::Null, err_body).to_json_line());
            }
        };

        // JSON-RPC 2.0 notification (no `id` key) -> NEVER send a response!
        if msg.id.is_notification() {
            if msg.method == "notifications/initialized" {
                self.initialized = true;
            }
            return None;
        }

        let id = msg.id.as_value().cloned().unwrap_or(Value::Null);

        if let Some(ref version) = msg.jsonrpc
            && version != "2.0"
        {
            return Some(
                JsonRpcResponse::err(
                    id,
                    JsonRpcErrorBody {
                        code: crate::protocol::ERR_INVALID_REQUEST,
                        message: format!("unsupported jsonrpc version `{version}`; expected `2.0`"),
                        data: None,
                    },
                )
                .to_json_line(),
            );
        }

        let response = match msg.method.as_str() {
            "initialize" => self.handle_initialize(id, msg.params),
            "ping" => JsonRpcResponse::ok(id, json!({})),
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => self.handle_tools_call(id, msg.params),
            other => JsonRpcResponse::err(
                id,
                JsonRpcErrorBody {
                    code: ERR_METHOD_NOT_FOUND,
                    message: format!("method not found: `{other}`"),
                    data: None,
                },
            ),
        };

        Some(response.to_json_line())
    }

    fn handle_initialize(&mut self, id: Value, params: Value) -> JsonRpcResponse {
        let init: InitializeParams = serde_json::from_value(params).unwrap_or_default();
        if let Some(info) = init.client_info {
            let trimmed_name = info.name.trim().to_string();
            if !trimmed_name.is_empty() {
                self.client_name = Some(trimmed_name);
            }
            let trimmed_ver = info.version.trim().to_string();
            if !trimmed_ver.is_empty() {
                self.client_version = Some(trimmed_ver);
            }
        }

        let negotiated_version = init
            .protocol_version
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_PROTOCOL_VERSION.to_string());

        JsonRpcResponse::ok(
            id,
            json!({
                "protocolVersion": negotiated_version,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "klens",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": MCP_INITIALIZE_INSTRUCTIONS
            }),
        )
    }

    fn handle_tools_list(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::ok(
            id,
            json!({
                "tools": tool_definitions()
            }),
        )
    }

    fn handle_tools_call(&self, id: Value, params: Value) -> JsonRpcResponse {
        let call: ToolCallParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(err) => {
                return JsonRpcResponse::err(
                    id,
                    JsonRpcErrorBody {
                        code: ERR_INVALID_PARAMS,
                        message: format!("invalid `tools/call` params: {err}"),
                        data: None,
                    },
                );
            }
        };

        // Enforce per-project `.klens/config.toml` access policy before executing ANY tool.
        let project_cfg = match check_tool_call_access(
            &self.config.project_root,
            self.client_name.as_deref(),
            &call.name,
            &call.arguments,
        ) {
            Ok(cfg) => cfg,
            Err(denial) => {
                let denied_result = CallToolResult::error_code(denial.code, denial.reason);
                return JsonRpcResponse::ok(
                    id,
                    serde_json::to_value(denied_result).unwrap_or_else(|_| json!({})),
                );
            }
        };

        let ctx = ToolContext {
            project_root: &self.config.project_root,
            mode: project_cfg.mode,
            readonly_cache_dir: self.config.readonly_cache_dir.as_deref(),
        };

        match execute_tool(&ctx, &call.name, &call.arguments) {
            Ok(exec) => {
                self.record_metric(
                    &call.name,
                    exec.raw_est_tokens,
                    exec.filtered_est_tokens,
                    exec.is_run_filtered,
                    exec.stale_memories_caught,
                );
                JsonRpcResponse::ok(
                    id,
                    serde_json::to_value(exec.result).unwrap_or_else(|_| json!({})),
                )
            }
            Err(McpError::UnknownTool(name)) => JsonRpcResponse::err(
                id,
                JsonRpcErrorBody {
                    code: ERR_INVALID_PARAMS,
                    message: format!("unknown tool `{name}`"),
                    data: None,
                },
            ),
            Err(McpError::InvalidParams(msg)) => JsonRpcResponse::err(
                id,
                JsonRpcErrorBody {
                    code: ERR_INVALID_PARAMS,
                    message: msg,
                    data: None,
                },
            ),
            Err(err) => {
                let err_result =
                    CallToolResult::error_code("TOOL_EXECUTION_ERROR", err.to_string());
                JsonRpcResponse::ok(
                    id,
                    serde_json::to_value(err_result).unwrap_or_else(|_| json!({})),
                )
            }
        }
    }

    fn record_metric(
        &self,
        tool: &str,
        raw_est_tokens: u64,
        filtered_est_tokens: u64,
        is_run_filtered: bool,
        stale_memories_caught: u64,
    ) {
        let Some(metrics_path) = &self.config.metrics_path else {
            return;
        };

        let project_name = self
            .config
            .project_root
            .root()
            .file_name()
            .and_then(|s| s.to_str())
            .map(ToOwned::to_owned);

        let mut event = MetricEvent::new(
            now_iso8601_utc(),
            self.config.project_root.project_id(),
            project_name,
            self.client_name.as_deref().unwrap_or("unknown"),
            self.client_version.as_deref().unwrap_or(""),
            tool,
            raw_est_tokens,
            filtered_est_tokens,
            is_run_filtered,
        );
        event.stale_memories_caught = stale_memories_caught;

        if let Err(err) = append_metric_event(metrics_path, &event) {
            let _ = writeln!(
                io::stderr(),
                "[klens-mcp] warning: failed to append telemetry metric: {err}"
            );
        }
    }
}
