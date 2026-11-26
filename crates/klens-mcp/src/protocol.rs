//! JSON-RPC 2.0 and Model Context Protocol (MCP) wire types + Windows-safe LF framing.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Default MCP protocol version advertised by `klens-mcp`.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";

/// Standard JSON-RPC 2.0 error codes.
pub const ERR_PARSE_ERROR: i32 = -32700;
pub const ERR_INVALID_REQUEST: i32 = -32600;
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
pub const ERR_INVALID_PARAMS: i32 = -32602;
pub const ERR_INTERNAL_ERROR: i32 = -32603;

/// Parsed JSON-RPC 2.0 `id` field distinguishing an omitted `id` (notification)
/// from an explicit `null`, integer, or string `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestId {
    /// `id` property was NOT present in the JSON object -> JSON-RPC notification (no reply!).
    Missing,
    /// `id` property was present (`null`, number, or string) -> MUST be echoed verbatim.
    Present(Value),
}

impl RequestId {
    /// Returns `true` when this message is a notification (no `id` key).
    pub const fn is_notification(&self) -> bool {
        matches!(self, Self::Missing)
    }

    /// Borrow the response `id` value if present.
    pub fn as_value(&self) -> Option<&Value> {
        match self {
            Self::Missing => None,
            Self::Present(v) => Some(v),
        }
    }
}

/// Incoming JSON-RPC 2.0 request or notification parsed from one `stdin` line.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    pub jsonrpc: Option<String>,
    pub id: RequestId,
    pub method: String,
    pub params: Value,
}

impl IncomingMessage {
    /// Parse a single JSON-RPC 2.0 message object, preserving the distinction between
    /// missing `id` (notification) and explicit `"id": null` / number / string.
    pub fn parse_line(line: &str) -> Result<Self, JsonRpcErrorBody> {
        let raw: Value = serde_json::from_str(line).map_err(|e| JsonRpcErrorBody {
            code: ERR_PARSE_ERROR,
            message: format!("invalid JSON: {e}"),
            data: None,
        })?;

        let Some(obj) = raw.as_object() else {
            return Err(JsonRpcErrorBody {
                code: ERR_INVALID_REQUEST,
                message: "JSON-RPC message must be a JSON object".to_string(),
                data: None,
            });
        };

        let id = match obj.get("id") {
            None => RequestId::Missing,
            Some(v) => {
                if v.is_null() || v.is_string() || v.is_i64() || v.is_u64() {
                    RequestId::Present(v.clone())
                } else {
                    return Err(JsonRpcErrorBody {
                        code: ERR_INVALID_REQUEST,
                        message: "JSON-RPC `id` must be string, integer, or null".to_string(),
                        data: None,
                    });
                }
            }
        };

        let jsonrpc = obj
            .get("jsonrpc")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            return Err(JsonRpcErrorBody {
                code: ERR_INVALID_REQUEST,
                message: "missing string `method` field".to_string(),
                data: None,
            });
        };

        let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));

        Ok(Self {
            jsonrpc,
            id,
            method: method.to_string(),
            params,
        })
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcErrorBody {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Outgoing JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorBody>,
}

impl JsonRpcResponse {
    /// Build a successful JSON-RPC 2.0 response echoing `id`.
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build a JSON-RPC 2.0 error response echoing `id` (or `Value::Null` on parse errors).
    pub fn err(id: Value, error: JsonRpcErrorBody) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Serialize to a single compact JSON line (no embedded newlines).
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"serialization error\"}}".to_string()
        })
    }
}

/// MCP `initialize` client metadata.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
}

/// MCP `initialize` request parameters.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    #[serde(default)]
    pub protocol_version: Option<String>,
    #[serde(default)]
    pub client_info: Option<ClientInfo>,
}

/// MCP `tools/call` request parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

/// MCP tool call content block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
}

/// MCP `tools/call` response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<ToolContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl CallToolResult {
    /// Successful plain-text or JSON-text MCP tool result.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent {
                kind: "text".to_string(),
                text: text.into(),
            }],
            is_error: None,
        }
    }

    /// Structured MCP tool-level error result (`isError: true`).
    pub fn error_code(code: &str, message: impl Into<String>) -> Self {
        let payload = json!({
            "schema_version": klens_core::SCHEMA_VERSION,
            "error": code,
            "message": message.into(),
        });
        Self {
            content: vec![ToolContent {
                kind: "text".to_string(),
                text: payload.to_string(),
            }],
            is_error: Some(true),
        }
    }
}

/// Strip trailing Windows `\r` and `\n` line terminators without altering interior text.
pub fn trim_line_endings(raw: &str) -> &str {
    raw.trim_end_matches(['\r', '\n'])
}

/// Write a single JSON-RPC message terminated strictly with pure `\n` (LF) and immediately
/// `flush()` the writer (Windows stdio safety guarantee).
pub fn write_lf_frame<W: Write>(writer: &mut W, json_line: &str) -> io::Result<()> {
    // Defense-in-depth: strip any accidental CR/LF from the serialized payload.
    let clean = json_line.replace(['\r', '\n'], "");
    writer.write_all(clean.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}
