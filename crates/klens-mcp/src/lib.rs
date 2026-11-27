#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

//! Karasu Lens (`klens-mcp`) — ultra-lightweight, Windows-safe `stdio` MCP server.
//!
//! Guarantees:
//! - `#![deny(clippy::print_stdout)]` & `#![forbid(unsafe_code)]`: zero accidental stdout
//!   pollution; all diagnostic warnings go strictly to `stderr`.
//! - Windows `stdio` framing: strips incoming `\r\n`, writes strictly pure `\n` (LF), and
//!   flushes after every JSON-RPC response.
//! - Token budget lock: Phase 3A's 6 tools stay `<= 850` tokens (`< 1,200` hard ceiling).
//! - Project access policy enforced before every `tools/call` (`mode` & `allowed_clients`).

mod blueprint_handler;
mod check_handler;
pub mod error;
mod handler_common;
mod handlers;
mod memory_handler;
pub mod policy;
pub mod protocol;
pub mod server;
pub mod tools;

pub use blueprint_handler::collect_handoff_input;
pub use error::McpError;
pub use memory_handler::LazyCodeSymbolResolver;
pub use policy::{
    PROJECT_ACCESS_RESTRICTED, PolicyDenial, check_tool_access, check_tool_call_access,
    evaluate_policy, evaluate_policy_for_call, is_read_only_tool, is_read_only_tool_call,
};
pub use protocol::{
    CallToolResult, ClientInfo, DEFAULT_PROTOCOL_VERSION, IncomingMessage, InitializeParams,
    JsonRpcErrorBody, JsonRpcResponse, RequestId, ToolCallParams, ToolContent, trim_line_endings,
    write_lf_frame,
};
pub use server::{MCP_INITIALIZE_INSTRUCTIONS, McpServer, McpServerConfig};
pub use tools::{
    MAX_TOOLS_LIST_TOKENS, PHASE3A_TOOLS_LIST_TARGET_TOKENS, PHASE4_TOOLS_LIST_TARGET_TOKENS,
    ToolAnnotations, ToolDefinition, tool_definitions,
};
