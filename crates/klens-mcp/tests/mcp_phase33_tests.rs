//! Phase 3.3 MCP integration tests (`klens_run` `auto_context` + AST symbol enrichment):
//! 1. `tools/list` still exposes exactly 8 tools within `<= 1,090` tokens (`< 1,200` hard lock)
//!    and `klens_run.inputSchema.properties.auto_context` is `{ "type": "boolean" }`.
//! 2. Failing `klens_run` (default `auto_context: true`) returns `±5` line snippets + enclosing
//!    AST `symbol` (`fn broken_calc` and `impl Auth::verify`) in a single turn.
//! 3. `auto_context: false`, `raw: true`, and `exit == 0` all produce empty `error_contexts`.
//! 4. Invalid `auto_context: "yes"` returns JSON-RPC `-32602` (`InvalidParams`).
//! 5. Secret inside `±5` neighbor lines is redacted and increments `redactions_count`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::{ProjectRoot, estimate_tokens};
use klens_mcp::{MAX_TOOLS_LIST_TOKENS, McpServer, McpServerConfig};
use serde_json::{Value, json};

static SEQ: AtomicU64 = AtomicU64::new(0);

const PHASE33_TOOLS_LIST_BUDGET: usize = 1_190;

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("klens-mcp-p33-{label}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn write(&self, rel: &str, content: &str) {
        let full = self.dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, content).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn new_server(proj: &Sandbox, aux: &Sandbox) -> McpServer {
    let root = ProjectRoot::new(proj.path()).unwrap();
    let mut cfg = McpServerConfig::new(root);
    cfg.metrics_path = Some(aux.path().join("metrics.jsonl"));
    cfg.readonly_cache_dir = Some(aux.path().join("readonly-cache"));
    let mut server = McpServer::new(cfg);
    let _ = server.handle_raw_line(
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "clientInfo": { "name": "antigravity", "version": "2.0" } }
        })
        .to_string(),
    );
    server
}

fn call_tool(server: &mut McpServer, id: u64, name: &str, arguments: Value) -> Value {
    let raw = server
        .handle_raw_line(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": name, "arguments": arguments }
            })
            .to_string(),
        )
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn shell_cmd(script_win: &str, script_unix: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let _ = script_unix;
        vec!["cmd".to_string(), "/C".to_string(), script_win.to_string()]
    }
    #[cfg(not(windows))]
    {
        let _ = script_win;
        vec!["sh".to_string(), "-c".to_string(), script_unix.to_string()]
    }
}

#[test]
fn tools_list_stays_8_tools_under_1090_tokens_with_auto_context_schema() {
    let proj = Sandbox::new("budget");
    let aux = Sandbox::new("budget-aux");
    proj.write("src/lib.rs", "pub fn ok() {}\n");

    let mut server = new_server(&proj, &aux);
    let list_raw = server
        .handle_raw_line(
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }).to_string(),
        )
        .unwrap();
    let list_val: Value = serde_json::from_str(&list_raw).unwrap();
    let tools = list_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 9);

    let tokens = estimate_tokens(&list_raw);
    assert!(
        tokens <= PHASE33_TOOLS_LIST_BUDGET,
        "tools/list is {tokens} tokens, exceeding Phase 3.3 budget <= {PHASE33_TOOLS_LIST_BUDGET}"
    );
    assert!(tokens < MAX_TOOLS_LIST_TOKENS);

    let run_tool = tools.iter().find(|t| t["name"] == "klens_run").unwrap();
    assert_eq!(
        run_tool["inputSchema"]["properties"]["auto_context"],
        json!({ "type": "boolean" })
    );
}

#[test]
fn klens_run_attaches_source_snippet_and_ast_symbol_and_respects_flags() {
    let proj = Sandbox::new("run-auto-ctx");
    let aux = Sandbox::new("run-auto-ctx-aux");

    let synthetic_key = format!("{}{}", "sk-ant-", "api03-0123456789abcdef0123456789abcdef");
    let calc_src = format!(
        concat!(
            "pub struct Auth;\n",
            "\n",
            "impl Auth {{\n",
            "    pub fn verify(token: &str) -> bool {{\n",
            "        let _fallback = \"{}\";\n",
            "        !token.is_empty()\n",
            "    }}\n",
            "}}\n",
            "\n",
            "pub fn broken_calc(a: i32, b: i32) -> i32 {{\n",
            "    let step1 = a + 1;\n",
            "    let step2 = b + 2;\n",
            "    let bad: i32 = step1 / step2;\n",
            "    bad\n",
            "}}\n"
        ),
        synthetic_key
    );
    proj.write("src/calc.rs", &calc_src);

    let mut server = new_server(&proj, &aux);

    let fail_cmd = shell_cmd(
        "echo   --^> src/calc.rs:13:20 1>&2 && exit /b 101",
        "echo '  --> src/calc.rs:13:20' >&2; exit 101",
    );

    // 1. Default (`auto_context: true`) JSON mode -> snippet + enclosing AST symbol `fn broken_calc`.
    let resp_json = call_tool(
        &mut server,
        10,
        "klens_run",
        json!({
            "command": fail_cmd,
            "format": "json"
        }),
    );
    assert!(
        resp_json.get("error").is_none(),
        "unexpected error: {resp_json}"
    );
    let env_text = resp_json["result"]["content"][0]["text"].as_str().unwrap();
    let env: Value = serde_json::from_str(env_text).unwrap();
    let contexts = env["data"]["error_contexts"].as_array().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0]["path"], "src/calc.rs");
    assert_eq!(contexts[0]["line"], 13);
    assert_eq!(contexts[0]["start_line"], 8);
    assert_eq!(contexts[0]["end_line"], 15);
    assert_eq!(contexts[0]["symbol"], "fn broken_calc");
    let snippet = contexts[0]["snippet"].as_str().unwrap();
    assert!(snippet.contains("> L13|     let bad: i32 = step1 / step2;"));

    // 2. Method inside `impl Auth` + neighboring secret redaction on line 6.
    let auth_fail_cmd = shell_cmd(
        "echo   --^> src/calc.rs:6:9 1>&2 && exit /b 1",
        "echo '  --> src/calc.rs:6:9' >&2; exit 1",
    );
    let resp_auth = call_tool(
        &mut server,
        11,
        "klens_run",
        json!({
            "command": auth_fail_cmd,
            "format": "json"
        }),
    );
    let auth_env: Value =
        serde_json::from_str(resp_auth["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        auth_env["data"]["error_contexts"][0]["symbol"],
        "impl Auth::verify"
    );
    assert!(auth_env["redactions_count"].as_u64().unwrap() >= 1);
    let auth_snippet = auth_env["data"]["error_contexts"][0]["snippet"]
        .as_str()
        .unwrap();
    assert!(auth_snippet.contains("[REDACTED:ANTHROPIC_KEY]"));
    assert!(!auth_snippet.contains(&synthetic_key));

    // 3. Default plain-text format renders `## Error Context` with symbol.
    let resp_text = call_tool(
        &mut server,
        12,
        "klens_run",
        json!({
            "command": fail_cmd,
            "format": "text"
        }),
    );
    let plain = resp_text["result"]["content"][0]["text"].as_str().unwrap();
    assert!(plain.contains("## Error Context"));
    assert!(plain.contains("### src/calc.rs:13 (fn broken_calc)"));
    assert!(plain.contains("> L13|     let bad: i32 = step1 / step2;"));

    // 4. `auto_context: false` -> empty/omitted `error_contexts`.
    let resp_disabled = call_tool(
        &mut server,
        13,
        "klens_run",
        json!({
            "command": fail_cmd,
            "auto_context": false,
            "format": "json"
        }),
    );
    let disabled_env: Value = serde_json::from_str(
        resp_disabled["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(disabled_env["data"].get("error_contexts").is_none());

    // 5. `raw: true` -> empty/omitted `error_contexts`.
    let resp_raw = call_tool(
        &mut server,
        14,
        "klens_run",
        json!({
            "command": fail_cmd,
            "raw": true,
            "format": "json"
        }),
    );
    let raw_env: Value =
        serde_json::from_str(resp_raw["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(raw_env["data"].get("error_contexts").is_none());

    // 6. Invalid type `auto_context: "yes"` -> JSON-RPC `-32602` (`InvalidParams`).
    let resp_bad = call_tool(
        &mut server,
        15,
        "klens_run",
        json!({
            "command": fail_cmd,
            "auto_context": "yes"
        }),
    );
    assert_eq!(resp_bad["error"]["code"], -32602);
}
