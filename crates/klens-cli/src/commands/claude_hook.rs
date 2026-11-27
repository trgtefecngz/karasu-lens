//! `klens hook pre-tool`: Claude Code `PreToolUse` hook for the Bash tool.
//!
//! When the agent runs a simple, known-noisy command (`cargo test`, `npm install`, `git log`,
//! ...), the hook rewrites it to `klens run -- <command>`: same program, same arguments, same
//! exit code, but filtered output with a raw log. Everything else passes through untouched.
//!
//! Safety rules:
//! - Only commands made of plain words (letters, digits, `-_./:=@%+,` and spaces) are rewritten;
//!   any shell syntax (pipes, `&&`, quotes, `$`, redirects, globs, ...) passes through, so the
//!   rewritten line runs exactly the same argv.
//! - The hook never returns a `permissionDecision`: the user's normal permission flow is kept
//!   (returning `allow` would skip the permission prompt).
//! - It stays silent (no output, exit 0) on any doubt: unknown input, a folder klens refuses
//!   as a project, `run_in_background`, or `KLENS_HOOKS=off`.

use std::io::Read as _;
use std::path::Path;

use serde_json::{Value, json};

/// Largest hook input read from stdin.
const MAX_HOOK_INPUT_BYTES: u64 = 1024 * 1024;

/// `(program, allowed first arguments)`; an empty list allows any arguments.
const NOISY_COMMANDS: &[(&str, &[&str])] = &[
    ("cargo", &["build", "check", "test", "clippy", "doc"]),
    ("npm", &["test", "ci", "install", "run"]),
    ("pnpm", &["test", "install", "build", "lint", "run"]),
    ("yarn", &["test", "install", "build", "lint", "run"]),
    ("pytest", &[]),
    ("go", &["test", "build", "vet"]),
    ("tsc", &[]),
    ("eslint", &[]),
    ("git", &["log", "diff", "show"]),
    ("dotnet", &["build", "test"]),
    ("mvn", &["test", "package", "verify", "compile"]),
    ("gradle", &["build", "test"]),
    ("./gradlew", &["build", "test"]),
];

/// `npm run` / `pnpm run` / `yarn run` scripts that are builds or checks, not servers.
const RUN_SCRIPTS: &[&str] = &["build", "test", "lint", "typecheck", "check"];

/// Return the rewritten command line, or `None` to leave the command unchanged.
pub(crate) fn rewrite_bash_command(command: &str, klens_binary: &str) -> Option<String> {
    // Only ASCII spaces/newlines are trimmed: any other whitespace (NBSP, U+2028, ...) stays
    // and is rejected below, so the rewritten argv is exactly the original one.
    let trimmed = command.trim_matches([' ', '\n', '\r']);
    if trimmed.is_empty() || !trimmed.chars().all(is_plain_char) {
        return None;
    }
    if !binary_is_hook_safe(klens_binary) {
        return None;
    }
    let mut words = trimmed.split_whitespace();
    let program = words.next()?;
    let first_arg = words.next();
    let (_, allowed) = NOISY_COMMANDS.iter().find(|(name, _)| *name == program)?;
    if !allowed.is_empty() {
        let arg = first_arg?;
        if !allowed.contains(&arg) {
            return None;
        }
        if arg == "run"
            && !words
                .next()
                .is_some_and(|script| RUN_SCRIPTS.contains(&script))
        {
            return None;
        }
    }
    let binary = if cfg!(windows) {
        klens_binary.replace('\\', "/")
    } else {
        klens_binary.to_string()
    };
    Some(format!("\"{binary}\" run -- {trimmed}"))
}

/// The klens path is embedded in the rewritten command line, so it must be plain too
/// (`\` only as the Windows separator).
pub(crate) fn binary_is_hook_safe(binary: &str) -> bool {
    !binary.is_empty()
        && binary
            .chars()
            .all(|c| is_plain_char(c) || (cfg!(windows) && c == '\\'))
}

/// `true` when any Claude Code permission rule (allow/deny/ask) in `settings` names `program`
/// or all Bash commands. Such commands are never rewritten: the user's rules are written for
/// the original command line and must keep applying to exactly that line. A settings file that
/// cannot be read as JSON also counts (fail safe).
pub(crate) fn permission_rules_mention(program: &str, settings: &[Value]) -> bool {
    settings.iter().any(|doc| {
        let Some(permissions) = doc.get("permissions") else {
            return false;
        };
        ["allow", "deny", "ask"].iter().any(|list| {
            permissions
                .get(list)
                .and_then(Value::as_array)
                .is_some_and(|rules| {
                    rules
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|rule| bash_rule_mentions(rule.trim(), program))
                })
        })
    })
}

fn bash_rule_mentions(rule: &str, program: &str) -> bool {
    if rule == "Bash" {
        return true;
    }
    let Some(inner) = rule.strip_prefix("Bash(").and_then(|r| r.strip_suffix(')')) else {
        return false;
    };
    let first = inner
        .split(|c: char| c.is_whitespace() || c == ':')
        .next()
        .unwrap_or("")
        .trim_matches('"');
    first.is_empty()
        || first.contains('*')
        || first == program
        || first.rsplit('/').next() == program.rsplit('/').next()
}

/// Settings files whose permission rules apply to this session: the user's, and the
/// project's shared and local ones (`CLAUDE_PROJECT_DIR`, else the command's folder).
fn claude_settings_documents(cwd: &Path) -> Vec<Value> {
    let mut files = Vec::new();
    if let Ok(home) = klens_adapters::resolve_home_dir() {
        files.push(home.join(".claude").join("settings.json"));
    }
    let project = std::env::var_os("CLAUDE_PROJECT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cwd.to_path_buf());
    files.push(project.join(".claude").join("settings.json"));
    files.push(project.join(".claude").join("settings.local.json"));
    files
        .iter()
        .filter(|path| path.exists())
        .map(|path| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|text| {
                    serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')).ok()
                })
                // Unreadable settings: assume rules exist (never rewrite).
                .unwrap_or_else(|| json!({ "permissions": { "ask": ["Bash"] } }))
        })
        .collect()
}

fn is_plain_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '_' | '.' | '/' | ':' | '=' | '@' | '%' | '+' | ',' | ' '
        )
}

/// Hook output for a Claude Code `PreToolUse` event, or `None` to stay silent.
/// `settings` are the parsed Claude Code settings documents (see [`claude_settings_documents`]).
pub(crate) fn pre_tool_output(
    input: &Value,
    klens_binary: &str,
    settings: &[Value],
) -> Option<Value> {
    if input.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return None;
    }
    let tool_input = input.get("tool_input")?.as_object()?;
    if tool_input
        .get("run_in_background")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    let cwd = Path::new(input.get("cwd").and_then(Value::as_str)?);
    // Only at a project root (`.git`/`.klens` right here: no nested `.klens/runs` in
    // sub-folders), only where klens accepts the folder, and only in `active` mode
    // (`read_only` must stay zero-footprint, `paused` must stay idle).
    if !cwd.join(".git").exists() && !cwd.join(".klens").exists() {
        return None;
    }
    klens_core::ProjectRoot::new(cwd).ok()?;
    let config =
        klens_core::ProjectConfig::load_or_default(&cwd.join(".klens").join("config.toml")).ok()?;
    if config.mode != klens_core::ProjectMode::Active {
        return None;
    }

    let command = tool_input.get("command").and_then(Value::as_str)?;
    let rewritten = rewrite_bash_command(command, klens_binary)?;
    let program = command.split_whitespace().next()?;
    if permission_rules_mention(program, settings) {
        return None;
    }
    // `updatedInput` replaces the whole input: keep `description`, `timeout`, ... as they were.
    let mut updated = tool_input.clone();
    updated.insert("command".to_string(), Value::String(rewritten));
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": Value::Object(updated),
        }
    }))
}

/// Entry point: read the hook JSON from stdin, print the decision (or nothing).
pub(crate) fn run_pre_tool_hook() -> String {
    if std::env::var("KLENS_HOOKS").is_ok_and(|v| v.eq_ignore_ascii_case("off")) {
        return String::new();
    }
    let mut raw = String::new();
    if std::io::stdin()
        .take(MAX_HOOK_INPUT_BYTES)
        .read_to_string(&mut raw)
        .is_err()
    {
        return String::new();
    }
    let Ok(input) = serde_json::from_str::<Value>(&raw) else {
        return String::new();
    };
    let Ok(binary) = std::env::current_exe() else {
        return String::new();
    };
    let binary = binary.to_string_lossy();
    let binary = binary.trim_start_matches(r"\\?\");
    let settings = input
        .get("cwd")
        .and_then(Value::as_str)
        .map(|cwd| claude_settings_documents(Path::new(cwd)))
        .unwrap_or_default();
    pre_tool_output(&input, binary, &settings)
        .map(|out| out.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    const BIN: &str = r"C:\Users\me\.cargo\bin\klens.exe";
    #[cfg(windows)]
    const SHOWN_BIN: &str = "C:/Users/me/.cargo/bin/klens.exe";
    #[cfg(not(windows))]
    const BIN: &str = "/home/me/.cargo/bin/klens";
    #[cfg(not(windows))]
    const SHOWN_BIN: &str = "/home/me/.cargo/bin/klens";

    fn rewrite(command: &str) -> Option<String> {
        rewrite_bash_command(command, BIN)
    }

    /// A project root folder (has `.git`) with an optional `.klens/config.toml`.
    struct Project(std::path::PathBuf);

    impl Project {
        fn new(label: &str, config: Option<&str>) -> Self {
            let dir =
                std::env::temp_dir().join(format!("klens-hook-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join(".git")).unwrap();
            if let Some(cfg) = config {
                std::fs::create_dir_all(dir.join(".klens")).unwrap();
                std::fs::write(dir.join(".klens").join("config.toml"), cfg).unwrap();
            }
            Self(dir)
        }

        fn input(&self, command: &str) -> Value {
            json!({
                "tool_name": "Bash",
                "cwd": self.0.display().to_string(),
                "tool_input": { "command": command, "description": "Run tests", "timeout": 60000 }
            })
        }
    }

    impl Drop for Project {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn noisy_simple_commands_are_routed_through_klens_run() {
        for command in [
            "cargo test",
            "cargo test -p klens-core --lib",
            "npm test",
            "npm run build",
            "pnpm install",
            "pytest tests/test_api.py -x",
            "go test ./...",
            "git log --oneline -20",
            "./gradlew test",
            "cargo test\n",
        ] {
            assert_eq!(
                rewrite(command),
                Some(format!("\"{SHOWN_BIN}\" run -- {}", command.trim_end())),
                "{command:?}"
            );
        }
    }

    #[test]
    fn shell_syntax_servers_and_unknown_commands_pass_through() {
        for command in [
            "cargo test 2>&1 | tail -20",
            "cd app && npm test",
            "cargo test; echo done",
            "FOO=1 cargo test",
            "cargo test -- --nocapture \"x y\"",
            "git log $BRANCH",
            "pytest tests/*.py",
            "cargo run",
            "npm start",
            "npm run dev",
            "git status",
            "git commit -m wip",
            "echo hello",
            "klens run -- cargo test",
            "cargo test\nrm -rf x",
            "cargo\ttest",
            "cargo test\u{a0}",
            "\u{2028}cargo test",
            "",
        ] {
            assert_eq!(rewrite(command), None, "{command:?}");
        }
    }

    #[test]
    fn binary_paths_that_cannot_be_embedded_safely_disable_the_rewrite() {
        for binary in [
            "",
            "C:/Program Files (x86)/klens.exe",
            "/opt/kl ens$/klens",
            "/ç/klens",
        ] {
            assert_eq!(rewrite_bash_command("cargo test", binary), None, "{binary}");
        }
    }

    #[test]
    fn hook_output_keeps_other_fields_and_never_approves() {
        let project = Project::new("ok", None);
        let out = pre_tool_output(&project.input("cargo test"), BIN, &[]).expect("rewritten");

        let specific = &out["hookSpecificOutput"];
        assert_eq!(specific["hookEventName"], "PreToolUse");
        assert!(specific.get("permissionDecision").is_none(), "{out}");
        assert_eq!(specific["updatedInput"]["description"], "Run tests");
        assert_eq!(specific["updatedInput"]["timeout"], 60000);
        assert!(
            specific["updatedInput"]["command"]
                .as_str()
                .unwrap()
                .ends_with("run -- cargo test")
        );
    }

    #[test]
    fn read_only_paused_and_non_root_folders_stay_silent() {
        let read_only = Project::new("ro", Some("mode = \"read_only\"\n"));
        assert!(pre_tool_output(&read_only.input("cargo test"), BIN, &[]).is_none());
        let paused = Project::new("paused", Some("mode = \"paused\"\n"));
        assert!(pre_tool_output(&paused.input("cargo test"), BIN, &[]).is_none());
        let broken = Project::new("broken", Some("mode = \n"));
        assert!(pre_tool_output(&broken.input("cargo test"), BIN, &[]).is_none());

        let root = Project::new("subdir", None);
        let sub = root.0.join("src");
        std::fs::create_dir_all(&sub).unwrap();
        let input = json!({
            "tool_name": "Bash", "cwd": sub.display().to_string(),
            "tool_input": { "command": "cargo test" }
        });
        assert!(
            pre_tool_output(&input, BIN, &[]).is_none(),
            "nested .klens/runs"
        );
    }

    #[test]
    fn commands_named_in_permission_rules_are_never_rewritten() {
        let project = Project::new("rules", None);
        for rules in [
            json!({ "permissions": { "deny": ["Bash(git log:*)"] } }),
            json!({ "permissions": { "ask": ["Bash(git log)"] } }),
            json!({ "permissions": { "allow": ["Bash(git:*)"] } }),
            json!({ "permissions": { "deny": ["Bash"] } }),
            json!({ "permissions": { "ask": ["Bash(*)"] } }),
        ] {
            assert!(
                pre_tool_output(
                    &project.input("git log -5"),
                    BIN,
                    std::slice::from_ref(&rules)
                )
                .is_none(),
                "{rules}"
            );
        }
        // Rules about other programs or other tools do not block the rewrite.
        let unrelated = json!({ "permissions": {
            "allow": ["Bash(npm test:*)", "Read(./src/**)"], "deny": ["WebFetch"]
        } });
        assert!(pre_tool_output(&project.input("git log -5"), BIN, &[unrelated]).is_some());
    }

    #[test]
    fn other_tools_background_runs_and_missing_folders_stay_silent() {
        let project = Project::new("other", None);
        let cwd = project.0.display().to_string();
        let read = json!({ "tool_name": "Read", "cwd": cwd, "tool_input": { "file_path": "x" } });
        assert!(pre_tool_output(&read, BIN, &[]).is_none());
        let background = json!({
            "tool_name": "Bash", "cwd": cwd,
            "tool_input": { "command": "cargo test", "run_in_background": true }
        });
        assert!(pre_tool_output(&background, BIN, &[]).is_none());
        let missing = json!({
            "tool_name": "Bash", "cwd": "Z:/definitely/missing/folder",
            "tool_input": { "command": "cargo test" }
        });
        assert!(pre_tool_output(&missing, BIN, &[]).is_none());
    }
}
