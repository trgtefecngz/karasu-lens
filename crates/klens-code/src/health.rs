use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use klens_core::{ProvenanceEnvelope, TrustLevel};
use serde::{Deserialize, Serialize};

use crate::diff_check::find_protected_path_violations;
use crate::error::CodeError;
use crate::git::{is_git_repo, ls_tracked_files};
use crate::graph::{
    CodeGraph, GOD_NODE_LINE_THRESHOLD, build_code_graph, is_generated_lockfile_path,
};
use crate::index::CodeIndex;

/// Deterministic traffic-light indicator for each `klens health` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrafficLight {
    Green,
    Yellow,
    Red,
}

impl TrafficLight {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Green => "GREEN",
            Self::Yellow => "YELLOW",
            Self::Red => "RED",
        }
    }
}

/// Single deterministic health check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    pub id: String,
    pub title: String,
    pub light: TrafficLight,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// Complete deterministic health report payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthPayload {
    pub overall: TrafficLight,
    pub checks: Vec<HealthCheck>,
}

impl HealthPayload {
    /// Append an additional deterministic health check (e.g., memory staleness from CLI)
    /// and update the aggregate `overall` traffic light.
    pub fn push_check(&mut self, check: HealthCheck) {
        if check.light > self.overall {
            self.overall = check.light;
        }
        self.checks.push(check);
    }
}

/// Run the 5 deterministic traffic-light health checks on the workspace.
pub fn run_health_check(
    index: &mut CodeIndex,
) -> Result<ProvenanceEnvelope<HealthPayload>, CodeError> {
    let graph_env = build_code_graph(index)?;
    let graph = graph_env.data;
    let project_id = index.project_root().project_id().to_string();

    let checks = vec![
        check_god_nodes(&graph),
        check_cycles(&graph),
        check_env_gitignore(index.project_root().root()),
        check_protected_paths(index),
        check_last_test_status(index.project_root().root()),
    ];

    let overall = checks
        .iter()
        .map(|c| c.light)
        .max()
        .unwrap_or(TrafficLight::Green);

    let payload = HealthPayload { overall, checks };

    Ok(ProvenanceEnvelope::new(
        TrustLevel::VerifiedAst,
        project_id,
        payload,
    ))
}

fn is_test_file_path(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    if norm.starts_with("tests/") || norm.contains("/tests/") {
        return true;
    }
    let file_name = norm.rsplit('/').next().unwrap_or(&norm);
    file_name.ends_with("_test.rs")
        || file_name.ends_with("_tests.rs")
        || file_name.ends_with("_test.go")
        || (file_name.starts_with("test_") && file_name.ends_with(".py"))
        || file_name.contains(".test.")
        || file_name.contains(".spec.")
}

fn check_god_nodes(graph: &CodeGraph) -> HealthCheck {
    let mut prod_oversize_details = Vec::new();
    let mut test_oversize_details = Vec::new();
    let mut coupling_details = Vec::new();

    for node in &graph.nodes {
        if is_generated_lockfile_path(&node.path) {
            continue;
        }
        if node.lines > GOD_NODE_LINE_THRESHOLD {
            if is_test_file_path(&node.path) {
                test_oversize_details.push(format!(
                    "{} [test] ({} lines > {GOD_NODE_LINE_THRESHOLD}, in={}, out={})",
                    node.path, node.lines, node.in_degree, node.out_degree
                ));
            } else {
                prod_oversize_details.push(format!(
                    "{} ({} lines > {GOD_NODE_LINE_THRESHOLD}, in={}, out={})",
                    node.path, node.lines, node.in_degree, node.out_degree
                ));
            }
        } else if node.is_god_node {
            coupling_details.push(format!(
                "{} ({} lines, high coupling in={}, out={})",
                node.path, node.lines, node.in_degree, node.out_degree
            ));
        }
    }

    prod_oversize_details.sort();
    test_oversize_details.sort();
    coupling_details.sort();

    if !prod_oversize_details.is_empty() {
        let prod_count = prod_oversize_details.len();
        let test_count = test_oversize_details.len();
        let coupling_count = coupling_details.len();
        let mut details = prod_oversize_details;
        details.extend(test_oversize_details);
        details.extend(coupling_details);

        let mut extras = Vec::new();
        if test_count > 0 {
            extras.push(format!(
                "{test_count} test file(s) > {GOD_NODE_LINE_THRESHOLD} lines"
            ));
        }
        if coupling_count > 0 {
            extras.push(format!("{coupling_count} high-coupling file(s)"));
        }
        let summary = if extras.is_empty() {
            format!("{prod_count} production file(s) > {GOD_NODE_LINE_THRESHOLD} lines")
        } else {
            format!(
                "{prod_count} production file(s) > {GOD_NODE_LINE_THRESHOLD} lines (+ {})",
                extras.join(", ")
            )
        };
        HealthCheck {
            id: "god_nodes".to_string(),
            title: "God Nodes (>800 lines)".to_string(),
            light: TrafficLight::Red,
            summary,
            details,
        }
    } else if !test_oversize_details.is_empty() || !coupling_details.is_empty() {
        let test_count = test_oversize_details.len();
        let coupling_count = coupling_details.len();
        let mut details = test_oversize_details;
        details.extend(coupling_details);

        let summary = match (test_count, coupling_count) {
            (t, 0) => format!(
                "0 production files > {GOD_NODE_LINE_THRESHOLD} lines ({t} test file(s) > {GOD_NODE_LINE_THRESHOLD} lines)"
            ),
            (0, c) => format!(
                "0 production files > {GOD_NODE_LINE_THRESHOLD} lines ({c} high-coupling file(s))"
            ),
            (t, c) => format!(
                "0 production files > {GOD_NODE_LINE_THRESHOLD} lines ({t} test file(s) > {GOD_NODE_LINE_THRESHOLD} lines, {c} high-coupling file(s))"
            ),
        };
        HealthCheck {
            id: "god_nodes".to_string(),
            title: "God Nodes (>800 lines)".to_string(),
            light: TrafficLight::Yellow,
            summary,
            details,
        }
    } else {
        HealthCheck {
            id: "god_nodes".to_string(),
            title: "God Nodes (>800 lines)".to_string(),
            light: TrafficLight::Green,
            summary: format!(
                "0 God Nodes (all {} indexed files <= {GOD_NODE_LINE_THRESHOLD} lines)",
                graph.nodes.len()
            ),
            details: Vec::new(),
        }
    }
}

fn check_cycles(graph: &CodeGraph) -> HealthCheck {
    if graph.cycles.is_empty() {
        HealthCheck {
            id: "cycles".to_string(),
            title: "Circular Dependencies".to_string(),
            light: TrafficLight::Green,
            summary: "0 circular dependencies detected".to_string(),
            details: Vec::new(),
        }
    } else {
        let details: Vec<String> = graph
            .cycles
            .iter()
            .map(|cycle| {
                cycle
                    .iter()
                    .map(|id| id.strip_prefix("file:").unwrap_or(id.as_str()))
                    .collect::<Vec<_>>()
                    .join(" -> ")
            })
            .collect();
        HealthCheck {
            id: "cycles".to_string(),
            title: "Circular Dependencies".to_string(),
            light: TrafficLight::Red,
            summary: format!("{} circular dependency cycle(s) detected", details.len()),
            details,
        }
    }
}

fn check_env_gitignore(root: &Path) -> HealthCheck {
    let gitignore_path = root.join(".gitignore");
    let gitignore_has_env = fs::read_to_string(&gitignore_path)
        .ok()
        .is_some_and(|text| gitignore_covers_env(&text));

    // Only check existence metadata of `.env` — never read its contents.
    let env_exists_at_root = root.join(".env").is_file();

    let tracked_env_files = if is_git_repo(root) {
        let mut tracked = ls_tracked_files(root, &[".env", ".env.*", "**/.env", "**/.env.*"]);
        tracked.sort();
        tracked.dedup();
        tracked
    } else {
        Vec::new()
    };

    if !tracked_env_files.is_empty() {
        let details = tracked_env_files
            .into_iter()
            .map(|p| format!("tracked in git: {p}"))
            .collect();
        return HealthCheck {
            id: "env_gitignore".to_string(),
            title: ".env .gitignore Guard".to_string(),
            light: TrafficLight::Red,
            summary: "sensitive .env file(s) are tracked by git".to_string(),
            details,
        };
    }

    if env_exists_at_root && !gitignore_has_env {
        return HealthCheck {
            id: "env_gitignore".to_string(),
            title: ".env .gitignore Guard".to_string(),
            light: TrafficLight::Red,
            summary: ".env exists at project root but is NOT ignored in .gitignore".to_string(),
            details: vec![".env is unprotected by .gitignore".to_string()],
        };
    }

    if !gitignore_has_env {
        return HealthCheck {
            id: "env_gitignore".to_string(),
            title: ".env .gitignore Guard".to_string(),
            light: TrafficLight::Yellow,
            summary: if gitignore_path.is_file() {
                ".gitignore does not explicitly ignore .env (no .env file currently present)"
                    .to_string()
            } else {
                ".gitignore is missing (no .env file currently present)".to_string()
            },
            details: Vec::new(),
        };
    }

    HealthCheck {
        id: "env_gitignore".to_string(),
        title: ".env .gitignore Guard".to_string(),
        light: TrafficLight::Green,
        summary: ".env is properly ignored by .gitignore and untracked in git".to_string(),
        details: Vec::new(),
    }
}

fn gitignore_covers_env(content: &str) -> bool {
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let norm = line.trim_start_matches('/').trim_start_matches("**/");
        if matches!(norm, ".env" | ".env*" | ".env.*" | "*.env" | ".env.local") {
            return true;
        }
    }
    false
}

fn check_protected_paths(index: &CodeIndex) -> HealthCheck {
    let patterns_count = index.project_config().protected_paths.len();
    if patterns_count == 0 {
        return HealthCheck {
            id: "protected_paths".to_string(),
            title: "Protected Paths Integrity".to_string(),
            light: TrafficLight::Green,
            summary: "no protected_paths configured (0 violations)".to_string(),
            details: Vec::new(),
        };
    }

    let (is_git, violations) = find_protected_path_violations(index);
    if !is_git {
        return HealthCheck {
            id: "protected_paths".to_string(),
            title: "Protected Paths Integrity".to_string(),
            light: TrafficLight::Yellow,
            summary: format!(
                "{patterns_count} protected_paths configured, but project is not a git repo"
            ),
            details: Vec::new(),
        };
    }

    if !violations.is_empty() {
        let details: Vec<String> = violations
            .into_iter()
            .map(|p| format!("modified protected path: {p}"))
            .collect();
        return HealthCheck {
            id: "protected_paths".to_string(),
            title: "Protected Paths Integrity".to_string(),
            light: TrafficLight::Red,
            summary: format!(
                "{} protected_path violation(s) detected in git working tree",
                details.len()
            ),
            details,
        };
    }

    HealthCheck {
        id: "protected_paths".to_string(),
        title: "Protected Paths Integrity".to_string(),
        light: TrafficLight::Green,
        summary: format!("{patterns_count} protected_path pattern(s) intact (0 violations)"),
        details: Vec::new(),
    }
}

#[derive(Debug, Deserialize)]
struct RunMetaSnapshot {
    #[serde(default)]
    run_id: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    exit_code: i32,
}

fn check_last_test_status(root: &Path) -> HealthCheck {
    let runs_dir = root.join(".klens").join("runs");
    let Ok(entries) = fs::read_dir(&runs_dir) else {
        return HealthCheck {
            id: "last_test_status".to_string(),
            title: "Last Test Run".to_string(),
            light: TrafficLight::Yellow,
            summary: "no recorded test runs found in .klens/runs/".to_string(),
            details: Vec::new(),
        };
    };

    let mut meta_files: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".meta.json") {
            meta_files.push(name);
        }
    }
    meta_files.sort();

    let mut latest_test: Option<RunMetaSnapshot> = None;
    let mut latest_any: Option<RunMetaSnapshot> = None;

    // Iterate newest-first (lexicographically descending `<timestamp>-<id>.meta.json`).
    for file_name in meta_files.into_iter().rev() {
        let Ok(raw) = fs::read_to_string(runs_dir.join(&file_name)) else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<RunMetaSnapshot>(&raw) else {
            continue;
        };
        if looks_like_test_command(&meta.command) {
            latest_test = Some(meta);
            break;
        }
        if latest_any.is_none() {
            latest_any = Some(meta);
        }
    }

    match latest_test.or(latest_any) {
        Some(run) if run.exit_code == 0 => HealthCheck {
            id: "last_test_status".to_string(),
            title: "Last Test Run".to_string(),
            light: TrafficLight::Green,
            summary: format!("last run passed (exit 0): {}", run.command),
            details: if run.run_id.is_empty() {
                Vec::new()
            } else {
                vec![format!("run_id={}", run.run_id)]
            },
        },
        Some(run) => HealthCheck {
            id: "last_test_status".to_string(),
            title: "Last Test Run".to_string(),
            light: TrafficLight::Red,
            summary: format!("last run failed (exit {}): {}", run.exit_code, run.command),
            details: if run.run_id.is_empty() {
                Vec::new()
            } else {
                vec![format!("run_id={}", run.run_id)]
            },
        },
        None => HealthCheck {
            id: "last_test_status".to_string(),
            title: "Last Test Run".to_string(),
            light: TrafficLight::Yellow,
            summary: "no recorded test runs found in .klens/runs/".to_string(),
            details: Vec::new(),
        },
    }
}

fn looks_like_test_command(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    lower.contains("test")
        || lower.contains("pytest")
        || lower.contains("vitest")
        || lower.contains("jest")
}

/// Render `klens health` envelope into deterministic plain text.
pub fn format_health_text(envelope: &ProvenanceEnvelope<HealthPayload>) -> String {
    let data = &envelope.data;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] health overall={} checks={}",
        crate::trust_label(envelope.trust),
        data.overall.as_str(),
        data.checks.len()
    );

    for check in &data.checks {
        let _ = writeln!(
            out,
            "  [{}] {} ({}): {}",
            check.light.as_str(),
            check.title,
            check.id,
            check.summary
        );
        for detail in &check.details {
            let _ = writeln!(out, "      - {detail}");
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::is_test_file_path;

    #[test]
    fn test_file_path_classifier_distinguishes_test_and_production_files() {
        for test_path in [
            "tests/integration.rs",
            "crates/klens-ui/tests/ui_tests.rs",
            "src/parser_test.rs",
            "src/parser_tests.rs",
            "web/app.test.ts",
            "web/app.spec.tsx",
            "py/test_api.py",
            "go/server_test.go",
            r"crates\klens-cli\tests\lifecycle_cli_tests.rs",
        ] {
            assert!(
                is_test_file_path(test_path),
                "expected `{test_path}` to be classified as a test file"
            );
        }

        for prod_path in [
            "src/lib.rs",
            "crates/klens-code/src/health.rs",
            "src/testing_utils.rs",
            "src/contest.rs",
            "web/latest.ts",
            "py/attest.py",
        ] {
            assert!(
                !is_test_file_path(prod_path),
                "expected `{prod_path}` to be classified as a production file"
            );
        }
    }
}
