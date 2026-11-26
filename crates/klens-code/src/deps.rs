use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use klens_core::RelPath;
use serde::{Deserialize, Serialize};

use crate::error::CodeError;
use crate::index::CodeIndex;

/// Supported dependency manifest ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyEcosystem {
    Cargo,
    Npm,
    Python,
    Go,
}

impl DependencyEcosystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Python => "python",
            Self::Go => "go",
        }
    }
}

/// A single version-locked dependency entry extracted from a project manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DependencyEntry {
    pub ecosystem: DependencyEcosystem,
    pub manifest_path: String,
    pub section: String,
    pub name: String,
    pub version: String,
    pub is_external: bool,
}

/// Complete, deterministic dependency inventory across all discovered manifests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyInventory {
    pub manifests_scanned: Vec<String>,
    pub dependencies: Vec<DependencyEntry>,
}

/// Check whether a normalized relative path is a supported dependency manifest.
pub fn is_dependency_manifest(rel_path: &str) -> bool {
    let file_name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    matches!(
        file_name,
        "Cargo.toml" | "package.json" | "pyproject.toml" | "go.mod"
    )
}

/// Collect the deterministic, version-locked dependency inventory for the workspace.
pub fn collect_dependencies(index: &CodeIndex) -> Result<DependencyInventory, CodeError> {
    let files = index.discover_files(None)?;
    let manifest_paths: Vec<RelPath> = files
        .into_iter()
        .filter(|rel| is_dependency_manifest(rel.as_str()))
        .collect();

    // Pre-scan root/workspace Cargo.toml `[workspace.dependencies]` so member crates
    // using `foo.workspace = true` resolve to the exact workspace version.
    let mut workspace_cargo_versions: BTreeMap<String, String> = BTreeMap::new();
    let mut manifest_contents: Vec<(String, String)> = Vec::with_capacity(manifest_paths.len());

    for rel in &manifest_paths {
        let Ok((abs, canonical_rel)) = index.project_root().resolve_existing_with_extra(
            rel.as_str(),
            &index.project_config().extra_sensitive_patterns,
        ) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(&abs) else {
            continue;
        };
        if canonical_rel.file_name() == Some("Cargo.toml") {
            extract_cargo_workspace_versions(&content, &mut workspace_cargo_versions);
        }
        manifest_contents.push((canonical_rel.as_str().to_string(), content));
    }

    let mut manifests_scanned = Vec::with_capacity(manifest_contents.len());
    let mut all_deps = Vec::new();
    for (rel_str, content) in &manifest_contents {
        manifests_scanned.push(rel_str.clone());
        let parsed = parse_manifest_dependencies(rel_str, content, &workspace_cargo_versions);
        all_deps.extend(parsed);
    }

    manifests_scanned.sort();
    manifests_scanned.dedup();
    all_deps.sort();
    all_deps.dedup();

    Ok(DependencyInventory {
        manifests_scanned,
        dependencies: all_deps,
    })
}

/// Extract `[workspace.dependencies]` versions from a `Cargo.toml` text.
pub fn extract_cargo_workspace_versions(content: &str, out: &mut BTreeMap<String, String>) {
    let Ok(doc) = toml::from_str::<toml::Value>(content) else {
        return;
    };
    let Some(ws_deps) = doc
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table)
    else {
        return;
    };
    for (name, val) in ws_deps {
        if let Some((ver, _)) = parse_cargo_dep_spec(val, &BTreeMap::new()) {
            out.entry(name.clone()).or_insert(ver);
        }
    }
}

/// Parse dependencies from a single manifest's raw text content.
pub fn parse_manifest_dependencies(
    manifest_path: &str,
    content: &str,
    workspace_cargo_versions: &BTreeMap<String, String>,
) -> Vec<DependencyEntry> {
    let file_name = manifest_path.rsplit('/').next().unwrap_or(manifest_path);
    let mut deps = match file_name {
        "Cargo.toml" => parse_cargo_toml(manifest_path, content, workspace_cargo_versions),
        "package.json" => parse_package_json(manifest_path, content),
        "pyproject.toml" => parse_pyproject_toml(manifest_path, content),
        "go.mod" => parse_go_mod(manifest_path, content),
        _ => Vec::new(),
    };
    deps.sort();
    deps.dedup();
    deps
}

/// Compute newly added external dependencies between `before` and `after` manifest snapshots.
pub fn diff_added_external_dependencies(
    before: &[DependencyEntry],
    after: &[DependencyEntry],
) -> Vec<DependencyEntry> {
    let existing: BTreeSet<(DependencyEcosystem, &str)> = before
        .iter()
        .filter(|d| d.is_external)
        .map(|d| (d.ecosystem, d.name.as_str()))
        .collect();

    let mut added: Vec<DependencyEntry> = after
        .iter()
        .filter(|d| d.is_external && !existing.contains(&(d.ecosystem, d.name.as_str())))
        .cloned()
        .collect();
    added.sort();
    added.dedup();
    added
}

/// Deduplicated `(ecosystem, name, version)` summary suitable for compact project maps.
pub fn summarize_unique_external_deps(inventory: &DependencyInventory) -> Vec<DependencyEntry> {
    let mut seen: BTreeSet<(DependencyEcosystem, String, String)> = BTreeSet::new();
    let mut out = Vec::new();
    for dep in &inventory.dependencies {
        if !dep.is_external {
            continue;
        }
        let key = (dep.ecosystem, dep.name.clone(), dep.version.clone());
        if seen.insert(key) {
            out.push(dep.clone());
        }
    }
    out.sort_by(|a, b| (a.ecosystem, &a.name, &a.version).cmp(&(b.ecosystem, &b.name, &b.version)));
    out
}

fn parse_cargo_toml(
    manifest_path: &str,
    content: &str,
    workspace_cargo_versions: &BTreeMap<String, String>,
) -> Vec<DependencyEntry> {
    let Ok(doc) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let Some(table) = doc.as_table() else {
        return Vec::new();
    };

    let mut local_ws = workspace_cargo_versions.clone();
    extract_cargo_workspace_versions(content, &mut local_ws);

    let mut out = Vec::new();

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dep_table) = table.get(section).and_then(toml::Value::as_table) {
            collect_cargo_table(manifest_path, section, dep_table, &local_ws, &mut out);
        }
    }

    if let Some(ws_deps) = table
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        collect_cargo_table(
            manifest_path,
            "workspace.dependencies",
            ws_deps,
            &local_ws,
            &mut out,
        );
    }

    if let Some(targets) = table.get("target").and_then(toml::Value::as_table) {
        for (target_cfg, target_val) in targets {
            let Some(target_tbl) = target_val.as_table() else {
                continue;
            };
            for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(dep_table) = target_tbl.get(section).and_then(toml::Value::as_table) {
                    let full_section = format!("target.{target_cfg}.{section}");
                    collect_cargo_table(
                        manifest_path,
                        &full_section,
                        dep_table,
                        &local_ws,
                        &mut out,
                    );
                }
            }
        }
    }

    out
}

fn collect_cargo_table(
    manifest_path: &str,
    section: &str,
    dep_table: &toml::map::Map<String, toml::Value>,
    workspace_versions: &BTreeMap<String, String>,
    out: &mut Vec<DependencyEntry>,
) {
    for (dep_key, spec) in dep_table {
        let Some((version, is_external)) = parse_cargo_dep_spec(spec, workspace_versions) else {
            continue;
        };
        let real_name = spec
            .as_table()
            .and_then(|t| t.get("package"))
            .and_then(toml::Value::as_str)
            .unwrap_or(dep_key.as_str());
        let resolved_version = if version == "workspace" {
            workspace_versions
                .get(dep_key)
                .or_else(|| workspace_versions.get(real_name))
                .cloned()
                .unwrap_or_else(|| "workspace".to_string())
        } else {
            version
        };
        let resolved_external = is_external && !resolved_version.starts_with("path:");
        out.push(DependencyEntry {
            ecosystem: DependencyEcosystem::Cargo,
            manifest_path: manifest_path.to_string(),
            section: section.to_string(),
            name: real_name.to_string(),
            version: resolved_version,
            is_external: resolved_external,
        });
    }
}

fn parse_cargo_dep_spec(
    val: &toml::Value,
    _workspace_versions: &BTreeMap<String, String>,
) -> Option<(String, bool)> {
    if let Some(ver) = val.as_str() {
        return Some((ver.trim().to_string(), true));
    }
    let tbl = val.as_table()?;
    if let Some(ver) = tbl.get("version").and_then(toml::Value::as_str) {
        let is_path = tbl.contains_key("path");
        return Some((ver.trim().to_string(), !is_path));
    }
    if tbl.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
        return Some(("workspace".to_string(), true));
    }
    if let Some(git) = tbl.get("git").and_then(toml::Value::as_str) {
        let rev = tbl
            .get("tag")
            .or_else(|| tbl.get("rev"))
            .or_else(|| tbl.get("branch"))
            .and_then(toml::Value::as_str);
        let spec = match rev {
            Some(r) => format!("git:{git}#{r}"),
            None => format!("git:{git}"),
        };
        return Some((spec, true));
    }
    if let Some(path) = tbl.get("path").and_then(toml::Value::as_str) {
        return Some((format!("path:{path}"), false));
    }
    None
}

fn parse_package_json(manifest_path: &str, content: &str) -> Vec<DependencyEntry> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let Some(obj) = val.as_object() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(deps) = obj.get(section).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (name, ver_val) in deps {
            let Some(ver) = ver_val.as_str() else {
                continue;
            };
            let trimmed = ver.trim();
            let is_external = !trimmed.starts_with("file:") && !trimmed.starts_with("workspace:");
            out.push(DependencyEntry {
                ecosystem: DependencyEcosystem::Npm,
                manifest_path: manifest_path.to_string(),
                section: section.to_string(),
                name: name.clone(),
                version: trimmed.to_string(),
                is_external,
            });
        }
    }
    out
}

fn parse_pyproject_toml(manifest_path: &str, content: &str) -> Vec<DependencyEntry> {
    let Ok(doc) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // PEP 621: `[project].dependencies` & `[project.optional-dependencies]`
    if let Some(project) = doc.get("project").and_then(toml::Value::as_table) {
        if let Some(deps) = project.get("dependencies").and_then(toml::Value::as_array) {
            for item in deps {
                if let Some(spec) = item.as_str()
                    && let Some((name, ver)) = parse_pep508_requirement(spec)
                {
                    out.push(DependencyEntry {
                        ecosystem: DependencyEcosystem::Python,
                        manifest_path: manifest_path.to_string(),
                        section: "project.dependencies".to_string(),
                        name,
                        version: ver,
                        is_external: true,
                    });
                }
            }
        }
        if let Some(opt_tbl) = project
            .get("optional-dependencies")
            .and_then(toml::Value::as_table)
        {
            for (group, val) in opt_tbl {
                if let Some(arr) = val.as_array() {
                    for item in arr {
                        if let Some(spec) = item.as_str()
                            && let Some((name, ver)) = parse_pep508_requirement(spec)
                        {
                            out.push(DependencyEntry {
                                ecosystem: DependencyEcosystem::Python,
                                manifest_path: manifest_path.to_string(),
                                section: format!("project.optional-dependencies.{group}"),
                                name,
                                version: ver,
                                is_external: true,
                            });
                        }
                    }
                }
            }
        }
    }

    // Poetry: `[tool.poetry.dependencies]`, `[tool.poetry.dev-dependencies]`, `[tool.poetry.group.*.dependencies]`
    if let Some(poetry) = doc
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(toml::Value::as_table)
    {
        for section in ["dependencies", "dev-dependencies"] {
            if let Some(tbl) = poetry.get(section).and_then(toml::Value::as_table) {
                collect_poetry_table(
                    manifest_path,
                    &format!("tool.poetry.{section}"),
                    tbl,
                    &mut out,
                );
            }
        }
        if let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) {
            for (group, group_val) in groups {
                if let Some(tbl) = group_val
                    .get("dependencies")
                    .and_then(toml::Value::as_table)
                {
                    collect_poetry_table(
                        manifest_path,
                        &format!("tool.poetry.group.{group}.dependencies"),
                        tbl,
                        &mut out,
                    );
                }
            }
        }
    }

    out
}

fn collect_poetry_table(
    manifest_path: &str,
    section: &str,
    tbl: &toml::map::Map<String, toml::Value>,
    out: &mut Vec<DependencyEntry>,
) {
    for (name, val) in tbl {
        if name.eq_ignore_ascii_case("python") {
            continue;
        }
        let (version, is_external) = if let Some(s) = val.as_str() {
            (s.trim().to_string(), true)
        } else if let Some(sub) = val.as_table() {
            if let Some(v) = sub.get("version").and_then(toml::Value::as_str) {
                (v.trim().to_string(), !sub.contains_key("path"))
            } else if let Some(p) = sub.get("path").and_then(toml::Value::as_str) {
                (format!("path:{p}"), false)
            } else if let Some(g) = sub.get("git").and_then(toml::Value::as_str) {
                (format!("git:{g}"), true)
            } else {
                ("*".to_string(), true)
            }
        } else {
            continue;
        };
        out.push(DependencyEntry {
            ecosystem: DependencyEcosystem::Python,
            manifest_path: manifest_path.to_string(),
            section: section.to_string(),
            name: name.clone(),
            version,
            is_external,
        });
    }
}

fn parse_pep508_requirement(raw: &str) -> Option<(String, String)> {
    // Strip environment marker (`; python_version < ...`).
    let without_marker = raw.split(';').next().unwrap_or(raw).trim();
    if without_marker.is_empty() {
        return None;
    }

    // Extract package name (optionally followed by `[extras]`).
    let mut name_end = 0usize;
    for (idx, ch) in without_marker.char_indices() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            name_end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if name_end == 0 {
        return None;
    }
    let name = without_marker[..name_end].to_string();
    let mut rest = without_marker[name_end..].trim();
    if rest.starts_with('[')
        && let Some(close) = rest.find(']')
    {
        rest = rest[close + 1..].trim();
    }
    let version = if rest.is_empty() {
        "*".to_string()
    } else {
        rest.to_string()
    };
    Some((name, version))
}

fn parse_go_mod(manifest_path: &str, content: &str) -> Vec<DependencyEntry> {
    let mut out = Vec::new();
    let mut in_require_block = false;

    for raw_line in content.lines() {
        let (code_part, comment_part) = match raw_line.split_once("//") {
            Some((c, cm)) => (c.trim(), cm.trim()),
            None => (raw_line.trim(), ""),
        };
        if code_part.is_empty() {
            continue;
        }

        if in_require_block {
            if code_part.starts_with(')') {
                in_require_block = false;
                continue;
            }
            if let Some((module, version)) = parse_go_mod_pair(code_part) {
                let section = if comment_part.contains("indirect") {
                    "require_indirect"
                } else {
                    "require"
                };
                out.push(DependencyEntry {
                    ecosystem: DependencyEcosystem::Go,
                    manifest_path: manifest_path.to_string(),
                    section: section.to_string(),
                    name: module,
                    version,
                    is_external: true,
                });
            }
            continue;
        }

        if let Some(rest) = code_part.strip_prefix("require") {
            let trimmed = rest.trim();
            if trimmed.starts_with('(') {
                in_require_block = true;
                let after_open = trimmed.trim_start_matches('(').trim();
                if let Some(inside) = after_open.strip_suffix(')') {
                    in_require_block = false;
                    if let Some((module, version)) = parse_go_mod_pair(inside.trim()) {
                        out.push(DependencyEntry {
                            ecosystem: DependencyEcosystem::Go,
                            manifest_path: manifest_path.to_string(),
                            section: "require".to_string(),
                            name: module,
                            version,
                            is_external: true,
                        });
                    }
                }
            } else if let Some((module, version)) = parse_go_mod_pair(trimmed) {
                let section = if comment_part.contains("indirect") {
                    "require_indirect"
                } else {
                    "require"
                };
                out.push(DependencyEntry {
                    ecosystem: DependencyEcosystem::Go,
                    manifest_path: manifest_path.to_string(),
                    section: section.to_string(),
                    name: module,
                    version,
                    is_external: true,
                });
            }
        }
    }

    out
}

fn parse_go_mod_pair(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    let module = parts.next()?.trim_matches('"');
    let version = parts.next()?.trim_matches('"');
    if module.is_empty() || version.is_empty() {
        return None;
    }
    Some((module.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_package_json_pyproject_and_go_mod_deterministically() {
        let cargo = r#"
[workspace.dependencies]
serde = { version = "1.0.210", features = ["derive"] }
thiserror = "2.0"

[dependencies]
serde.workspace = true
klens-core = { path = "../klens-core" }
clap = "4.5"
"#;
        let mut ws = BTreeMap::new();
        extract_cargo_workspace_versions(cargo, &mut ws);
        let cargo_deps = parse_manifest_dependencies("Cargo.toml", cargo, &ws);
        assert!(cargo_deps.iter().any(|d| d.name == "serde"
            && d.version == "1.0.210"
            && d.section == "dependencies"
            && d.is_external));
        assert!(
            cargo_deps
                .iter()
                .any(|d| d.name == "clap" && d.version == "4.5" && d.is_external)
        );
        assert!(
            cargo_deps
                .iter()
                .any(|d| d.name == "klens-core" && !d.is_external)
        );

        let pkg_json = r#"{
            "dependencies": { "react": "^19.0.0", "local-pkg": "file:../local" },
            "devDependencies": { "typescript": "5.7.2" }
        }"#;
        let npm_deps = parse_manifest_dependencies("package.json", pkg_json, &ws);
        assert!(
            npm_deps
                .iter()
                .any(|d| d.name == "react" && d.version == "^19.0.0" && d.is_external)
        );
        assert!(
            npm_deps
                .iter()
                .any(|d| d.name == "typescript" && d.version == "5.7.2")
        );
        assert!(
            npm_deps
                .iter()
                .any(|d| d.name == "local-pkg" && !d.is_external)
        );

        let pyproject = r#"
[project]
name = "demo"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]==0.32.0; python_version >= '3.10'"
]

[tool.poetry.dependencies]
python = "^3.12"
pydantic = "^2.9.0"
"#;
        let py_deps = parse_manifest_dependencies("pyproject.toml", pyproject, &ws);
        assert!(
            py_deps
                .iter()
                .any(|d| d.name == "fastapi" && d.version == ">=0.115.0")
        );
        assert!(
            py_deps
                .iter()
                .any(|d| d.name == "uvicorn" && d.version == "==0.32.0")
        );
        assert!(
            py_deps
                .iter()
                .any(|d| d.name == "pydantic" && d.version == "^2.9.0")
        );
        assert!(!py_deps.iter().any(|d| d.name == "python"));

        let go_mod = r#"
module example.com/demo

go 1.23

require (
    github.com/spf13/cobra v1.8.1
    golang.org/x/sys v0.27.0 // indirect
)

require github.com/stretchr/testify v1.9.0
"#;
        let go_deps = parse_manifest_dependencies("go.mod", go_mod, &ws);
        assert!(go_deps.iter().any(|d| d.name == "github.com/spf13/cobra"
            && d.version == "v1.8.1"
            && d.section == "require"));
        assert!(go_deps.iter().any(|d| d.name == "golang.org/x/sys"
            && d.version == "v0.27.0"
            && d.section == "require_indirect"));
        assert!(
            go_deps
                .iter()
                .any(|d| d.name == "github.com/stretchr/testify" && d.version == "v1.9.0")
        );
    }
}
