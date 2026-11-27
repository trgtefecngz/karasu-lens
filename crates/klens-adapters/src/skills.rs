//! Embedded modular Skill Pack for Karasu Lens (`crates/klens-adapters/skills/`).
//!
//! All 4 skills are compiled into the binary via `include_str!` so `klens init` works
//! completely offline with zero external downloads.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AdapterError;
use crate::text_format::{TextFormat, apply_file_write, remove_empty_parents};

/// Verbosity mode for the optional Caveman-inspired `klens-concise` skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConciseLevel {
    /// Do not install `klens-concise`.
    Off,
    /// Short, direct responses while keeping code/errors/paths/warnings 100% intact.
    #[default]
    Balanced,
    /// Ultra-compact bullets and tables while keeping code/errors/paths/warnings 100% intact.
    Ultra,
}

impl ConciseLevel {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "balanced" => Some(Self::Balanced),
            "ultra" => Some(Self::Ultra),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Balanced => "balanced",
            Self::Ultra => "ultra",
        }
    }
}

/// Which embedded skills should be installed for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSelection {
    pub surgical_coding: bool,
    pub blueprint_architect: bool,
    pub concise: ConciseLevel,
    pub skill_forge: bool,
}

impl Default for SkillSelection {
    fn default() -> Self {
        Self {
            surgical_coding: true,
            blueprint_architect: true,
            concise: ConciseLevel::Balanced,
            skill_forge: false,
        }
    }
}

/// Static definition of an embedded Markdown skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedSkill {
    pub id: &'static str,
    pub default_enabled: bool,
    pub content: &'static str,
}

/// Built-in embedded skill pack (`docs/03-HOST-ADAPTERS-AND-SKILLS.md` Section 4).
pub const EMBEDDED_SKILLS: &[EmbeddedSkill] = &[
    EmbeddedSkill {
        id: "klens-surgical-coding",
        default_enabled: true,
        content: include_str!("../skills/klens-surgical-coding/SKILL.md"),
    },
    EmbeddedSkill {
        id: "klens-blueprint-architect",
        default_enabled: true,
        content: include_str!("../skills/klens-blueprint-architect/SKILL.md"),
    },
    EmbeddedSkill {
        id: "klens-concise",
        default_enabled: true,
        content: include_str!("../skills/klens-concise/SKILL.md"),
    },
    EmbeddedSkill {
        id: "klens-skill-forge",
        default_enabled: false,
        content: include_str!("../skills/klens-skill-forge/SKILL.md"),
    },
];

/// Return the embedded skills enabled by `selection` in deterministic order.
pub fn selected_skills(selection: &SkillSelection) -> Vec<EmbeddedSkill> {
    EMBEDDED_SKILLS
        .iter()
        .copied()
        .filter(|skill| match skill.id {
            "klens-surgical-coding" => selection.surgical_coding,
            "klens-blueprint-architect" => selection.blueprint_architect,
            "klens-concise" => selection.concise != ConciseLevel::Off,
            "klens-skill-forge" => selection.skill_forge,
            _ => false,
        })
        .collect()
}

/// Render an embedded skill's `SKILL.md` contents, injecting the chosen concise level
/// when rendering `klens-concise`.
pub fn render_skill_markdown(skill: &EmbeddedSkill, concise: ConciseLevel) -> String {
    let normalized = skill.content.replace("\r\n", "\n");
    if skill.id == "klens-concise" {
        format!(
            "{}\n## Active Mode\n\n- Current level: `{}`\n",
            normalized.trim_end_matches('\n'),
            concise.as_str()
        )
    } else {
        normalized
    }
}

/// Summary of syncing embedded skills into a directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillSyncReport {
    pub files_touched: Vec<PathBuf>,
    pub mutated_disk: bool,
    pub notes: Vec<String>,
}

/// Install selected skills as `<skills_root>/<skill-id>/SKILL.md` idempotently.
///
/// If `concise == Off`, removes any previously installed `klens-concise/SKILL.md`.
pub fn install_skills_into_dir(
    skills_root: &Path,
    selection: &SkillSelection,
    dry_run: bool,
    force: bool,
) -> Result<SkillSyncReport, AdapterError> {
    let mut report = SkillSyncReport::default();

    for skill in EMBEDDED_SKILLS {
        let enabled = match skill.id {
            "klens-surgical-coding" => selection.surgical_coding,
            "klens-blueprint-architect" => selection.blueprint_architect,
            "klens-concise" => selection.concise != ConciseLevel::Off,
            "klens-skill-forge" => selection.skill_forge,
            _ => false,
        };

        let skill_dir = skills_root.join(skill.id);
        let skill_file = skill_dir.join("SKILL.md");

        if enabled {
            let rendered = render_skill_markdown(skill, selection.concise);
            let encoded = TextFormat::default().encode(&rendered);
            let exists_identical = !force
                && skill_file.is_file()
                && fs::read(&skill_file).ok().as_deref() == Some(encoded.as_slice());

            if !exists_identical {
                let outcome = apply_file_write(&skill_file, &encoded, dry_run, false)?;
                if outcome.is_planned_change() || force {
                    report.files_touched.push(skill_file.clone());
                    if outcome.mutated_disk() {
                        report.mutated_disk = true;
                    }
                    let verb = if dry_run {
                        "would install"
                    } else {
                        "installed"
                    };
                    report.notes.push(format!("{verb} skill `{}`", skill.id));
                }
            }
        } else if skill_file.exists() {
            report.files_touched.push(skill_file.clone());
            if !dry_run {
                fs::remove_file(&skill_file).map_err(|source| AdapterError::Io {
                    path: skill_file.clone(),
                    source,
                })?;
                remove_empty_parents(&skill_dir, skills_root, false);
                report.mutated_disk = true;
            }
            let verb = if dry_run { "would remove" } else { "removed" };
            report
                .notes
                .push(format!("{verb} disabled skill `{}`", skill.id));
        }
    }

    Ok(report)
}

/// Remove only `klens-*` embedded skills from `<skills_root>` without touching user skills.
pub fn remove_klens_skills_from_dir(
    skills_root: &Path,
    stop_cleanup_at: &Path,
    dry_run: bool,
) -> Result<SkillSyncReport, AdapterError> {
    let mut report = SkillSyncReport::default();

    for skill in EMBEDDED_SKILLS {
        let skill_dir = skills_root.join(skill.id);
        let skill_file = skill_dir.join("SKILL.md");
        if skill_file.exists() {
            report.files_touched.push(skill_file.clone());
            if !dry_run {
                fs::remove_file(&skill_file).map_err(|source| AdapterError::Io {
                    path: skill_file.clone(),
                    source,
                })?;
                remove_empty_parents(&skill_dir, stop_cleanup_at, false);
                report.mutated_disk = true;
            }
            let verb = if dry_run { "would remove" } else { "removed" };
            report.notes.push(format!("{verb} skill `{}`", skill.id));
        }
    }

    Ok(report)
}

/// Count how many embedded `klens-*` skills are currently installed under `<skills_root>`.
pub fn count_installed_skills(skills_root: &Path) -> usize {
    EMBEDDED_SKILLS
        .iter()
        .filter(|skill| skills_root.join(skill.id).join("SKILL.md").is_file())
        .count()
}

/// Compact inline skill summary embedded into `AGENTS.md` and `KLENS.md` marked blocks.
pub fn render_inline_guide_block(
    selection: &SkillSelection,
    include_mcp_snippet: Option<&str>,
) -> String {
    let mut lines = vec![
        "## Karasu Lens (`klens`)".to_string(),
        String::new(),
        "Use `klens` MCP tools (or CLI equivalents) for verified, low-token code understanding:".to_string(),
        "- Start with `klens_map` / `klens_outline` before opening full files.".to_string(),
        "- Read surgically via `klens_read` (qualified symbols like `impl Foo::new` or line ranges).".to_string(),
        "- Search cleanly with `klens_find` and check blast radius with `klens_impact` before editing.".to_string(),
        "- Right after editing, run `klens_check` on the changed files (or `diff`) to catch syntax errors early.".to_string(),
        "- Execute tests/builds through `klens_run` to preserve 100% of error context while filtering noise.".to_string(),
        "- Never guess on `STALE`, `INFERRED`, `AMBIGUOUS_SYMBOL`, or `UNPARSED_FALLBACK` envelopes.".to_string(),
    ];

    if selection.blueprint_architect {
        lines.push(
            "- For greenfield or major architectural work, propose and lock decisions via `klens_blueprint` first."
                .to_string(),
        );
    }

    match selection.concise {
        ConciseLevel::Balanced => {
            lines.push(
                "- Concise mode (`balanced`): keep prose brief, never shorten code, errors, paths, or warnings."
                    .to_string(),
            );
        }
        ConciseLevel::Ultra => {
            lines.push(
                "- Concise mode (`ultra`): bullets/tables only, never shorten code, errors, paths, or warnings."
                    .to_string(),
            );
        }
        ConciseLevel::Off => {}
    }

    if let Some(snippet) = include_mcp_snippet {
        lines.push(String::new());
        lines.push("### Standard `stdio` MCP Configuration".to_string());
        lines.push(String::new());
        lines.push("```json".to_string());
        lines.push(snippet.trim_end().to_string());
        lines.push("```".to_string());
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_skill_pack_contains_all_four_skills() {
        assert_eq!(EMBEDDED_SKILLS.len(), 4);
        let ids: Vec<&str> = EMBEDDED_SKILLS.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![
                "klens-surgical-coding",
                "klens-blueprint-architect",
                "klens-concise",
                "klens-skill-forge",
            ]
        );
        for skill in EMBEDDED_SKILLS {
            assert!(skill.content.contains(&format!("name: {}", skill.id)));
        }
    }

    #[test]
    fn concise_level_controls_installation_and_renders_active_mode() {
        let mut sel = SkillSelection::default();
        assert_eq!(selected_skills(&sel).len(), 3);

        sel.concise = ConciseLevel::Off;
        assert_eq!(selected_skills(&sel).len(), 2);

        sel.concise = ConciseLevel::Ultra;
        sel.skill_forge = true;
        assert_eq!(selected_skills(&sel).len(), 4);

        let concise = EMBEDDED_SKILLS
            .iter()
            .find(|s| s.id == "klens-concise")
            .unwrap();
        let rendered = render_skill_markdown(concise, ConciseLevel::Ultra);
        assert!(rendered.contains("Current level: `ultra`"));
    }
}
