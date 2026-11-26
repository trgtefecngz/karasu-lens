---
name: klens-skill-forge
description: Template for turning repeating project workflows into clean, verifiable SKILL.md files (Skill-Creator-inspired).
default_enabled: false
version: 1
---

# Karasu Lens — Skill Forge Template

Use this template when the user wants to capture a repeating project workflow (for example: adding a new API endpoint, creating a database migration, or running a release checklist) as a reusable `SKILL.md`.

## Authoring Checklist

1. **Single clear trigger:** Define exactly when the skill should activate and when it must NOT activate.
2. **Concrete ordered steps:** List exact file paths, naming conventions, and `klens` commands (`klens_outline`, `klens_impact`, `klens_run`).
3. **Deterministic verification gate:** Every skill MUST end with concrete verification commands (tests, linters, schema checks) that prove success.
4. **Stay lean:** Keep each `SKILL.md` short and focused; link to existing project docs instead of copying large files.

## Minimal `SKILL.md` Skeleton

```markdown
---
name: <kebab-case-skill-name>
description: <One-sentence trigger description>
---

# <Workflow Title>

## When to Use
- <Trigger condition>

## Steps
1. Inspect existing patterns with `klens_find` / `klens_outline`.
2. Implement changes in `<target paths>`.
3. Verify blast radius with `klens_impact`.
4. Run `<verification command>` via `klens_run`.

## Non-Goals
- <What this skill must not touch>
```
