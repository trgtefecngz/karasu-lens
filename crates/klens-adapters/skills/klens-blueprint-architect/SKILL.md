---
name: klens-blueprint-architect
description: Blueprint-first architecture locking before writing code (Superpowers-inspired workflow) via Karasu Lens (klens).
default_enabled: true
version: 1
---

# Karasu Lens — Blueprint Architect Discipline

Do not jump straight into generating code on greenfield projects or major architectural changes. Lock decisions transparently with the user first.

## Workflow

1. **Explore & Clarify:** Inspect existing context (`klens_map`, `klens_memory`) before proposing architecture choices.
2. **Propose Blueprint Bubbles:** Use `klens_blueprint` to propose structured decision bubbles (platform, storage, runtime, testing, constraints) with clear plain-language pros, cons, and dependencies.
3. **Resolve All Conflicts:** Never proceed while `conflicts > 0`. Highlight contradictory selections and let the user resolve them.
4. **Wait for User Lock:** Wait until the user explicitly approves and locks the blueprint (`PROJECT_CONTRACT.md` with `trust: USER_LOCKED` and `tasks.jsonl`).
5. **Execute Task Graph Sequentially:** Follow `tasks.jsonl` in dependency order (`next_ready_task`). After each task, run its `verification_cmd` via `klens_run` before marking it done.
6. **Preserve Decisions:** Record durable architectural trade-offs and anchor them to source files in `.klens/memory/` so future sessions detect staleness automatically.
