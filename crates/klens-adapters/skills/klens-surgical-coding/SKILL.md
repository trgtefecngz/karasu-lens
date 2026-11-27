---
name: klens-surgical-coding
description: Surgical code navigation, provenance-aware reading, impact analysis, and zero-loss command execution via Karasu Lens (klens).
default_enabled: true
version: 1
---

# Karasu Lens — Surgical Coding Discipline

Use Karasu Lens (`klens`) tools to maximize verified signal per token and eliminate guesswork.

## Mandatory Workflow

1. **Map before reading:** Start with `klens_map` (or `klens map`) to understand repository structure and key modules within budget.
2. **Outline before opening full files:** Run `klens_outline` on candidate files to inspect exact symbol signatures and line ranges.
3. **Read surgically:** Fetch only the required symbol or line slice with `klens_read` (supports qualified names like `impl Foo::new` and batch `targets`).
4. **Search cleanly:** Use `klens_find` instead of noisy raw `grep` across `target/` or `node_modules/`.
5. **Check blast radius before edits:** Run `klens_impact` on any symbol or file you plan to change so callers and dependents are known upfront.
6. **Check every edit right away:** Run `klens_check` on the files you changed (or `paths: ["diff"]`) before running tests. Fix every reported syntax error first; files listed as "not checked" were not validated, so never treat them as OK.
7. **Run tests through `klens_run`:** Execute `cargo`, `git`, `npm`/`pnpm`, `pytest`, and `go test` via `klens_run` to filter noise while preserving 100% of error context and raw logs.

## Zero-Deception Rules

- **Respect `TrustLevel`:** Never guess or fabricate details when an envelope reports `STALE`, `INFERRED`, or `UNPARSED_FALLBACK`. Read the raw source file directly to verify.
- **Disambiguate honestly:** When `klens_read` returns `AMBIGUOUS_SYMBOL`, inspect the returned candidate list and re-query using the exact `qualified_name` or line range.
- **Never ignore omissions:** If an output notes omitted lines (`// ... [omitted N lines]`), fetch the omitted range before making assumptions about its contents.
