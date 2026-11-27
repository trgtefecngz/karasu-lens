<div align="center">

# Karasu Lens

**Precise, verifiable code context for AI coding agents — in a single offline binary.**

[![CI](https://github.com/trgtefecngz/karasu-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/trgtefecngz/karasu-lens/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/trgtefecngz/karasu-lens?label=release)](https://github.com/trgtefecngz/karasu-lens/releases/latest)
[![License: PolyForm Strict 1.0.0](https://img.shields.io/badge/license-PolyForm%20Strict%201.0.0-lightgrey.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux-informational)

</div>

---

Karasu Lens (`klens`) helps AI coding agents understand, run, and remember a codebase without
flooding their context window. Instead of re-reading whole files and scrolling through noisy
terminal logs, an agent asks `klens` for exactly what it needs: a single function, a ranked
project map, the blast radius of a change, or the failing part of a test run. Every answer says
how trustworthy it is.

Everything runs locally. The core makes no network requests, needs no runtime, and ships as one
executable.

> *"Better to omit or fall back honestly than to return misleading output."*

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Connecting an AI agent](#connecting-an-ai-agent)
- [Language support](#language-support)
- [Security](#security)
- [Command reference](#command-reference)
- [License](#license)

## Features

**Code understanding**
- Tree-sitter AST outlines and surgical reads by qualified symbol (`impl Foo::new`) or line range.
- Ambiguous symbol names are never guessed. `klens` lists every candidate instead.
- PageRank project maps that fit a token budget, optionally focused on one module.
- Blast-radius analysis for a file, a symbol, or your current `git diff`.

**Terminal runs without the noise**
- ANSI-cleaned, block-aware filtering for `cargo`, `git`, `tsc`, `jest`/`vitest`, `eslint`, `pytest`,
  `go test`, `docker`, `make`, `gradle`, and `dotnet`.
- Error blocks are kept intact. The raw log is always saved and can be re-read.
- On failure, the relevant source lines and their enclosing function are attached automatically.
- Runs never hang on background processes or exhaust memory. Very large output keeps its
  head and tail, and the skipped part is reported. Agent runs time out after 10 minutes unless
  the agent sets a different limit.
- Git-based safety checkpoints that never touch your branch, index, or stash. Every rollback
  first saves an automatic backup of your current work, so a rollback can always be undone.

**Verifiable project memory**
- Plain Markdown notes in `.klens/memory/`, compatible with Obsidian.
- Notes are anchored to files and symbols with BLAKE3 hashes. When the code changes, the note is
  flagged `STALE` instead of silently misleading the agent.

**Planning and a local dashboard**
- Blueprint board for locking architecture decisions into a project contract and task list.
- Local Web UI on `127.0.0.1` with a code and memory graph, run history, and real usage stats.
  It works fully offline, has light and dark themes, and comes in 6 languages.

## Installation

### Prebuilt binaries

Download the latest Windows or Linux binary and `SHA256SUMS.txt` from
[**Releases**](https://github.com/trgtefecngz/karasu-lens/releases/latest), then verify the checksum.

```powershell
# Windows (PowerShell)
(Get-FileHash -Algorithm SHA256 .\klens-<version>-windows-x86_64.exe).Hash.ToLowerInvariant()
```

```bash
# Linux
sha256sum -c SHA256SUMS.txt --ignore-missing
chmod +x ./klens-<version>-linux-x86_64
```

### Build from source

Building requires Rust 1.88 or newer. On Windows you also need the MSVC Build Tools, for the
bundled SQLite and Tree-sitter grammars.

```bash
cargo install --path crates/klens-cli --locked
klens --version
```

## Quick start

Run these commands inside a project folder.

```bash
klens map --budget 1200          # ranked overview of the project
klens outline src/main.rs        # symbols with line ranges
klens read src/main.rs --symbol main
klens run -- cargo test          # filtered test output, raw log kept
klens ui                         # open the local dashboard
```

To inspect a project without writing anything into it, add `--read-only`. The cache then lives in
`~/.klens/readonly-cache/`.

## Connecting an AI agent

`klens` ships native adapters for **Antigravity**, **Claude Code**, and **Codex**, plus a generic
option.

Once per machine, register `klens` for every installed agent so it works in every project:

```bash
klens setup             # user-scope MCP registration (supports --dry-run; undo: klens disconnect --host all)
```

For Claude Code it also adds a short, marker-delimited guide to `~/.claude/CLAUDE.md` saying
when a `klens` tool beats the built-in one (your own text in that file is kept; `disconnect`
removes only the guide), and a `PreToolUse` hook in `~/.claude/settings.json` that runs simple,
known-noisy commands (`cargo test`, `npm install`, `pytest`, `git log`, ...) through
`klens run`. Commands with any shell syntax (pipes, `&&`, quotes, `$`, redirects), commands
named in your own Claude Code permission rules, and projects in `read_only` or `paused` mode are
left untouched; the hook never approves a command on its own, and `KLENS_HOOKS=off` disables it.
The index cache stays in the project's `.klens/cache/` folder, which
ignores itself, so a project you only browse shows no new files in `git status`.

Per project, for skills, hooks, and `.gitignore` entries:

```bash
klens attach            # register the project and add .klens/ entries to .gitignore
klens init --host auto  # install the MCP server and skills for detected agents (supports --dry-run)
klens doctor            # verify the setup
```

The MCP server (`klens mcp`) exposes eight tools:

| Tool | Access | Purpose |
| :--- | :---: | :--- |
| `klens_map` | read | Ranked project map within a token budget |
| `klens_find` | read | Full-text and symbol search with exact line numbers |
| `klens_outline` | read | AST symbol outline with line ranges |
| `klens_read` | read | Read by symbol or lines, optionally with imports, memory, and impact |
| `klens_impact` | read | Blast radius of a file, a symbol, or the current diff |
| `klens_run` | exec | Run a command with filtered output and error context |
| `klens_memory` | write | Manage and verify project memory notes |
| `klens_blueprint` | write | Blueprint decisions, contract, tasks, and handoff |

You can restrict each project in its `.klens/config.toml`. The modes are `active`, `read_only`
(read tools only), and `paused` (all tools blocked).

## Language support

| Tier | Languages | Trust level |
| :--- | :--- | :--- |
| Built in | Rust, TypeScript/JavaScript (incl. TSX/JSX), Python, Go, C, C++, Java, C#, PHP, Ruby, plus Markdown, JSON, TOML, YAML | `VERIFIED_AST` |
| Optional | 20+ additional languages through Universal Ctags, or a custom parser | `EXTERNAL_PARSER` |
| Anything else | Line-numbered reads and full-text search, with no guessed symbols | `UNPARSED_FALLBACK` |

Optional parsers launch external programs. For that reason they can only be enabled globally, by
you:

```bash
klens ext enable ext-lang-ctags --global
```

Parser definitions are loaded only from `~/.klens/extensions/`. Any `.klens/extensions/` folder
inside a repository is ignored.

## Security

`klens` is designed to be safe to point at code you did not write.

- **Offline core.** Analysis commands make no network requests and send no telemetry.
- **Path confinement.** Every read and write stays inside the project root. Path traversal,
  escaping symlinks, and Windows path tricks are rejected.
- **Credential files are off-limits.** `.env*` and `.envrc`, private and signing keys, SSH keys,
  the `.ssh/`, `.aws/`, `.azure/`, `.config/gcloud/`, `.terraform.d/`, `.gnupg/` and `.kube/`
  folders, `.npmrc`, `.yarnrc.yml`, `.git-credentials`, `.cargo/credentials`, certificate stores,
  KeePass databases, shell history, and common tool token files (Docker, Vault, Codex, GitHub CLI)
  are never read, indexed, or searched. The full list is in [SECURITY.md](SECURITY.md).
- **No network paths.** Paths that point at a network share (`\\host\share`) are refused before
  any file access, so Windows never opens an SMB connection for them.
- **No surprise processes.** A repository cannot make `klens` run a program; optional parsers come
  only from your own `~/.klens` folder.
- **No accidental whole-disk indexing.** Your home folder, its parent folders, and drive roots
  (`C:\`, `/`) are never opened as a project.
- **Secret redaction.** Known secret formats are masked before output leaves `klens`, for example
  private key blocks, Anthropic, OpenAI and Google API keys, GitHub and GitLab tokens, AWS keys,
  `Bearer` tokens, JWTs, Slack, Stripe and npm tokens, and passwords inside database and remote URLs.
- **What redaction does not cover.** `klens run` runs the command you give it. A command such as
  `cat .env` prints that file, and only the known secret formats above are masked; anything else
  is shown as is. The raw logs under `.klens/runs/` keep the full, unredacted output (they are
  git-ignored, and owner-only on Unix). Redaction happens when a log is shown, not on disk.
- **Local UI hardening.** The dashboard binds to `127.0.0.1` only. It validates the `Host`
  header, uses an `HttpOnly` session cookie, and requires a CSRF check on every change.

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Command reference

<details>
<summary>All commands</summary>

| Area | Commands |
| :--- | :--- |
| Code analysis | `map`, `outline`, `read`, `find`, `impact`, `graph`, `diff-check`, `health` |
| Terminal and Git safety | `run`, `runs`, `checkpoint`, `checkpoints`, `rollback` |
| Memory and planning | `memory`, `blueprint`, `handoff` |
| Agents and setup | `mcp`, `init`, `attach`, `detach`, `detect`, `scan`, `disconnect`, `uninstall`, `doctor` |
| Extras | `ui`, `stats`, `ext`, `hook` |

Run `klens <command> --help` for the options of each command. Most analysis commands accept
`--json` and `--read-only`.

</details>

## License

Karasu Lens is **source-available** under the [PolyForm Strict License 1.0.0](LICENSE).

- ✅ Free for personal and other noncommercial use. This includes hobby projects, study, and
  research, as well as use by charitable, educational, and public organizations.
- ❌ You may not redistribute it, modify it, or build new works based on it.
- 💼 Commercial use requires a separate license. Please open an issue to get in touch.

Copyright © 2026 trgtefecngz.
