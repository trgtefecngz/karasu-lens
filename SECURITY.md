# Security Policy

## Supported Versions

Security fixes are provided for the latest release of Karasu Lens (`klens`). Please always use
the [latest release](https://github.com/trgtefecngz/karasu-lens/releases/latest).

| Version | Supported |
| :--- | :--- |
| Latest release | Yes |
| Older releases | No — please upgrade |

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub **Private Vulnerability Reporting**:

1. Open the repository's **Security** tab -> **Advisories** -> **Report a vulnerability**.
2. Include reproduction steps, affected version/platform, and impact details.

**Do not open public GitHub issues or pull requests for undisclosed security vulnerabilities.**

## Security Model Summary

- **Zero Outbound Network:** Core `klens` commands operate strictly offline with zero outbound HTTP/telemetry requests.
- **Loopback-Only Web UI:** `klens ui` binds strictly to `127.0.0.1` and enforces `Host` validation, a random per-launch `HttpOnly; SameSite=Strict` session cookie, and a triple CSRF gate (`Origin` + cookie + `X-Klens-Request: 1`) on all mutating routes.
- **Untrusted Repository Content Never Launches Programs:** Language-parser sidecars (`ext-lang-*`, incl. `ext-lang-ctags`) load manifests only from `~/.klens/extensions/` and are enabled only via `~/.klens/config.toml` (`klens ext enable <id> --global`). A repository's own `.klens/extensions/` manifests and project-level `enabled_extensions` entries for language parsers are ignored, so indexing, `klens doctor`, or the Web UI can never launch a repository-supplied program.
- **No Home-Directory or Drive-Root Indexing:** `klens` refuses to open the user home directory, any parent of it, or a filesystem/drive root (`C:\`, `/`) as a project root — in the CLI, `klens mcp`, and the Web UI.
- **Path Containment (`ProjectRoot`):** All project file reads and writes are canonicalized and confined inside the project root, blocking path traversal, escaping symlinks, and sensitive files. The locked built-in list (`crates/klens-core/src/sensitive.rs`) covers `.env*` and `.envrc`, `*.pem`/`*.key`, signing keys (`*.p8`, `*.pk8`), SSH keys (`id_rsa*`, `id_dsa*`, `id_ecdsa*`, `id_ed25519*`), the `.ssh/`, `.aws/`, `.azure/`, `.config/gcloud/`, `.terraform.d/`, `.gnupg/`, `.kube/` and `.git/` directories, `.npmrc`, `.pypirc`, `.netrc`/`_netrc`, `.git-credentials`, `.pgpass`, `.yarnrc.yml`, `.cargo/credentials` and `.cargo/credentials.toml`, certificate stores (`*.pfx`, `*.p12`, `*.jks`, `*.keystore`, `*.ppk`), KeePass databases (`*.kdbx`), tool token files (`.docker/config.json`, `.dockercfg`, `.codex/auth.json`, `.credentials.json`, `gh/hosts.yml`, `.vault-token`), and shell history (`.bash_history`). These files are never read, written, indexed, or searchable; projects can add more via `extra_sensitive_patterns` but cannot remove built-ins.
- **Output-Gate Secret Redaction:** `redact_secrets` automatically scrubs 15 high-precision secret categories (PEM private key blocks, Anthropic/OpenAI/Google API keys, GitHub and GitLab tokens, AWS access/secret keys, `Bearer` tokens, JWTs, Slack tokens, Stripe live keys, npm tokens, and the password part of database and web/remote URLs such as `postgres://user:password@host` or `https://user:token@host`; documentation placeholders like `${DB_PASSWORD}` are left alone) before CLI, MCP, handoff, or Web UI output leaves `klens`. Private key blocks are found over the whole file, so a line range, search hit or error window that starts inside a key body is masked too. Generic string assignments (e.g., `password = "..."`) are intentionally excluded to avoid false-positive code corruption and `pre-commit` blocks.
- **Command Output Is Only Pattern-Redacted:** the sensitive-file list stops `klens` from *reading* credential files, but `klens run` / `klens_run` executes whatever command it is given. A command such as `cat .env` or `type secrets.json` prints the file, and only the pattern redaction above masks what it recognises; values in other formats (e.g. `DB_PASS=hunter2`) are shown as is. Treat `klens_run` as a shell, not as a sandbox.
- **Repository Git Settings Never Run Programs:** every `git` command `klens` starts disables `core.fsmonitor`, hooks, commit signing and filter drivers defined by the repository's own `.git/config`, and patch output uses `--no-ext-diff --no-textconv`. Filters from your own global/system git config (e.g. Git LFS) keep working. A repository-local `core.hooksPath` pointing outside the repository is refused by `klens hook install`.
- **No Network Paths:** paths from AI agents, from command output and from the Web UI folder picker are only resolved when they are plain local paths. Network shares (`\\host\share`, `//host/share`, `\\?\UNC\...`) are refused before any filesystem call, so Windows never opens an SMB connection for them.
- **Linked State Folders Are Refused:** a `.klens` folder that is (or contains) a symbolic link or junction makes `klens` refuse the project, and AI host files are never written through a linked project `.claude` folder.
- **Bounded Reads:** `klens read` refuses files over 16 MiB instead of loading them into memory.
- **Raw Run Logs Stay Local:** `klens run` keeps unfiltered command output under `.klens/runs/`, which carries its own `.gitignore` so these logs are never offered for commit, even in projects that were not set up with `klens attach`. The recorded command line is redacted like any other output. **The raw log files themselves are not redacted:** they hold the command's output exactly as printed, secrets included. On Unix they are created owner-only (`0600`); on Windows they inherit the project folder's permissions. Redaction applies when a log is shown (`klens runs show`, `--raw`), not to the file on disk.
- **Checkpoints Exclude Credential Files:** `klens checkpoint` never stores files from the built-in sensitive list or the project's `extra_sensitive_patterns` in its git objects. `klens rollback` never restores, modifies or deletes those files, nor the project's `protected_paths`.
- **Web UI Content Security Policy:** every dashboard response carries a strict `Content-Security-Policy` (scripts and network requests only from the dashboard itself; no frames, forms, plugins or `<base>` overrides).
- **Host Config Edits:** when `klens init`/`disconnect` edits an AI host's config file (e.g. `~/.claude.json`), the user's key order and all unrelated entries are kept. `klens` re-checks the file immediately before writing; if the host changed it in the meantime, the edit is redone on the newer content instead of overwriting it.
- **`allowed_clients` Is Not Authentication:** the per-project `allowed_clients` list matches the name an MCP client reports about itself. It limits which agents a project is offered to; it does not stop a local program that claims an allowed name.
