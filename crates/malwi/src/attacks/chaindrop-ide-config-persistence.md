---
type: AttackPattern
description: ChainDrop worm commits .claude/settings.json and .vscode/tasks.json to GitHub repos for IDE-level persistence via SessionStart and folderOpen hooks (August 2026)
tags: [ide-hook-abuse, supply-chain-attack]
---
# ChainDrop IDE Config Persistence (August 2026)

## Carrier
GitHub repository branches — the worm uses the `createCommitOnBranch` GraphQL mutation to push five files to up to 50 branches per exposed repository, skipping `dependabot/*` and `copilot/*` branches. The commit uses the `github-actions[bot]` author identity, carries a green GitHub-verified badge, the message `chore: update config`, and a forged `Co-authored-by: claude <claude@users.noreply.github.com>` trailer.

## Technique
The worm commits five files to any writable branch of an exposed repository, establishing mutually reinforcing IDE-level hooks:

1. `.claude/settings.json` — registers a SessionStart hook with `matcher: "*"` that runs `node .vscode/setup.mjs`
2. `.vscode/tasks.json` — registers an Environment Setup task with `runOptions.runOn: "folderOpen"` that runs `node .claude/setup.mjs`
3. `.claude/setup.mjs` — the Bun-based setup loader (SHA-256 `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb`)
4. `.vscode/setup.mjs` — identical loader to #3 (byte-identical content; a different SHA in the tarball vs. the repository copy)
5. `.claude/math_init.js` — the second-stage credential stealer payload (SHA-256 `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`)

Each tool's trigger executes the other tool's setup script, bootstrapping Bun 1.3.13 from GitHub releases if absent, then executing the payload. Claude Code fires the SessionStart hook on project directory open without a workspace trust prompt; VS Code requires the workspace to be marked trusted or the user to allow automatic tasks.

## Payload/effect
The setup loaders download Bun 1.3.13 from GitHub (no signature or checksum verification) and execute `math_init.js`, which harvests GitHub tokens, npm tokens, cloud credentials, SSH keys, database connection strings, Vault tokens, Kubernetes service account tokens, GitHub Actions runner memory (`/proc/<pid>/mem`), and AI-tool credential stores (Claude, OpenAI, Codex, Cursor, Gemini). Exfiltration goes through an Ethereum-based C2 resolver (contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103`, selector `0x53ed5143`) to HTTPS path `/router`, with a fallback to public GitHub repositories named with Dune vocabulary and description `Shai-Hulud: Here We Go Again`. A `gh-token-monitor` dead-man's switch polls a stolen token every 60 seconds and executes a supplied handler on 4xx (presumably token revocation).

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a `.claude/settings.json` file containing a JSON `hooks` object with a `SessionStart` entry referencing a command that loads a file from `.vscode/` (or cross-references the paired IDE directory)
- a `.vscode/tasks.json` file containing a task with `runOptions.runOn: "folderOpen"` (or equivalent key referencing folder-open auto-execution) that spawns a command loading from `.claude/`
- `.claude/` and `.vscode/` directories planted together in the same commit, with cross-referencing setup files between the two
- a Git commit authored by a CI bot (e.g., `github-actions[bot]`) with message `chore: update config` and a `Co-authored-by` trailer referencing an AI tool or agent
- a `setup.mjs` (or similarly named loader) inside `.claude/` or `.vscode/` that checks for and downloads a standalone runtime (Bun, Deno, Node) before executing a bundled payload
- a credential-stealer payload referenced from the IDE hooks that sweeps for GitHub tokens, npm tokens, SSH keys, and cloud credentials

Literals from this incident, which confirm a replay but will not find a new one:
- filenames: `.claude/settings.json`, `.claude/setup.mjs`, `.claude/math_init.js`, `.vscode/tasks.json`, `.vscode/setup.mjs`
- SHA-256 hashes: `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` (setup.mjs in .claude/.vscode), `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` (setup.mjs in tarball), `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` (math_init.js), `14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128` (settings.json), `927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f` (tasks.json)
- commit message: `chore: update config` with `Co-authored-by: claude <claude@users.noreply.github.com>`
- Ethereum contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103`
- Bun version `1.3.13`

## Unconfirmed
The number of victim systems that actually triggered the IDE hooks versus merely had the files planted. The campaign's initial access vector (which credential was stolen first). Whether Anthropic has since hardened Claude Code to prompt on workspace trust when a repo contains hooks. The `gh-token-monitor` dead-man's switch handler was embedded in the payload but not confirmed active in the wild.

## Sources
- https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
- https://research.jfrog.com/post/shai-hulud-is-back-august/
- https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/
- https://lord.technology/2026/05/02/claude-codes-hook-system-just-got-weaponised.html
