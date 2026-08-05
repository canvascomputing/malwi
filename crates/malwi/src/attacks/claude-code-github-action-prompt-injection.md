---
type: AttackPattern
description: Claude Code GitHub Action indirect prompt injection via unsanitized event data in prompts for credential theft (June 2026).
tags: [untrusted-input-expansion]
---
# Claude Code GitHub Action Prompt Injection (June 2026)

## Carrier
GitHub issue bodies, PR titles, issue comments, and PR descriptions — all processed by the `anthropics/claude-code-action@v1` GitHub Action when triggered on `issues`, `pull_request`, `issue_comment`, or `pull_request_review` events. Attackers embedded malicious instructions in these locations, often hidden inside HTML comments (`<!-- -->`) invisible to human reviewers but parsed by the AI agent reading raw markdown.

## Technique
Indirect prompt injection: untrusted GitHub event data is interpolated directly into the LLM prompt, e.g. `prompt: | You're a GitHub issue first responder... **Issue:** #${{ github.event.issue.number }} **Title:** ${{ github.event.issue.title }}`. The AI interprets embedded instructions as authoritative. Bypass vectors include: (1) `checkWritePermissions` in agent mode trusting any `[bot]` actor; (2) `allowed_non_write_users: "*"` misconfiguration disabling human-actor checks; (3) the Read tool operates in-process, bypassing `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` protection; (4) prompt engineering tricks to bypass safety filters and truncate output to evade secret scanning.

## Payload/effect
The injected prompt instructs Claude Code to read `/proc/self/environ`, extracting environment variables including `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_URL`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `GEMINI_API_KEY`, `GITHUB_COPILOT_API_TOKEN`, `GITHUB_PERSONAL_ACCESS_TOKEN`, and `COPILOT_JOB_NONCE`. Using the OIDC credential pair, attackers replay the token exchange to obtain a privileged GitHub App installation token, enabling malicious code pushes to the action's source repository or the target repo. Exfiltration occurs via `mcp__github__update_issue`, PR comments, workflow run summaries, base64-encoded git commits, or `WebFetch`/`Bash` to attacker-controlled servers. The Clinejection variant additionally used GitHub Actions cache poisoning via Cacheract and published unauthorized `cline@2.3.0` to npm.

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- untrusted event data interpolated into an LLM prompt in CI: any `${{ github.event.* }}`
  expression reaching a `prompt:` field, a system message, or an agent instruction. Issue and PR
  titles, bodies, and comments are attacker-controlled text, and putting them in a prompt is the
  same class of mistake as putting them in a shell command
- an agent workflow with no human-actor gate: a permission check disabled with a wildcard, or a
  trigger (`issue_comment`, `issues`, `pull_request_target`) that any account can fire
- an agent granted write credentials or a token in the same job that reads untrusted input
- an agent process reading its own environment or the runner's: `/proc/self/environ`,
  `/proc/*/environ`, `env`, or a dump of `secrets` appearing in agent output or logs
- exfiltration through a channel the workflow already owns: a comment posted back to the issue, a
  branch pushed, a commit message, a build log

Literals from this incident, which confirm a replay but will not find a new one:
- `allowed_non_write_users: "*"`, `anthropics/claude-code-action@v1` without a `checkHumanActor` step
- `${{ github.event.issue.body }}`, `${{ github.event.issue.title }}`,
  `${{ github.event.comment.body }}` inside a `prompt:` block

## Sources
- https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/
- https://github.com/advisories/GHSA-xq4m-mc3c-vvg3
- https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/
- https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/
- https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents
- https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-claude-code-github-action-prompt-injection/
- https://thehackernews.com/2026/06/claude-code-github-action-flaw-let-one.html
