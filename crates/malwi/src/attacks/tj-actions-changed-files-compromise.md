---
type: AttackPattern
description: Existing version tags of the tj-actions/changed-files Action were retargeted to commit 0e58ed86, which ran memdump.py against the Runner.Worker process and printed CI secrets into public build logs (CVE-2025-30066, Mar 2025).
tags: [build-artifact-only]
---
# tj-actions/changed-files Action compromise (CVE-2025-30066, Mar 2025)

## Carrier
the `tj-actions/changed-files` GitHub Action, used by over 23,000 repositories. On 14-15 March
2025 a stolen maintainer token was used to retarget most existing release tags, `v1.0.0` through
`v45.0.7` including `v5`, `v35.7.7-sec`, and `v44.5.1`, at a single new commit
`0e58ed8671d6b60d0890c21b07f8835ace038e67`. Nothing was published to a registry and no dependency
manifest changed: a workflow pinning the Action by tag silently resolved to attacker code on its
next run

## Technique
the injected code lives in the committed `dist/index.js`, the bundled artifact almost nobody
reads. It is a double-base64-encoded Node.js snippet that curls a Python script,
`memdump.py`, from a gist at
`gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965/raw/memdump.py`. The
script walks `/proc`, finds the process whose `/proc/<pid>/cmdline` contains `Runner.Worker`, and
reads `/proc/<pid>/maps` and `/proc/<pid>/mem` to scrape the runner's memory for the regex
`"[^"]+":{"value":"[^"]*","isSecret":true}`. This reaches secrets the workflow never passed to
the step, because they are resident in the runner process regardless

## Payload/effect
every secret in the runner's memory, base64-encoded into the workflow's own build log: access
keys, GitHub Personal Access Tokens, npm tokens, and private RSA keys. On a public repository
those logs are world-readable, so exfiltration needed no outbound connection at all. Patched in
`v46.0.1`; the gist and the malicious commits were later removed

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a workflow pinning any third-party Action by mutable tag or branch (`uses: owner/action@v45`)
  rather than by full commit SHA: the tag is what the attacker moves
- a committed build artifact (`dist/`, `bundle.js`, a vendored bundle) containing a long encoded
  blob passed to a decoder and then to `eval`, `exec`, or `child_process`, when the readable
  source beside it contains nothing of the kind
- CI code reading another process's memory or command line: any access to `/proc/<pid>/mem`,
  `/proc/<pid>/maps`, `/proc/<pid>/cmdline`, or a debugger attach
- exfiltration by *printing* rather than by network call: secrets written to stdout in a job whose
  logs are public need no outbound connection, so egress filtering never fires

Literals from this incident, which confirm a replay but will not find a new one:
- `tj-actions/changed-files`, commit `0e58ed86`, `memdump.py`, `nikitastupin`
- `Runner.Worker`, and the scrape regex marker `isSecret`

## Sources
- https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
- https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised
- https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
