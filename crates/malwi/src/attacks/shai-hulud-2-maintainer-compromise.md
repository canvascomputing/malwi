---
type: AttackPattern
description: A self-propagating npm worm running in the preinstall phase via setup_bun.js and bun_environment.js, harvesting secrets into attacker GitHub repos and registering infected hosts as self-hosted runners (Nov-Dec 2025).
tags: [auto-executing-install-hook]
---
# Shai-Hulud 2.0, "The Second Coming" (Nov-Dec 2025)

## Carrier
compromised maintainer accounts across the npm ecosystem, reaching packages published by Zapier,
ENS Domains, PostHog, and Postman. Detected 24 November 2025, it backdoored roughly 796 unique
packages totalling over 20 million weekly downloads, created more than 27,000 GitHub repositories,
and exposed around 14,000 secrets across 487 organisations. It is a worm: stolen npm tokens are
used to publish the payload into further packages, so the blast radius grows without further
operator action

## Technique
the payload ships as two files, `setup_bun.js` and `bun_environment.js`, and executes in the
`preinstall` phase, before any other install step completes. Running that early widens exposure to
CI/CD runners that would never reach the package's own code. It installs the Bun runtime if
absent, then runs the second stage, which sweeps the host for credentials, including a TruffleHog
pass over the filesystem. Persistence is established by writing
`.github/workflows/discussion.yaml`, which registers the infected machine as a self-hosted runner
named `SHA1HULUD`, giving the operator arbitrary command execution through GitHub discussions

## Payload/effect
cloud credentials, npm and GitHub tokens, and environment secrets are written to
`cloud.json`, `contents.json`, `environment.json`, and `truffleSecrets.json`, then pushed to a
public repository under the victim's own GitHub account, described as
"Sha1-Hulud: The Continued Coming". A second workflow, `formatter_123456789.yml`, exfiltrates
repository secrets by uploading an artifact containing `toJSON(secrets)`. The malware carries a
dead man's switch that destroys user data if it detects containment

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- an install hook that runs in `preinstall`, ahead of every other step, so a CI runner is reached
  before the package's own code would ever be imported
- an install hook that downloads or installs a *runtime* (`bun`, `deno`, a standalone `node`) and
  then executes a bundled script with it, sidestepping whatever the project's own toolchain allows
- a filesystem-wide credential sweep at install time: recursive reads of `.env`, `~/.npmrc`,
  `~/.aws`, `~/.ssh`, or a bundled secret-scanner run over the tree
- CI config that registers a self-hosted runner, or that uploads an artifact containing
  `toJSON(secrets)`: both turn a one-off execution into standing access
- exfiltration to a repository under the *victim's own* account, which looks like ordinary
  authenticated traffic to the host the credentials already belong to
- a lockfile bump to a widely-used package with no matching upstream changelog or release notes

Literals from this incident, which confirm a replay but will not find a new one:
- `setup_bun.js`, `bun_environment.js`, `SHA1HULUD`, `Shai-Hulud`
- `truffleSecrets.json`, `cloud.json`, `formatter_123456789.yml`, `discussion.yaml`

## Sources
- https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/
- https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
- https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
