---
type: AttackPattern
description: About 25 typosquatted npm and PyPI packages posing as fixed Solana SDK builds, appending stealer code after the real exports and running it via postinstall or __init__.py to exfiltrate keys over Telegram (JFrog, 2025/2026).
tags: [auto-executing-install-hook]
---
# Solana FakeFix (JFrog, 2025/2026)

## Carrier
roughly 25 packages across two registries, posing as patched or community forks of Solana tooling:
on npm `@solana-labs/web3.js`, `@solana-labs/spl-toke`, `solana-web3-stable`, `solana-web3-fixed`,
`solana-web3-patched`, `solana-rpc-client`, `solana-mev-bot` among others; on PyPI `solana-web3`,
`solana-web3-py`, `solana-cli-py`, `spl-token-py`. The names sit close enough to real ecosystem
terminology to catch a developer searching for an SDK or a fix. The actor drove installs directly
by spamming GitHub issues from the account `PassWord1337`, recommending an
uninstall-then-install command to switch packages

## Technique
the packages ship largely legitimate Solana JavaScript bundles and append the stealer *after* the
real exports and the source-map comment, so the library genuinely works and casual testing shows
nothing. Execution needs no explicit call: on npm a `"postinstall": "node install.js"` runs at
install, and on PyPI the payload sits in `__init__.py`, so a bare `import` starts collection. The
appended block is an IIFE, which keeps it out of the module's exported surface

## Payload/effect
targeted reads of `~/.config/solana/id.json`, `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, AWS
credentials, `.env` files, and wallet files, plus any environment variable whose name contains
`KEY`, `SECRET`, `MNEMONIC`, `PRIVATE`, `TOKEN`, or `PASSWORD`. Exfiltration and command-and-control
run over Telegram, with bot tokens and chat IDs embedded in the code

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- code appended after a bundle's real exports or after `//# sourceMappingURL=`: nothing legitimate
  is emitted past that marker, so anything there was added after the build
- an IIFE (`;(function(){ ... })();`) at the very end of a vendored or published bundle
- a `"postinstall"` running a sibling script, or a Python `__init__.py` that does work on import
  rather than defining names: both execute without the caller invoking anything
- reads of a fixed list of credential paths (`~/.ssh/`, `~/.aws/`, `~/.config/`, `.env`) followed by
  an outbound send, especially in a package with no stated need for any of them
- environment enumeration filtered by a keyword list (`KEY`, `SECRET`, `MNEMONIC`, `TOKEN`)
- command-and-control over a consumer messaging API (`api.telegram.org`, a Discord webhook), which
  is ordinary allowed egress on most networks

Literals from this incident, which confirm a replay but will not find a new one:
- `@solana-labs/`, `solana-web3-stable`, `solana-web3-fixed`, `spl-token-py`, `PassWord1337`
- `api.telegram.org/bot`, `~/.config/solana/id.json`

## Sources
- https://research.jfrog.com/post/solana-fakefix/
- https://gbhackers.com/solana-fakefix-campaign/
