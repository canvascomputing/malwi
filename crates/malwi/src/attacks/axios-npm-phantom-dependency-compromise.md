---
type: AttackPattern
description: axios npm compromise uses phantom dependency plain-crypto-js to deploy cross-platform RAT via postinstall hook (March 2026).
tags: [auto-executing-install-hook]
---
# Axios Phantom Dependency Compromise (March 2026)

## Carrier
axios@1.14.1 (tagged latest) and axios@0.30.4 (tagged legacy), the popular JavaScript HTTP client with ~100 million weekly npm downloads. The attacker did not modify any axios source code.

## Technique
Phantom dependency with decoy replacement via maintainer account compromise (jasonsaayman). A `plain-crypto-js@^4.2.1` entry was added to axios's `package.json`. This package is never `require()`'d or `import()`'d anywhere in the axios source code — its sole purpose is to trigger npm's `postinstall` lifecycle hook. Staging: `plain-crypto-js@4.2.0` was published as a clean decoy typosquat of the legitimate `crypto-js` library. Hours later, `plain-crypto-js@4.2.1` was published with a `postinstall: "node setup.js"` hook. The dropper (`setup.js`, ~4209 bytes) uses two-layer obfuscation — reversed Base64 encoding then XOR cipher (key "OrDeR_7077" with quadratic index `7*r*r % 10`) — to decode runtime strings, detect the OS, and download a platform-specific RAT from `http://sfrclak.com:8000/6202033`. Anti-forensics: after launching the RAT, `setup.js` deletes itself (`fs.unlink(__filename)`), deletes the malicious `package.json`, and renames a pre-staged clean manifest stub (`package.md`, version 4.2.0) to `package.json`, leaving `node_modules/plain-crypto-js/package.json` fully clean.

## Payload/effect
Cross-platform Remote Access Trojan deployed to macOS, Windows, and Linux — all three platforms use the same RAT framework with identical C2 protocol, command set, and 60-second beacon cadence. macOS: C++ Mach-O binary delivered to `/Library/Caches/com.apple.act.mond`, launched via `/bin/zsh`. Windows: PowerShell RAT (`6202033.ps1`) delivered to `%TEMP%`, executed via `%PROGRAMDATA%\wt.exe` masquerading as Windows Terminal, persistence via HKCU Run key. Linux: Python RAT delivered to `/tmp/ld.py`, executed detached via `nohup python3`. The RAT performs system reconnaissance, command execution, binary injection (peinject), persistence, and C2 callback via HTTP POST with Base64-encoded JSON. Microsoft attributes the campaign to Sapphire Sleet (DPRK state actor); Elastic notes overlap with WAVESHAPER (Mandiant-tracked UNC1069).

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a package present in `node_modules/` that no manifest in the tree declares: a phantom
  dependency reaches disk through an install hook rather than through resolution, so the lockfile
  is not where it shows up
- an install hook that selects a payload per platform and deploys a persistent remote-access
  binary rather than doing setup work
- a command-and-control URL whose path imitates the registry the package came from
  (`packages.npm.org/...` served from an unrelated host): the path is shaped to survive a glance
  at a proxy log, so read the host, not the path
- a hardcoded, long-obsolete `User-Agent` in outbound traffic, especially one naming a Windows
  browser from a process running on macOS or Linux: real clients do not carry a fixed decade-old
  UA string
- outbound traffic to a bare IP or a non-standard port from a package whose stated purpose is
  local

Literals from this incident, which confirm a replay but will not find a new one:
- `plain-crypto-js` in `node_modules/`, `package.json`, `package-lock.json`, or `yarn.lock`
- `sfrclak.com:8000/6202033`, `packages.npm.org/product0`
- the user-agent `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`

## Sources
- https://github.com/axios/axios/issues/10636
- https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
- https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html
- https://socket.dev/blog/axios-npm-package-compromised
- https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/
- https://unit42.paloaltonetworks.com/axios-supply-chain-attack/
- https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections
