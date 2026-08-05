---
type: AttackPattern
description: A typosquat of buildrunner whose postinstall init.js pulls an obfuscated batch file from Codeberg, bypasses UAC via fodhelper.exe, and decodes a Pulsar RAT from PNG pixel data (Veracode, Feb 2026).
tags: [binary-media-disguise]
---
# buildrunner-dev npm package (Veracode, Feb 2026)

## Carrier
`buildrunner-dev`, a typosquat of the abandoned `buildrunner` / `build-runner` tools, positioned to
catch a mistype or an assumption that it is a maintained fork. The package itself carries almost
nothing: a `postinstall` hook in `package.json` runs `init.js`, which acts purely as a downloader
and fetches `packageloader.bat` from a Codeberg repository at install time. Because the payload is
never in the published tarball, a registry scan of the package contents finds a small clean file

## Technique
twelve layers deep. The fetched batch file runs to 1,653 lines carrying roughly 21 lines of real
instruction. It escalates through the `fodhelper.exe` UAC bypass, writing
`reg add "HKCU\Software\Classes\ms-settings\CurVer" /ve /d "<key>"` and then invoking
`C:\Windows\System32\fodhelper.exe`, which auto-elevates and follows the hijacked class. The
final stages arrive as ordinary-looking PNG files: the first two pixels encode the payload size as
a 32-bit integer (`(P(0,0).R << 24) | (P(0,0).G << 16) | (P(0,0).B << 8) | P(1,0).R`), and every
pixel after that carries three payload bytes across its R, G, and B channels. A 41x41 PNG held a
4,903-byte AMSI bypass

## Payload/effect
process hollowing into a legitimate host process, then Pulsar, an open-source .NET remote access
trojan giving full control of the machine

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- an install hook whose entire body is a fetch: the published package holds a downloader and the
  payload arrives later, so scanning the tarball contents proves nothing about what runs
- an install-time fetch from a code-hosting or paste host that is not the package's own registry
  (Codeberg, Gitea, a gist, a raw branch URL, a pastebin)
- an image, font, or other media file read byte-by-byte with per-channel bit arithmetic
  (`<< 24`, `& 0xFF`, `getpixel`, `GetPixel`, `.R`/`.G`/`.B` indexing) instead of being handed to a
  decoder as an asset: media that is parsed as a container rather than displayed
- a Windows auto-elevating binary invoked right after a write under `HKCU\Software\Classes`:
  the registry write plus the elevated launch is the bypass, whichever binary is named
- an obfuscated script whose real instruction count is a tiny fraction of its line count

Literals from this incident, which confirm a replay but will not find a new one:
- `buildrunner-dev`, `packageloader.bat`, `init.js`
- `fodhelper`, `ms-settings\CurVer`, `Pulsar`

## Sources
- https://www.veracode.com/blog/malicious-npm-package-hiding-in-plain-pixels/
- https://hackread.com/hackers-pulsar-rat-png-images-npm-supply-chain-attack/
