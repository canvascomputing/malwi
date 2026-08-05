---
type: AttackPattern
description: npm account takeover published 0.7.29, 0.8.0, and 1.0.0 with a preinstall script that branches on platform to drop a Monero miner and, on Windows, a credential stealer (Oct 2021).
tags: [auto-executing-install-hook]
---
# ua-parser-js (Oct 2021)

## Carrier
the real `ua-parser-js` package name, at roughly 8 million weekly downloads and a transitive
dependency of software shipped by Facebook among others. The maintainer's npm account was taken
over and three malicious versions were published under it: `0.7.29`, `0.8.0`, and `1.0.0`. The
window was narrow, roughly 12:15 to 16:26 GMT on 22 October 2021, but any `npm install` inside it
resolved to a poisoned version

## Technique
a `preinstall` script in `package.json` runs unconditionally on `npm install`, before any code of
the package is imported and before a developer has run anything. The script branches on the host
platform and fetches a different second-stage binary for Linux and for Windows, so a single
package covers both. Nothing about the library's own API is touched, so the package keeps working
and the compromise shows up only in install-time behaviour

## Payload/effect
an XMRig Monero cryptominer on both platforms, plus a Windows-only trojan that harvests browser
cookies and stored passwords across browsers, email and FTP clients, messaging apps, VPN
accounts, and Windows credentials. GitHub's advisory treats any host that ran it as fully
compromised and tells operators to rotate every secret on that machine from a different one,
because removing the package does not undo what the binary did

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- an install hook (`preinstall`, `postinstall`, `prepare`) that branches on the host platform
  (`process.platform`, `os.platform()`, `uname`) and selects a different payload per branch
- an install hook that writes an executable, `.dll`, or `.so` into the package directory and then
  runs it: the package's own code is never imported, so nothing in the library needs to look wrong
- a published version of a well-known package whose install script did not exist in the version
  before it

Literals from this incident, which confirm a replay but will not find a new one:
- `ua-parser-js` pinned at `0.7.29`, `0.8.0`, or `1.0.0`
- `jsextension`, `xmrig`, `stratum+tcp://`, `pool.minexmr.com`

## Sources
- https://github.com/advisories/GHSA-pjwm-rvh2-c87w
- https://github.com/faisalman/ua-parser-js/issues/536
- https://www.rapid7.com/blog/post/2021/10/25/npm-library-ua-parser-js-hijacked-what-you-need-to-know/
