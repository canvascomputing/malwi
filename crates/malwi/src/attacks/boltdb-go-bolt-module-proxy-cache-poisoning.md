---
type: AttackPattern
description: Go Module Proxy cache poisoning: boltdb-go/bolt typosquat served cached backdoor since Nov 2021, C2 via obfuscated TCP in db.go (Feb 2025).
tags: [registry-namespace-abuse]
---
# BoltDB Go Module Proxy Cache Poisoning (February 2025)

## Carrier
A malicious Go module, `github.com/boltdb-go/bolt` (v1.3.1), typosquatting the legitimate `github.com/boltdb/bolt` BoltDB database package. The module was cached indefinitely by the Go Module Mirror (proxy.golang.org) starting November 2021 and continued serving the malicious version even after the GitHub source repository was cleaned up.

## Technique
The attacker created a GitHub repository impersonating BoltDB, published a backdoored version v1.3.1, and relied on the Go Module Mirror's automatic, indefinite caching to maintain persistence. After caching, the attacker rewrote the Git tag for v1.3.1 to point to a clean, legitimate commit, exploiting mutable Git tags to evade manual auditing while the proxy continued serving the original malicious blob. The module proxy's `.info` file for the malicious module lacked resolved Git commit SHA references linking back to the malicious code, hiding its provenance.

## Payload/effect
A remote access backdoor embedded in `db.go` that activates when a developer calls the package's `Open()` function. The `ApiInit()` function spawns a goroutine establishing a persistent TCP connection to C2 server `49.12.198[.]231:20022` (Hetzner Online, AS24940). It listens for shell commands from the C2 server, executes them via `exec.Command` on the infected host with no validation, and returns output to the attacker. A built-in `recover()` restarts the backdoor after 30 seconds if it crashes. The C2 address is obfuscated across `cursor.go` using three integer constants (`MaxMemSize`, `MaxIndex`, `MaxPort`) decoded by a `_r()` helper function that calls `strings.ReplaceAll` three times — replacing '5' with '.', removing '6' and '7' — to reconstruct the IP:port.

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a module path one edit away from a well-known one: a `-go` or `-js` suffix added, a hyphen moved,
  an owner and repo segment swapped. `github.com/boltdb-go/bolt` against `github.com/boltdb/bolt`
  is a name-confusion attack, and the import line is the only place it appears
- a dependency resolved through an immutable module proxy or registry cache. Once cached the
  artifact outlives its source: deleting the upstream repository and account does not revoke it,
  so "the repo is gone" is not remediation and the module keeps serving years later
- a network address assembled at run time from numeric constants rather than written as a literal:
  integer constants concatenated and passed through `strings.ReplaceAll`, `replace`, `strconv`, or
  arithmetic to produce an IP and port. The constants are named to look like configuration limits
- an exported initialiser in a storage, parsing, or utility library that opens a socket: a package
  with no networking in its purpose dialling out at init is the finding, whatever the address
- a `go.mod` or lockfile entry whose upstream repository no longer exists, was renamed, or was
  never the canonical home of that import path

Literals from this incident, which confirm a replay but will not find a new one:
- module path `github.com/boltdb-go/bolt` at `v1.3.1`, attacker alias `boltdb-go`
- `ApiInit()` and the `_r()` decoder in `db.go`
- the constants `MaxMemSize`, `MaxIndex`, `MaxPort`, decoding to `49.12.198[.]231:20022`
- Go vulnerability ID `GO-2025-3451`

## Sources
- https://socket.dev/blog/malicious-package-exploits-go-module-proxy-caching-for-persistence
- https://thehackernews.com/2025/02/malicious-go-package-exploits-module.html
- https://arstechnica.com/security/2025/02/backdoored-package-in-go-mirror-site-went-unnoticed-for-3-years/
- https://osv.dev/vulnerability/GO-2025-3451
