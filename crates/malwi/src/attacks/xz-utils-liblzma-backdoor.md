---
type: AttackPattern
description: Payload bytes parked in git test fixtures, assembled only by a build-to-host.m4 present in the release tarball but not in the repository, hijacking glibc IFUNC resolution to backdoor OpenSSH (CVE-2024-3094, Mar 2024).
tags: [build-artifact-only]
---
# xz-utils / liblzma backdoor (CVE-2024-3094, Mar 2024)

## Carrier
two files checked into the public xz repository as test fixtures,
`tests/files/bad-3-corrupt_lzma2.xz` and `tests/files/good-large_compressed.lzma`, which hold
payload bytes and were not used by any test in 5.6.0. The assembly step lives in a modified
`build-to-host.m4` that appears only in the released tarballs for 5.6.0 and 5.6.1 and in neither
the upstream source of build-to-host nor xz's git history. Reviewing the repository shows nothing;
the artifact people actually build from is a different set of bytes. It was contributed over a
multi-year campaign by a maintainer who had earned commit rights

## Technique
`./configure`, run from the released tarball, executes an obfuscated script appended by the
modified `.m4` at the end of configure, which conditionally rewrites the Makefile. The build then
pipes the "test" fixtures through a `tr` substitution and `xz` to reconstitute an object file and
links it into liblzma. At run time the object hijacks glibc IFUNC resolution to divert the symbol
resolution used by OpenSSH's linked-in liblzma

## Payload/effect
pre-authentication unauthenticated remote code execution in OpenSSH for anyone holding the
attacker's hardcoded ED448 key. Found by Andres Freund from a half-second of unexplained sshd
latency and reported to oss-security on 29 March 2024; CVSS 10.0

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a build script (`.m4`, `configure.ac`, `Makefile.am`, `CMakeLists.txt`, `build.rs`, `setup.py`)
  that reads a file from a test, fixture, sample, or data directory and pipes it into a decoder
  (`xz`, `gzip`, `base64`, `tr`, `openssl`) whose output reaches compilation or linking
- any divergence between the repository and the distributed archive: a build input present in the
  tarball but absent from version control is the whole attack, and reviewing the repository is
  what misses it
- a test fixture no test references, or one whose size or entropy does not match what its
  extension implies
- a build step that appends to or rewrites the Makefile from inside `configure`
- symbol interposition set up at link time: IFUNC resolvers, `LD_PRELOAD` wiring, or `__attribute__((ifunc))`
  in a compression or utility library that has no reason to resolve symbols dynamically

Literals from this incident, which confirm a replay but will not find a new one:
- `build-to-host.m4`, `bad-3-corrupt_lzma2.xz`, `good-large_compressed.lzma`
- `xz` or `liblzma` pinned at `5.6.0` or `5.6.1`

## Sources
- https://www.openwall.com/lists/oss-security/2024/03/29/4
- https://securitylabs.datadoghq.com/articles/xz-backdoor-cve-2024-3094/
