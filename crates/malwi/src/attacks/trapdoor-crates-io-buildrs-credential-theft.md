---
type: AttackPattern
description: Crates.io packages with malicious build.rs XOR-encrypt crypto wallet files and exfiltrate via GitHub Gist API (May 2026)
tags: [auto-executing-install-hook]
---
# TrapDoor Crates.io Build.rs Credential Theft (May 2026)

## Carrier
Six Crates.io packages disguised as Sui and Move blockchain development helpers:
`move-analyzer-build`, `move-compiler-tools`, `move-project-builder`,
`sui-framework-helpers`, `sui-move-build-helper`, `sui-sdk-build-utils`. Each package's
`Cargo.toml` declares `build = "build.rs"`, and the library source is a stub (e.g.
`sui-framework-helpers` contains only `pub fn placeholder() {}`).

## Technique
The `build.rs` script runs during `cargo build`, `cargo install`, and `cargo check`
(triggered by rust-analyzer in IDEs). It scans for cryptocurrency wallet/keystore files at
hardcoded paths (`.sui/sui_config/sui.keystore`, `.aptos/config.yaml`,
`.config/solana/id.json`), concatenates the contents with their paths, XOR-encrypts the
result with the hardcoded key `cargo-build-helper-2026`, converts to hexadecimal, writes
a local fallback to `/tmp/.cargo_build_log_<pid>.hex`, then exfiltrates via `curl` POST to
`https://api.github.com/gists` with a request body like
`{"public":true,"files":{"build.log":{"content":"<hex_data>"}}}`, spoofs the
`User-Agent` as `cargo/1.95`, and retries up to 3 times. An early-exit check skips
network activity if no wallet files are found.

Attribution to the broader TrapDoor campaign is unconfirmed at the code level: SlowMist
notes the Rust sample lacks the shared infrastructure URLs, the campaign marker
`P-2024-001`, and any code-level linkage to the npm/PyPI samples. Attribution relies
entirely on Socket's external correlation (same GitHub account `ddjidd564`, overlapping
time window, shared victim profile).

## Payload/effect
One-time stealer targeting Sui, Aptos, and Solana wallet configuration files and private
keys. Exfiltrated data is stored as a public GitHub Gist (visible to anyone who knows the
Gist URL). No persistence, no propagation, no remote configuration retrieval. The Rust
payload is less complex than the corresponding npm sample, operating as a single-shot
stealer with fixed-key XOR obfuscation.

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a Rust `build.rs` that scans user home directories for cryptocurrency wallet files,
  performs byte-level XOR encryption, and exfiltrates the result via `curl` POST to a
  code-hosting API
- a `build.rs` that calls `std::process::Command::new("curl")` with a POST body containing
  JSON with `"public":true` and a file key like `"build.log"` or `"config"`
- a `build.rs` that references cryptocurrency wallet paths under
  `~/.sui/`, `~/.aptos/`, or `~/.config/solana/`

Literals from this incident, which confirm a replay but will not find a new one:
- `cargo-build-helper-2026`
- `api.github.com/gists`, User-Agent `cargo/1.95`
- `.sui/sui_config/sui.keystore`, `.aptos/config.yaml`, `.config/solana/id.json`
- `move-analyzer-build`, `move-compiler-tools`, `move-project-builder`,
  `sui-framework-helpers`, `sui-move-build-helper`, `sui-sdk-build-utils`
- GitHub account `ddjidd564`

## Sources
- https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
- https://prismor.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
- https://slowmist.medium.com/threat-intelligence-trapdoor-analysis-a-cross-ecosystem-supply-chain-credential-theft-operation-a9a4e11616ea
- https://phoenix.security/trapdoor-supply-chain-ai-poisoning-npm-pypi-crates/
