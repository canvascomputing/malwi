---
type: AttackPattern
description: MavenGate hijacks abandoned Maven groupId namespaces by purchasing expired reverse-domains, asserting ownership via DNS TXT records, and publishing malicious JARs (January 2024).
tags: [registry-namespace-abuse]
---
# MavenGate (January 2024)

## Carrier
Malicious JAR artifact published to Maven Central or JitPack under a hijacked groupId whose reverse-domain segments correspond to an expired domain name.

## Technique
Attackers identify abandoned Maven groupId values whose reverse-domain segments have expired, then purchase those domains. They assert ownership by publishing a DNS TXT record on the newly-owned domain, satisfying the groupId verification requirement of Maven Central and JitPack. If the groupId is unmanaged by any existing account, the attacker claims it directly. If an existing account holds the groupId, the attacker contacts repository support with domain-ownership proof to request a transfer. Once the groupId is controlled, a malicious version is published — either a re-release of an existing version or a new, higher version number — that overrides the legitimate artifact during dependency resolution.

## Payload/effect
The malicious JAR replaces the legitimate library within the build's dependency resolution graph. Attack variants target existing versions (when the attacker's repository appears earlier in the build's repository list) or target future upgrades (publishing a newer version number and waiting for developers to upgrade). This enables arbitrary code injection into applications, build-process compromise via malicious Maven plugins, and downstream infrastructure access. No specific malware payload was publicly confirmed — Oversecured demonstrated the technique using a benign "Hello World!" Android library under `com.oversecured` and stated it would be unethical to test on real dependencies. Actual deployment by threat actors has not been publicly documented.

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a Maven groupId whose corresponding reverse-domain (groupId segments reversed, e.g. `com.example.foo` → `foo.example.com`) has a domain registration date within 30–90 days of the artifact's first published version
- a newly published artifact on a public Maven repository whose groupId was recently verified via a domain-owned DNS TXT record for groupId claim
- a groupId that has no pre-existing account on the repository or was transferred to a new account

Literals from this incident, which confirm a replay but will not find a new one:
- `com.opencsv`, `co.fs2`, `net.jpountz.lz4`, `org.mvel`, `org.tpolecat`
- `com.oversecured`
- 33,938 domains analyzed, 6,170 expired

## Sources
- https://oversecured.com/blog/introducing-mavengate-a-supply-chain-attack-method-for-java-and-android-applications
- https://thehackernews.com/2024/01/hackers-hijack-popular-java-and-android.html
- https://nesbitt.io/2026/02/14/package-management-namespaces.html
