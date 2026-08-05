---
type: AttackPattern
description: The node-ipc maintainer added peacenotwar as a dependency, then shipped 10.1.1 and 10.1.2 which geolocate the host IP and overwrite files when it resolves to Russia or Belarus (CVE-2022-23812, Mar 2022).
tags: [trust-based-distribution-compromise]
---
# node-ipc "protestware" (CVE-2022-23812, Mar 2022)

## Carrier
`peacenotwar`, a dependency the node-ipc maintainer (RIAEvangelist) added to their own popular
package, and the node-ipc versions `10.1.1` and `10.1.2` published on 8 March 2022. No account
was stolen and no typosquat was involved: the signing identity, the repository, and the publish
were all legitimate, which is what makes this class hard to catch. The maintainer restated and
reshaped the behaviour across several releases before removing it in `10.1.3`

## Technique
the module geolocates the running machine by its outbound IP address at import time, then
branches on the country the lookup returns. Because the check runs wherever the dependency is
imported, it reaches transitively into every project that pulled node-ipc in without naming it
directly. The trigger is environmental, not attacker-controlled, so a sandbox in another region
sees nothing at all

## Payload/effect
on a match, the module recursively overwrites files on the user's drive, replacing their contents
with a heart emoji. Snyk classed it as a supply-chain attack rather than a protest, on the
grounds that the impact is destruction of a victim's data by one maintainer plus subsequent
attempts to restate and obscure that the sabotage was deliberate

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- code that reaches the network at import or install time purely to learn where it is running: an
  IP-geolocation lookup, a reverse DNS, a locale or timezone read used as a location proxy
- that result compared against a list of places or organisations, then branching into destructive
  filesystem calls: a write that replaces contents rather than appending, `unlink`, `rmSync`,
  `rm -rf`, `shutil.rmtree`
- a dependency whose behaviour depends on who is running it rather than on what it was asked to do

Literals from this incident, which confirm a replay but will not find a new one:
- `peacenotwar`, `RIAEvangelist`, `node-ipc` pinned at `10.1.1` or `10.1.2`
- `api.ipgeolocation.io`, and the country strings `russia` / `belarus`

## Sources
- https://github.com/advisories/GHSA-97m3-w2cp-4xx6
- https://tag-security.cncf.io/community/catalog/compromises/2022/node-ipc-peacenotwar/
