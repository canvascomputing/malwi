---
type: AttackPattern
description: A new co-maintainer of event-stream added flatmap-stream, whose payload decrypted only when the host package description matched Copay, keeping it inert in every other environment (Nov 2018).
tags: [trust-based-distribution-compromise]
---
# event-stream / flatmap-stream (Nov 2018)

## Carrier
`flatmap-stream`, added as a direct dependency of `event-stream` 3.3.6 in September 2018 by
`right9ctrl`, a volunteer to whom the original author Dominic Tarr had handed maintenance after
six years of not using the package himself. event-stream was drawing roughly 8 million downloads
over the two and a half months the dependency went unnoticed, and the malicious code lived in the
new dependency rather than in event-stream itself

## Technique
the payload ships encrypted, and the decryption key is not a constant: it is read at runtime from
the *consuming* application's own `npm_package_description` environment variable, which npm sets
from the top-level `package.json`. The ciphertext decrypts to valid code only when that
description is "A Secure Bitcoin Wallet". Anywhere else the decryption produces garbage and
nothing runs, so a generic sandbox, a CI build, and a security scanner all see an inert module

## Payload/effect
inside Copay, the decrypted stage patched the wallet's own code to harvest account details and
private keys from accounts holding more than 100 BTC or 1000 BCH, and posted them to a collection
service at `111.90.151.134`. It was reported by Ayrton Sparling (FallingSnow) as issue #116 on
20 November 2018; npm unpublished flatmap-stream and event-stream 3.3.6

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a decryption key sourced from the *consuming* project rather than from a literal: a read of
  package metadata, an environment variable the host sets, a directory name, or a hostname, passed
  into a cipher constructor
- the decrypted result then executed: `createDecipher`/`createDecipheriv`/`AES` feeding `eval`,
  `new Function(`, `require`, `exec`, or `compile`
- a payload that produces garbage anywhere but one target, which is what defeats a sandbox: the
  giveaway is the key's provenance, not the ciphertext
- a dependency added by a recently-onboarded maintainer that no existing code path imports

Literals from this incident, which confirm a replay but will not find a new one:
- `flatmap-stream`, `right9ctrl`, `event-stream` pinned at `3.3.6`
- `npm_package_description`, `111.90.151.134`

## Sources
- https://github.com/dominictarr/event-stream/issues/116
- https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
- https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/
