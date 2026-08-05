---
type: AttackPattern
description: The cdn.polyfill.io domain was sold to Funnull, which served conditional redirect malware from googie-anaiytics.com to mobile visitors of over 100,000 embedding sites (Sansec, Jun 2024).
tags: [trust-based-distribution-compromise]
---
# polyfill.io CDN takeover (Sansec, Jun 2024)

## Carrier
`<script src="https://cdn.polyfill.io/v3/polyfill.min.js">`, embedded directly in the HTML of
more than 100,000 sites including Intuit and the World Economic Forum. In February 2024 the
domain and the project's GitHub account were bought by Funnull, a Chinese company. Nothing in any
dependency manifest changed: the trusted artifact is a URL the page fetches at run time, so no
lockfile, registry, or package audit sees the handover at all

## Technique
the JavaScript served from the domain was modified to inject a loader from
`www.googie-anaiytics.com`, a typo-domain shaped to pass a glance at a network log. The injected
code is gated so it fires rarely and never for the people most likely to notice: it runs only for
mobile user agents, skips Windows and macOS, varies its firing probability by hour of day, checks
for `admin_id` and `adminlevels` cookies and stays quiet if it finds them, and delays itself when
it detects Baidu, CNZZ, Matomo, or Google Analytics on the page. It also carries
reverse-engineering protection, so fetching the script once as a researcher usually returns
benign content

## Payload/effect
redirects to scam and sports-betting destinations including `https://kuurza.com/redirect?from=bitget`
and `https://w9.vty70.net/`. Namecheap suspended the domain on 27 June 2024 and Cloudflare began
rewriting requests to its own copy. Sansec flagged `bootcdn.net`, `staticfile.net`,
`staticfile.org`, `unionadjs.com`, and `xhsbpza.com` for related activity going back to June 2023

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a `<script src>`, `<link>`, or dynamic loader fetching code at run time from a host outside the
  project's own origin: no manifest or lockfile records it, so a package audit cannot see it
- such a remote script carrying no `integrity=` attribute and no pinned version path, so the host
  may change what it serves without anything on the consuming side changing
- a third-party host whose name is one character or one homoglyph from a service the reader
  expects (`googie` for `google`), which is what survives a glance at a network log
- served JavaScript generated per request rather than an immutable versioned asset

Literals from this incident, which confirm a replay but will not find a new one:
- `polyfill.io`, `googie-anaiytics`, `kuurza.com`, `vty70.net`
- the related hosts `bootcdn.net`, `staticfile.net`, `staticfile.org`, `unionadjs.com`, `xhsbpza.com`

## Sources
- https://sansec.io/research/polyfill-supply-chain-attack
- https://censys.com/blog/july-2-polyfill-io-supply-chain-attack-digging-into-the-web-of-compromised-domains/
