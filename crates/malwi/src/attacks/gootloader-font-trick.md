---
type: AttackPattern
description: A WOFF2 font is Z85-encoded inside a page's JavaScript with its glyph vectors swapped, so the filename a victim reads never exists as text in the source (Huntress, Nov 2025).
tags: [binary-media-disguise]
---
# GootLoader font trick (Huntress, Nov 2025)

## Carrier
a custom WOFF2 web font embedded inside the JavaScript of a compromised WordPress page, not served
as a separate font asset. The 32KB font is Z85-encoded, a Base85 variant, into roughly 40K of
JavaScript sitting in a variable assignment

## Technique
glyph vector substitution rather than character mapping. The font's metadata looks entirely
legitimate, but the vector paths defining each glyph have been swapped: asked for the shape of
`O`, the font returns the coordinates that draw `F`. The source carries only gibberish such as
`Oa9Z±h•`, which the browser renders as `Florida`. This defeats static analysis directly, because
searching for `invoice` or `contract` returns nothing: those words never exist as text anywhere in
the page. Delivery pairs with WordPress comment endpoints serving XOR-encrypted ZIPs with a unique
key per file, and the archive is malformed such that Python's zip module, 7-Zip, and VirusTotal
all unpack a harmless `.TXT` while Windows File Explorer extracts the real JavaScript payload

## Payload/effect
a malware loader; Huntress observed three infections from 27 October 2025, two reaching
hands-on-keyboard intrusion with domain-controller compromise inside 17 hours

## Detectable signal
The shape, which catches a variant sharing no text with this incident:
- a font, image, or other binary format embedded inside source as an encoded string rather than
  shipped as an asset: a `wOF2`, `OTTO`, `PNG`, or `GIF8` magic value inside a JavaScript string,
  a variable assignment, or a `data:` URI
- a Base85, Z85, or other non-standard alphabet decoder in page JavaScript, especially one whose
  output is handed to a `@font-face` or `Blob`
- a rendering layer that changes what text means: a custom glyph table, a private-use-area code
  point range, or a substitution table applied to displayed strings. The absence of expected
  keywords in a page that visibly displays them is itself the signal
- an archive that unpacks differently under two extractors, or whose central directory disagrees
  with its local headers
- content served from a comment, upload, or user-content endpoint of a CMS rather than from its
  asset path

Literals from this incident, which confirm a replay but will not find a new one:
- `wOF2` inside a `.js` file, a Z85 alphabet string, `GootLoader`

## Sources
- https://www.huntress.com/blog/gootloader-threat-detection-woff2-obfuscation
- https://thehackernews.com/2025/11/gootloader-is-back-using-new-font-trick.html
