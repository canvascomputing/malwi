# Research OSINT chain

`malwi research` audits the attack corpus for techniques it cannot recognize and fills each gap
from public sources. This note records the topology and the three decisions that shaped it.

## Why the command exists

The scanner's judgement is bounded by `crates/malwi/src/attacks/`: one page per real
supply-chain incident, seeded into the Seeker's and Tracer's stores every run. The corpus goes
stale the moment a new campaign lands, and growing it meant a human writing a page and editing a
hand-maintained `PAGES` array. `research` makes the scanner extend its own knowledge, and
`build.rs` makes a new page cost no Rust edit at all.

## Topology

Four roles, split the way a research task actually splits: audit, gather, write, check.

| Pool | Label | Tools | Hands over to |
|---|---|---|---|
| Curator | `curation` | `brave_search`, `manage_knowledge` | the driver |
| Scout | `scouting` | `brave_search`, `fetch_url`, `manage_knowledge` | `editing` |
| Editor | `editing` | `fetch_url`, `manage_knowledge` | `verification` |
| Verifier | `verification` | `fetch_url`, `manage_knowledge` | nothing |

## The Curator runs on its own queue

The whole chain is shaped by one result: until the gap list lands there is nothing for any pool
to claim. `create_ticket_on_result` returns a single ticket, so a hook could not fan one audit
out into N scouting tickets. A separate queue, drained before the pools are built, keeps the
fan-out an ordinary driver step that a test can drive without a model.

The audit queue takes the same `--max-turns` and `--max-time` the research queue does. An
uncapped Curator searches until it is satisfied and leaves nothing of the budget for the pools it
feeds.

## Verification gates installation

The Verifier exists because an unverified page is worse than a missing one: it is what every
future scan believes. It fetches a cited source before any verdict, and its `accepted` is the
only thing that moves a page out of the run store.

Agents never write into the source tree. The Editor drafts into the run's `Knowledge` store,
`research.rs` copies accepted slugs out, and `attacks::install` rewrites the front matter so
`type: AttackPattern` is the command's guarantee rather than the model's. A slug the binary
already ships is refused outright: a run may add pages, never rewrite one.

## The signal generalizes or the page is worthless

A page is read by a Seeker that turns it into greps against code it has never seen. A signal
written as this incident's filenames and hosts matches a replay of that incident and nothing else,
which for a corpus meant to catch the *next* attack is the same as matching nothing.

Every `## Detectable signal` therefore states the shape first and the literals second, and the
shape is written to survive losing every proper noun: "an install hook that selects a payload by
`process.platform`, then executes it" holds for the next package, while "a `postinstall` fetching
`evil.com/x.exe`" holds for exactly one. The Verifier is told to strike the proper nouns out of the
shape bullets and reject the page if nothing matchable is left.

`attacks.rs` carries three tests over the generated `PAGES` table: OKF frontmatter plus the five
sections, a signal that leads with the shape, and at least one cited URL. They apply to every page
regardless of who wrote it, which is what keeps the twelve hand-written pages and the researched
ones readable to the same agent.

## Tags ride on the verdict

OKF supports `tags` and the seeded pages use them, but `manage_knowledge` has no tags field, so
the Editor cannot set them when it saves a draft. Without somewhere to put them, every researched
page would permanently lack a key the hand-written ones carry. They ride on the Verifier's verdict
instead: by the time it answers it has read both the page and the index, which is what it takes to
pick a tag the corpus already uses rather than a synonym that splits it in two.

## The page body carries its sources

The seeded pages carry no citations, because a human wrote them. A researched page carries a
`## Sources` section, and the Editor is told not to hand-write front matter at all. Both fell out
of the first live run: the Verifier rejected a well-researched page for having nothing fetchable
in it, and the same draft reached the store with two front-matter blocks because the model
copied the format template literally. The template is now the body only, and the command owns
the front matter.

## The Curator is told the shape of the supply chain

The seeded corpus is npm-heavy, because npm incidents are the best reported. Left to itself the
audit read those pages and then searched npm, so an early run named five gaps that were five npm
campaigns: the corpus's own skew fed straight back into it. `curator.md` now names the routes
code takes into a build — registries beyond npm, CI/CD, container layers, editor and browser
extensions, model artifacts, toolchains, mirrors and signing infrastructure — and asks for the
per-ecosystem count before any search. The technique-not-headline rule stands beside it: an
uncovered ecosystem is worth a gap because its mechanisms differ, not because it is uncovered.

## The audit is anchored to today

The same run searched for campaigns from 2024 and 2025, several of which are already pages. The
cause is structural rather than a bad prompt: a model's recall of supply-chain incidents ends at
its training cutoff, and the corpus was written from that same period, so unprompted recall
returns what the pages already carry. `curator.md` takes `{date}` — one of agentwerk's built-in
role placeholders, expanded per request beside `{context}` — and asks the audit to read the newest
incident date off the index and search the window between that and today, naming the year in the
query. The date bounds the search window, not the definition of a gap: an old technique no page
describes is still a blind spot, so the rule is written to scope queries rather than reject ages.
