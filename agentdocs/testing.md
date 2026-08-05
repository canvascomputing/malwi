# Testing

How tests are organized and written. Commands used to run them live in [workflow.md](workflow.md).

## Layers

**One layer: inline tests that run without a network.**

- Inline `#[cfg(test)] mod tests` lives next to the code it covers.
- A test needing a model implements `Provider` inline, as `FinishMock` in `main.rs` does.
- Fixtures (sample trees to scan) live under `crates/malwi/tests/fixtures/`.

## Purpose

**One test, one observable behavior.**

- A test exists because a single contract would otherwise go undemonstrated.
- A failure points to one cause: no grab-bag assertions across unrelated concerns.
- A sibling that already covers the same behavior with different inputs is merged or removed.
- Behaviour is tested at the layer where it lives: unit, integration, or inline.

## Naming

**The name states the behavior, not the method called.**

- Accepted: `cluster_hits_splits_distant_lines`, `reporter_verdict_is_claimed_by_label_and_merged`.
- Rejected: `test_scan`, `test_report`, `test_extension`.
- The body verifies what the name claims, with no surprise assertions.
- The name is the first line of the documentation the test provides.

## API focus

**Tests exercise the public CLI and library surface the way operators hold it.**

- Drive `Scanner::discover`, `build_analysis`, and `ModelTable::resolve_for` through their own entry points.
- Mock at trust boundaries (the LLM provider), never at the subject under test.
- Assert observable outcomes (report JSON, exit code, stderr summary), not call logs or internal ordering.
- The arrange/act/assert shape mirrors how a real operator would invoke the binary.

## State transitions

**Ticket and report state MUST be visible through the public API.**

- Build starting state by calling real actions, not by field assignment that bypasses invariants.
- Read resulting state back through a public query, not by peeking at private fields.
- Assert both starting and final state so the transition is shown, not implied.
- Cover illegal transitions and verify state is unchanged after a rejection.
- One transition per test so a failure locates the exact broken action.

## Clarity

**Setup is hidden. Intent is highlighted.**

- Push scaffolding into factories, builders, and fixtures so the body reads as a short story.
- Name literals that carry meaning: `SUSPECT_PYTHON_FILE`, not `"a.py"`; `EXPIRED_TIMEOUT`, not `0`.
- Keep the act step a single visible line; do not bury it in setup.
- Comments are justified only to pin an architectural invariant the test guards.

## Coverage shape

**Every public operation has a test that demonstrates intended usage.**

- Error cases, edge conditions, and boundaries sit at the same interface level as the happy path.
- Overlapping cases that exercise the same branch with trivial input changes are merged.
- A missing behavior is added before a duplicate case is kept for symmetry.
- IMPORTANT: a public method with no test is a documentation gap, not just a coverage gap.
