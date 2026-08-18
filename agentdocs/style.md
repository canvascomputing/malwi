# Style

Naming and comment rules, plus README structure. Skim the section matching what is being written.

## Module placement

**A type lives next to the abstraction, owner, or protocol it belongs to.**

- CLI argument parsing, the `--models` table, and help text live in `cli.rs`.
- The directory walker, the catalogues, and the grep passes live in `discovery.rs`.
- The JSON assembler, the event renderer, and the terminal summary live in `report.rs`.
- Role prompts live in `roles/`, indicator catalogues in `threats/`, incident pages in `attacks/`.
- A helper called from a single private function is inlined; a helper called from two siblings earns a free function in the same file.

## Name disambiguation

**Names are disambiguated through content, not through redundant prefixes.**

- Specific compound names stand alone: `ScanTree`, `Hit`, `CompiledCatalogue`.
- Acronyms follow Rust API guidelines: `IocEntry`, not `IOCEntry`.
- Two structs may not share a bare name within one module; both stay qualified.
- The binary is `malwi`; never `malwi-cli`, never `malwi_scanner`.

## Failure variants

**Failure variants use passive-voice past-participle: `<Subject><Verb-ed>`.**

- Accepted: `DirectoryUnreadable`, `ExtensionUnsupported`, `DeadlineReached`, `OperatorCancelled`.
- Rejected: adjective-first forms such as `InvalidX`, `UnexpectedX`, or `MissingX`.
- Rejected: noun-suffix forms such as `XError`; the `Error` suffix is reserved for the top-level `Error` and its domain sub-enums.
- State-transition events use the same form: `ScanStarted`, `ExtensionDispatched`, `FindingsReported`.
- Whether a failure is terminal is documented on the variant, not encoded in the name.

## Variant shape

**Tuple for one payload. Struct for multiple fields or a meaningful field name.**

- Tuple form: `DirectoryUnreadable(io::Error)`, `ExtensionUnsupported(String)`.
- Struct form: `CliError::ConflictingFlags { left, right }`.
- Struct form is also used when a single field name carries meaning the type alone does not.
- Two-arm result enums use one word per variant: `Success` / `Error`, with no `is_*` predicates.

## Payload fields

**One vocabulary is used across every error and report type.**

- Human-readable strings MUST be named `message: String`, never `error`.
- Wrapped underlying errors MUST be named `source`, as in `WriteFailed { source: io::Error }`.
- Typed metadata uses descriptive names: `path`, `line`, `column`, `category`, `status`.

## Time-typed fields

**Public API fields MUST use `std::time::Duration`. The type is the unit.**

- No `_ms`, `_MS`, or `_seconds` suffix on public API names.
- Internal helpers and on-the-wire JSON may use raw integers where the protocol requires it.
- The `--max-time` CLI flag accepts `30`, `30s`, `5m`, or `1h`; the parser converts to `Duration`.

## Path identifiers

**A directory path uses `_dir`. A file path uses `_file`. The bare suffix `_path` is used only when the value can be either.**

- Directories: `scan_dir`, `workspace_dir`, `output_dir`. Matches `std::fs::read_dir`, `std::env::current_dir`.
- Files: `analysis_file`, `tickets_file`. The value is always a concrete file on disk.
- `_path` is for genuinely ambiguous cases: input that could name either, or a value passed through as opaque.
- IMPORTANT: `folder` is never used; it has no std analog.

## Counter identifiers

**Counters use a bare plural noun. No `_count` suffix on fields or on methods that return a count.**

- Report and struct fields: `findings`, `files`, `extensions`, `patterns`, `substrings`.
- Event payloads follow suit: `usage` carries token counts, not a `token_count`.
- Accessor methods mirror the field form: `RunStats::input_tokens` carries the count under that name.
- The `_count` suffix is reserved for the rare case where the plural would clash with a sibling collection field on the same type, as `RunStats::label_count()` does beside the `labels` map.

## Builders

**Builder methods are bare nouns. No `with_` prefix.**

- Examples: `.dir()`, `.label()`, `.knowledge()`, `.template()`.
- The `with_` prefix is used only when a bare name clashes with a trait method.

## Constructors

**`new()` for the primary path. Named constructors carry semantics.**

- `new()` is the primary constructor.
- Named constructors: `open()`, `from_env()`, `from_args()`, `empty()`.

## Doc comments (`///`)

**State the purpose in one sentence. No "This function…" or "Returns…".**

- Noun phrase for types and fields; verb for functions.
- Additional paragraphs are added only for a constraint, invariant, or non-obvious semantic.
- Trivial getters, `Default::default`, `From` impls, and self-explanatory variants are left undocumented.
- Within one type, coverage is all-or-none: every member has a real doc comment, or none does.

## Module docs (`//!`)

**Every file begins with a `//!` that states what the file contributes to the binary.**

- One sentence; two only when the second adds context the first cannot carry.
- State the problem the file solves, not the types it defines.
- Do not list the contents of the file.
- The `//!` stays even when the filename is already descriptive.

## Line comments (`//`)

**Four reasons are allowed. Everything else is deleted.**

Allowed:

- Order-dependency or crash-safety, such as `Register analysts BEFORE discovery so tickets drain live.`
- API quirk or workaround, such as `template_variable binds per agent, not per ticket.`
- Non-obvious constraint, such as `Clear knowledge so each scan starts fresh.`
- Plain section label in a long function, on its own line above the block it introduces.

Not allowed:

- Restating what the code does on the same line.
- Task, PR, issue, or changelog references.
- Commented-out code.
- Stub or aspirational markers; use `unimplemented!(...)` or return `Ok(())`.
- IMPORTANT: no `TODO`, `FIXME`, or `NOTE`. Fix it or file an issue.
- Decorative banners of any kind: `// ── Title`, `// ==== Title ====`, `// ----- Title -----`.

## Tests

**Test names carry intent. Setup is not narrated.**

- A comment is justified only to pin an architectural invariant the test guards.
- A module-level `//!` describing the test file's scope is acceptable.

## Threats, roles, and attack pages

**Files under `threats/`, `roles/`, and `attacks/` are model input, not docs. They follow prompting conventions, not Rust conventions.**

- Each `threats/<lang>.json` entry carries the prose an analyst reads verbatim in its `reason`.
- Each `roles/*.md` follows the role / strengths / guidelines / output split of the [prompting guide](https://github.com/canvascomputing/prompting).
- `{placeholder}` markers are bound through `Agent::template(...)`; never inline a Rust format string.
- Adding an indicator or an incident page does not require a Rust code change, apart from listing a new page in `PAGES`.

## README structure

**Terse, example-driven, scannable.**

- Fixed section order: Installation, Quick Start, Usage, Output, Development.
- Every subsection leads with a minimal example, then explains.
- Enumerations use bullets or grouped bullets; tables are used only for flag reference and event reference.
- Facts live in one place; other sections cross-link rather than repeat.

## README voice

**Direct and neutral. No marketing language.**

- "Scans a directory for indicators of compromise", not "empowers security teams".
- Examples stay minimal; show the smallest snippet that demonstrates the feature.
- Example models are `claude-haiku-4-5-20251001` or `claude-sonnet-4-20250514`.
- Update triggers: a new CLI flag, a new role, a new event kind, a new environment variable, or a changed default.

## README cell length

**One sentence per cell. No semicolons stapling two facts together.**

- Hard cap: roughly fifteen words per cell.
- A second short sentence is allowed only when it carries information the first cannot.
- A description that needs more than two sentences moves to prose under the table.
- Em dashes are not used; colons or two sentences replace them.

## README descriptions

**In README table cells, bullet descriptions, and inline `//` comments, describe what the operator gets, not how it works inside.**

- The reader may be new to the agentic concept: write for them.
- The README is an abstraction: internal type names, private field names, and enum variant names do not belong there. The reference lives in the API docs.
- Accepted: "Cap the scan duration.", "A ticket finished successfully."
- Rejected: "(carries typed `PolicyKind`)", "drives the loop", "one-shot".
- Jargon and internal terms are cut even when they are shorter.
