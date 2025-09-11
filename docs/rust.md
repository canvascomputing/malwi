# Rust Crate Scanning

malwi can inspect Rust crates by downloading them from crates.io and statically
analyzing the extracted `.rs` files. The crate code is never built or executed.

## Usage

```bash
# Scan the latest version of a crate
malwi cargo serde

# Specify a version and output format
malwi cargo tokio 1.38.0 --format json
```

## Dependencies

- [`tree-sitter-rust`](https://github.com/tree-sitter/tree-sitter-rust) – provides the
  parser used to generate Rust ASTs.

## Environment variables

No special variables are required for basic scans. To enable LLM or MCP assisted
triage (`--triage-llm`), set one of:

- `OPENAI_API_KEY`
- `MISTRAL_API_KEY`
- `GEMINI_API_KEY`

## Limitations

Rust support is **experimental**. Macro expansion, build scripts (`build.rs`), and
other complex token trees may not be fully analyzed, which can result in false
positives or missed detections.

