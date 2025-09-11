# malwi - AI Python Malware Scanner

<img src="malwi-logo.png" alt="Logo">
<a href='https://huggingface.co/schirrmacher/malwi'><img src='https://img.shields.io/badge/%F0%9F%A4%97%20HF-Model-blue'></a>&ensp; 

## malwi specializes in finding malware

### Key Features

- 🛡️ **AI-Powered Python Malware Detection**: Leverages advanced AI to identify malicious code in Python projects with high accuracy.

- ⚡ **Lightning-Fast Codebase Scanning**: Scans entire repositories in seconds, so you can focus on development—not security worries.

- 🔒 **100% Offline & Private**: Your code never leaves your machine. Full control, zero data exposure.

- 💰 **Free & Open-Source**: No hidden costs. Built on transparent research and openly available data.

- 🇪🇺 **Developed in the EU**: Committed to open-source principles and European data standards.

- 🦀 **Experimental Rust Crate Scanning**: Download and analyze crates from crates.io using `malwi cargo <crate>`.

### 1) Install
```
pip install --user malwi
```

### 2) Run
```bash
malwi scan examples/malicious
```

### 3) Evaluate: a [recent zero-day](https://socket.dev/blog/malicious-pypi-package-targets-discord-developers-with-RAT) detected with high confidence
```
                  __          __
  .--------.---.-|  .--.--.--|__|
  |        |  _  |  |  |  |  |  |
  |__|__|__|___._|__|________|__|
     AI Python Malware Scanner


- target: examples
- seconds: 1.87
- files: 14
  ├── scanned: 4 (.py)
  ├── skipped: 10 (.cfg, .md, .toml, .txt)
  └── suspicious:
      ├── examples/malicious/discordpydebug-0.0.4/setup.py
      │   └── <module>
      │       ├── archive compression
      │       └── package installation execution
      └── examples/malicious/discordpydebug-0.0.4/src/discordpydebug/__init__.py
          ├── <module>
          │   ├── process management
          │   ├── deserialization
          │   ├── system interaction
          │   └── user io
          ├── run
          │   └── fs linking
          ├── debug
          │   ├── fs linking
          │   └── archive compression
          └── runcommand
              └── process management

=> 👹 malicious 0.98
```

## Commands and Options

### Scan Command
```bash
malwi scan <path> [options]
```

**Common Options:**
- `--format {demo,markdown,json,yaml,tokens,code}` - Output format (default: demo)
  - `demo` - Human-readable terminal output with emojis and tree structure
  - `markdown` - Structured markdown report for documentation
  - `json` - Machine-readable JSON for integration with other tools
  - `yaml` - YAML format for configuration management
  - `tokens` - Raw token analysis with embedding counts
  - `code` - Extracted code snippets from suspicious objects
- `--save FILE` - Save output to file
- `--threshold FLOAT` - Maliciousness threshold (default: 0.7)
- `--extensions EXT [EXT ...]` - File extensions to scan (default: .py, .js)
- `--quiet` - Suppress progress output
- `--batch` - Process child directories independently

**Triage Options:**
- `--triage` - Interactive review of findings with manual classification
- `--triage-mcp` - AI-powered automatic false positive detection

**File Management:**
- `--move [DIR]` - Copy suspicious files to directory (default: findings)

### Examples
```bash
# Basic scan
malwi scan examples/malicious

# Interactive triage
malwi scan examples --triage

# AI-powered triage (requires API key)
export MISTRAL_API_KEY="your-api-key"
malwi scan examples --triage-mcp

# Custom output
malwi scan examples --format json --save report.json --threshold 0.8

# Batch processing
malwi scan parent_directory --batch --format yaml
```

**Environment Variables:**
- `OPENAI_API_KEY` - For OpenAI-based triage
- `MISTRAL_API_KEY` - For Mistral AI triage
- `GEMINI_API_KEY` - For Gemini AI triage

## PyPI Package Scanning

malwi can directly scan PyPI packages without executing malicious logic, typically placed in `setup.py` or `__init__.py` files:

```bash
malwi pypi requests
````

```
                  __          __
  .--------.---.-|  .--.--.--|__|
  |        |  _  |  |  |  |  |  |
  |__|__|__|___._|__|________|__|
     AI Python Malware Scanner


- target: downloads/requests-2.32.4.tar
- seconds: 3.10
- files: 84
  ├── scanned: 34
  └── skipped: 50

=> 🟢 good
```

## Rust Crate Scanning

malwi can download and scan Rust crates from [crates.io](https://crates.io) without building or executing their code:

```bash
malwi cargo serde
# scan a specific version
malwi cargo tokio 1.38.0
```

### Requirements

- `tree-sitter-rust` grammar library must be installed (included with the Python package)

### Environment Variables

No additional variables are needed for basic scanning. For AI-assisted triage, set one of:

- `OPENAI_API_KEY`
- `MISTRAL_API_KEY`
- `GEMINI_API_KEY`

### Limitations

Rust analysis is **experimental**. Macro expansion, build scripts, and complex token trees may not be fully supported, which can lead to false positives or missed findings.

## Why malwi?

Malicious actors are increasingly [targeting open-source projects](https://arxiv.org/pdf/2404.04991), introducing packages designed to compromise security.

Common malicious behaviors include:

- **Data exfiltration**: Theft of sensitive information such as credentials, API keys, or user data.
- **Backdoors**: Unauthorized remote access to systems, enabling attackers to exploit vulnerabilities.
- **Destructive actions**: Deliberate sabotage, including file deletion, database corruption, or application disruption.

## How does it work?

malwi is based on the design of [_Zero Day Malware Detection with Alpha: Fast DBI with Transformer Models for Real World Application_ (2025)](https://arxiv.org/pdf/2504.14886v1).

Imagine there is a function like:

```python
def runcommand(value):
    output = subprocess.run(value, shell=True, capture_output=True)
    return [output.stdout, output.stderr]
```

### 1. Files are compiled to create an Abstract Syntax Tree with [Tree-sitter](https://tree-sitter.github.io/tree-sitter/index.html)

```
module [0, 0] - [3, 0]
  function_definition [0, 0] - [2, 41]
    name: identifier [0, 4] - [0, 14]
    parameters: parameters [0, 14] - [0, 21]
      identifier [0, 15] - [0, 20]
...
```

### 2. The AST is transpiled to dummy bytecode

The bytecode is enhanced with security related instructions.

```
TARGETED_FILE PUSH_NULL LOAD_GLOBAL PROCESS_MANAGEMENT LOAD_ATTR run LOAD_PARAM value LOAD_CONST BOOLEAN LOAD_CONST BOOLEAN KW_NAMES shell capture_output CALL STRING_VERSION STORE_GLOBAL output LOAD_GLOBAL output LOAD_ATTR stdout LOAD_GLOBAL output LOAD_ATTR stderr BUILD_LIST STRING_VERSION RETURN_VALUE
```

### 3. The bytecode is fed into a pre-trained [DistilBERT](https://huggingface.co/docs/transformers/model_doc/distilbert)

A DistilBERT model trained on [malware-samples](https://github.com/schirrmacher/malwi-samples) is used to identify suspicious code patterns.

```
=> Maliciousness: 0.98
```

## Python API

malwi provides a comprehensive Python API for integrating malware detection into your applications.

### Quick Start

```python
import malwi

report = malwi.MalwiReport.create(input_path="suspicious_file.py")

for obj in report.malicious_objects:
    print(f"File: {obj.file_path}")
```

### `MalwiReport`

```python
MalwiReport.create(
    input_path,               # str or Path - file/directory to scan
    accepted_extensions=None, # List[str] - file extensions to scan (e.g., ['py', 'js'])
    silent=False,             # bool - suppress progress messages
    malicious_threshold=0.7,  # float - threshold for malicious classification (0.0-1.0)
    on_finding=None           # callable - callback when malicious objects found
) -> MalwiReport              # Returns: MalwiReport instance with scan results
```

```python
import malwi

report = malwi.MalwiReport.create("suspicious_directory/")

# Properties
report.malicious              # bool: True if malicious objects detected
report.confidence             # float: Overall confidence score (0.0-1.0)
report.duration               # float: Scan duration in seconds
report.all_objects            # List[MalwiObject]: All analyzed code objects
report.malicious_objects      # List[MalwiObject]: Objects exceeding threshold
report.threshold              # float: Maliciousness threshold used (0.0-1.0)
report.all_files              # List[Path]: All files found in input path
report.skipped_files          # List[Path]: Files skipped (wrong extension)
report.processed_files        # int: Number of files successfully processed
report.activities             # List[str]: Suspicious activities detected
report.input_path             # str: Original input path scanned
report.start_time             # str: ISO 8601 timestamp when scan started
report.all_file_types         # List[str]: All file extensions found
report.version                # str: Malwi version with model hash

# Methods
report.to_demo_text()         # str: Human-readable tree summary
report.to_json()              # str: JSON formatted report
report.to_yaml()              # str: YAML formatted report
report.to_markdown()          # str: Markdown formatted report

# Pre-load models to avoid delay on first prediction
malwi.MalwiReport.load_models_into_memory()
```

### `MalwiObject`
```python
obj = report.all_objects[0]

# Core properties
obj.name                # str: Function/class/module name
obj.file_path           # str: Path to source file
obj.language            # str: Programming language ('python'/'javascript')
obj.maliciousness       # float|None: ML confidence score (0.0-1.0)
obj.warnings            # List[str]: Compilation warnings/errors

# Source code and AST compilation
obj.file_source_code    # str: Complete content of source file
obj.source_code         # str|None: Extracted source for this specific object
obj.byte_code           # List[Instruction]|None: Compiled AST bytecode
obj.location            # Tuple[int,int]|None: Start and end line numbers
obj.embedding_count     # int: Number of DistilBERT tokens (cached)

# Analysis methods
obj.predict()           # dict: Run ML prediction and update maliciousness
obj.to_tokens()         # List[str]: Extract tokens for analysis
obj.to_token_string()   # str: Space-separated token string
obj.to_string()         # str: Bytecode as readable string
obj.to_hash()           # str: SHA256 hash of bytecode
obj.to_dict()           # dict: Serializable representation
obj.to_yaml()           # str: YAML formatted output
obj.to_json()           # str: JSON formatted output

# Class methods
MalwiObject.all_tokens(language="python")  # List[str]: All possible tokens
```

## Benchmarks?

```
training_loss: 0.0110
epochs_completed: 3.0000
original_train_samples: 598540.0000
windowed_train_features: 831865.0000
original_validation_samples: 149636.0000
windowed_validation_features: 204781.0000
benign_samples_used: 734930.0000
malicious_samples_used: 13246.0000
benign_to_malicious_ratio: 60.0000
vocab_size: 30522.0000
max_length: 512.0000
window_stride: 128.0000
batch_size: 16.0000
eval_loss: 0.0107
eval_accuracy: 0.9980
eval_f1: 0.9521
eval_precision: 0.9832
eval_recall: 0.9229
eval_runtime: 115.5982
eval_samples_per_second: 1771.4900
eval_steps_per_second: 110.7200
epoch: 3.0000
```

## Contributing & Support

- Found a bug or have a feature request? [Open an issue](https://github.com/schirrmacher/malwi/issues).
- Do you have access to malicious packages in Rust, Go, or other languages? [Contact via GitHub profile](https://github.com/schirrmacher).
- Struggling with false-positive findings? [Create a Pull-Request](https://github.com/schirrmacher/malwi-samples/pulls).

## Research

### Prerequisites

1. **Package Manager**: Install [uv](https://docs.astral.sh/uv/) for fast Python dependency management
2. **Training Data**: The research CLI will automatically clone [malwi-samples](https://github.com/schirrmacher/malwi-samples) when needed

### Quick Start

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest tests

# Train a model from scratch (full pipeline with automatic data download)
./research download preprocess train
```

#### Individual Pipeline Steps
```bash
# 1. Download training data (clones malwi-samples + downloads repositories)
./research download

# 2. Data preprocessing only (parallel processing, ~4 min on 32 cores)
./research preprocess --language python

# 3. Model training only (tokenizer + DistilBERT, ~40 minutes on NVIDIA RTX 4090)
./research train
```

## Limitations

The malicious dataset includes some boilerplate functions, such as setup functions, which can also appear in benign code. These cause false positives during scans. The goal is to triage and reduce such false positives to improve malwi's accuracy.

## What's next?

The first iteration focuses on **maliciousness of Python source code**.

Future iterations will cover malware scanning for more languages (JavaScript, Rust, Go) and more formats (binaries, logs).

