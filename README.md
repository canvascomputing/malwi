# malwi - AI Python Malware Scanner

<img src="malwi-logo.png" alt="Logo">
<a href='https://huggingface.co/schirrmacher/malwi'><img src='https://img.shields.io/badge/%F0%9F%A4%97%20HF-Model-blue'></a>&ensp; 

## **malwi** detects Python malware using AI.

It specializes in finding **zero-day vulnerabilities** and can classify code as malicious or benign without requiring internet access.

### Key Features
- 🇪🇺 Open-source project built on open research and data
- 🔒 Runs completely offline - no data leaves your machine
- ⚡ Fast scanning of entire codebases

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

## Limitations

The malicious dataset includes some boilerplate functions, such as setup functions, which can also appear in benign code. These cause false positives during scans. The goal is to triage and reduce such false positives to improve malwi's accuracy.

## What's next?

The first iteration focuses on **maliciousness of Python source code**.

Future iterations will cover malware scanning for more languages (JavaScript, Rust, Go) and more formats (binaries, logs).

## Contributing & Support

- Found a bug or have a feature request? [Open an issue](https://github.com/schirrmacher/malwi/issues).
- Do you have access to malicious packages in Rust, Go, or other languages? [Contact via GitHub profile](https://github.com/schirrmacher).
- Struggling with false-positive findings? [Create a Pull-Request](https://github.com/schirrmacher/malwi-samples/pulls).

## Development

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
./research --steps download preprocess train
```

### Research CLI

The research CLI (`./research`) provides a streamlined interface for the entire training pipeline:

#### Complete Pipeline
```bash
# Full pipeline: Download data → Preprocess → Train models
./research --steps download preprocess train --language python

# Default pipeline (preprocess + train, assumes data exists)
./research --language python
```

#### Individual Pipeline Steps
```bash
# 1. Download training data (clones malwi-samples + downloads repositories)
./research --steps download

# 2. Data preprocessing only (parallel processing, ~4 min on 32 cores)
./research --steps preprocess --language python

# 3. Model training only (tokenizer + DistilBERT, ~40 minutes on NVIDIA RTX 4090)
./research --steps train
```
