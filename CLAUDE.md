# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

malwi is an AI-powered Python malware scanner that detects zero-day vulnerabilities without requiring internet access. It uses a 3-step pipeline:

1. **AST Compilation**: Python/JavaScript files → language-independent bytecode via AST parsing
2. **Token Mapping**: Bytecode → tokens via custom mappings  
3. **DistilBERT Analysis**: Tokens → maliciousness scores and final classification

## Key Commands

**Development Setup:**
```bash
# Uses uv package manager
uv sync
```

**Testing:**
```bash
uv run pytest tests
```

**Linting:**
```bash
uv run ruff check .
uv run ruff format .
```

**Download Training Data:**
```bash
# Download all required data (malwi-samples + benign/malicious repos)
./cmds/download_data.sh
```

**Training Models:**
```bash
# Full DistilBERT training pipeline (with parallel preprocessing)
./cmds/preprocess_and_train_distilbert.sh

# Data preprocessing only (parallel by default)
./cmds/preprocess_data.sh
```

**Performance Tuning:**
```bash
# Configure parallel preprocessing (default: all CPU cores)
NUM_PROCESSES=8 ./cmds/preprocess_data.sh

# Disable parallel processing for debugging
uv run python -m src.research.preprocess '.repo_cache/benign_repos' benign.csv --no-parallel

# Custom chunk size for large datasets
uv run python -m src.research.preprocess '../malwi-samples' output.csv --chunk-size 50
```

**Regenerate Test Data:**
```bash
# When compiler changes affect output format
uv run python util/regenerate_test_data.py
```

**Repository Pinning:**
```bash
# Update pinned repository commits for reproducible training
uv run python util/pin_repositories.py

# Update model commit hash for releases
python util/update_model_commit.py

# Download data with latest commits (non-reproducible)
uv run python -m src.research.download_data --use-latest
```

**Usage:**
```bash
# Scan local files/directories
uv run python -m src.cli.entry scan examples/malicious

# Scan PyPI packages
uv run python -m src.cli.entry pypi requests
uv run python -m src.cli.entry pypi numpy 1.24.0 --format json --folder downloads

# Different output formats
uv run python -m src.cli.entry scan examples --format yaml
uv run python -m src.cli.entry pypi django --format markdown --save output.md

# Interactive triage (manually review findings)
uv run python -m src.cli.entry scan examples --triage

# AI-powered triage (automatic false positive detection)
export MISTRAL_API_KEY="your-mistral-api-key"
uv run python -m src.cli.entry scan examples --triage-mcp

# Alternative: Gemini AI triage
export GEMINI_API_KEY="your-gemini-api-key" 
uv run python -m src.cli.entry scan examples --triage-mcp
```

## Building Package

**For end-user distribution (excludes training files):**
```bash
# Backup training files and build clean package
python util/build_helpers.py backup
python -m build --wheel
python util/build_helpers.py restore

# The wheel will only contain files needed for scanning:
# - malwi_object.py, predict_distilbert.py, ast_to_malwicode.py
# - mapping.py, pypi.py, syntax_mapping/
# Training files are excluded: train_*.py, preprocess.py, etc.
```

## Research Workflow

**For AI model training research and performance tracking:**

### Tagging Research Commits
When you complete a training run and have performance metrics:

1. **Tag Format**: `{commit_hash}_f1/{score}` where score is the F1 performance metric
2. **Tag Command**: `git tag {commit_hash}_f1/{score}`
3. **Example**: `git tag 2b4abcab_f1/0.958`

### Recording Research Progress
Use this workflow to document research progress:

**Prompt Template for Claude:**
```
Research commit: [commit_hash]
F1 Score: [score] 
Change: [brief description of what was changed]
Reasoning: [why the performance improved/decreased]

Please tag this commit and update RESEARCH.md with the chronological entry.
```

**Example:**
```
Research commit: abc123de
F1 Score: 0.962
Change: Optimized string tokenization with caching
Reasoning: Reduced noise in token mapping improved model accuracy by 0.4 points

Please tag this commit and update RESEARCH.md with the chronological entry.
```

**Claude will:**
1. Create the git tag with format `{commit}_f1/{score}`
2. Update `RESEARCH.md` with chronological entry
3. Add analysis of performance trend vs previous experiments
4. Suggest next research directions based on patterns

### Research Documentation
- **RESEARCH.md**: Chronological tracking of all model training experiments
- **Performance metrics**: F1 scores, precision, recall tracked over time
- **Failed experiments**: Documented to prevent repeating unsuccessful approaches
- **Key insights**: Analysis of what works and what doesn't

## Release

1. Run pytests
2. Create a version bump, adapt the minor version in:
   - `src/malwi/_version.py` (central version file)
   - Run `uv sync` to update uv.lock
3. **Update model commit hash**: `python util/update_model_commit.py` to get latest HuggingFace model commit and update `src/malwi/_version.py`
4. Build clean package: `python util/build_helpers.py backup && python -m build --wheel && python util/build_helpers.py restore`
5. Create a git commit with: version bump and model commit update
6. Run: `git tag v<version>` (e.g., `git tag v0.0.15`)

**Note**: Version and model commit hash are now centralized in `src/malwi/_version.py`. All other files automatically read from this central location.

## Model Version Pinning

Each malwi release is pinned to a specific HuggingFace model commit hash to ensure reproducibility:

**Get current model commit hash:**
```bash
python util/get_hf_model_info.py 0.0.21
```

**Update model configuration:**
```bash
# Edit src/research/predict_distilbert.py and add the commit hash to VERSION_TO_MODEL_CONFIG
# Example: "0.0.21": {"repo": "schirrmacher/malwi", "revision": "21f808cda19f6a465bbdd568960f6b0291321cdf"}
```

This ensures that:
- Older malwi versions always use compatible models
- Model updates don't break existing installations
- Reproducible results across different environments

## Architecture Notes

- **Entry Point**: `src/cli/entry.py` - Main CLI interface and subcommand routing
- **Scan Command**: `src/cli/scan.py` - Local file/directory scanning functionality
- **PyPI Command**: `src/cli/pypi.py` - PyPI package downloading and scanning
- **Core Pipeline**: `src/common/malwi_object.py` → `src/common/bytecode.py` → `src/common/predict_distilbert.py`
- **Data Preprocessing**: `src/research/preprocess.py` - Parallel processing for fast AST compilation
- **AST Compilation**: `src/common/bytecode.py` - Language-independent bytecode generation (renamed from ast_to_malwicode.py)
- **File Operations**: `src/common/files.py` - File copying and utility functions
- **Mapping System**: JSON configs in `src/common/syntax_mapping/` define bytecode-to-token mappings
- **Models**: Pre-trained DistilBERT model stored in `malwi-models/`
- **Training Data**: Requires `malwi-samples` repository cloned in parent directory

## Triage Functionality

malwi provides two triage modes to help reduce false positives and validate malicious findings:

### Interactive Triage (`--triage`)
- **Purpose**: Manually review each malicious finding before reporting
- **Workflow**: Prompts user for each finding with options:
  - `Suspicious (keep as malicious)` - Preserves the finding in the report
  - `Benign (false positive)` - Automatically comments out the code in source files
  - `Skip (unsure)` - Leaves finding in report without modification
  - `Quit (stop triaging)` - Stops triage process and generates report
- **Use case**: When you want human oversight of AI classification decisions

### AI-Powered Triage (`--triage-mcp`)
- **Purpose**: Automatic false positive detection using AI analysis
- **Providers**: Supports both Mistral and Gemini AI services
- **Workflow**: 
  1. AI analyzes each malicious finding with context (file path, code, maliciousness score)
  2. AI classifies findings as suspicious, benign, or unsure
  3. Benign findings are automatically commented out in source files
  4. Suspicious findings are preserved in the final report
- **Configuration**: Requires API key environment variable

### Environment Variables

**Mistral AI (prioritized if both are set):**
```bash
export MISTRAL_API_KEY="your-mistral-api-key"
```

**Gemini AI:**
```bash  
export GEMINI_API_KEY="your-gemini-api-key"
```

### File Modification Behavior

When triage identifies benign findings, malwi automatically comments out the **specific code lines** from the `source_code` attribute of benign objects:

**Before triage:**
```python
import subprocess
def legitimate_func():
    return "hello"
os.system('rm -rf /')  # Flagged as malicious but is benign
```

**After benign classification:**
```python
import subprocess
def legitimate_func():
    return "hello"
# os.system('rm -rf /')  # Commented out (flagged but benign)
```

This targeted approach neutralizes only the specific code sections that were incorrectly flagged as malicious, preserving legitimate functionality while eliminating false positive threats.

## CLI Subcommand Structure

The CLI follows a modular subcommand architecture with clear separation of concerns:

### Creating New Subcommands

To add a new subcommand (e.g., `git`):

1. **Create subcommand file**: `src/cli/git.py`
2. **Implement command function**: `git_command(args)`
3. **Create parser setup function**: `setup_git_parser(subparsers)`
4. **Register in entry.py**: Import and call `setup_git_parser(subparsers)`

### Example Subcommand Structure

```python
# src/cli/new_command.py
from common.messaging import configure_messaging, info

def new_command(args):
    """Execute the new subcommand."""
    configure_messaging(quiet=args.quiet)
    info("Processing new command...")
    # Command implementation here

def setup_new_parser(subparsers):
    """Set up the new subcommand parser."""
    parser = subparsers.add_parser("new", help="Description of new command")
    parser.add_argument("--option", help="Command option")
    parser.set_defaults(func=new_command)
```

```python
# src/cli/entry.py - Add import and setup call
from cli.new_command import setup_new_parser

def main():
    # ... existing code ...
    setup_new_parser(subparsers)
    # ... rest of main function ...
```

### Current Subcommands

- **scan**: Local file/directory scanning (`src/cli/scan.py`)
- **pypi**: PyPI package scanning (`src/cli/pypi.py`)

## Performance

- **Parallel Preprocessing**: ~6-8x faster with multi-core processing (40 min → 5-7 min on 8 cores)
- **Chunk-based Processing**: Each CPU core processes independent file chunks and writes to separate CSV files
- **Automatic Merging**: Chunk CSVs are merged into final output to avoid I/O bottlenecks

## Reproducible Training

malwi uses pinned repository commits to ensure reproducible training data:

- **Pinned Repositories**: All 533 training repositories are pinned to specific commit hashes in `util/pinned_repositories.json`
- **Automatic Verification**: Training data downloads use pinned commits by default  
- **Cache Optimization**: Repository caches include commit hashes in directory names (e.g., `pymatting_a60fdb63`)
- **Fallback Support**: Missing repositories fall back to latest commits with warnings

**Benefits:**
- Identical training data across different machines and time periods
- Reproducible model training results
- Version control for training data dependencies
- Easy rollback to previous training data states

## Important Considerations

- **Language Support**: Supports both Python and JavaScript files through language-independent AST compilation
- **Output Formats**: Supports demo, markdown, json, yaml formats via `--format` flag
- **Performance**: F1=0.96, Recall=0.95, Precision≥0.95 for DistilBERT model