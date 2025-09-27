#!/usr/bin/env python3
"""
Ultimate Research CLI for malwi training pipeline.
Provides a unified interface for downloading data, preprocessing, and training models.
"""

import argparse
import sys
import subprocess
import os
from pathlib import Path
from typing import List, Optional
from enum import Enum

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)

# Import the default constants for function signatures
from research.train_tokenizer import DEFAULT_TOP_N_TOKENS
from research.train_distilbert import DEFAULT_BENIGN_TO_MALICIOUS_RATIO

# We'll import these functions dynamically when needed to avoid import errors


class Step(Enum):
    """Available pipeline steps."""

    DOWNLOAD = "download"
    PREPROCESS = "preprocess"
    TRAIN = "train"


class Language(Enum):
    """Supported programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    BOTH = "both"


def train_tokenizer_api(
    training_csv: str,
    output_path: str = "malwi_models",
    top_n_tokens: int = DEFAULT_TOP_N_TOKENS,
    force_retrain: bool = True,
) -> bool:
    """
    Train tokenizer with unified CSV file.

    Args:
        training_csv: Path to unified training CSV file
        output_path: Output directory for tokenizer
        top_n_tokens: Number of top tokens to use
        force_retrain: Whether to force retrain

    Returns:
        True if successful, False otherwise
    """
    try:
        # Import dynamically to avoid import errors
        from research.train_tokenizer import train_tokenizer
        import pandas as pd

        # Create a mock args object for the function
        class Args:
            def __init__(self):
                self.training = training_csv
                self.output_path = Path(output_path)
                self.top_n_tokens = top_n_tokens
                self.force_retrain = force_retrain
                self.save_computed_tokens = True
                self.function_mapping_path = Path(
                    "src/common/syntax_mapping/function_mapping.json"
                )
                self.vocab_size = 30522
                self.max_length = 512
                self.token_column = "tokens"

        args = Args()
        train_tokenizer(args)
        return True
    except Exception as e:
        error(f"Tokenizer training failed: {e}")
        return False


def train_distilbert_api(
    training_csv: str,
    epochs: int = 3,
    hidden_size: int = 256,
    num_proc: int = 1,
    benign_ratio: float = DEFAULT_BENIGN_TO_MALICIOUS_RATIO,
) -> bool:
    """
    Train DistilBERT model with training data.

    Args:
        training_csv: Path to training CSV file
        epochs: Number of training epochs
        hidden_size: Hidden layer size
        num_proc: Number of processes

    Returns:
        True if successful, False otherwise
    """
    try:
        # Import dynamically to avoid import errors
        from research.train_distilbert import run_training

        # Create a mock args object for the existing function
        class Args:
            def __init__(self):
                self.training = training_csv
                self.epochs = epochs
                self.hidden_size = hidden_size
                self.num_proc = num_proc
                self.benign_ratio = benign_ratio
                self.tokenizer_path = Path("malwi_models")
                self.model_output_path = Path("malwi_models")
                self.model_name = "distilbert-base-uncased"
                self.max_length = 512
                self.window_stride = 128
                self.batch_size = 16
                self.save_steps = 0
                self.benign_ratio = DEFAULT_BENIGN_TO_MALICIOUS_RATIO
                self.token_column = "tokens"
                self.vocab_size = 30522

        args = Args()
        run_training(args)
        return True
    except Exception as e:
        error(f"DistilBERT training failed: {e}")
        return False


def clone_or_update_repo(repo_url: str, target_path: Path) -> bool:
    """
    Clone or update a git repository.

    Args:
        repo_url: URL of the repository to clone
        target_path: Path where to clone/update the repository

    Returns:
        True if successful, False otherwise
    """
    try:
        if not target_path.exists():
            info(f"   • Cloning repository: {repo_url}")
            original_dir = os.getcwd()
            os.chdir(target_path.parent)
            subprocess.run(["git", "clone", repo_url, target_path.name], check=True)
            os.chdir(original_dir)
            success(f"   Repository cloned successfully to {target_path}")
        else:
            info(f"   • Updating existing repository: {target_path}")
            original_dir = os.getcwd()
            os.chdir(target_path)
            subprocess.run(["git", "pull", "origin", "main"], check=True)
            os.chdir(original_dir)
            success(f"   Repository updated successfully")
        return True
    except subprocess.CalledProcessError as e:
        error(f"Git operation failed for {repo_url}: {e}")
        return False
    except Exception as e:
        error(f"Unexpected error during git operation: {e}")
        return False


def get_directory_size(directory_path: Path) -> str:
    """
    Get the size of a directory in human-readable format.

    Args:
        directory_path: Path to the directory

    Returns:
        Human-readable size string (e.g., "1.2G", "500M")
    """
    try:
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(directory_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)

        # Convert to human-readable format
        for unit in ["B", "K", "M", "G", "T"]:
            if total_size < 1024.0:
                return f"{total_size:.1f}{unit}"
            total_size /= 1024.0
        return f"{total_size:.1f}P"
    except Exception:
        return "unknown"


class ResearchCLI:
    """Main research CLI orchestrator."""

    def __init__(self):
        """Initialize the research CLI."""
        self.parser = self._setup_parser()

    def _setup_parser(self) -> argparse.ArgumentParser:
        """Set up the argument parser with subcommands."""
        parser = argparse.ArgumentParser(
            description="malwi Research CLI - Unified interface for training pipeline",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        # Create subparsers (but also support legacy direct args)
        subparsers = parser.add_subparsers(
            dest="command", help="Available commands", metavar="command", required=False
        )

        # Add legacy support: direct pipeline steps as positional args
        parser.add_argument(
            "legacy_steps",
            nargs="*",
            help=argparse.SUPPRESS,  # Hide from help
        )

        # Language selection for legacy mode
        parser.add_argument(
            "--language",
            "-l",
            choices=[lang.value for lang in Language],
            default=Language.BOTH.value,
            help="Programming language(s) to process (default: both)",
        )

        # Legacy support: pipeline steps subcommand
        steps_parser = subparsers.add_parser(
            "steps",
            help="Execute pipeline steps",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Run full pipeline for Python
  ./research steps download preprocess train --language python

  # Preprocess and train (default steps)
  ./research steps --language python

  # Download data only
  ./research steps download
            """,
        )

        # Pipeline steps
        steps_parser.add_argument(
            "pipeline_steps",
            nargs="*",
            choices=[step.value for step in Step],
            default=["preprocess", "train"],
            help="Pipeline steps to execute (default: preprocess train)",
        )

        # Language selection for steps
        steps_parser.add_argument(
            "--language",
            "-l",
            choices=[lang.value for lang in Language],
            default=Language.BOTH.value,
            help="Programming language(s) to process (default: both)",
        )

        # Eval subcommand
        eval_parser = subparsers.add_parser(
            "eval",
            help="Evaluate model and tokenizer metrics",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Evaluate with default paths
  ./research eval

  # Evaluate custom tokenizer and model
  ./research eval -t custom_tokenizer/ -m custom_model/

  # Evaluate only tokenizer
  ./research eval -t custom_tokenizer/
            """,
        )

        eval_parser.add_argument(
            "--tokenizer",
            "-t",
            type=str,
            default="malwi_models",
            help="Path to tokenizer directory (default: malwi_models)",
        )

        eval_parser.add_argument(
            "--model",
            "-m",
            type=str,
            default="malwi_models",
            help="Path to model directory (default: malwi_models)",
        )

        eval_parser.add_argument(
            "--test-data",
            type=str,
            default="training_processed.csv",
            help="Path to test data CSV (default: training_processed.csv)",
        )

        eval_parser.add_argument(
            "--ratio",
            type=float,
            default=0.2,
            help="Percentage of each category to use for evaluation (default: 0.2 = 20%%)",
        )

        return parser

    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Run the research CLI with the given arguments.

        Args:
            args: Command line arguments (if None, uses sys.argv)

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        parsed_args = self.parser.parse_args(args)

        # Configure messaging
        configure_messaging(quiet=False)

        # Handle subcommands
        try:
            if parsed_args.command == "steps":
                return self._handle_steps_command(parsed_args)
            elif parsed_args.command == "eval":
                return self._handle_eval_command(parsed_args)
            else:
                # Legacy support: if no command specified, check for legacy steps
                if not parsed_args.command and parsed_args.legacy_steps:
                    # Convert legacy args to steps format
                    parsed_args.pipeline_steps = parsed_args.legacy_steps
                    return self._handle_steps_command(parsed_args)
                elif not parsed_args.command and not parsed_args.legacy_steps:
                    # Default behavior - run preprocess and train
                    parsed_args.pipeline_steps = ["preprocess", "train"]
                    return self._handle_steps_command(parsed_args)
                else:
                    error(f"Unknown command: {parsed_args.command}")
                    return 1
        except KeyboardInterrupt:
            warning("Operation interrupted by user")
            return 130
        except Exception as e:
            error(f"Operation failed: {e}")
            return 1

    def _handle_steps_command(self, args: argparse.Namespace) -> int:
        """
        Handle the steps subcommand.

        Args:
            args: Parsed command line arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        # Use default steps if none provided
        steps_to_execute = (
            args.pipeline_steps if args.pipeline_steps else ["preprocess", "train"]
        )

        # Execute pipeline steps
        for step in steps_to_execute:
            if not self._execute_step(step, args):
                return 1

        success("Pipeline completed successfully!")
        return 0

    def _execute_step(self, step: str, args: argparse.Namespace) -> bool:
        """
        Execute a single pipeline step.

        Args:
            step: Step name to execute
            args: Parsed command line arguments

        Returns:
            True if step succeeded, False otherwise
        """

        info(f"🚀 Executing step: {step.upper()}")

        if step == Step.DOWNLOAD.value:
            return self._download_data(args)
        elif step == Step.PREPROCESS.value:
            return self._preprocess_data(args)
        elif step == Step.TRAIN.value:
            return self._train_model(args)
        else:
            error(f"Unknown step: {step}")
            return False

    def _download_data(self, args: argparse.Namespace) -> bool:
        """
        Download malware samples and benign code.

        Args:
            args: Parsed command line arguments

        Returns:
            True if download succeeded, False otherwise
        """
        info("📥 Downloading data")
        info(f"   Language(s): {args.language}")

        try:
            # Step 1: Clone/update malwi-samples repository
            progress("Step 1: Downloading malwi-samples...")
            malwi_samples_path = Path("../malwi-samples")

            if not clone_or_update_repo(
                "https://github.com/schirrmacher/malwi-samples.git", malwi_samples_path
            ):
                error("Failed to clone/update malwi-samples repository")
                return False

            # Step 2: Download training repositories (benign + malicious)
            progress("Step 2: Downloading training repositories...")
            info("   • Using pinned commits for reproducible training")
            info("   • This may take 10-30 minutes depending on network speed")

            # Process language-specific repositories
            if args.language in [Language.PYTHON.value, Language.BOTH.value]:
                info("   • Processing Python repositories...")
                # Import download functions dynamically
                from research.download_data import (
                    process_benign_repositories,
                    process_malicious_repositories,
                    BENIGN_REPO_URLS,
                    MALICIOUS_REPO_URLS,
                )

                process_benign_repositories(BENIGN_REPO_URLS)
                process_malicious_repositories(MALICIOUS_REPO_URLS)

            if args.language in [Language.JAVASCRIPT.value, Language.BOTH.value]:
                warning("JavaScript repository processing not yet implemented")

            success("   Repository download completed")

            # Step 3: Show summary
            success("Data download completed successfully!")
            info("📁 Downloaded data:")
            info("   • ../malwi-samples/ - Malware samples for training")
            info("   • .repo_cache/benign_repos/ - Benign Python repositories (pinned)")
            info(
                "   • .repo_cache/malicious_repos/ - Malicious package datasets (pinned)"
            )

            # Show disk usage summary
            info("💾 Disk usage summary:")
            if malwi_samples_path.exists():
                size = get_directory_size(malwi_samples_path)
                info(f"   • malwi-samples: {size}")

            repo_cache_path = Path(".repo_cache")
            if repo_cache_path.exists():
                size = get_directory_size(repo_cache_path)
                info(f"   • Repository cache: {size}")

            return True

        except subprocess.CalledProcessError as e:
            error(f"Error during download: {e}")
            return False
        except Exception as e:
            error(f"Unexpected error during download: {e}")
            return False

    def _preprocess_data(self, args: argparse.Namespace) -> bool:
        """
        Preprocess code samples into training data.

        Args:
            args: Parsed command line arguments

        Returns:
            True if preprocessing succeeded, False otherwise
        """
        info("⚙️  Preprocessing data")
        info(f"   Language(s): {args.language}")

        try:
            # Step 1: Clean up previous outputs
            progress("Step 1: Cleanup")
            info("   • Removing previous output files...")
            for file in [
                "training.csv",
                "training_processed.csv",
            ]:
                if Path(file).exists():
                    Path(file).unlink()
            success("   Cleanup completed")

            # Step 2: Generate AST data from source files
            progress("Step 2: Generate AST Data (Parallel Processing)")

            if args.language in [Language.PYTHON.value, Language.BOTH.value]:
                info("   • Generating unified training data with categories...")
                # Import preprocess function and CSV utilities dynamically
                from research.preprocess import preprocess_data
                import pandas as pd
                import os

                # Create temporary CSVs first, then merge
                temp_csvs = []

                # Generate benign data from cached repos
                info("   • Processing benign repositories...")
                temp_benign_repos = Path("temp_benign_repos.csv")
                preprocess_data(
                    input_path=Path(".repo_cache/benign_repos"),
                    output_path=temp_benign_repos,
                    extensions=[".py"],
                    use_parallel=True,
                    timeout_minutes=240,  # 4 hours for 200k+ files
                    label="benign",
                )
                if temp_benign_repos.exists():
                    temp_csvs.append(temp_benign_repos)

                # Add false-positives from malwi-samples
                info("   • Processing benign samples...")
                temp_benign_samples = Path("temp_benign_samples.csv")
                preprocess_data(
                    input_path=Path("../malwi-samples/python/benign"),
                    output_path=temp_benign_samples,
                    extensions=[".py"],
                    use_parallel=True,
                    timeout_minutes=90,  # Even malwi-samples can be large
                    label="benign",
                )
                if temp_benign_samples.exists():
                    temp_csvs.append(temp_benign_samples)

                info("   • Processing malicious samples...")
                # Generate malicious data
                temp_malicious = Path("temp_malicious.csv")
                preprocess_data(
                    input_path=Path("../malwi-samples/python/malicious"),
                    output_path=temp_malicious,
                    extensions=[".py"],
                    use_parallel=True,
                    timeout_minutes=120,  # 2 hours for malicious samples
                    label="malicious",
                )
                if temp_malicious.exists():
                    temp_csvs.append(temp_malicious)

                info("   • Processing suspicious samples...")
                # Add suspicious findings
                temp_suspicious = Path("temp_suspicious.csv")
                preprocess_data(
                    input_path=Path("../malwi-samples/python/suspicious"),
                    output_path=temp_suspicious,
                    extensions=[".py"],
                    use_parallel=True,
                    timeout_minutes=90,  # 1.5 hours for suspicious samples
                    label="suspicious",
                )
                if temp_suspicious.exists():
                    temp_csvs.append(temp_suspicious)

                # Check for telemetry category
                telemetry_path = Path("../malwi-samples/python/telemetry")
                if telemetry_path.exists():
                    info("   • Processing telemetry samples...")
                    temp_telemetry = Path("temp_telemetry.csv")
                    preprocess_data(
                        input_path=telemetry_path,
                        output_path=temp_telemetry,
                        extensions=[".py"],
                        use_parallel=True,
                        timeout_minutes=90,
                        label="telemetry",
                    )
                    if temp_telemetry.exists():
                        temp_csvs.append(temp_telemetry)

                # Merge all temporary CSVs into single training.csv
                info("   • Merging all categories into unified training.csv...")
                if temp_csvs:
                    dfs = []
                    for csv_file in temp_csvs:
                        try:
                            df = pd.read_csv(csv_file)
                            dfs.append(df)
                            info(
                                f"     - Loaded {len(df)} samples from {csv_file.name}"
                            )
                        except Exception as e:
                            warning(f"     - Failed to load {csv_file}: {e}")

                    if dfs:
                        merged_df = pd.concat(dfs, ignore_index=True)
                        merged_df.to_csv("training.csv", index=False)
                        success(
                            f"   Created unified training.csv with {len(merged_df)} samples"
                        )

                        # Show category distribution
                        if "label" in merged_df.columns:
                            category_counts = merged_df["label"].value_counts()
                            info("   Category distribution:")
                            for category, count in category_counts.items():
                                info(f"     - {category}: {count} samples")

                    # Clean up temporary files
                    for csv_file in temp_csvs:
                        try:
                            csv_file.unlink()
                        except Exception:
                            pass

            if args.language in [Language.JAVASCRIPT.value, Language.BOTH.value]:
                warning("JavaScript preprocessing not yet implemented")

            success("   AST data generation completed")

            # Step 3: Filter and process the data
            progress("Step 3: Data Processing")
            info("   • Filtering and processing unified data...")
            # Import filter function dynamically
            from research.filter_data import process_unified_csv

            # Process the unified CSV
            if Path("training.csv").exists():
                process_unified_csv(
                    input_csv="training.csv",
                    output_csv="training_processed.csv",
                    triage_dir="triaging",
                )
                success("   Data processing completed")
            else:
                error("   training.csv not found, cannot proceed with data processing")

            # Step 4: Summary
            success("Data preprocessing completed successfully!")
            info("📁 Generated files:")
            info("   • training.csv (unified training data with categories)")
            info("   • training_processed.csv (processed unified data)")

            return True

        except subprocess.CalledProcessError as e:
            error(f"Error during preprocessing: {e}")
            return False
        except Exception as e:
            error(f"Unexpected error during preprocessing: {e}")
            return False

    def _train_model(self, args: argparse.Namespace) -> bool:
        """
        Train the DistilBERT model (includes tokenizer training).

        Args:
            args: Parsed command line arguments

        Returns:
            True if training succeeded, False otherwise
        """
        info("🧠 Training model")
        info(f"   Language(s): {args.language}")

        try:
            # Step 1: Check if processed data exists
            if not Path("training_processed.csv").exists():
                error("Processed data file not found: training_processed.csv")
                error(
                    "   Please run 'preprocess' step first to generate processed data"
                )
                return False

            success("Processed data file found")

            # Step 2: Train tokenizer first
            progress("Step 1: Training custom tokenizer...")
            info("   • Training on: training_processed.csv")
            info(f"   • Total tokens: {DEFAULT_TOP_N_TOKENS} (default)")
            info("   • Output directory: malwi_models/")

            if not train_tokenizer_api(
                training_csv="training_processed.csv",
                output_path="malwi_models",
                top_n_tokens=DEFAULT_TOP_N_TOKENS,
                force_retrain=True,
            ):
                return False

            success("Tokenizer training completed successfully!")
            info("📋 Generated tokenizer files in malwi_models/:")
            info("   • tokenizer.json - Main tokenizer configuration")
            info("   • tokenizer_config.json - Tokenizer metadata")
            info("   • vocab.json - Vocabulary mapping")
            info("   • merges.txt - BPE merge rules")
            info("   • computed_special_tokens.txt - All special tokens (base + data)")
            info("   • base_tokens_from_function_mapping.txt - Base tokens only")

            # Step 3: Check if tokenizer was created successfully
            if not Path("malwi_models/tokenizer.json").exists():
                error("Tokenizer training failed")
                return False

            success("Tokenizer found at malwi_models/")

            # Step 4: Train DistilBERT model
            progress("Step 2: Training DistilBERT model...")
            info("   • Loading pre-trained tokenizer from malwi_models/")
            info("   • Training data: training_processed.csv")
            info("   • Model size: 256 hidden dimensions (smaller, faster model)")
            info("   • Epochs: 3")
            info("   • Using 1 processor for training")
            info("   Note: Set HIDDEN_SIZE=512 for larger model with better accuracy")

            # Get configurable parameters from environment or use defaults
            epochs = os.environ.get("EPOCHS", "3")
            hidden_size = os.environ.get("HIDDEN_SIZE", "256")
            num_proc = os.environ.get("NUM_PROC", "1")

            if not train_distilbert_api(
                training_csv="training_processed.csv",
                epochs=int(epochs),
                hidden_size=int(hidden_size),
                num_proc=int(num_proc),
            ):
                return False

            success("DistilBERT model training completed!")
            info("📋 Model files saved to malwi_models/:")
            info("   • Trained DistilBERT model weights and config")
            info("   • Training metrics and logs")
            info("   • Pre-existing tokenizer (preserved)")

            # Final summary
            success("Complete model training pipeline finished successfully!")
            info("📁 All outputs are in malwi_models/:")
            info(
                f"   • Tokenizer (trained on your data's top {DEFAULT_TOP_N_TOKENS} tokens)"
            )
            info(f"   • Trained DistilBERT model ({hidden_size} hidden dimensions)")
            info("   • Training metrics and logs")
            info("💡 Tip: For different configurations, set environment variables:")
            info(
                "   HIDDEN_SIZE=512 TOTAL_TOKENS=20000 python -m research.cli --steps train"
            )

            return True

        except subprocess.CalledProcessError as e:
            error(f"Error during training: {e}")
            return False
        except Exception as e:
            error(f"Unexpected error during training: {e}")
            return False

    def _handle_eval_command(self, args: argparse.Namespace) -> int:
        """
        Handle the eval subcommand to evaluate model and tokenizer metrics.

        Args:
            args: Parsed command line arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        info("📊 Evaluating model and tokenizer metrics")

        try:
            # Import evaluation modules
            from pathlib import Path
            import pandas as pd
            from transformers import (
                PreTrainedTokenizerFast,
                DistilBertForSequenceClassification,
            )
            from research.train_distilbert import load_pretrained_tokenizer
            from sklearn.metrics import (
                classification_report,
                precision_recall_fscore_support,
            )
            import torch

            # Validate paths
            tokenizer_path = Path(args.tokenizer)
            model_path = Path(args.model)
            test_data_path = Path(args.test_data)

            info(f"   • Tokenizer path: {tokenizer_path}")
            info(f"   • Model path: {model_path}")
            info(f"   • Test data: {test_data_path}")

            # Check if tokenizer exists
            if not tokenizer_path.exists():
                error(f"Tokenizer directory not found: {tokenizer_path}")
                return 1

            tokenizer_config_file = tokenizer_path / "tokenizer.json"
            if not tokenizer_config_file.exists():
                error(f"Tokenizer config not found: {tokenizer_config_file}")
                return 1

            # Check if model exists
            if not model_path.exists():
                error(f"Model directory not found: {model_path}")
                return 1

            model_config_file = model_path / "config.json"
            if not model_config_file.exists():
                error(f"Model config not found: {model_config_file}")
                return 1

            # Check if test data exists
            if not test_data_path.exists():
                error(f"Test data not found: {test_data_path}")
                return 1

            success("All required files found")

            # Load tokenizer
            progress("Loading tokenizer...")
            try:
                tokenizer = load_pretrained_tokenizer(tokenizer_path, max_length=512)
                success(f"Tokenizer loaded successfully")
                info(f"   • Vocabulary size: {tokenizer.vocab_size}")
                info(f"   • Max length: {tokenizer.model_max_length}")
            except Exception as e:
                error(f"Failed to load tokenizer: {e}")
                return 1

            # Load model
            progress("Loading model...")
            try:
                model = DistilBertForSequenceClassification.from_pretrained(
                    str(model_path)
                )
                success(f"Model loaded successfully")
                info(f"   • Model type: {model.__class__.__name__}")
                info(f"   • Number of labels: {model.num_labels}")
                info(f"   • Hidden size: {model.config.hidden_size}")
            except Exception as e:
                error(f"Failed to load model: {e}")
                return 1

            # Load test data
            progress("Loading test data...")
            try:
                df = pd.read_csv(test_data_path)
                success(f"Test data loaded: {len(df)} samples")

                if "label" in df.columns:
                    label_counts = df["label"].value_counts()
                    info("   Category distribution:")
                    for category, count in label_counts.items():
                        info(f"     - {category}: {count} samples")
                else:
                    warning("No 'label' column found in test data")

            except Exception as e:
                error(f"Failed to load test data: {e}")
                return 1

            # Evaluate tokenizer metrics
            progress("Evaluating tokenizer...")
            if "ast" in df.columns:
                # Count tokens for sample of ASTs
                sample_size = min(100, len(df))
                sample_df = df.head(sample_size)

                total_tokens = 0
                out_of_vocab_count = 0

                for ast_str in sample_df["ast"].head(sample_size):
                    if pd.notna(ast_str):
                        tokens = ast_str.split()
                        total_tokens += len(tokens)

                        # Check tokenization
                        tokenized = tokenizer(ast_str, truncation=True, max_length=512)
                        input_ids = tokenized["input_ids"]

                        # Count unknown tokens (usually token ID 0 or [UNK])
                        unk_token_id = (
                            tokenizer.unk_token_id
                            if hasattr(tokenizer, "unk_token_id")
                            else 0
                        )
                        if unk_token_id is not None:
                            out_of_vocab_count += input_ids.count(unk_token_id)

                avg_tokens_per_sample = (
                    total_tokens / sample_size if sample_size > 0 else 0
                )
                oov_rate = (
                    (out_of_vocab_count / total_tokens * 100) if total_tokens > 0 else 0
                )

                success("Tokenizer evaluation completed")
                info(f"   • Average tokens per sample: {avg_tokens_per_sample:.1f}")
                info(f"   • Out-of-vocabulary rate: {oov_rate:.2f}%")
            else:
                warning("No 'ast' column found - skipping tokenizer evaluation")

            # Evaluate model if we have labels
            if "label" in df.columns and "ast" in df.columns:
                progress("Evaluating model performance...")

                # Prepare labels mapping
                unique_labels = sorted(df["label"].unique())
                label_to_id = {label: i for i, label in enumerate(unique_labels)}
                id_to_label = {i: label for label, i in label_to_id.items()}

                info(f"   • Label mapping: {label_to_id}")

                # Take a stratified sample by category using the ratio parameter
                info(f"   • Using {args.ratio:.1%} of each category for evaluation")

                eval_dfs = []
                for label in unique_labels:
                    label_df = df[df["label"] == label]
                    sample_size = max(1, int(len(label_df) * args.ratio))
                    # Ensure we don't exceed available samples
                    sample_size = min(sample_size, len(label_df))
                    label_sample = label_df.sample(n=sample_size, random_state=42)
                    eval_dfs.append(label_sample)
                    info(f"     - {label}: {sample_size}/{len(label_df)} samples")

                eval_df = pd.concat(eval_dfs, ignore_index=True)
                info(f"   • Total evaluation samples: {len(eval_df)}")

                # Prepare inputs and labels
                texts = eval_df["ast"].tolist()
                true_labels = [label_to_id[label] for label in eval_df["label"]]

                # Tokenize texts
                inputs = tokenizer(
                    texts,
                    truncation=True,
                    padding=True,
                    max_length=512,
                    return_tensors="pt",
                )

                # Make predictions
                model.eval()
                with torch.no_grad():
                    outputs = model(**inputs)
                    predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
                    predicted_labels = torch.argmax(predictions, dim=-1).tolist()

                # Calculate metrics
                precision, recall, f1, support = precision_recall_fscore_support(
                    true_labels, predicted_labels, average="weighted", zero_division=0
                )
                macro_precision, macro_recall, macro_f1, _ = (
                    precision_recall_fscore_support(
                        true_labels, predicted_labels, average="macro", zero_division=0
                    )
                )

                # Per-category metrics
                (
                    precision_per_class,
                    recall_per_class,
                    f1_per_class,
                    support_per_class,
                ) = precision_recall_fscore_support(
                    true_labels, predicted_labels, average=None, zero_division=0
                )

                success("Model evaluation completed")
                info("📈 Overall Metrics:")
                info(f"   • Weighted F1: {f1:.4f}")
                info(f"   • Weighted Precision: {precision:.4f}")
                info(f"   • Weighted Recall: {recall:.4f}")
                info(f"   • Macro F1: {macro_f1:.4f}")
                info(f"   • Macro Precision: {macro_precision:.4f}")
                info(f"   • Macro Recall: {macro_recall:.4f}")

                info("📊 Per-Category Metrics:")
                for i, (prec, rec, f1_score, supp) in enumerate(
                    zip(
                        precision_per_class,
                        recall_per_class,
                        f1_per_class,
                        support_per_class,
                    )
                ):
                    category_name = id_to_label.get(i, f"class_{i}")
                    info(f"   • {category_name}:")
                    info(f"     - F1: {f1_score:.4f}")
                    info(f"     - Precision: {prec:.4f}")
                    info(f"     - Recall: {rec:.4f}")
                    info(f"     - Support: {supp}")

                # Detailed classification report
                info("📋 Detailed Classification Report:")
                target_names = [id_to_label[i] for i in range(len(unique_labels))]
                report = classification_report(
                    true_labels, predicted_labels, target_names=target_names
                )
                for line in report.split("\n"):
                    if line.strip():
                        info(f"   {line}")

            else:
                warning(
                    "Cannot evaluate model performance - missing 'label' or 'ast' columns"
                )

            success("🎯 Evaluation completed successfully!")
            return 0

        except Exception as e:
            error(f"Evaluation failed: {e}")
            return 1


def main():
    """Main entry point for the research CLI."""
    cli = ResearchCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
