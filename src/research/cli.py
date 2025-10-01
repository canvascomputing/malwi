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
    PREPROCESS_RL = "preprocess_rl"
    TRAIN_RL = "train_rl"
    TRAIN_LSTM = "train_lstm"
    TRAIN_LONGFORMER = "train_longformer"


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

        # Train RL subcommand
        train_rl_parser = subparsers.add_parser(
            "train_rl",
            help="Train reinforcement learning agent for early exit decisions",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Train RL agent with default settings
  ./research train_rl training_processed.csv

  # Train with custom parameters
  ./research train_rl training_processed.csv --epochs 10 --n-steps 4096

  # Train with different PPO hyperparameters
  ./research train_rl training_processed.csv --learning-rate 1e-4 --batch-size 128
            """,
        )

        train_rl_parser.add_argument(
            "training_csv",
            type=str,
            help="Path to preprocessed training CSV file with package column",
        )

        train_rl_parser.add_argument(
            "--distilbert-model-path",
            type=str,
            default="malwi_models",
            help="Path to pretrained DistilBERT model (default: malwi_models)",
        )

        train_rl_parser.add_argument(
            "--tokenizer-path",
            type=str,
            default="malwi_models",
            help="Path to tokenizer (default: malwi_models)",
        )

        train_rl_parser.add_argument(
            "--output-path",
            type=str,
            default="malwi_rl_models",
            help="Output directory for RL models (default: malwi_rl_models)",
        )

        train_rl_parser.add_argument(
            "--epochs",
            type=int,
            default=3,
            help="Number of training epochs (default: 3)",
        )

        train_rl_parser.add_argument(
            "--learning-rate",
            type=float,
            default=3e-4,
            help="Learning rate for PPO (default: 3e-4)",
        )

        train_rl_parser.add_argument(
            "--n-steps",
            type=int,
            default=2048,
            help="Number of steps per PPO update (default: 2048)",
        )

        train_rl_parser.add_argument(
            "--batch-size",
            type=int,
            default=64,
            help="Batch size for PPO (default: 64)",
        )

        train_rl_parser.add_argument(
            "--ppo-epochs",
            type=int,
            default=10,
            help="Number of PPO optimization epochs per update (default: 10)",
        )

        train_rl_parser.add_argument(
            "--gamma",
            type=float,
            default=0.99,
            help="Discount factor for rewards (default: 0.99)",
        )

        train_rl_parser.add_argument(
            "--min-benign-samples",
            type=int,
            default=1,
            help="Minimum benign samples per malicious package (default: 1)",
        )

        train_rl_parser.add_argument(
            "--max-benign-samples",
            type=int,
            default=5,
            help="Maximum benign samples per malicious package (default: 5)",
        )

        train_rl_parser.add_argument(
            "--save-freq",
            type=int,
            default=10,
            help="Save model every N packages (default: 10)",
        )

        train_rl_parser.add_argument(
            "--seed",
            type=int,
            default=42,
            help="Random seed for reproducibility (default: 42)",
        )

        train_rl_parser.add_argument(
            "--test-split",
            type=float,
            default=0.2,
            help="Fraction of data to hold out for testing (default: 0.2 = 20%%)",
        )

        # Train Longformer subcommand
        train_longformer_parser = subparsers.add_parser(
            "train_longformer",
            help="Train Longformer model for package-level malware detection",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Train Longformer with default settings
  ./research train_longformer training_data.csv

  # Train with custom parameters
  ./research train_longformer training_data.csv --max-length 2048 --batch-size 4 --epochs 5

  # Train with validation split
  ./research train_longformer training_data.csv --val-csv validation_data.csv --label-aggregation majority
            """,
        )

        train_longformer_parser.add_argument(
            "csv_path",
            type=str,
            help="Path to training CSV file with tokens, label, package columns",
        )

        train_longformer_parser.add_argument(
            "--output-model",
            type=str,
            default="malwi_models/longformer_model",
            help="Path to save trained model (default: malwi_models/longformer_model)",
        )

        train_longformer_parser.add_argument(
            "--tokenizer-path",
            type=str,
            default="malwi_models",
            help="Path to tokenizer directory (default: malwi_models)",
        )

        train_longformer_parser.add_argument(
            "--val-csv",
            type=str,
            help="Path to validation CSV file (optional)",
        )

        train_longformer_parser.add_argument(
            "--max-length",
            type=int,
            default=4096,
            help="Maximum sequence length (default: 4096)",
        )

        train_longformer_parser.add_argument(
            "--batch-size",
            type=int,
            default=2,
            help="Batch size (default: 2)",
        )

        train_longformer_parser.add_argument(
            "--epochs",
            type=int,
            default=3,
            help="Number of training epochs (default: 3)",
        )

        train_longformer_parser.add_argument(
            "--learning-rate",
            type=float,
            default=2e-5,
            help="Learning rate (default: 2e-5)",
        )

        train_longformer_parser.add_argument(
            "--gradient-accumulation-steps",
            type=int,
            default=4,
            help="Gradient accumulation steps (default: 4)",
        )

        train_longformer_parser.add_argument(
            "--no-fp16",
            action="store_true",
            help="Disable mixed precision training",
        )

        train_longformer_parser.add_argument(
            "--device",
            type=str,
            help="Device to use (cuda/cpu, auto-detected if not specified)",
        )

        train_longformer_parser.add_argument(
            "--label-aggregation",
            type=str,
            default="any_positive",
            choices=["majority", "any_positive", "weighted"],
            help="Label aggregation strategy (default: any_positive)",
        )

        train_longformer_parser.add_argument(
            "--model-size",
            type=str,
            default="small",
            choices=["small", "base"],
            help="Model size configuration (small: faster training, base: standard Longformer) (default: small)",
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
            elif parsed_args.command == "train_rl":
                return self._handle_train_rl_command(parsed_args)
            elif parsed_args.command == "train_longformer":
                return self._handle_train_longformer_command(parsed_args)
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
        elif step == Step.PREPROCESS_RL.value:
            return self._preprocess_rl_step(args)
        elif step == Step.TRAIN_RL.value:
            return self._train_rl_step(args)
        elif step == Step.TRAIN_LSTM.value:
            return self._train_lstm_step(args)
        elif step == Step.TRAIN_LONGFORMER.value:
            return self._train_longformer_step(args)
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

                info("   • Processing suspicious samples (as malicious)...")
                # Add suspicious findings - categorized as malicious (insufficient data)
                temp_suspicious = Path("temp_suspicious.csv")
                preprocess_data(
                    input_path=Path("../malwi-samples/python/suspicious"),
                    output_path=temp_suspicious,
                    extensions=[".py"],
                    use_parallel=True,
                    timeout_minutes=90,  # 1.5 hours for suspicious samples
                    label="malicious",
                )
                if temp_suspicious.exists():
                    temp_csvs.append(temp_suspicious)

                # Check for telemetry category
                telemetry_path = Path("../malwi-samples/python/telemetry")
                if telemetry_path.exists():
                    info("   • Processing telemetry samples (as malicious)...")
                    temp_telemetry = Path("temp_telemetry.csv")
                    preprocess_data(
                        input_path=telemetry_path,
                        output_path=temp_telemetry,
                        extensions=[".py"],
                        use_parallel=True,
                        timeout_minutes=90,
                        label="malicious",
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

    def _preprocess_rl_step(self, args: argparse.Namespace) -> bool:
        """
        Preprocess data for RL training by computing DistilBERT embeddings.

        Args:
            args: Parsed command line arguments

        Returns:
            True if preprocessing succeeded, False otherwise
        """
        info("🔄 Preprocessing data for RL training")

        try:
            from research.preprocess_rl import preprocess_rl_embeddings

            # Check if processed data exists
            training_csv = "training_processed.csv"
            if not Path(training_csv).exists():
                error(f"Training CSV not found: {training_csv}")
                error("   Please run 'preprocess' step first to generate training data")
                return False

            success(f"🟢 Training CSV found: {training_csv}")

            # Check if DistilBERT model exists
            distilbert_path = Path("malwi_models")
            if not distilbert_path.exists():
                error(f"DistilBERT model not found: {distilbert_path}")
                error("   Please run 'train' step first to train DistilBERT model")
                return False

            success(f"🟢 DistilBERT model found: {distilbert_path}")

            # Output file
            output_csv = "training_rl_embeddings.csv"

            # Check if output already exists
            if Path(output_csv).exists():
                warning(f"Output file already exists: {output_csv}")
                warning("   Will overwrite existing file")

            # Run preprocessing
            return preprocess_rl_embeddings(
                input_csv=training_csv,
                output_csv=output_csv,
                distilbert_model_path=str(distilbert_path),
                batch_size=32,
            )

        except Exception as e:
            error(f"RL preprocessing failed: {e}")
            import traceback

            traceback.print_exc()
            return False

    def _train_rl_step(self, args: argparse.Namespace) -> bool:
        """
        Execute RL training as a pipeline step.

        Args:
            args: Parsed command line arguments

        Returns:
            True if training succeeded, False otherwise
        """
        info("🤖 Training Reinforcement Learning Agent")

        try:
            from research.train_rl import train_rl_agent

            # Check which training data exists
            embedding_csv = "training_rl_embeddings.csv"
            training_csv = "training_processed.csv"

            use_embeddings = Path(embedding_csv).exists()

            if use_embeddings:
                training_csv = embedding_csv
                success(f"🟢 Training CSV found: {training_csv}")
                info("   Using pre-computed embeddings for fast training")
            elif Path(training_csv).exists():
                success(f"🟢 Training CSV found: {training_csv}")
                warning(
                    "   Using tokens (slower). Run 'preprocess_rl' step for faster training with pre-computed embeddings"
                )
            else:
                error(f"Training CSV not found")
                error("   Please run 'preprocess' step first to generate training data")
                error("   Then optionally run 'preprocess_rl' for faster training")
                return False

            # Check if DistilBERT model exists (only needed without embeddings)
            distilbert_path = Path("malwi_models")
            if not use_embeddings and not distilbert_path.exists():
                error(f"DistilBERT model not found: {distilbert_path}")
                error("   Please run 'train' step first to train DistilBERT model")
                return False

            if not use_embeddings:
                success(f"DistilBERT model found: {distilbert_path}")

            # Create args object for train_rl_agent with defaults
            class RLArgs:
                def __init__(self):
                    self.training_csv = training_csv
                    self.use_embeddings = use_embeddings
                    self.distilbert_model_path = (
                        str(distilbert_path) if distilbert_path.exists() else None
                    )
                    self.tokenizer_path = str(
                        distilbert_path
                    )  # Tokenizer is in same dir as model
                    self.output_path = "malwi_rl_models"
                    self.epochs = int(os.environ.get("RL_EPOCHS", "3"))
                    self.learning_rate = float(
                        os.environ.get("RL_LEARNING_RATE", "3e-4")
                    )
                    self.n_steps = int(os.environ.get("RL_N_STEPS", "2048"))
                    self.batch_size = int(os.environ.get("RL_BATCH_SIZE", "64"))
                    self.ppo_epochs = int(os.environ.get("RL_PPO_EPOCHS", "10"))
                    self.gamma = float(os.environ.get("RL_GAMMA", "0.99"))
                    self.min_benign_samples = int(os.environ.get("RL_MIN_BENIGN", "1"))
                    self.max_benign_samples = int(os.environ.get("RL_MAX_BENIGN", "5"))
                    self.save_freq = int(os.environ.get("RL_SAVE_FREQ", "10"))
                    self.seed = int(os.environ.get("RL_SEED", "42"))
                    self.test_split = float(os.environ.get("RL_TEST_SPLIT", "0.2"))

            rl_args = RLArgs()

            # Display training configuration
            info("📋 RL Training Configuration:")
            info(f"   • Training data: {rl_args.training_csv}")
            info(f"   • DistilBERT model: {rl_args.distilbert_model_path}")
            info(f"   • Output path: {rl_args.output_path}")
            info(f"   • Epochs: {rl_args.epochs}")
            info(f"   • Learning rate: {rl_args.learning_rate}")
            info(f"   • PPO steps: {rl_args.n_steps}")
            info(f"   • Batch size: {rl_args.batch_size}")
            info(f"   • PPO epochs: {rl_args.ppo_epochs}")
            info(f"   • Gamma: {rl_args.gamma}")
            info(
                f"   • Benign samples: {rl_args.min_benign_samples}-{rl_args.max_benign_samples} per package"
            )
            info(f"   • Save frequency: every {rl_args.save_freq} packages")
            info(f"   • Random seed: {rl_args.seed}")
            info(
                "💡 Tip: Configure via environment variables (RL_EPOCHS, RL_LEARNING_RATE, etc.)"
            )

            # Train the RL agent
            progress("Starting RL agent training...")
            train_rl_agent(rl_args)

            success("🎉 RL agent training completed successfully!")
            info(f"📁 Trained models saved to: {rl_args.output_path}")
            info("💡 Use src/research/rl/evaluate.py to test the trained agent")

            return True

        except Exception as e:
            error(f"RL training failed: {e}")
            import traceback

            traceback.print_exc()
            return False

    def _train_lstm_step(self, args: argparse.Namespace) -> bool:
        """
        Execute LSTM training as a pipeline step.

        Args:
            args: Parsed command line arguments

        Returns:
            True if training succeeded, False otherwise
        """
        info("🧠 Training LSTM Model")

        try:
            from research.train_lstm import train_lstm_model

            # Check if pre-computed embeddings exist
            embedding_csv = "training_rl_embeddings.csv"
            if not Path(embedding_csv).exists():
                error(f"Pre-computed embeddings not found: {embedding_csv}")
                error("   Please run 'preprocess_rl' step first to generate embeddings")
                return False

            success(f"🟢 Embeddings CSV found: {embedding_csv}")

            # LSTM training configuration from environment variables
            output_model = os.environ.get(
                "LSTM_MODEL_PATH", "malwi_models/malware_lstm_model.pth"
            )
            epochs = int(os.environ.get("LSTM_EPOCHS", "10"))
            batch_size = int(os.environ.get("LSTM_BATCH_SIZE", "16"))
            learning_rate = float(os.environ.get("LSTM_LEARNING_RATE", "0.001"))
            hidden_dim = int(os.environ.get("LSTM_HIDDEN_DIM", "128"))
            num_layers = int(os.environ.get("LSTM_NUM_LAYERS", "2"))
            dropout = float(os.environ.get("LSTM_DROPOUT", "0.3"))
            max_benign_samples = int(os.environ.get("LSTM_MAX_BENIGN", "10"))

            # Display training configuration
            info("📋 LSTM Training Configuration:")
            info(f"   • Training data: {embedding_csv}")
            info(f"   • Output model: {output_model}")
            info(f"   • Epochs: {epochs}")
            info(f"   • Batch size: {batch_size}")
            info(f"   • Learning rate: {learning_rate}")
            info(f"   • Hidden dimension: {hidden_dim}")
            info(f"   • LSTM layers: {num_layers}")
            info(f"   • Dropout: {dropout}")
            info(f"   • Max benign samples: {max_benign_samples}")
            info(
                "💡 Tip: Configure via environment variables (LSTM_EPOCHS, LSTM_BATCH_SIZE, etc.)"
            )

            # Train the LSTM model
            progress("Starting LSTM training...")
            success_result = train_lstm_model(
                csv_path=embedding_csv,
                output_model=output_model,
                epochs=epochs,
                batch_size=batch_size,
                learning_rate=learning_rate,
                hidden_dim=hidden_dim,
                num_layers=num_layers,
                dropout=dropout,
                max_benign_samples=max_benign_samples,
                device="auto",
            )

            if success_result:
                success("🎉 LSTM training completed successfully!")
                info(f"📁 Trained model saved to: {output_model}")
                info("💡 Use the model for faster malware sequence classification")
                return True
            else:
                error("LSTM training failed")
                return False

        except Exception as e:
            error(f"LSTM training failed: {e}")
            import traceback

            traceback.print_exc()
            return False

    def _handle_train_rl_command(self, args: argparse.Namespace) -> int:
        """
        Handle the train_rl subcommand to train reinforcement learning agent.

        Args:
            args: Parsed command line arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        info("🤖 Training Reinforcement Learning Agent")

        try:
            # Import RL training function
            from research.train_rl import train_rl_agent

            # Validate input file
            training_csv_path = Path(args.training_csv)
            if not training_csv_path.exists():
                error(f"Training CSV not found: {args.training_csv}")
                error("   Please run preprocessing first to generate training data")
                return 1

            success(f"Training CSV found: {args.training_csv}")

            # Validate DistilBERT model
            distilbert_path = Path(args.distilbert_model_path)
            if not distilbert_path.exists():
                error(f"DistilBERT model not found: {args.distilbert_model_path}")
                error("   Please train DistilBERT model first using 'train' command")
                return 1

            success(f"DistilBERT model found: {args.distilbert_model_path}")

            # Display training configuration
            info("📋 RL Training Configuration:")
            info(f"   • Training data: {args.training_csv}")
            info(f"   • DistilBERT model: {args.distilbert_model_path}")
            info(f"   • Output path: {args.output_path}")
            info(f"   • Epochs: {args.epochs}")
            info(f"   • Learning rate: {args.learning_rate}")
            info(f"   • PPO steps: {args.n_steps}")
            info(f"   • Batch size: {args.batch_size}")
            info(f"   • PPO epochs: {args.ppo_epochs}")
            info(f"   • Gamma: {args.gamma}")
            info(
                f"   • Benign samples: {args.min_benign_samples}-{args.max_benign_samples} per package"
            )
            info(f"   • Save frequency: every {args.save_freq} packages")
            info(f"   • Random seed: {args.seed}")

            # Train the RL agent
            progress("Starting RL agent training...")
            train_rl_agent(args)

            success("🎉 RL agent training completed successfully!")
            info(f"📁 Trained models saved to: {args.output_path}")
            info("💡 Use the evaluate.py script to test the trained agent")

            return 0

        except Exception as e:
            error(f"RL training failed: {e}")
            import traceback

            traceback.print_exc()
            return 1

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

    def _handle_train_longformer_command(self, args: argparse.Namespace) -> int:
        """
        Handle the train_longformer subcommand.

        Args:
            args: Parsed command line arguments

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        info("🔬 Training Longformer Model for Package-Level Detection")

        try:
            # Import Longformer training function
            from research.train_longformer import train_longformer
            from research.train_longformer import LongformerTrainingConfig

            # Validate input file
            csv_path = Path(args.csv_path)
            if not csv_path.exists():
                error(f"Training CSV not found: {args.csv_path}")
                error("   Please run preprocessing first to generate training data")
                return 1

            success(f"Training CSV found: {args.csv_path}")

            # Validate tokenizer
            tokenizer_path = Path(args.tokenizer_path)
            if not tokenizer_path.exists():
                error(f"Tokenizer not found: {args.tokenizer_path}")
                error("   Please train DistilBERT model first to generate tokenizer")
                return 1

            success(f"Tokenizer found: {args.tokenizer_path}")

            # Display training configuration
            info("📋 Longformer Training Configuration:")
            info(f"   • Input CSV: {args.csv_path}")
            info(f"   • Output Model: {args.output_model}")
            info(f"   • Tokenizer: {args.tokenizer_path}")
            info(f"   • Max Length: {args.max_length}")
            info(f"   • Batch Size: {args.batch_size}")
            info(f"   • Epochs: {args.epochs}")
            info(f"   • Learning Rate: {args.learning_rate}")
            info(f"   • Gradient Accumulation: {args.gradient_accumulation_steps}")
            info(f"   • Mixed Precision: {not args.no_fp16}")
            info(f"   • Label Aggregation: {args.label_aggregation}")
            info(f"   • Model Size: {args.model_size}")
            if args.val_csv:
                info(f"   • Validation CSV: {args.val_csv}")

            # Create training configuration
            config = LongformerTrainingConfig(
                max_length=args.max_length,
                batch_size=args.batch_size,
                epochs=args.epochs,
                learning_rate=args.learning_rate,
                gradient_accumulation_steps=args.gradient_accumulation_steps,
                fp16=not args.no_fp16,
                label_aggregation_strategy=args.label_aggregation,
                model_size=args.model_size,
            )

            # Train the model
            progress("Starting Longformer training...")
            success_result = train_longformer(
                csv_path=args.csv_path,
                output_model=args.output_model,
                tokenizer_path=args.tokenizer_path,
                config=config,
                val_csv=args.val_csv,
                device=args.device,
            )

            if success_result:
                success("🎉 Longformer training completed successfully!")
                info(f"📁 Trained model saved to: {args.output_model}")
                info("💡 Use the model for package-level malware detection")
                return 0
            else:
                error("Longformer training failed")
                return 1

        except Exception as e:
            error(f"Longformer training failed: {e}")
            import traceback

            traceback.print_exc()
            return 1

    def _train_longformer_step(self, args: argparse.Namespace) -> bool:
        """
        Execute Longformer training as a pipeline step.

        Args:
            args: Parsed command line arguments

        Returns:
            True if training succeeded, False otherwise
        """
        info("🔬 Training Longformer Model")

        try:
            from research.train_longformer import train_longformer
            from research.train_longformer import LongformerTrainingConfig

            # Check if training data exists
            training_csv = "training_processed.csv"
            if not Path(training_csv).exists():
                error(f"Training data not found: {training_csv}")
                error("   Please run 'preprocess' step first to generate training data")
                return False

            success(f"🟢 Training data found: {training_csv}")

            # Check if tokenizer exists
            tokenizer_path = "malwi_models"
            if not Path(tokenizer_path).exists():
                error(f"Tokenizer not found: {tokenizer_path}")
                error("   Please run 'train' step first to generate tokenizer")
                return False

            success(f"🟢 Tokenizer found: {tokenizer_path}")

            # Longformer training configuration from environment variables
            output_model = os.environ.get(
                "LONGFORMER_MODEL_PATH", "malwi_models/longformer_model"
            )
            epochs = int(os.environ.get("LONGFORMER_EPOCHS", "3"))
            batch_size = int(os.environ.get("LONGFORMER_BATCH_SIZE", "2"))
            learning_rate = float(os.environ.get("LONGFORMER_LEARNING_RATE", "2e-5"))
            max_length = int(os.environ.get("LONGFORMER_MAX_LENGTH", "4096"))
            gradient_accumulation_steps = int(
                os.environ.get("LONGFORMER_GRADIENT_ACCUMULATION_STEPS", "4")
            )
            label_aggregation = os.environ.get(
                "LONGFORMER_LABEL_AGGREGATION", "any_positive"
            )
            model_size = os.environ.get("LONGFORMER_MODEL_SIZE", "small")

            info("🔧 Longformer Configuration:")
            info(f"   • Model Path: {output_model}")
            info(f"   • Epochs: {epochs}")
            info(f"   • Batch Size: {batch_size}")
            info(f"   • Learning Rate: {learning_rate}")
            info(f"   • Max Length: {max_length}")
            info(f"   • Gradient Accumulation: {gradient_accumulation_steps}")
            info(f"   • Label Aggregation: {label_aggregation}")
            info(f"   • Model Size: {model_size}")
            info(
                "💡 Tip: Configure via environment variables (LONGFORMER_EPOCHS, LONGFORMER_BATCH_SIZE, LONGFORMER_MODEL_SIZE, etc.)"
            )

            # Create training configuration
            config = LongformerTrainingConfig(
                max_length=max_length,
                batch_size=batch_size,
                epochs=epochs,
                learning_rate=learning_rate,
                gradient_accumulation_steps=gradient_accumulation_steps,
                label_aggregation_strategy=label_aggregation,
                model_size=model_size,
            )

            # Train the Longformer model
            progress("Starting Longformer training...")
            success_result = train_longformer(
                csv_path=training_csv,
                output_model=output_model,
                tokenizer_path=tokenizer_path,
                config=config,
                device="auto",
            )

            if success_result:
                success("🎉 Longformer training completed successfully!")
                info(f"📁 Trained model saved to: {output_model}")
                info("💡 Use the model for package-level malware detection")
                return True
            else:
                error("Longformer training failed")
                return False

        except Exception as e:
            error(f"Longformer training failed: {e}")
            import traceback

            traceback.print_exc()
            return False


def main():
    """Main entry point for the research CLI."""
    cli = ResearchCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
