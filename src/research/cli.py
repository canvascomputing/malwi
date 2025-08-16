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
    benign_csv: str,
    malicious_csv: str,
    output_path: str = "malwi_models",
    top_n_tokens: int = 15000,
    force_retrain: bool = True,
) -> bool:
    """
    Train tokenizer with a clean API interface.

    Args:
        benign_csv: Path to benign CSV file
        malicious_csv: Path to malicious CSV file
        output_path: Output directory for tokenizer
        top_n_tokens: Number of top tokens to use
        force_retrain: Whether to force retrain

    Returns:
        True if successful, False otherwise
    """
    try:
        # Import dynamically to avoid import errors
        from research.train_tokenizer import train_tokenizer

        # Create a mock args object for the existing function
        class Args:
            def __init__(self):
                self.benign = benign_csv
                self.malicious = malicious_csv
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
    benign_csv: str,
    malicious_csv: str,
    epochs: int = 3,
    hidden_size: int = 256,
    num_proc: int = 1,
) -> bool:
    """
    Train DistilBERT model with a clean API interface.

    Args:
        benign_csv: Path to benign CSV file
        malicious_csv: Path to malicious CSV file
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
                self.benign = benign_csv
                self.malicious = malicious_csv
                self.epochs = epochs
                self.hidden_size = hidden_size
                self.num_proc = num_proc
                self.tokenizer_path = Path("malwi_models")
                self.model_output_path = Path("malwi_models")
                self.model_name = "distilbert-base-uncased"
                self.max_length = 512
                self.window_stride = 128
                self.batch_size = 16
                self.save_steps = 0
                self.benign_to_malicious_ratio = 60.0
                self.token_column = "tokens"

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
            epilog="""
Examples:
  # Run full pipeline for Python
  ./research download preprocess train --language python
  
  # Preprocess and train (default steps)
  ./research --language python
  
  # Download data only
  ./research download
            """,
        )

        # Pipeline steps
        parser.add_argument(
            "pipeline_steps",
            nargs="*",
            choices=[step.value for step in Step],
            default=["preprocess", "train"],
            help="Pipeline steps to execute (default: preprocess train)",
        )

        # Language selection
        parser.add_argument(
            "--language",
            "-l",
            choices=[lang.value for lang in Language],
            default=Language.BOTH.value,
            help="Programming language(s) to process (default: both)",
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

        # Execute pipeline steps directly
        try:
            return self._handle_steps_command(parsed_args)
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
                "benign.csv",
                "malicious.csv",
                "malicious_processed.csv",
                "benign_processed.csv",
            ]:
                if Path(file).exists():
                    Path(file).unlink()
            success("   Cleanup completed")

            # Step 2: Generate AST data from source files
            progress("Step 2: Generate AST Data (Parallel Processing)")

            if args.language in [Language.PYTHON.value, Language.BOTH.value]:
                info("   • Generating benign Python AST data...")
                # Import preprocess function dynamically
                from research.preprocess import preprocess_data

                # Generate benign data from cached repos
                preprocess_data(
                    input_path=Path(".repo_cache/benign_repos"),
                    output_path=Path("benign.csv"),
                    extensions=[".py"],
                    use_parallel=True,
                )

                # Add false-positives from malwi-samples
                preprocess_data(
                    input_path=Path("../malwi-samples/python/benign"),
                    output_path=Path("benign.csv"),
                    extensions=[".py"],
                    use_parallel=True,
                )

                info("   • Generating malicious Python AST data...")
                # Generate malicious data
                preprocess_data(
                    input_path=Path("../malwi-samples/python/malicious"),
                    output_path=Path("malicious.csv"),
                    extensions=[".py"],
                    use_parallel=True,
                )

                # Add suspicious findings for future training categories
                preprocess_data(
                    input_path=Path("../malwi-samples/python/suspicious"),
                    output_path=Path("malicious.csv"),
                    extensions=[".py"],
                    use_parallel=True,
                )

            if args.language in [Language.JAVASCRIPT.value, Language.BOTH.value]:
                warning("JavaScript preprocessing not yet implemented")

            success("   AST data generation completed")

            # Step 3: Filter and process the data
            progress("Step 3: Data Processing")
            info("   • Filtering and processing data...")
            # Import filter function dynamically
            from research.filter_data import process_csv_files

            process_csv_files(
                benign="benign.csv", malicious="malicious.csv", triage_dir="triaging"
            )
            success("   Data processing completed")

            # Step 4: Summary
            success("Data preprocessing completed successfully!")
            info("📁 Generated files:")
            info("   • benign.csv (raw benign data)")
            info("   • malicious.csv (raw malicious data)")
            info("   • benign_processed.csv (processed benign data)")
            info("   • malicious_processed.csv (processed malicious data)")

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
            required_files = ["benign_processed.csv", "malicious_processed.csv"]
            for file in required_files:
                if not Path(file).exists():
                    error(f"Processed data file not found: {file}")
                    error(
                        "   Please run --steps preprocess first to generate processed data"
                    )
                    return False

            success("Processed data files found")

            # Step 2: Train tokenizer first
            progress("Step 1: Training custom tokenizer...")
            info("   • Training on: benign_processed.csv, malicious_processed.csv")
            info("   • Total tokens: 15000 (default)")
            info("   • Output directory: malwi_models/")

            if not train_tokenizer_api(
                benign_csv="benign_processed.csv",
                malicious_csv="malicious_processed.csv",
                output_path="malwi_models",
                top_n_tokens=15000,
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
            info("   • Training data: benign_processed.csv, malicious_processed.csv")
            info("   • Model size: 256 hidden dimensions (smaller, faster model)")
            info("   • Epochs: 3")
            info("   • Using 1 processor for training")
            info("   Note: Set HIDDEN_SIZE=512 for larger model with better accuracy")

            # Get configurable parameters from environment or use defaults
            epochs = os.environ.get("EPOCHS", "3")
            hidden_size = os.environ.get("HIDDEN_SIZE", "256")
            num_proc = os.environ.get("NUM_PROC", "1")

            if not train_distilbert_api(
                benign_csv="benign_processed.csv",
                malicious_csv="malicious_processed.csv",
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
            info("   • Tokenizer (trained on your data's top 15000 tokens)")
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


def main():
    """Main entry point for the research CLI."""
    cli = ResearchCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
