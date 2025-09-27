import os
import pathlib
import shutil
import argparse
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from transformers import (
    DistilBertConfig,
    DistilBertForSequenceClassification,
    PreTrainedTokenizerFast,
    Trainer,
    TrainingArguments,
)

from datasets import Dataset, DatasetDict
from datasets.utils.logging import disable_progress_bar

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent

DEFAULT_MODEL_NAME = "distilbert-base-uncased"
DEFAULT_TOKENIZER_CLI_PATH = Path("malwi_models")
DEFAULT_MODEL_OUTPUT_CLI_PATH = Path("malwi_models")
DEFAULT_MAX_LENGTH = 512
DEFAULT_WINDOW_STRIDE = 128
DEFAULT_EPOCHS = 3
DEFAULT_BATCH_SIZE = 16
DEFAULT_VOCAB_SIZE = 30522
DEFAULT_SAVE_STEPS = 0
DEFAULT_BENIGN_TO_MALICIOUS_RATIO = 20.0
DEFAULT_HIDDEN_SIZE = 256  # Default to smaller model for faster training
DEFAULT_NUM_PROC = (
    os.cpu_count() if os.cpu_count() is not None and os.cpu_count() > 1 else 2
)


def load_asts_from_csv(
    csv_file_path: str,
    token_column_name: str = "tokens",
    label_column_name: str = "label",
) -> tuple[list[str], list[str]]:
    """Load AST tokens and their corresponding labels from CSV."""
    asts = []
    labels = []
    try:
        df = pd.read_csv(csv_file_path)
        if token_column_name not in df.columns:
            warning(
                f"Column '{token_column_name}' not found in {csv_file_path}. Returning empty list."
            )
            return [], []

        for idx, row in df.iterrows():
            ast_data = row[token_column_name]
            if (
                pd.isna(ast_data)
                or not isinstance(ast_data, str)
                or not ast_data.strip()
            ):
                continue
            asts.append(ast_data.strip())

            # Get label if it exists, otherwise infer from filename
            if label_column_name in df.columns and not pd.isna(row[label_column_name]):
                labels.append(str(row[label_column_name]).strip())
            else:
                # Infer label from filename (legacy support)
                if "benign" in csv_file_path.lower():
                    labels.append("benign")
                elif "malicious" in csv_file_path.lower():
                    labels.append("malicious")
                else:
                    labels.append("unknown")

        success(f"Loaded {len(asts)} sample strings from {csv_file_path}")
    except FileNotFoundError:
        error(f"File not found at {csv_file_path}. Returning empty list.")
        return [], []
    except Exception as e:
        error(f"Reading CSV {csv_file_path}: {e}. Returning empty list.")
        return [], []
    return asts, labels


def load_pretrained_tokenizer(tokenizer_path: Path, max_length: int):
    """
    Load a pre-trained tokenizer from the specified path.
    This tokenizer should have been created by train_tokenizer.py.
    """
    tokenizer_config_file = tokenizer_path / "tokenizer.json"

    if not tokenizer_config_file.exists():
        error(
            f"No tokenizer found at {tokenizer_path}. Please run train_tokenizer.py first."
        )
        raise FileNotFoundError(f"Tokenizer not found at {tokenizer_path}")

    info(f"Loading pre-trained tokenizer from {tokenizer_path}")
    try:
        tokenizer = PreTrainedTokenizerFast.from_pretrained(
            str(tokenizer_path), model_max_length=max_length
        )
        success(f"Successfully loaded tokenizer with vocab size: {len(tokenizer)}")
        return tokenizer
    except Exception as e:
        error(f"Failed to load tokenizer from {tokenizer_path}: {e}")
        raise


def save_training_metrics(metrics_dict: dict, output_path: Path):
    """Save training metrics to a text file."""
    metrics_file = output_path / "training_metrics.txt"

    try:
        with open(metrics_file, "w") as f:
            f.write("Training Metrics Summary\n")
            f.write("=" * 40 + "\n\n")

            for key, value in metrics_dict.items():
                if isinstance(value, (int, float)):
                    f.write(f"{key}: {value:.4f}\n")
                else:
                    f.write(f"{key}: {value}\n")

            f.write("\n" + "=" * 40 + "\n")
            f.write("Training completed successfully\n")

        success(f"Training metrics saved to: {metrics_file}")

    except Exception as e:
        warning(f"Could not save training metrics: {e}")


def save_model_with_prefix(trainer, tokenizer, output_path: Path):
    """Save model and tokenizer with prefixes in the same directory."""
    info(f"Saving model and tokenizer with prefixes to {output_path}...")

    # Create output directory if it doesn't exist
    output_path.mkdir(parents=True, exist_ok=True)

    # Save model files with distilbert prefix
    trainer.save_model(str(output_path))

    # Rename model files to add distilbert prefix
    model_file_mappings = {
        "config.json": "config.json",
        "pytorch_model.bin": "pytorch_model.bin",
        "model.safetensors": "model.safetensors",
        "training_args.bin": "training_args.bin",
    }

    for original_name, new_name in model_file_mappings.items():
        original_path = output_path / original_name
        new_path = output_path / new_name
        if original_path.exists():
            original_path.rename(new_path)
            success(f"Renamed {original_name} to {new_name}")

    # Save tokenizer files with tokenizer prefix
    tokenizer.save_pretrained(str(output_path))

    # Rename tokenizer files to add tokenizer prefix
    tokenizer_file_mappings = {
        "tokenizer.json": "tokenizer.json",
        "tokenizer_config.json": "tokenizer_config.json",
        "vocab.json": "vocab.json",
        "merges.txt": "merges.txt",
        "special_tokens_map.json": "special_tokens_map.json",
    }

    for original_name, new_name in tokenizer_file_mappings.items():
        original_path = output_path / original_name
        new_path = output_path / new_name
        if original_path.exists():
            original_path.rename(new_path)
            success(f"Renamed {original_name} to {new_name}")


def cleanup_checkpoints(results_path: Path):
    """
    Clean up intermediate training checkpoints to save disk space.
    Keeps only the final best model and removes intermediate checkpoint directories.

    Args:
        results_path: Path to the training results directory containing checkpoints
    """
    try:
        if not results_path.exists():
            return

        # Find all checkpoint directories (checkpoint-*)
        checkpoint_dirs = list(results_path.glob("checkpoint-*"))

        if checkpoint_dirs:
            info(f"Cleaning up {len(checkpoint_dirs)} training checkpoints...")
            import shutil

            for checkpoint_dir in checkpoint_dirs:
                shutil.rmtree(checkpoint_dir)
                info(f"Removed checkpoint: {checkpoint_dir.name}")

            success(
                f"Cleaned up {len(checkpoint_dirs)} checkpoints from {results_path}"
            )
        else:
            info("No checkpoints found to clean up")

    except Exception as e:
        warning(f"Failed to clean up checkpoints: {e}")
        # Don't fail the entire process for cleanup issues


def cleanup_model_directory(model_output_path: Path):
    """Clean up the model directory, keeping only essential prefixed model files and tokenizer."""
    info(f"Cleaning up model directory: {model_output_path}")

    # Essential files to keep (with prefixes)
    essential_files = {
        "config.json",
        "pytorch_model.bin",
        "model.safetensors",
        "training_args.bin",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.json",
        "merges.txt",
        "special_tokens_map.json",
        "training_metrics.txt",
    }

    if not model_output_path.exists():
        warning(f"Directory {model_output_path} does not exist, skipping cleanup.")
        return

    try:
        for item in model_output_path.iterdir():
            if item.is_file():
                # Check if file should be kept
                if item.name not in essential_files:
                    info(f"Removing file: {item}")
                    item.unlink()
                else:
                    info(f"Keeping essential file: {item}")

            elif item.is_dir():
                # Remove all directories (results, logs, checkpoints, etc.)
                info(f"Removing directory: {item}")
                shutil.rmtree(item)

    except Exception as e:
        warning(f"Error during cleanup: {e}")


def run_training(args):
    """Train DistilBERT model with CSV containing all categories."""
    disable_progress_bar()

    progress("Starting DistilBERT model training...")

    # Load data from unified CSV
    training_asts, training_labels = load_asts_from_csv(
        args.training, args.token_column, "label"
    )

    info(f"Loaded {len(training_asts)} training samples")

    if not training_asts:
        error("No training samples loaded. Cannot proceed with training.")
        return

    # Show category distribution
    from collections import Counter

    label_counts = Counter(training_labels)
    info("Category distribution:")
    for label, count in sorted(label_counts.items()):
        info(f"  - {label}: {count} samples")

    # Apply benign ratio balancing if configured
    all_texts_for_training = training_asts
    all_labels_text = training_labels

    if hasattr(args, "benign_ratio") and args.benign_ratio > 0:
        # Separate benign from non-benign samples
        benign_indices = [
            i for i, label in enumerate(training_labels) if label == "benign"
        ]
        non_benign_indices = [
            i for i, label in enumerate(training_labels) if label != "benign"
        ]

        benign_asts = [training_asts[i] for i in benign_indices]
        benign_labels = [training_labels[i] for i in benign_indices]
        non_benign_asts = [training_asts[i] for i in non_benign_indices]
        non_benign_labels = [training_labels[i] for i in non_benign_indices]

        info(f"Original benign samples: {len(benign_asts)}")
        info(f"Original non-benign samples: {len(non_benign_asts)}")

        if (
            non_benign_asts
            and len(benign_asts) > len(non_benign_asts) * args.benign_ratio
        ):
            target_benign_count = int(len(non_benign_asts) * args.benign_ratio)
            if target_benign_count < len(benign_asts):
                info(
                    f"Downsampling benign samples from {len(benign_asts)} to {target_benign_count}"
                )
                import numpy as np

                rng = np.random.RandomState(42)
                selected_indices = rng.choice(
                    len(benign_asts), size=target_benign_count, replace=False
                )
                benign_asts = [benign_asts[i] for i in selected_indices]
                benign_labels = [benign_labels[i] for i in selected_indices]

        # Recombine the balanced data
        all_texts_for_training = benign_asts + non_benign_asts
        all_labels_text = benign_labels + non_benign_labels

        info(f"Balanced benign samples: {len(benign_asts)}")
        info(f"Balanced non-benign samples: {len(non_benign_asts)}")
    else:
        info("No benign ratio balancing applied")

    # Create a label map for converting string labels to integers
    unique_labels = sorted(set(all_labels_text))
    label_to_id = {label: idx for idx, label in enumerate(unique_labels)}
    id_to_label = {idx: label for label, idx in label_to_id.items()}

    info(f"Label mapping: {label_to_id}")

    # Convert string labels to integer labels
    all_labels_for_training = [label_to_id[label] for label in all_labels_text]
    num_labels = len(unique_labels)

    if not all_texts_for_training:
        error("No data available for training after filtering.")
        return

    info(f"Total training samples: {len(all_texts_for_training)}")

    (
        distilbert_train_texts,
        distilbert_val_texts,
        distilbert_train_labels,
        distilbert_val_labels,
    ) = train_test_split(
        all_texts_for_training,
        all_labels_for_training,
        test_size=0.2,
        random_state=42,
        stratify=all_labels_for_training if all_labels_for_training else None,
    )

    if not distilbert_train_texts:
        error("No training data available after train/test split. Cannot proceed.")
        return

    # Calculate category distribution for metrics
    from collections import Counter

    train_label_counts = Counter(distilbert_train_labels)
    val_label_counts = Counter(distilbert_val_labels)
    total_label_counts = Counter(all_labels_for_training)

    info("Training set category distribution:")
    for label, count in sorted(train_label_counts.items()):
        percentage = (count / len(distilbert_train_labels)) * 100
        info(f"  - {label}: {count} samples ({percentage:.1f}%)")

    info("Validation set category distribution:")
    for label, count in sorted(val_label_counts.items()):
        percentage = (count / len(distilbert_val_labels)) * 100
        info(f"  - {label}: {count} samples ({percentage:.1f}%)")

    # Verify all categories are present in validation set
    missing_in_val = set(train_label_counts.keys()) - set(val_label_counts.keys())
    if missing_in_val:
        warning(f"Categories missing in validation set: {missing_in_val}")
    else:
        success("All training categories are represented in validation set")

    try:
        tokenizer = load_pretrained_tokenizer(
            tokenizer_path=Path(args.tokenizer_path),
            max_length=args.max_length,
        )
    except Exception as e:
        error(f"Failed to load tokenizer: {e}")
        error(
            "Please ensure you have run train_tokenizer.py first to create the tokenizer."
        )
        return

    info("Converting data to Hugging Face Dataset format...")
    train_data_dict = {"text": distilbert_train_texts, "label": distilbert_train_labels}
    val_data_dict = {"text": distilbert_val_texts, "label": distilbert_val_labels}

    train_hf_dataset = Dataset.from_dict(train_data_dict)
    val_hf_dataset = Dataset.from_dict(val_data_dict)

    raw_datasets = DatasetDict(
        {"train": train_hf_dataset, "validation": val_hf_dataset}
    )

    info("Tokenizing datasets with windowing using .map()...")

    # --- Updated Tokenization Function with Windowing ---
    def tokenize_and_split(examples):
        """Tokenize texts. For long texts, create multiple overlapping windows (features)."""
        # Tokenize the batch of texts. `return_overflowing_tokens` will create multiple
        # features from a single long text.
        tokenized_outputs = tokenizer(
            examples["text"],
            truncation=True,
            padding="max_length",
            max_length=args.max_length,
            stride=args.window_stride,  # The overlap between windows
            return_overflowing_tokens=True,
        )

        # `overflow_to_sample_mapping` tells us which original example each new feature came from.
        # We use this to assign the correct label to each new feature (window).
        sample_mapping = tokenized_outputs.pop("overflow_to_sample_mapping")

        original_labels = examples["label"]
        new_labels = [original_labels[sample_idx] for sample_idx in sample_mapping]
        tokenized_outputs["label"] = new_labels

        return tokenized_outputs

    num_proc = args.num_proc if args.num_proc > 0 else None

    # The new columns will be 'input_ids', 'attention_mask', and the new 'label' list.
    # We must remove the original columns ('text', 'label') that are now replaced.
    tokenized_datasets = raw_datasets.map(
        tokenize_and_split,
        batched=True,
        num_proc=num_proc,
        remove_columns=raw_datasets["train"].column_names,
    )

    info(f"Original training samples: {len(raw_datasets['train'])}")
    info(f"Windowed training features: {len(tokenized_datasets['train'])}")
    info(f"Original validation samples: {len(raw_datasets['validation'])}")
    info(f"Windowed validation features: {len(tokenized_datasets['validation'])}")
    success("Dataset tokenization and windowing completed")

    train_dataset_for_trainer = tokenized_datasets["train"]
    val_dataset_for_trainer = tokenized_datasets["validation"]

    model_output_path = Path(args.model_output_path)
    results_path = model_output_path / "results"
    logs_path = model_output_path / "logs"

    info(f"Setting up DistilBERT model with hidden_size={args.hidden_size}...")

    # Load the base config but override key parameters for our custom model
    config = DistilBertConfig.from_pretrained(args.model_name, num_labels=num_labels)
    config.pad_token_id = tokenizer.pad_token_id
    config.cls_token_id = tokenizer.cls_token_id
    config.sep_token_id = tokenizer.sep_token_id
    config.id2label = id_to_label
    config.label2id = label_to_id

    # Configure model size based on hidden_size parameter
    config.hidden_size = args.hidden_size
    config.dim = args.hidden_size  # DistilBERT uses 'dim' internally

    # Adjust other dimensions proportionally
    if args.hidden_size == 256:
        # Smaller model configuration
        config.n_heads = 4  # 256/64 = 4 heads (vs 12 for 768)
        config.n_layers = 4  # Fewer layers for smaller model (vs 6)
        config.hidden_dim = 1024  # FFN dimension (vs 3072)
    elif args.hidden_size == 512:
        # Medium model configuration
        config.n_heads = 8  # 512/64 = 8 heads
        config.n_layers = 6  # Standard number of layers
        config.hidden_dim = 2048  # FFN dimension
    # Note: 768 would be the original size with 12 heads, 6 layers, 3072 hidden_dim

    # Create model from scratch with the custom configuration
    # Note: We're not loading pretrained weights since dimensions changed
    info(
        f"Creating new DistilBERT model from scratch (not loading pretrained weights)..."
    )
    info(f"Model configuration:")
    info(f"  - Hidden size: {config.hidden_size}")
    info(f"  - Attention heads: {config.n_heads}")
    info(f"  - Layers: {config.n_layers}")
    info(f"  - FFN dimension: {config.hidden_dim}")
    info(f"  - Max position embeddings: {config.max_position_embeddings}")
    info(f"  - Number of labels: {num_labels} ({', '.join(unique_labels)})")

    model = DistilBertForSequenceClassification(config=config)

    # Calculate and display model size
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    info(f"Model parameters: {total_params:,} total, {trainable_params:,} trainable")

    # Set up training arguments
    training_args = TrainingArguments(
        output_dir=str(results_path),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_dir=str(logs_path),
        logging_steps=100,
        load_best_model_at_end=True,
        metric_for_best_model="eval_f1",
        greater_is_better=True,
        save_total_limit=2,
        report_to="none",
        fp16=False,
        dataloader_num_workers=0,
        save_safetensors=True,
    )

    # Create compute_metrics function with access to label names
    def compute_metrics(pred):
        labels = pred.label_ids
        preds = pred.predictions.argmax(-1)

        # Weighted average (influenced by sample counts)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, preds, average="weighted", zero_division=0
        )
        acc = accuracy_score(labels, preds)

        # Macro average (equal weight for all categories - better for imbalanced data)
        macro_precision, macro_recall, macro_f1, _ = precision_recall_fscore_support(
            labels, preds, average="macro", zero_division=0
        )

        # Per-category metrics for detailed analysis
        precision_per_class, recall_per_class, f1_per_class, support_per_class = (
            precision_recall_fscore_support(
                labels, preds, average=None, zero_division=0
            )
        )

        # Create comprehensive metrics dict
        metrics = {
            "accuracy": acc,
            "f1": f1,
            "precision": precision,
            "recall": recall,
            "macro_f1": macro_f1,
            "macro_precision": macro_precision,
            "macro_recall": macro_recall,
        }

        # Add per-class metrics with category names
        for i, (prec, rec, f1_score, support) in enumerate(
            zip(precision_per_class, recall_per_class, f1_per_class, support_per_class)
        ):
            category_name = id_to_label.get(i, f"class_{i}")
            metrics[f"f1_{category_name}"] = f1_score
            metrics[f"precision_{category_name}"] = prec
            metrics[f"recall_{category_name}"] = rec
            metrics[f"support_{category_name}"] = support

        return metrics

    # Initialize trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset_for_trainer,
        eval_dataset=val_dataset_for_trainer,
        tokenizer=tokenizer,
        compute_metrics=compute_metrics,
    )

    # Start training
    progress("Starting model training...")
    info(f"Training for {args.epochs} epochs...")

    try:
        train_result = trainer.train()

        # Save the model
        info("Saving model and tokenizer...")
        save_model_with_prefix(trainer, tokenizer, model_output_path)

        # Evaluate on validation set
        info("Evaluating model on validation set...")
        eval_results = trainer.evaluate()

        # Save metrics including category sample counts
        metrics = {
            "training_loss": train_result.training_loss,
            **eval_results,
            "model_hidden_size": args.hidden_size,
            "num_labels": num_labels,
            "total_params": total_params,
            "trainable_params": trainable_params,
            # Category sample counts
            "total_training_samples": len(distilbert_train_labels),
            "total_validation_samples": len(distilbert_val_labels),
            "total_samples": len(all_labels_for_training),
        }

        # Add individual category counts for training set
        for label, count in train_label_counts.items():
            metrics[f"train_{label}_samples"] = count
            metrics[f"train_{label}_percentage"] = (
                count / len(distilbert_train_labels)
            ) * 100

        # Add individual category counts for validation set
        for label, count in val_label_counts.items():
            metrics[f"val_{label}_samples"] = count
            metrics[f"val_{label}_percentage"] = (
                count / len(distilbert_val_labels)
            ) * 100

        # Add total category counts across entire dataset
        for label, count in total_label_counts.items():
            metrics[f"total_{label}_samples"] = count
            metrics[f"total_{label}_percentage"] = (
                count / len(all_labels_for_training)
            ) * 100

        save_training_metrics(metrics, model_output_path)

        # Print results
        success("Training completed successfully!")
        info(f"Final training loss: {train_result.training_loss:.4f}")
        info(f"Validation accuracy: {eval_results['eval_accuracy']:.4f}")
        info(f"Validation F1 (weighted): {eval_results['eval_f1']:.4f}")
        info(f"Validation F1 (macro): {eval_results['eval_macro_f1']:.4f}")
        info(f"Validation precision: {eval_results['eval_precision']:.4f}")
        info(f"Validation recall: {eval_results['eval_recall']:.4f}")

        # Print individual category F1 scores
        info("Per-category F1 scores:")
        for category_name in sorted(unique_labels):
            f1_key = f"eval_f1_{category_name}"
            if f1_key in eval_results:
                info(f"  - {category_name}: {eval_results[f1_key]:.4f}")
            else:
                warning(f"  - {category_name}: F1 score not found")

        # Clean up checkpoints
        cleanup_checkpoints(results_path)

    except Exception as e:
        error(f"Training failed: {e}")
        import traceback

        traceback.print_exc()
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train DistilBERT model from training CSV with categories"
    )
    parser.add_argument("training", help="Path to training CSV file")
    parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    parser.add_argument(
        "--tokenizer-path", type=Path, default=DEFAULT_TOKENIZER_CLI_PATH
    )
    parser.add_argument(
        "--model-output-path", type=Path, default=DEFAULT_MODEL_OUTPUT_CLI_PATH
    )
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument(
        "--window-stride",
        type=int,
        default=DEFAULT_WINDOW_STRIDE,
        help="Overlap stride for windowing long inputs during training.",
    )
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--vocab-size", type=int, default=DEFAULT_VOCAB_SIZE)
    parser.add_argument("--save-steps", type=int, default=DEFAULT_SAVE_STEPS)
    parser.add_argument("--num-proc", type=int, default=DEFAULT_NUM_PROC)
    parser.add_argument(
        "--hidden-size",
        type=int,
        default=DEFAULT_HIDDEN_SIZE,
        choices=[256, 512],
        help="Hidden size for DistilBERT model (256 for smaller/faster, 512 for standard)",
    )
    parser.add_argument(
        "--token-column",
        type=str,
        default="tokens",
        help="Name of column to use from CSV",
    )
    parser.add_argument(
        "--benign-ratio",
        type=float,
        default=DEFAULT_BENIGN_TO_MALICIOUS_RATIO,
        help="Ratio of benign to other categories (e.g., 2.0 for 2:1 benign:others). Set to 0 to disable balancing.",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)
    run_training(args)
