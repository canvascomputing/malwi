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
DEFAULT_BENIGN_TO_MALICIOUS_RATIO = 60.0
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


def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    # Use weighted average for multi-class classification
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="weighted", zero_division=0
    )
    acc = accuracy_score(labels, preds)
    return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}


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
    disable_progress_bar()

    progress("Starting DistilBERT model training...")

    # Load data with labels from both CSVs
    benign_asts, benign_labels = load_asts_from_csv(
        args.benign, args.token_column, "label"
    )
    malicious_asts, malicious_labels = load_asts_from_csv(
        args.malicious, args.token_column, "label"
    )

    info(f"Loaded {len(benign_asts)} benign samples")
    info(f"Loaded {len(malicious_asts)} malicious samples")

    if not malicious_asts:
        error("No malicious samples loaded. Cannot proceed with training.")
        return

    if (
        benign_asts
        and args.benign_to_malicious_ratio > 0
        and len(benign_asts) > len(malicious_asts) * args.benign_to_malicious_ratio
    ):
        target_benign_count = int(len(malicious_asts) * args.benign_to_malicious_ratio)
        if target_benign_count < len(
            benign_asts
        ):  # Ensure we are actually downsampling
            info(
                f"Downsampling benign samples from {len(benign_asts)} to {target_benign_count}"
            )
            rng = np.random.RandomState(42)
            benign_indices = rng.choice(
                len(benign_asts), size=target_benign_count, replace=False
            )
            benign_asts = [benign_asts[i] for i in benign_indices]
    elif not benign_asts:
        warning("No benign samples loaded.")

    info(f"Using {len(benign_asts)} benign samples for training")
    info(f"Using {len(malicious_asts)} malicious samples for training")

    # Combine all texts and labels
    all_texts_for_training = benign_asts + malicious_asts
    all_labels_text = benign_labels + malicious_labels

    # Create a label map for converting string labels to integers
    unique_labels = sorted(set(all_labels_text))
    label_to_id = {label: idx for idx, label in enumerate(unique_labels)}
    id_to_label = {idx: label for label, idx in label_to_id.items()}

    info(f"Label mapping: {label_to_id}")

    # Convert string labels to integer labels
    all_labels_for_training = [label_to_id[label] for label in all_labels_text]
    num_labels = len(unique_labels)

    if not all_texts_for_training:
        error("No data available for training after filtering or downsampling.")
        return

    info(f"Total original samples: {len(all_texts_for_training)}")

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

    model = DistilBertForSequenceClassification(config=config)

    # Calculate and display model size
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    info(f"Model size: {total_params:,} parameters ({trainable_params:,} trainable)")
    info(
        f"Model size in MB: {total_params * 4 / 1024 / 1024:.2f} MB (assuming float32)"
    )

    if len(tokenizer) != model.config.vocab_size:
        info(
            f"Resizing model token embeddings from {model.config.vocab_size} to {len(tokenizer)}"
        )
        model.resize_token_embeddings(len(tokenizer))

    training_arguments = TrainingArguments(
        output_dir=str(results_path),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir=str(logs_path),
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy="epoch" if args.save_steps == 0 else "steps",
        save_steps=args.save_steps if args.save_steps > 0 else None,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        save_total_limit=5 if args.save_steps > 0 else None,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_arguments,
        train_dataset=train_dataset_for_trainer,
        eval_dataset=val_dataset_for_trainer,
        compute_metrics=compute_metrics,
        tokenizer=tokenizer,
    )

    info("Starting model training...")
    train_result = trainer.train()

    info("Evaluating final model...")
    eval_result = trainer.evaluate()

    save_model_with_prefix(trainer, tokenizer, model_output_path)

    training_metrics = {
        "training_loss": train_result.training_loss,
        "epochs_completed": args.epochs,
        "original_train_samples": len(distilbert_train_texts),
        "windowed_train_features": len(train_dataset_for_trainer),
        "original_validation_samples": len(distilbert_val_texts),
        "windowed_validation_features": len(val_dataset_for_trainer),
        "benign_samples_used": len(benign_asts),
        "malicious_samples_used": len(malicious_asts),
        "benign_to_malicious_ratio": args.benign_to_malicious_ratio,
        "vocab_size": args.vocab_size,
        "max_length": args.max_length,
        "window_stride": args.window_stride,
        "batch_size": args.batch_size,
        **eval_result,
    }

    save_training_metrics(training_metrics, model_output_path)
    cleanup_model_directory(model_output_path)

    success("DistilBERT model training completed successfully")
    success(f"Final model saved to: {model_output_path}")
    success(f"Training metrics saved to: {model_output_path}/training_metrics.txt")
    success(
        f"Model configuration: hidden_size={args.hidden_size}, layers={config.n_layers}, heads={config.n_heads}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--benign", "-b", required=True, help="Path to benign CSV")
    parser.add_argument(
        "--malicious", "-m", required=True, help="Path to malicious CSV"
    )
    parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    parser.add_argument(
        "--tokenizer-path", type=Path, default=DEFAULT_TOKENIZER_CLI_PATH
    )
    parser.add_argument(
        "--model-output-path", type=Path, default=DEFAULT_MODEL_OUTPUT_CLI_PATH
    )
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    # --- New CLI Argument for Windowing ---
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
        "--benign-to-malicious-ratio",
        type=float,
        default=DEFAULT_BENIGN_TO_MALICIOUS_RATIO,
        help="Ratio of benign to malicious samples to use for training (e.g., 1.0 for 1:1). Set to 0 or negative to disable downsampling.",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)
    run_training(args)
