"""
Longformer training script for package-level malware detection.

This script trains a Longformer model on concatenated package sequences,
enabling detection of malware patterns that span multiple files.
"""

import argparse
import os
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.amp import GradScaler, autocast
from transformers import get_linear_schedule_with_warmup
from pathlib import Path
import numpy as np
from sklearn.metrics import classification_report, multilabel_confusion_matrix
from typing import Dict, List, Optional
import logging
import time

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)
from transformers import LongformerForSequenceClassification, LongformerConfig
from research.longformer_constants import (
    LABEL_TO_ID,
    ID_TO_LABEL,
    NUM_LABELS,
)
from research.longformer_dataset import create_longformer_dataloaders


class LongformerTrainingConfig:
    """Configuration for Longformer training."""

    def __init__(
        self,
        max_length: int = 4098,
        batch_size: int = 2,
        learning_rate: float = 2e-5,
        epochs: int = 3,
        warmup_steps: int = 500,
        weight_decay: float = 0.01,
        gradient_accumulation_steps: int = 4,
        fp16: bool = True,
        label_aggregation_strategy: str = "any_positive",
    ):
        self.max_length = max_length
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.warmup_steps = warmup_steps
        self.weight_decay = weight_decay
        self.gradient_accumulation_steps = gradient_accumulation_steps
        self.fp16 = fp16
        self.label_aggregation_strategy = label_aggregation_strategy

    def __repr__(self):
        return f"LongformerTrainingConfig({self.__dict__})"


def train_longformer(
    csv_path: str,
    output_model: str = "malwi_models/longformer_model",
    tokenizer_path: str = "malwi_models",
    config: Optional[LongformerTrainingConfig] = None,
    val_csv: Optional[str] = None,
    device: Optional[str] = None,
) -> bool:
    """
    Train Longformer model for package-level malware detection.

    Args:
        csv_path: Path to training CSV with tokens, label, package columns
        output_model: Path to save trained model
        tokenizer_path: Path to tokenizer directory
        config: Training configuration
        val_csv: Path to validation CSV (optional)
        device: Device to use for training

    Returns:
        True if training succeeded, False otherwise
    """
    try:
        # Use default config if not provided
        if config is None:
            config = LongformerTrainingConfig()

        info(f"Training configuration: {config}")

        # Setup device
        if device is None:
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            device = torch.device(device)

        info(f"Using device: {device}")

        # Validate input file
        if not Path(csv_path).exists():
            error(f"Training CSV not found: {csv_path}")
            return False

        # Validate tokenizer path
        if not Path(tokenizer_path).exists():
            error(f"Tokenizer not found: {tokenizer_path}")
            return False

        # Create data loaders
        progress("Creating data loaders...")
        train_loader, val_loader = create_longformer_dataloaders(
            train_csv=csv_path,
            val_csv=val_csv,
            tokenizer_path=tokenizer_path,
            batch_size=config.batch_size,
            max_length=config.max_length,
            val_split=0.2,  # Explicitly set 20% validation split
            max_benign_samples_per_package=10,  # Max 10 samples per benign collection
            benign_ratio=4,  # Create 4 random benign collections per benign package
            label_aggregation_strategy=config.label_aggregation_strategy,
        )

        info(f"Training batches: {len(train_loader)}")
        if val_loader:
            info(f"Validation batches: {len(val_loader)}")

        # Get label distribution
        if hasattr(train_loader.dataset, "get_label_distribution"):
            label_dist = train_loader.dataset.get_label_distribution()
            info(f"Label distribution: {label_dist}")

        # Get tokenizer info for model initialization
        dataset = train_loader.dataset
        if hasattr(dataset, "dataset"):  # Handle Subset wrapper
            dataset = dataset.dataset

        actual_tokenizer = dataset.tokenizer if hasattr(dataset, "tokenizer") else None

        if actual_tokenizer is None:
            error("Could not access tokenizer from dataset")
            return False

        # Use the ACTUAL tokenizer vocab size, not a custom one
        actual_vocab_size = len(actual_tokenizer)
        info(f"Dataset tokenizer vocab size: {actual_vocab_size}")
        info(f"Dataset tokenizer type: {type(actual_tokenizer)}")

        # Initialize model with correct vocab size
        progress("Initializing Longformer model...")

        # Create Longformer config for sequence classification
        model_config = LongformerConfig.from_pretrained(
            "allenai/longformer-base-4096",
            num_labels=NUM_LABELS,
            attention_window=512,
            problem_type="multi_label_classification",
            classifier_dropout=0.1,
        )

        # Load model with standard Longformer config
        model = LongformerForSequenceClassification.from_pretrained(
            "allenai/longformer-base-4096",
            config=model_config,
        )

        info(
            f"Model vocab_size: {model.config.vocab_size}, Tokenizer vocab_size: {actual_vocab_size}"
        )

        info(
            f"Initialized Longformer with max_length={config.max_length}, vocab_size={model.config.vocab_size}, num_labels={NUM_LABELS}"
        )

        # Store for saving config later
        tokenizer_vocab_size = (
            model.config.vocab_size
        )  # Use the actual model vocab size

        # Validate that training data is compatible with model vocabulary
        progress("Validating data compatibility...")
        try:
            first_batch = next(iter(train_loader))
            input_ids = first_batch["input_ids"]
            max_token_id = input_ids.max().item()
            min_token_id = input_ids.min().item()

            info(
                f"Data validation: token ID range [{min_token_id}, {max_token_id}], model vocab_size: {model.config.vocab_size}"
            )

            if max_token_id >= model.config.vocab_size:
                error(
                    f"CRITICAL: Data contains token ID {max_token_id} but model only has {model.config.vocab_size} tokens!"
                )
                error("This will cause the CUDA indexing error.")
                error(
                    "The training data must be preprocessed with a tokenizer compatible with Longformer's vocabulary."
                )
                error(
                    "Please ensure the tokenizer maps tokens correctly to Longformer's vocabulary range."
                )
                return False

            if min_token_id < 0:
                error(f"CRITICAL: Data contains negative token ID {min_token_id}!")
                return False

            success(
                "✓ Data validation passed - token IDs are compatible with model vocabulary"
            )

        except Exception as e:
            warning(f"Could not validate data compatibility: {e}")

        model.to(device)

        # Setup optimizer and scheduler
        optimizer = AdamW(
            model.parameters(),
            lr=config.learning_rate,
            weight_decay=config.weight_decay,
        )

        total_steps = (
            len(train_loader) * config.epochs // config.gradient_accumulation_steps
        )
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=config.warmup_steps,
            num_training_steps=total_steps,
        )

        # Setup mixed precision training
        scaler = GradScaler("cuda") if config.fp16 and device.type == "cuda" else None

        info(f"Starting training for {config.epochs} epochs...")

        # Training loop
        best_f1_score = 0.0  # Use F1 score instead of loss for model selection
        best_val_loss = float("inf")
        training_stats = []

        for epoch in range(config.epochs):
            epoch_start_time = time.time()

            # Training phase
            model.train()
            train_loss = train_epoch(
                model=model,
                train_loader=train_loader,
                optimizer=optimizer,
                scheduler=scheduler,
                scaler=scaler,
                device=device,
                epoch=epoch + 1,
                gradient_accumulation_steps=config.gradient_accumulation_steps,
            )

            # Validation phase
            val_loss = None
            val_metrics = None
            if val_loader:
                model.eval()
                val_loss, val_metrics = evaluate_model(
                    model=model,
                    val_loader=val_loader,
                    device=device,
                )

            epoch_time = time.time() - epoch_start_time

            # Log epoch results
            epoch_stats = {
                "epoch": epoch + 1,
                "train_loss": train_loss,
                "val_loss": val_loss,
                "epoch_time": epoch_time,
            }

            if val_metrics:
                epoch_stats.update(val_metrics)

            training_stats.append(epoch_stats)

            info(
                f"Epoch {epoch + 1}/{config.epochs} - "
                f"Train Loss: {train_loss:.4f}"
                + (f", Val Loss: {val_loss:.4f}" if val_loss else "")
                + f", Time: {epoch_time:.1f}s"
            )

            # Save best model based on F1 score (or validation loss if no validation)
            current_f1 = val_metrics.get("malicious_f1", 0.0) if val_metrics else 0.0
            current_val_loss = val_loss if val_loss is not None else train_loss

            # Use F1 score for model selection if available, otherwise use loss
            save_model_flag = False
            if val_metrics and current_f1 > best_f1_score:
                best_f1_score = current_f1
                save_model_flag = True
                info(f"New best F1 score: {best_f1_score:.4f}")
            elif not val_metrics and current_val_loss < best_val_loss:
                best_val_loss = current_val_loss
                save_model_flag = True
                info(f"New best validation loss: {best_val_loss:.4f}")

            if save_model_flag:
                save_model(
                    model, output_model, epoch + 1, epoch_stats, tokenizer_vocab_size
                )

        # Save final training statistics
        output_dir = Path(output_model)
        output_dir.mkdir(parents=True, exist_ok=True)
        stats_path = output_dir / "training_stats.json"
        import json

        with open(stats_path, "w") as f:
            json.dump(training_stats, f, indent=2)

        success(f"✅ Longformer training completed successfully!")
        info(f"📁 Model saved to: {output_model}")
        info(f"📊 Training stats saved to: {stats_path}")

        return True

    except Exception as e:
        error(f"Longformer training failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def train_epoch(
    model,
    train_loader,
    optimizer,
    scheduler,
    scaler,
    device,
    epoch: int,
    gradient_accumulation_steps: int = 1,
) -> float:
    """Train model for one epoch."""
    model.train()
    total_loss = 0.0
    num_batches = 0

    optimizer.zero_grad()

    for batch_idx, batch in enumerate(train_loader):
        # Move batch to device
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        global_attention_mask = batch["global_attention_mask"].to(device)
        labels = batch["labels"].to(device)

        # Forward pass with mixed precision
        if scaler:
            with autocast("cuda"):
                outputs = model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    global_attention_mask=global_attention_mask,
                    labels=labels,
                )
                loss = outputs.loss
        else:
            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                global_attention_mask=global_attention_mask,
                labels=labels,
            )
            loss = outputs.loss

        # Scale loss for gradient accumulation
        loss = loss / gradient_accumulation_steps

        # Backward pass
        if scaler:
            scaler.scale(loss).backward()
        else:
            loss.backward()

        # Update weights
        if (batch_idx + 1) % gradient_accumulation_steps == 0:
            if scaler:
                scaler.step(optimizer)
                scaler.update()
            else:
                optimizer.step()

            # Step scheduler after each optimization step (not each batch)
            scheduler.step()
            optimizer.zero_grad()

        total_loss += loss.item() * gradient_accumulation_steps
        num_batches += 1

        # Log progress
        if batch_idx % 10 == 0:
            progress(
                f"Epoch {epoch} - Batch {batch_idx}/{len(train_loader)} - "
                f"Loss: {loss.item() * gradient_accumulation_steps:.4f}"
            )

    return total_loss / num_batches


def evaluate_model(model, val_loader, device) -> tuple:
    """Evaluate model on validation set."""
    model.eval()
    total_loss = 0.0
    all_predictions = []
    all_labels = []

    with torch.no_grad():
        for batch in val_loader:
            # Move batch to device
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            global_attention_mask = batch["global_attention_mask"].to(device)
            labels = batch["labels"].to(device)

            # Forward pass in evaluation mode
            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                global_attention_mask=global_attention_mask,
                labels=labels,
            )

            if outputs.loss is not None:
                total_loss += outputs.loss.item()

            # Get predictions using sigmoid
            probabilities = torch.sigmoid(outputs.logits)
            predictions = (probabilities > 0.5).float()

            all_predictions.append(predictions.cpu())
            all_labels.append(labels.cpu())

    avg_loss = total_loss / len(val_loader)

    # Compute metrics
    all_predictions = torch.cat(all_predictions, dim=0).numpy()
    all_labels = torch.cat(all_labels, dim=0).numpy()

    # Calculate per-label metrics
    metrics = {}
    all_f1_scores = []

    for label_idx, label_name in ID_TO_LABEL.items():
        y_true = all_labels[:, label_idx]
        y_pred = all_predictions[:, label_idx]

        if y_true.sum() > 0:  # Only calculate if label exists in validation set
            from sklearn.metrics import precision_score, recall_score, f1_score

            precision = precision_score(y_true, y_pred, zero_division=0)
            recall = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)

            metrics[f"{label_name}_precision"] = precision
            metrics[f"{label_name}_recall"] = recall
            metrics[f"{label_name}_f1"] = f1
            all_f1_scores.append(f1)

    # Calculate overall metrics
    if all_f1_scores:
        metrics["macro_f1"] = sum(all_f1_scores) / len(all_f1_scores)
        metrics["micro_f1"] = f1_score(
            all_labels.flatten(), all_predictions.flatten(), zero_division=0
        )
        metrics["f1_score"] = metrics["macro_f1"]  # For model selection

    return avg_loss, metrics


def save_model(
    model, output_path: str, epoch: int, stats: Dict, tokenizer_vocab_size: int = None
):
    """Save model and training metadata."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save model state dict
    model_path = output_dir / "pytorch_model.bin"
    torch.save(model.state_dict(), model_path)

    # Save model config
    config_path = output_dir / "config.json"
    import json

    config_data = {
        "model_type": "longformer",
        "max_position_embeddings": model.config.max_position_embeddings,
        "hidden_size": model.config.hidden_size,
        "vocab_size": tokenizer_vocab_size or model.config.vocab_size,
        "num_labels": len(LABEL_TO_ID),
        "label_to_id": LABEL_TO_ID,
        "id_to_label": ID_TO_LABEL,
        "epoch": epoch,
        "training_stats": stats,
    }

    with open(config_path, "w") as f:
        json.dump(config_data, f, indent=2)

    info(f"Model saved to {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train Longformer model for package-level malware detection"
    )
    parser.add_argument(
        "csv_path",
        type=str,
        help="Path to training CSV file with tokens, label, package columns",
    )
    parser.add_argument(
        "--output-model",
        type=str,
        default="malwi_models/longformer_model",
        help="Path to save trained model (default: malwi_models/longformer_model)",
    )
    parser.add_argument(
        "--tokenizer-path",
        type=str,
        default="malwi_models",
        help="Path to tokenizer directory (default: malwi_models)",
    )
    parser.add_argument(
        "--val-csv",
        type=str,
        help="Path to validation CSV file (optional)",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=4098,
        help="Maximum sequence length (default: 4098)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2,
        help="Batch size (default: 2)",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs (default: 3)",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=2e-5,
        help="Learning rate (default: 2e-5)",
    )
    parser.add_argument(
        "--gradient-accumulation-steps",
        type=int,
        default=4,
        help="Gradient accumulation steps (default: 4)",
    )
    parser.add_argument(
        "--no-fp16",
        action="store_true",
        help="Disable mixed precision training",
    )
    parser.add_argument(
        "--device",
        type=str,
        help="Device to use (cuda/cpu, auto-detected if not specified)",
    )
    parser.add_argument(
        "--label-aggregation",
        type=str,
        default="any_positive",
        choices=["majority", "any_positive", "weighted"],
        help="Label aggregation strategy (default: any_positive)",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)

    # Create training config
    config = LongformerTrainingConfig(
        max_length=args.max_length,
        batch_size=args.batch_size,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        fp16=not args.no_fp16,
        label_aggregation_strategy=args.label_aggregation,
    )

    # Run training
    success_result = train_longformer(
        csv_path=args.csv_path,
        output_model=args.output_model,
        tokenizer_path=args.tokenizer_path,
        config=config,
        val_csv=args.val_csv,
        device=args.device,
    )

    exit(0 if success_result else 1)
