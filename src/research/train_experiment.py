"""
Experimental End-to-End Training: DistilBERT + LSTM

This script implements Strategy 2: Full End-to-End training where both
DistilBERT and LSTM components are trained together for sequence-based
malware detection.
"""

import argparse
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
)
from torch.utils.data import Dataset, DataLoader
from torch.nn.utils.rnn import pad_sequence
from transformers import DistilBertModel, PreTrainedTokenizerFast
from collections import Counter
import math
import json
import time

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)

# Label constants
BENIGN_LABEL = 0
MALICIOUS_LABEL = 1


class UnifiedMalwareDetector(nn.Module):
    """
    End-to-end model combining DistilBERT token encoding with LSTM sequence modeling.

    Architecture:
    1. DistilBERT: Token sequence → contextual embeddings
    2. LSTM: Embedding sequence → sequential patterns
    3. Attention: Weighted pooling of LSTM outputs
    4. Classification: Final malware prediction
    """

    def __init__(
        self,
        distilbert_path: str = "malwi_models",
        lstm_hidden_dim: int = 128,
        lstm_num_layers: int = 2,
        dropout: float = 0.3,
        num_classes: int = 2,
        freeze_distilbert: bool = False,
    ):
        super().__init__()

        # 1. Load pre-trained DistilBERT (our malware-specific model)
        info(f"Loading DistilBERT from: {distilbert_path}")
        self.distilbert = DistilBertModel.from_pretrained(distilbert_path)

        # Option to freeze DistilBERT parameters
        if freeze_distilbert:
            info("Freezing DistilBERT parameters")
            for param in self.distilbert.parameters():
                param.requires_grad = False
        else:
            info("DistilBERT parameters will be fine-tuned")

        distilbert_dim = self.distilbert.config.hidden_size  # 768 or custom

        # 2. LSTM Component for sequence modeling
        self.lstm = nn.LSTM(
            input_size=distilbert_dim,
            hidden_size=lstm_hidden_dim,
            num_layers=lstm_num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_num_layers > 1 else 0,
        )

        # 3. Attention mechanism for pooling
        lstm_output_dim = lstm_hidden_dim * 2  # bidirectional
        self.temporal_weights = nn.Linear(lstm_output_dim, 1)

        # 4. Classification head
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(lstm_output_dim * 2, lstm_output_dim),  # mean + weighted pooling
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(lstm_output_dim, lstm_hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(lstm_hidden_dim, num_classes),
        )

        self.dropout = nn.Dropout(dropout)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        hidden_state: Optional[Tuple[torch.Tensor, torch.Tensor]] = None,
    ) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]:
        """
        Forward pass through unified model with optional state persistence.

        Args:
            input_ids: Tokenized sequences [batch_size, seq_len]
            attention_mask: Padding mask [batch_size, seq_len]
            hidden_state: Optional tuple of (hidden, cell) states from previous window

        Returns:
            Tuple of (logits, (hidden, cell)) for classification and state carryover
        """
        # 1. DistilBERT: Tokens → Contextual Embeddings
        with torch.amp.autocast("cuda"):  # Mixed precision for memory efficiency
            distilbert_outputs = self.distilbert(
                input_ids=input_ids, attention_mask=attention_mask, return_dict=True
            )
            token_embeddings = (
                distilbert_outputs.last_hidden_state
            )  # [batch_size, seq_len, hidden_dim]

        # 2. LSTM: Embeddings → Sequential Patterns (with state carryover)
        if hidden_state is not None:
            lstm_outputs, (hidden, cell) = self.lstm(token_embeddings, hidden_state)
        else:
            lstm_outputs, (hidden, cell) = self.lstm(token_embeddings)
        # lstm_outputs: [batch_size, seq_len, lstm_dim*2]

        # 3. Attention-based Pooling (exclude padding tokens)
        seq_mask = attention_mask.unsqueeze(-1).float()  # [batch_size, seq_len, 1]

        # Mean pooling
        masked_lstm = lstm_outputs * seq_mask
        sum_embeddings = masked_lstm.sum(dim=1)  # [batch_size, lstm_dim*2]
        seq_lengths = attention_mask.sum(dim=1, keepdim=True).float()  # [batch_size, 1]
        mean_pooled = sum_embeddings / seq_lengths.clamp(min=1)

        # Weighted pooling (learned attention)
        attention_weights = self.temporal_weights(
            lstm_outputs
        )  # [batch_size, seq_len, 1]
        attention_weights = attention_weights.masked_fill(
            ~attention_mask.unsqueeze(-1).bool(), -float("inf")
        )
        attention_weights = F.softmax(attention_weights, dim=1)
        weighted_pooled = (lstm_outputs * attention_weights).sum(
            dim=1
        )  # [batch_size, lstm_dim*2]

        # 4. Combine pooling strategies (no max pooling to prevent shortcuts)
        combined_features = torch.cat([mean_pooled, weighted_pooled], dim=-1)
        combined_features = self.dropout(combined_features)

        # 5. Classification
        logits = self.classifier(combined_features)

        return logits, (hidden, cell)

    def forward_package(
        self,
        package_windows: List[Tuple[torch.Tensor, torch.Tensor]],
    ) -> torch.Tensor:
        """
        Process a complete package with multiple windows, maintaining LSTM state.

        Args:
            package_windows: List of (input_ids, attention_mask) tuples for each window

        Returns:
            Final classification logits for the package
        """
        hidden_state = None
        all_logits = []

        # Process each window sequentially, maintaining state
        for input_ids, attention_mask in package_windows:
            # Add batch dimension if needed
            if input_ids.dim() == 1:
                input_ids = input_ids.unsqueeze(0)
                attention_mask = attention_mask.unsqueeze(0)

            # Forward pass with state carryover
            logits, hidden_state = self.forward(input_ids, attention_mask, hidden_state)
            all_logits.append(logits)

        # Aggregate logits from all windows (average or max pooling)
        # Using average for stability
        final_logits = torch.stack(all_logits).mean(dim=0)

        return final_logits


class UnifiedDataset(Dataset):
    """
    Dataset for end-to-end training with tokenized sequences.

    Handles variable-length sequences with package-aware sampling strategy:
    - Malicious: Complete packages + random benign samples (mixed)
    - Benign: Random samples from all benign packages (diverse)
    """

    def __init__(
        self,
        malicious_packages: Dict[str, List[str]],  # package_name -> [token_strings]
        benign_packages: Dict[str, List[str]],
        tokenizer,
        max_sequence_length: int = 512,
        window_stride: int = 128,  # Overlap between windows
        max_benign_samples: int = 100,
        malicious_ratio: float = 0.3,
        random_seed: int = 42,
    ):
        super().__init__()

        self.tokenizer = tokenizer
        self.max_seq_len = max_sequence_length
        self.window_stride = window_stride
        self.rng = np.random.RandomState(random_seed)

        # Store all windowed features (not just raw sequences)
        self.input_ids = []
        self.attention_masks = []
        self.labels = []
        self.sequence_types = []

        # Get all benign token strings for random sampling
        all_benign_tokens = []
        for package_tokens in benign_packages.values():
            all_benign_tokens.extend(package_tokens)

        info(f"Total benign tokens available: {len(all_benign_tokens)}")

        # Process sequences and create windowed features
        self._process_sequences(
            malicious_packages,
            benign_packages,
            all_benign_tokens,
            max_benign_samples,
            malicious_ratio,
        )

    def _tokenize_and_split(self, sequence_text: str, label: int, seq_type: str):
        """Tokenize text and create overlapping windows like original DistilBERT training."""
        try:
            # Tokenize with windowing - creates multiple features for long sequences
            tokenized_outputs = self.tokenizer(
                sequence_text,
                truncation=True,
                padding="max_length",
                max_length=self.max_seq_len,
                stride=self.window_stride,  # Overlap between windows
                return_overflowing_tokens=True,  # Create multiple windows
                return_tensors="pt",
            )

            # Extract components
            input_ids = tokenized_outputs["input_ids"]
            attention_mask = tokenized_outputs["attention_mask"]

            # Handle overflow mapping if present (multiple windows created)
            if "overflow_to_sample_mapping" in tokenized_outputs:
                # Multiple windows were created
                num_windows = len(input_ids)
                for i in range(num_windows):
                    self.input_ids.append(input_ids[i])
                    self.attention_masks.append(attention_mask[i])
                    self.labels.append(label)
                    self.sequence_types.append(
                        f"{seq_type}_window_{i + 1}of{num_windows}"
                    )
            else:
                # Single window (sequence fit within max_length)
                self.input_ids.append(input_ids.squeeze(0))
                self.attention_masks.append(attention_mask.squeeze(0))
                self.labels.append(label)
                self.sequence_types.append(f"{seq_type}_single_window")

        except Exception as e:
            warning(f"Tokenization failed for sequence: {e}")
            # Create empty window as fallback
            self.input_ids.append(torch.zeros(self.max_seq_len, dtype=torch.long))
            self.attention_masks.append(torch.zeros(self.max_seq_len, dtype=torch.long))
            self.labels.append(label)
            self.sequence_types.append(f"{seq_type}_failed")

    def _process_sequences(
        self,
        malicious_packages,
        benign_packages,
        all_benign_tokens,
        max_benign_samples,
        malicious_ratio,
    ):
        """Process sequences and create windowed features using proper tokenization."""

        # 1. Create Mixed Malicious Sequences
        info("Processing malicious packages...")
        for package_name, malicious_tokens in malicious_packages.items():
            if not malicious_tokens:
                continue

            # Calculate benign samples needed based on ratio
            num_mal = len(malicious_tokens)
            num_ben_needed = int(num_mal * (1 - malicious_ratio) / malicious_ratio)
            num_ben_needed = min(
                num_ben_needed,
                len(all_benign_tokens),
                max(0, max_benign_samples - num_mal),
            )

            if num_ben_needed > 0 and len(all_benign_tokens) >= num_ben_needed:
                # Sample random benign tokens
                selected_benign_indices = self.rng.choice(
                    len(all_benign_tokens), size=num_ben_needed, replace=False
                )
                selected_benign_tokens = [
                    all_benign_tokens[i] for i in selected_benign_indices
                ]

                # Create mixed sequence - join all tokens into one string
                all_tokens = malicious_tokens + selected_benign_tokens
                self.rng.shuffle(all_tokens)  # Shuffle for variety

                # Join tokens into a single string for tokenizer
                sequence_text = " ".join(all_tokens)
                seq_type = f"mixed_package_{num_mal}mal_{num_ben_needed}ben"

                # Tokenize and create windowed features
                self._tokenize_and_split(sequence_text, MALICIOUS_LABEL, seq_type)
            else:
                # Only malicious tokens if no benign available
                sequence_text = " ".join(malicious_tokens)
                seq_type = f"pure_malicious_{num_mal}tokens"
                self._tokenize_and_split(sequence_text, MALICIOUS_LABEL, seq_type)

        malicious_windows_count = sum(
            1 for label in self.labels if label == MALICIOUS_LABEL
        )
        info(
            f"Created {malicious_windows_count} malicious windows from {len(malicious_packages)} packages"
        )

        # 2. Create Pure Benign Sequences
        info("Processing benign sequences...")
        num_benign_sequences_needed = (
            len([l for l in self.labels if l == MALICIOUS_LABEL])
            // len(set(self.labels))
            if self.labels
            else 0
        )

        # Create approximately equal number of benign sequences (before windowing)
        benign_seqs_to_create = len(
            malicious_packages
        )  # Same number as malicious packages

        for _ in range(benign_seqs_to_create):
            if not all_benign_tokens:
                break

            # Random number of benign samples
            num_samples = self.rng.randint(
                10, min(max_benign_samples, len(all_benign_tokens)) + 1
            )

            selected_indices = self.rng.choice(
                len(all_benign_tokens), size=num_samples, replace=False
            )
            selected_tokens = [all_benign_tokens[i] for i in selected_indices]

            # Join tokens into sequence
            sequence_text = " ".join(selected_tokens)
            seq_type = f"benign_random_{num_samples}samples"

            # Tokenize and create windowed features
            self._tokenize_and_split(sequence_text, BENIGN_LABEL, seq_type)

        benign_windows_count = sum(1 for label in self.labels if label == BENIGN_LABEL)
        info(
            f"Created {benign_windows_count} benign windows from {benign_seqs_to_create} sequences"
        )
        info(
            f"Total windowed features: {len(self.labels)} ({malicious_windows_count} malicious, {benign_windows_count} benign)"
        )

    def __len__(self):
        return len(self.input_ids)

    def __getitem__(self, idx):
        """Return pre-tokenized windowed feature."""
        return {
            "input_ids": self.input_ids[idx],
            "attention_mask": self.attention_masks[idx],
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


def collate_fn(batch):
    """Custom collate function for DataLoader."""
    input_ids = torch.stack([item["input_ids"] for item in batch])
    attention_mask = torch.stack([item["attention_mask"] for item in batch])
    labels = torch.stack([item["labels"] for item in batch])

    return {"input_ids": input_ids, "attention_mask": attention_mask, "labels": labels}


def train_unified_model(
    csv_path: str,
    distilbert_model_path: str = "malwi_models",
    tokenizer_path: str = "malwi_models",
    output_model: str = "malwi_models/unified_model",
    epochs: int = 5,
    batch_size: int = 8,  # Smaller due to memory requirements
    learning_rate: float = 2e-5,  # Lower LR for fine-tuning
    max_sequence_length: int = 512,
    window_stride: int = 128,  # Windowing overlap
    lstm_hidden_dim: int = 128,
    lstm_num_layers: int = 2,
    dropout: float = 0.3,
    max_benign_samples: int = 100,
    malicious_ratio: float = 0.3,
    device: str = "auto",
    save_every_n_epochs: int = 1,
) -> bool:
    """
    Train unified DistilBERT + LSTM model end-to-end.
    """
    configure_messaging(quiet=False)

    info("🧠🔗 Training Unified DistilBERT + LSTM Model (End-to-End)")

    # Device setup
    if device == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device(device)

    info(f"Using device: {device}")

    # Load data
    progress("Loading training data...")
    try:
        df = pd.read_csv(csv_path)
        info(f"Loaded {len(df)} samples from {csv_path}")
    except Exception as e:
        error(f"Failed to load CSV: {e}")
        return False

    # Load tokenizer
    progress("Loading tokenizer...")
    try:
        from research.train_distilbert import load_pretrained_tokenizer

        tokenizer = load_pretrained_tokenizer(
            Path(tokenizer_path), max_length=max_sequence_length
        )
        info(f"Loaded tokenizer from {tokenizer_path}")
    except Exception as e:
        error(f"Failed to load tokenizer: {e}")
        return False

    # Process data - convert to package structure with tokens
    malicious_packages = {}
    benign_packages = {}

    for _, row in df.iterrows():
        # Convert AST back to token string (space-separated)
        tokens = row["tokens"] if pd.notna(row["tokens"]) else ""
        package = row["package"] if pd.notna(row["package"]) else "unknown"
        label = row["label"]

        if label == "malicious":
            if package not in malicious_packages:
                malicious_packages[package] = []
            malicious_packages[package].append(tokens)
        else:  # benign
            if package not in benign_packages:
                benign_packages[package] = []
            benign_packages[package].append(tokens)

    info(
        f"Loaded {len(malicious_packages)} malicious packages and {len(benign_packages)} benign packages"
    )

    # Create dataset with windowing support
    dataset = UnifiedDataset(
        malicious_packages=malicious_packages,
        benign_packages=benign_packages,
        tokenizer=tokenizer,
        max_sequence_length=max_sequence_length,
        window_stride=window_stride,
        max_benign_samples=max_benign_samples,
        malicious_ratio=malicious_ratio,
    )

    # Analyze dataset composition (windowed features)
    sequence_type_counts = Counter(dataset.sequence_types)
    info("Windowed dataset composition:")
    for seq_type, count in sequence_type_counts.items():
        info(f"  - {seq_type}: {count}")

    # Show windowing statistics
    total_windows = len(dataset)
    malicious_windows = sum(1 for label in dataset.labels if label == MALICIOUS_LABEL)
    benign_windows = sum(1 for label in dataset.labels if label == BENIGN_LABEL)
    info(f"Total windowed features: {total_windows}")
    info(f"  - Malicious windows: {malicious_windows}")
    info(f"  - Benign windows: {benign_windows}")
    info(f"  - Window size: {max_sequence_length}, Stride: {window_stride}")

    # Split dataset (80/20)
    from sklearn.model_selection import train_test_split

    train_indices, val_indices = train_test_split(
        range(len(dataset)), test_size=0.2, random_state=42, stratify=dataset.labels
    )

    train_dataset = torch.utils.data.Subset(dataset, train_indices)
    val_dataset = torch.utils.data.Subset(dataset, val_indices)

    info(f"Train size: {len(train_dataset)}, Validation size: {len(val_dataset)}")

    # Create data loaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        collate_fn=collate_fn,
        num_workers=2,
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=collate_fn,
        num_workers=2,
    )

    # Initialize model
    progress("Initializing unified model...")
    model = UnifiedMalwareDetector(
        distilbert_path=distilbert_model_path,
        lstm_hidden_dim=lstm_hidden_dim,
        lstm_num_layers=lstm_num_layers,
        dropout=dropout,
        num_classes=2,
        freeze_distilbert=False,  # Strategy 2: Full end-to-end
    )

    model.to(device)

    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    info(f"Model parameters: {trainable_params:,} trainable / {total_params:,} total")

    # Optimizer and scheduler
    optimizer = optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    scheduler = optim.lr_scheduler.LinearLR(
        optimizer, start_factor=1.0, end_factor=0.1, total_iters=epochs
    )

    # Loss function with class balancing
    criterion = nn.CrossEntropyLoss()

    # Mixed precision scaler
    scaler = torch.amp.GradScaler("cuda") if device.type == "cuda" else None

    # Training loop
    best_val_f1 = 0.0

    for epoch in range(epochs):
        info(f"\n--- Epoch {epoch + 1}/{epochs} ---")

        # Training phase
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        progress_bar = range(len(train_loader))

        for batch_idx, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            optimizer.zero_grad()

            # Forward pass with mixed precision
            if scaler:
                with torch.amp.autocast("cuda"):
                    outputs = model(input_ids, attention_mask)
                    loss = criterion(outputs, labels)

                scaler.scale(loss).backward()
                scaler.step(optimizer)
                scaler.update()
            else:
                outputs = model(input_ids, attention_mask)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()

            # Statistics
            train_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            train_total += labels.size(0)
            train_correct += (predicted == labels).sum().item()

            # Progress update
            if batch_idx % 10 == 0:
                progress(
                    f"Batch {batch_idx}/{len(train_loader)}, Loss: {loss.item():.4f}"
                )

        train_acc = 100.0 * train_correct / train_total
        avg_train_loss = train_loss / len(train_loader)

        # Validation phase
        model.eval()
        val_loss = 0.0
        val_predictions = []
        val_targets = []

        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels = batch["labels"].to(device)

                if scaler:
                    with torch.amp.autocast("cuda"):
                        outputs = model(input_ids, attention_mask)
                        loss = criterion(outputs, labels)
                else:
                    outputs = model(input_ids, attention_mask)
                    loss = criterion(outputs, labels)

                val_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)

                val_predictions.extend(predicted.cpu().numpy())
                val_targets.extend(labels.cpu().numpy())

        # Calculate validation metrics
        val_acc = accuracy_score(val_targets, val_predictions)
        val_precision = precision_score(val_targets, val_predictions, zero_division=0)
        val_recall = recall_score(val_targets, val_predictions, zero_division=0)
        val_f1 = f1_score(val_targets, val_predictions, zero_division=0)
        avg_val_loss = val_loss / len(val_loader)

        # Update learning rate
        scheduler.step()
        current_lr = scheduler.get_last_lr()[0]

        # Print epoch results
        info(f"Train Loss: {avg_train_loss:.4f}, Train Acc: {train_acc:.2f}%")
        info(f"Val Loss: {avg_val_loss:.4f}, Val Acc: {val_acc:.4f}")
        info(
            f"Val Precision: {val_precision:.4f}, Val Recall: {val_recall:.4f}, Val F1: {val_f1:.4f}"
        )
        info(f"Learning Rate: {current_lr:.2e}")

        # Save best model
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_model_path = f"{output_model}_best.pth"
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "val_f1": val_f1,
                    "val_acc": val_acc,
                },
                best_model_path,
            )
            success(f"New best model saved: F1={val_f1:.4f}")

        # Save checkpoint
        if (epoch + 1) % save_every_n_epochs == 0:
            checkpoint_path = f"{output_model}_epoch_{epoch + 1}.pth"
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "val_f1": val_f1,
                    "val_acc": val_acc,
                },
                checkpoint_path,
            )
            info(f"Checkpoint saved: {checkpoint_path}")

    # Final evaluation
    info("\n--- Final Validation Results ---")
    model.eval()
    final_predictions = []
    final_targets = []

    with torch.no_grad():
        for batch in val_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids, attention_mask)
            _, predicted = torch.max(outputs.data, 1)

            final_predictions.extend(predicted.cpu().numpy())
            final_targets.extend(labels.cpu().numpy())

    # Classification report
    target_names = ["benign", "malicious"]
    report = classification_report(
        final_targets, final_predictions, target_names=target_names
    )
    info("Classification Report:")
    for line in report.split("\n"):
        if line.strip():
            info(f"  {line}")

    # Save final model
    final_model_path = f"{output_model}_final.pth"
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "training_config": {
                "epochs": epochs,
                "batch_size": batch_size,
                "learning_rate": learning_rate,
                "lstm_hidden_dim": lstm_hidden_dim,
                "lstm_num_layers": lstm_num_layers,
                "dropout": dropout,
                "max_sequence_length": max_sequence_length,
            },
            "final_metrics": {
                "val_f1": f1_score(final_targets, final_predictions),
                "val_accuracy": accuracy_score(final_targets, final_predictions),
                "val_precision": precision_score(final_targets, final_predictions),
                "val_recall": recall_score(final_targets, final_predictions),
            },
        },
        final_model_path,
    )

    success(f"🎉 Training completed! Models saved to {output_model}_*.pth")
    info(f"Best validation F1: {best_val_f1:.4f}")

    return True


def main():
    """Main entry point for unified model training."""
    parser = argparse.ArgumentParser(
        description="Train unified DistilBERT + LSTM model end-to-end"
    )

    parser.add_argument(
        "csv_path",
        type=str,
        help="Path to training CSV file with tokens and package columns",
    )

    parser.add_argument(
        "--distilbert-model",
        type=str,
        default="malwi_models",
        help="Path to pre-trained DistilBERT model (default: malwi_models)",
    )

    parser.add_argument(
        "--tokenizer-path",
        type=str,
        default="malwi_models",
        help="Path to tokenizer (default: malwi_models)",
    )

    parser.add_argument(
        "--output-model",
        type=str,
        default="malwi_models/unified_model",
        help="Output path for trained model (default: malwi_models/unified_model)",
    )

    parser.add_argument(
        "--epochs", type=int, default=5, help="Number of training epochs (default: 5)"
    )

    parser.add_argument(
        "--batch-size", type=int, default=8, help="Training batch size (default: 8)"
    )

    parser.add_argument(
        "--learning-rate",
        type=float,
        default=2e-5,
        help="Learning rate (default: 2e-5)",
    )

    parser.add_argument(
        "--max-seq-length",
        type=int,
        default=512,
        help="Maximum sequence length (default: 512)",
    )

    parser.add_argument(
        "--window-stride",
        type=int,
        default=128,
        help="Overlap stride for windowing long sequences (default: 128)",
    )

    parser.add_argument(
        "--lstm-hidden-dim",
        type=int,
        default=128,
        help="LSTM hidden dimension (default: 128)",
    )

    parser.add_argument(
        "--device", type=str, default="auto", help="Device to use (auto/cpu/cuda)"
    )

    args = parser.parse_args()

    # Train the unified model
    success = train_unified_model(
        csv_path=args.csv_path,
        distilbert_model_path=args.distilbert_model,
        tokenizer_path=args.tokenizer_path,
        output_model=args.output_model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        max_sequence_length=args.max_seq_length,
        window_stride=args.window_stride,
        lstm_hidden_dim=args.lstm_hidden_dim,
        device=args.device,
    )

    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
