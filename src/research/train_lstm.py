"""
LSTM training for malware detection.

This module implements training strategies for sequence-based malware detection.
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
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from torch.utils.data import Dataset, DataLoader
from torch.nn.utils.rnn import pad_sequence
from collections import Counter
import math

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)

# Label constants - Binary classification
BENIGN_LABEL = 0
MALICIOUS_LABEL = 1


# Using LSTM without additional attention layers
# LSTMs capture sequence patterns through their gating mechanisms


class MalwareLSTM(nn.Module):
    """
    LSTM model for sequence-based malware detection.
    """

    def __init__(
        self,
        embedding_dim: int = 256,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_classes: int = 2,  # Binary: Benign, Malicious
    ):
        super().__init__()

        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # Embedding dropout to prevent over-reliance on individual embeddings
        self.embedding_dropout = nn.Dropout(0.2)

        # Noise injection for robustness
        self.noise_factor = 0.1

        # LSTMs process sequences inherently

        # Bidirectional LSTM
        self.lstm = nn.LSTM(
            input_size=embedding_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True,
        )

        # Using temporal pooling instead of attention layers

        # Temporal pooling: combine max, mean, and weighted pooling
        self.temporal_weights = nn.Linear(hidden_dim * 2, 1)

        # Classification head with multiple pathways
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(
                hidden_dim * 4, hidden_dim * 2
            ),  # 2 pooling methods × 2 (bidirectional)
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, sequences, attention_mask, training=True):
        batch_size, seq_len, _ = sequences.shape

        # LSTM processes sequences inherently

        # Apply embedding dropout and noise during training
        if training:
            sequences = self.embedding_dropout(sequences)
            # Add Gaussian noise to prevent over-reliance on exact values
            noise = torch.randn_like(sequences) * self.noise_factor
            sequences = sequences + noise

        # LSTM forward pass
        lstm_out, (hidden, cell) = self.lstm(sequences)

        # Simplified temporal pooling on LSTM outputs without max pooling (reduces shortcut learning)
        # 1. Mean pooling (considers all positions equally)
        sum_pooled = (lstm_out * attention_mask.unsqueeze(-1)).sum(dim=1)
        mean_pooled = sum_pooled / attention_mask.sum(dim=1, keepdim=True)

        # 2. Weighted pooling (learns position importance)
        weights = self.temporal_weights(lstm_out)
        weights = weights.masked_fill(~attention_mask.unsqueeze(-1), -float("inf"))
        weights = F.softmax(weights, dim=1)
        weighted_pooled = (lstm_out * weights).sum(dim=1)

        # Combine pooling strategies (excluding max pooling)
        combined_features = torch.cat([mean_pooled, weighted_pooled], dim=-1)

        # Classification
        logits = self.classifier(combined_features)

        return logits


class MalwareDataset(Dataset):
    """
    Binary dataset with package-aware malware detection.

    Strategy:
    - Malicious sequences: Create mixed sequences with malicious package content + random benign samples
    - Benign sequences: Pure benign sequences from benign packages
    """

    def __init__(
        self,
        malicious_packages: Dict[str, List[np.ndarray]],
        benign_packages: Dict[str, List[np.ndarray]],
        max_benign_samples: int = 100,
        malicious_ratio: float = 0.3,  # 30% malicious content in mixed sequences
        random_seed: int = 42,
    ):
        super().__init__()

        self.malicious_packages = malicious_packages
        self.benign_packages = benign_packages
        self.max_benign_samples = max_benign_samples
        self.malicious_ratio = malicious_ratio
        self.rng = np.random.RandomState(random_seed)

        self.sequences = []
        self.labels = []
        self.sequence_types = []  # Track sequence composition for analysis

        # Get all benign embeddings for sampling
        all_benign_embeds = []
        for package_embeds in benign_packages.values():
            all_benign_embeds.extend(package_embeds)

        # 1. Create Mixed Malicious Sequences
        # Use entire malicious packages + random benign samples
        for package_name, malicious_embeds in malicious_packages.items():
            if not malicious_embeds:
                continue

            # Calculate how many benign samples to add
            num_mal = len(malicious_embeds)
            num_ben_needed = int(
                num_mal * (1 - self.malicious_ratio) / self.malicious_ratio
            )
            num_ben_needed = min(
                num_ben_needed,
                len(all_benign_embeds),
                max(0, self.max_benign_samples - num_mal),
            )

            if num_ben_needed > 0:
                # Sample random benign embeddings
                selected_benign_indices = self.rng.choice(
                    len(all_benign_embeds), size=num_ben_needed, replace=False
                )
                selected_benign = [
                    all_benign_embeds[i] for i in selected_benign_indices
                ]

                # Create mixed sequence
                sequence = malicious_embeds + selected_benign
                self.rng.shuffle(sequence)

                self.sequences.append(sequence)
                self.labels.append(MALICIOUS_LABEL)
                self.sequence_types.append(
                    f"mixed_package_{num_mal}mal_{num_ben_needed}ben"
                )

        # 2. Create Pure Benign Sequences
        # Use random samples from all benign embeddings (shuffle across packages)
        num_benign_sequences_needed = len(self.sequences)  # Balance dataset

        for _ in range(num_benign_sequences_needed):
            if not all_benign_embeds:
                break

            # Create benign sequence with random samples from all benign packages
            num_samples = self.rng.randint(
                10, min(self.max_benign_samples, len(all_benign_embeds)) + 1
            )

            selected_indices = self.rng.choice(
                len(all_benign_embeds), size=num_samples, replace=False
            )
            sequence = [all_benign_embeds[i] for i in selected_indices]

            self.sequences.append(sequence)
            self.labels.append(BENIGN_LABEL)
            self.sequence_types.append(f"benign_random_{num_samples}samples")

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        return self.sequences[idx], self.labels[idx]


class FocalLoss(nn.Module):
    """
    Focal loss to focus on hard examples and prevent over-reliance
    on easy classifications.
    """

    def __init__(self, alpha=1, gamma=2, reduction="mean"):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, reduction="none")
        pt = torch.exp(-ce_loss)
        focal_loss = self.alpha * (1 - pt) ** self.gamma * ce_loss

        if self.reduction == "mean":
            return focal_loss.mean()
        elif self.reduction == "sum":
            return focal_loss.sum()
        return focal_loss


def train_lstm_model(
    csv_path: str,
    output_model: str = "malwi_models/malware_lstm_model.pth",
    epochs: int = 20,
    batch_size: int = 16,
    learning_rate: float = 0.001,
    embedding_dim: int = 256,
    hidden_dim: int = 128,
    num_layers: int = 2,
    dropout: float = 0.3,
    max_benign_samples: int = 100,
    use_focal_loss: bool = True,
    device: str = "auto",
) -> bool:
    """
    Train LSTM model for malware detection.
    """
    configure_messaging(quiet=False)

    info("🧠 Training LSTM Model for Malware Detection")

    # Load embeddings
    progress("Loading embeddings...")
    try:
        embeddings_df = pd.read_csv(csv_path)
    except FileNotFoundError:
        error(f"CSV file not found: {csv_path}")
        return False
    except Exception as e:
        error(f"Failed to load CSV file: {e}")
        return False

    # Process embeddings - packages are labeled consistently (no mixed packages exist)
    malicious_packages = {}
    benign_packages = {}

    for _, row in embeddings_df.iterrows():
        embedding = np.array([float(x) for x in row["embedding"].split(",")])
        package = row["package"]
        label = row["label"]

        if label == "malicious":
            if package not in malicious_packages:
                malicious_packages[package] = []
            malicious_packages[package].append(embedding)
        else:  # benign
            if package not in benign_packages:
                benign_packages[package] = []
            benign_packages[package].append(embedding)

    info(
        f"Loaded {len(malicious_packages)} malicious packages and {len(benign_packages)} benign packages"
    )

    # Check if we have enough data
    if len(malicious_packages) == 0 or len(benign_packages) == 0:
        error("Insufficient data: need both malicious packages and benign packages")
        return False

    # Create dataset with package-aware approach
    dataset = MalwareDataset(
        malicious_packages,
        benign_packages,
        max_benign_samples=max_benign_samples,
    )

    # Analyze dataset composition
    sequence_type_counts = Counter(dataset.sequence_types)

    info("Dataset composition:")
    for seq_type, count in sequence_type_counts.items():
        info(f"  • {seq_type}: {count}")

    # Split dataset
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(
        dataset, [train_size, val_size]
    )

    # Create data loaders with custom collate
    def collate_fn(batch):
        sequences, labels = zip(*batch)
        sequences = [torch.from_numpy(np.array(seq)).float() for seq in sequences]
        padded = pad_sequence(sequences, batch_first=True, padding_value=0.0)
        labels = torch.tensor(labels, dtype=torch.long)

        # Create attention mask
        lengths = torch.tensor([len(seq) for seq in sequences])
        max_len = padded.size(1)
        attention_mask = torch.arange(max_len).unsqueeze(0) < lengths.unsqueeze(1)

        return padded, attention_mask, labels

    train_loader = DataLoader(
        train_dataset, batch_size=batch_size, shuffle=True, collate_fn=collate_fn
    )
    val_loader = DataLoader(
        val_dataset, batch_size=batch_size, shuffle=False, collate_fn=collate_fn
    )

    # Initialize model
    if device == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device(device)
    model = MalwareLSTM(
        embedding_dim=embedding_dim,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        dropout=dropout,
        num_classes=2,  # Binary: Benign, Malicious
    )
    model.to(device)

    # Loss and optimizer
    if use_focal_loss:
        criterion = FocalLoss(alpha=1, gamma=2)
        info("Using Focal Loss to focus on hard examples")
    else:
        criterion = nn.CrossEntropyLoss()

    optimizer = optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
        optimizer, T_0=5, T_mult=2
    )

    # Training loop
    best_val_f1 = 0.0

    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        train_preds = []
        train_labels = []

        for sequences, attention_mask, labels in train_loader:
            sequences = sequences.to(device)
            attention_mask = attention_mask.to(device)
            labels = labels.to(device)

            optimizer.zero_grad()
            logits = model(sequences, attention_mask, training=True)

            # Classification loss
            loss = criterion(logits, labels)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            train_loss += loss.item()
            preds = torch.argmax(logits, dim=1)
            train_preds.extend(preds.cpu().numpy())
            train_labels.extend(labels.cpu().numpy())

        # Validation
        model.eval()
        val_loss = 0.0
        val_preds = []
        val_labels = []

        with torch.no_grad():
            for sequences, attention_mask, labels in val_loader:
                sequences = sequences.to(device)
                attention_mask = attention_mask.to(device)
                labels = labels.to(device)

                logits = model(sequences, attention_mask, training=False)
                loss = criterion(logits, labels)

                val_loss += loss.item()
                preds = torch.argmax(logits, dim=1)
                val_preds.extend(preds.cpu().numpy())
                val_labels.extend(labels.cpu().numpy())

        # Calculate metrics
        # Binary classification - direct comparison
        train_acc = accuracy_score(train_labels, train_preds)
        train_f1 = f1_score(train_labels, train_preds, zero_division=0)
        val_acc = accuracy_score(val_labels, val_preds)
        val_f1 = f1_score(val_labels, val_preds, zero_division=0)

        info(f"Epoch {epoch + 1}/{epochs}:")
        info(
            f"  Train Loss: {train_loss / len(train_loader):.4f}, Acc: {train_acc:.4f}, F1: {train_f1:.4f}"
        )

        info(
            f"  Val Loss: {val_loss / len(val_loader):.4f}, Acc: {val_acc:.4f}, F1: {val_f1:.4f}"
        )

        scheduler.step()

        # Save best model
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            torch.save(model.state_dict(), output_model)
            success(f"New best model saved with F1: {val_f1:.4f}")

    success(f"Training completed! Best validation F1: {best_val_f1:.4f}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train LSTM model for malware detection"
    )
    parser.add_argument("csv_path", help="Path to embeddings CSV")
    parser.add_argument("--output-model", default="malwi_models/malware_lstm_model.pth")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument(
        "--use-focal-loss", action="store_true", help="Use focal loss for hard examples"
    )

    args = parser.parse_args()

    success_result = train_lstm_model(
        args.csv_path,
        output_model=args.output_model,
        epochs=args.epochs,
        use_focal_loss=args.use_focal_loss,
    )

    exit(0 if success_result else 1)
