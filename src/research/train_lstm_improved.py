"""
Improved LSTM training with sequence-aware learning.

This module implements advanced training strategies to ensure the LSTM learns
sequence patterns rather than just detecting individual malicious embeddings.
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
import math

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
SUSPICIOUS_LABEL = 2  # New: mixed sequences


class SequenceAttentionLayer(nn.Module):
    """
    Custom attention layer that learns to focus on sequence patterns
    rather than individual embeddings.
    """

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.hidden_dim = hidden_dim

        # Multi-head self-attention for sequence relationships
        self.self_attention = nn.MultiheadAttention(
            embed_dim=hidden_dim * 2,  # Bidirectional
            num_heads=4,
            dropout=0.1,
            batch_first=True,
        )

        # Pattern detection convolutions
        self.pattern_conv = nn.Conv1d(
            in_channels=hidden_dim * 2,
            out_channels=hidden_dim,
            kernel_size=3,
            padding=1,
        )

        # Positional encoding to emphasize sequence order
        self.positional_encoding = PositionalEncoding(hidden_dim * 2)

    def forward(self, lstm_output, attention_mask):
        batch_size, seq_len, hidden_dim = lstm_output.shape

        # Add positional encoding
        lstm_output = self.positional_encoding(lstm_output)

        # Self-attention to learn relationships
        attn_output, attn_weights = self.self_attention(
            lstm_output, lstm_output, lstm_output, key_padding_mask=~attention_mask
        )

        # Convolutional pattern detection
        conv_input = lstm_output.transpose(1, 2)  # [batch, channels, seq_len]
        conv_output = self.pattern_conv(conv_input)
        conv_output = conv_output.transpose(1, 2)  # [batch, seq_len, channels]

        # Combine attention and convolution
        combined = attn_output + conv_output.repeat(1, 1, 2)  # Match dimensions

        return combined, attn_weights


class PositionalEncoding(nn.Module):
    """Sinusoidal positional encoding to emphasize sequence position."""

    def __init__(self, d_model: int, max_len: int = 5000):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe)

    def forward(self, x):
        return x + self.pe[: x.size(1), :].unsqueeze(0)


class ImprovedMalwareLSTM(nn.Module):
    """
    Enhanced LSTM model that learns sequence patterns rather than
    individual embedding detection.
    """

    def __init__(
        self,
        embedding_dim: int = 256,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_classes: int = 3,  # Benign, Malicious, Suspicious
    ):
        super().__init__()

        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim

        # Embedding dropout to prevent over-reliance on individual embeddings
        self.embedding_dropout = nn.Dropout(0.2)

        # Noise injection for robustness
        self.noise_factor = 0.1

        # Bidirectional LSTM
        self.lstm = nn.LSTM(
            input_size=embedding_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True,
        )

        # Sequence attention layer
        self.sequence_attention = SequenceAttentionLayer(hidden_dim)

        # Temporal pooling: combine max, mean, and weighted pooling
        self.temporal_weights = nn.Linear(hidden_dim * 2, 1)

        # Classification head with multiple pathways
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(
                hidden_dim * 6, hidden_dim * 2
            ),  # 3 pooling methods × 2 (bidirectional)
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, sequences, attention_mask, training=True):
        batch_size, seq_len, _ = sequences.shape

        # Apply embedding dropout and noise during training
        if training:
            sequences = self.embedding_dropout(sequences)
            # Add Gaussian noise to prevent over-reliance on exact values
            noise = torch.randn_like(sequences) * self.noise_factor
            sequences = sequences + noise

        # LSTM forward pass
        lstm_out, (hidden, cell) = self.lstm(sequences)

        # Apply sequence attention
        attended_out, attn_weights = self.sequence_attention(lstm_out, attention_mask)

        # Temporal pooling strategies
        # 1. Max pooling (can lead to single embedding detection - use carefully)
        masked_lstm = attended_out.masked_fill(
            ~attention_mask.unsqueeze(-1), -float("inf")
        )
        max_pooled = torch.max(masked_lstm, dim=1)[0]
        max_pooled = torch.where(
            torch.isfinite(max_pooled), max_pooled, torch.zeros_like(max_pooled)
        )

        # 2. Mean pooling (considers all embeddings equally)
        sum_pooled = (attended_out * attention_mask.unsqueeze(-1)).sum(dim=1)
        mean_pooled = sum_pooled / attention_mask.sum(dim=1, keepdim=True)

        # 3. Weighted pooling (learns importance of positions)
        weights = self.temporal_weights(attended_out)  # [batch, seq_len, 1]
        weights = weights.masked_fill(~attention_mask.unsqueeze(-1), -float("inf"))
        weights = F.softmax(weights, dim=1)
        weighted_pooled = (attended_out * weights).sum(dim=1)

        # Combine all pooling strategies
        combined_features = torch.cat(
            [max_pooled, mean_pooled, weighted_pooled], dim=-1
        )

        # Classification
        logits = self.classifier(combined_features)

        return logits, attn_weights


class ImprovedMalwareDataset(Dataset):
    """
    Enhanced dataset that creates more challenging training examples
    requiring true sequence understanding.
    """

    def __init__(
        self,
        malicious_packages: Dict[str, List[np.ndarray]],
        benign_embeddings: List[np.ndarray],
        max_benign_samples: int = 10,
        random_seed: int = 42,
        contamination_ratio: float = 0.3,  # For mixed sequences
    ):
        super().__init__()

        self.malicious_packages = malicious_packages
        self.benign_embeddings = benign_embeddings
        self.max_benign_samples = max_benign_samples
        self.contamination_ratio = contamination_ratio
        self.rng = np.random.RandomState(random_seed)

        self.sequences = []
        self.labels = []
        self.sequence_types = []  # Track sequence composition for analysis

        # Strategy 1: Pure malicious sequences (concentrated malicious behavior)
        for package_name, embeddings in malicious_packages.items():
            sequence = list(embeddings)
            self.sequences.append(sequence)
            self.labels.append(MALICIOUS_LABEL)
            self.sequence_types.append("pure_malicious")

        # Strategy 2: Pure benign sequences
        n_benign_sequences = len(malicious_packages)
        for _ in range(n_benign_sequences):
            n_samples = self.rng.randint(3, max_benign_samples + 1)
            selected = self.rng.choice(
                len(benign_embeddings),
                size=min(n_samples, len(benign_embeddings)),
                replace=False,
            )
            sequence = [benign_embeddings[idx] for idx in selected]
            self.sequences.append(sequence)
            self.labels.append(BENIGN_LABEL)
            self.sequence_types.append("pure_benign")

        # Strategy 3: Mixed sequences with contextual labeling
        # These force the model to learn patterns, not just detect presence
        n_mixed = len(malicious_packages) // 2

        # 3a: Mostly benign with small malicious (should be SUSPICIOUS or BENIGN based on context)
        for _ in range(n_mixed):
            n_benign = self.rng.randint(7, 10)
            n_malicious = 1  # Single malicious embedding

            # Random benign embeddings
            selected_benign = self.rng.choice(
                len(benign_embeddings), size=n_benign, replace=False
            )
            # Random malicious embedding
            mal_package = self.rng.choice(list(malicious_packages.keys()))
            mal_embeddings = malicious_packages[mal_package]
            mal_idx = self.rng.randint(0, len(mal_embeddings))

            # Create sequence with malicious at random position
            sequence = [
                benign_embeddings[idx] for idx in selected_benign[: n_benign // 2]
            ]
            sequence.append(mal_embeddings[mal_idx])
            sequence.extend(
                [benign_embeddings[idx] for idx in selected_benign[n_benign // 2 :]]
            )

            # Label as SUSPICIOUS - legitimate code with one suspicious call
            self.sequences.append(sequence)
            self.labels.append(SUSPICIOUS_LABEL)
            self.sequence_types.append("mostly_benign_with_mal")

        # 3b: Malicious patterns hidden in benign context
        for _ in range(n_mixed):
            # Start and end with benign, malicious cluster in middle
            n_benign_start = self.rng.randint(2, 4)
            n_benign_end = self.rng.randint(2, 4)

            mal_package = self.rng.choice(list(malicious_packages.keys()))
            mal_embeddings = malicious_packages[mal_package][:3]  # Take 3 malicious

            selected_benign = self.rng.choice(
                len(benign_embeddings),
                size=n_benign_start + n_benign_end,
                replace=False,
            )

            sequence = [
                benign_embeddings[idx] for idx in selected_benign[:n_benign_start]
            ]
            sequence.extend(mal_embeddings)  # Clustered malicious
            sequence.extend(
                [benign_embeddings[idx] for idx in selected_benign[n_benign_start:]]
            )

            # Label as MALICIOUS - concentrated malicious behavior pattern
            self.sequences.append(sequence)
            self.labels.append(MALICIOUS_LABEL)
            self.sequence_types.append("malicious_cluster_pattern")

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


def train_improved_lstm(
    csv_path: str,
    output_model: str = "malwi_models/malware_lstm_improved.pth",
    epochs: int = 20,
    batch_size: int = 16,
    learning_rate: float = 0.001,
    hidden_dim: int = 128,
    num_layers: int = 2,
    dropout: float = 0.3,
    max_benign_samples: int = 10,
    use_focal_loss: bool = True,
) -> bool:
    """
    Train improved LSTM model with sequence-aware learning.
    """
    configure_messaging(quiet=False)

    info("🧠 Training Improved LSTM Model with Sequence Pattern Learning")

    # Load embeddings
    progress("Loading embeddings...")
    embeddings_df = pd.read_csv(csv_path)

    # Process embeddings
    malicious_packages = {}
    benign_embeddings = []

    for _, row in embeddings_df.iterrows():
        embedding = np.array([float(x) for x in row["embedding"].split(",")])

        if row["label"] == "malicious":
            package = row["package"]
            if package not in malicious_packages:
                malicious_packages[package] = []
            malicious_packages[package].append(embedding)
        else:
            benign_embeddings.append(embedding)

    info(
        f"Loaded {len(malicious_packages)} malicious packages and {len(benign_embeddings)} benign samples"
    )

    # Create improved dataset
    dataset = ImprovedMalwareDataset(
        malicious_packages,
        benign_embeddings,
        max_benign_samples=max_benign_samples,
    )

    # Analyze dataset composition
    sequence_type_counts = {}
    for seq_type in dataset.sequence_types:
        sequence_type_counts[seq_type] = sequence_type_counts.get(seq_type, 0) + 1

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
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = ImprovedMalwareLSTM(
        embedding_dim=256,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        dropout=dropout,
        num_classes=3,  # Benign, Malicious, Suspicious
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
            logits, _ = model(sequences, attention_mask, training=True)
            loss = criterion(logits, labels)

            # Add regularization to prevent single-embedding reliance
            # Penalize high variance in attention weights (encourages distributed attention)

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

                logits, attn_weights = model(sequences, attention_mask, training=False)
                loss = criterion(logits, labels)

                val_loss += loss.item()
                preds = torch.argmax(logits, dim=1)
                val_preds.extend(preds.cpu().numpy())
                val_labels.extend(labels.cpu().numpy())

        # Calculate metrics
        # Map 3-class predictions to binary for backward compatibility
        train_binary_preds = [
            1 if p > 0 else 0 for p in train_preds
        ]  # Malicious/Suspicious = 1
        train_binary_labels = [1 if l > 0 else 0 for l in train_labels]
        val_binary_preds = [1 if p > 0 else 0 for p in val_preds]
        val_binary_labels = [1 if l > 0 else 0 for l in val_labels]

        train_acc = accuracy_score(train_binary_labels, train_binary_preds)
        train_f1 = f1_score(train_binary_labels, train_binary_preds, zero_division=0)
        val_acc = accuracy_score(val_binary_labels, val_binary_preds)
        val_f1 = f1_score(val_binary_labels, val_binary_preds, zero_division=0)

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
        description="Train improved LSTM model with sequence-aware learning"
    )
    parser.add_argument("csv_path", help="Path to embeddings CSV")
    parser.add_argument(
        "--output-model", default="malwi_models/malware_lstm_improved.pth"
    )
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument(
        "--use-focal-loss", action="store_true", help="Use focal loss for hard examples"
    )

    args = parser.parse_args()

    success_result = train_improved_lstm(
        args.csv_path,
        output_model=args.output_model,
        epochs=args.epochs,
        use_focal_loss=args.use_focal_loss,
    )

    exit(0 if success_result else 1)
