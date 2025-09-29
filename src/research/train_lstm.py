"""
Train LSTM model on pre-computed embeddings for malware detection.

This module trains a simpler LSTM-based classifier using pre-computed DistilBERT embeddings
from preprocess_rl.py, avoiding the overhead of reinforcement learning.
"""

import argparse
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from pathlib import Path
from typing import Dict, List, Tuple
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from torch.utils.data import Dataset, DataLoader
from torch.nn.utils.rnn import pad_sequence

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)


class MalwareSequenceDataset(Dataset):
    """Dataset for malware sequences with pre-computed embeddings."""

    def __init__(
        self,
        malicious_packages: Dict[str, List[np.ndarray]],
        benign_embeddings: List[np.ndarray],
        max_benign_samples: int = 10,
        random_seed: int = 42,
    ):
        """
        Initialize dataset with malicious packages and benign samples.

        Args:
            malicious_packages: Dict mapping package names to lists of embeddings
            benign_embeddings: List of benign sample embeddings
            max_benign_samples: Maximum number of benign samples to include per sequence
            random_seed: Random seed for reproducible sampling
        """
        self.malicious_packages = malicious_packages
        self.benign_embeddings = benign_embeddings
        self.max_benign_samples = max_benign_samples
        self.rng = np.random.RandomState(random_seed)

        # Build sequences: one per malicious package + some benign sequences
        self.sequences = []
        self.labels = []

        # Add malicious sequences (one per package)
        for package_name, embeddings in malicious_packages.items():
            # Add some random benign samples to the sequence
            n_benign = self.rng.randint(1, max_benign_samples + 1)
            selected_benign = self.rng.choice(
                len(benign_embeddings),
                size=min(n_benign, len(benign_embeddings)),
                replace=False,
            )

            # Create sequence: benign samples + malicious samples
            sequence = []
            for idx in selected_benign:
                sequence.append(benign_embeddings[idx])
            for emb in embeddings:
                sequence.append(emb)

            self.sequences.append(sequence)
            self.labels.append(1)  # Malicious

        # Add some purely benign sequences
        n_benign_sequences = len(malicious_packages) // 2
        for _ in range(n_benign_sequences):
            n_samples = self.rng.randint(1, max_benign_samples + 1)
            selected_benign = self.rng.choice(
                len(benign_embeddings),
                size=min(n_samples, len(benign_embeddings)),
                replace=False,
            )

            sequence = [benign_embeddings[idx] for idx in selected_benign]
            self.sequences.append(sequence)
            self.labels.append(0)  # Benign

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        sequence = self.sequences[idx]
        label = self.labels[idx]

        # Convert to tensor
        sequence_tensor = torch.stack([torch.from_numpy(emb) for emb in sequence])

        return sequence_tensor, torch.tensor(label, dtype=torch.long)


def collate_fn(batch):
    """Collate function to handle variable-length sequences."""
    sequences, labels = zip(*batch)

    # Pad sequences to same length
    padded_sequences = pad_sequence(sequences, batch_first=True, padding_value=0.0)

    # Create attention mask (1 for real tokens, 0 for padding)
    lengths = torch.tensor([len(seq) for seq in sequences])
    batch_size, max_len = padded_sequences.shape[:2]
    attention_mask = torch.arange(max_len).expand(
        batch_size, max_len
    ) < lengths.unsqueeze(1)

    labels = torch.stack(labels)

    return padded_sequences, attention_mask, labels


class MalwareLSTM(nn.Module):
    """LSTM model for malware detection on embedding sequences."""

    def __init__(
        self,
        embedding_dim: int = 256,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_classes: int = 2,
    ):
        """
        Initialize LSTM model.

        Args:
            embedding_dim: Dimension of input embeddings (from DistilBERT)
            hidden_dim: Hidden dimension of LSTM
            num_layers: Number of LSTM layers
            dropout: Dropout rate
            num_classes: Number of output classes (2 for binary classification)
        """
        super().__init__()

        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # LSTM layers
        self.lstm = nn.LSTM(
            input_size=embedding_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True,
        )

        # Classification head
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),  # *2 for bidirectional
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, sequences, attention_mask):
        """
        Forward pass.

        Args:
            sequences: Padded sequences [batch_size, seq_len, embedding_dim]
            attention_mask: Attention mask [batch_size, seq_len]

        Returns:
            logits: Classification logits [batch_size, num_classes]
        """
        batch_size, seq_len, _ = sequences.shape

        # LSTM forward pass
        lstm_out, (hidden, cell) = self.lstm(sequences)

        # Use attention mask to get the last valid output for each sequence
        # Find the last non-padded position for each sequence
        lengths = attention_mask.sum(dim=1) - 1  # -1 for 0-indexing

        # Gather the last valid LSTM output for each sequence
        batch_indices = torch.arange(batch_size, device=sequences.device)
        last_outputs = lstm_out[batch_indices, lengths]

        # Classification
        logits = self.classifier(last_outputs)

        return logits


def load_embeddings_data(
    csv_path: str,
) -> Tuple[Dict[str, List[np.ndarray]], List[np.ndarray]]:
    """Load pre-computed embeddings from CSV."""
    from research.train_rl import load_and_organize_embeddings

    progress(f"Loading embeddings from {csv_path}...")

    # Load with train/test split disabled
    train_mal, train_benign, _, _, _, _ = load_and_organize_embeddings(
        csv_path, test_split=0.0
    )

    info(
        f"Loaded {len(train_mal)} malicious packages and {len(train_benign)} benign samples"
    )

    return train_mal, train_benign


def train_lstm_model(
    csv_path: str,
    output_model_path: str,
    epochs: int = 10,
    batch_size: int = 16,
    learning_rate: float = 0.001,
    hidden_dim: int = 128,
    num_layers: int = 2,
    dropout: float = 0.3,
    max_benign_samples: int = 10,
    device: str = "auto",
) -> bool:
    """
    Train LSTM model on pre-computed embeddings.

    Args:
        csv_path: Path to CSV with pre-computed embeddings
        output_model_path: Path to save trained model
        epochs: Number of training epochs
        batch_size: Batch size for training
        learning_rate: Learning rate for optimizer
        hidden_dim: Hidden dimension of LSTM
        num_layers: Number of LSTM layers
        dropout: Dropout rate
        max_benign_samples: Maximum benign samples per sequence
        device: Device to use ('auto', 'cuda', 'cpu')

    Returns:
        True if training succeeded, False otherwise
    """
    try:
        # Set device
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"
        device = torch.device(device)
        info(f"Using device: {device}")

        # Load data
        malicious_packages, benign_embeddings = load_embeddings_data(csv_path)

        if not malicious_packages or not benign_embeddings:
            error("No data loaded. Check CSV file and ensure it has embeddings.")
            return False

        # Determine embedding dimension
        first_embedding = next(iter(malicious_packages.values()))[0]
        embedding_dim = first_embedding.shape[0]
        info(f"Embedding dimension: {embedding_dim}")

        # Create dataset and dataloader
        progress("Creating dataset...")
        dataset = MalwareSequenceDataset(
            malicious_packages=malicious_packages,
            benign_embeddings=benign_embeddings,
            max_benign_samples=max_benign_samples,
        )

        info(f"Created dataset with {len(dataset)} sequences")
        info(f"Malicious sequences: {sum(dataset.labels)}")
        info(f"Benign sequences: {len(dataset.labels) - sum(dataset.labels)}")

        # Split into train/validation
        train_size = int(0.8 * len(dataset))
        val_size = len(dataset) - train_size
        train_dataset, val_dataset = torch.utils.data.random_split(
            dataset, [train_size, val_size]
        )

        train_loader = DataLoader(
            train_dataset, batch_size=batch_size, shuffle=True, collate_fn=collate_fn
        )
        val_loader = DataLoader(
            val_dataset, batch_size=batch_size, shuffle=False, collate_fn=collate_fn
        )

        # Create model
        progress("Initializing model...")
        model = MalwareLSTM(
            embedding_dim=embedding_dim,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            dropout=dropout,
        ).to(device)

        info(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

        # Training setup
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=5, gamma=0.5)

        best_val_f1 = 0.0

        # Training loop
        progress("Starting training...")
        for epoch in range(epochs):
            # Training phase
            model.train()
            train_loss = 0.0
            train_preds = []
            train_labels = []

            for batch_idx, (sequences, attention_mask, labels) in enumerate(
                train_loader
            ):
                sequences = sequences.to(device)
                attention_mask = attention_mask.to(device)
                labels = labels.to(device)

                optimizer.zero_grad()

                logits = model(sequences, attention_mask)
                loss = criterion(logits, labels)

                loss.backward()
                optimizer.step()

                train_loss += loss.item()

                # Collect predictions
                preds = torch.argmax(logits, dim=1)
                train_preds.extend(preds.cpu().numpy())
                train_labels.extend(labels.cpu().numpy())

            # Validation phase
            model.eval()
            val_loss = 0.0
            val_preds = []
            val_labels = []

            with torch.no_grad():
                for sequences, attention_mask, labels in val_loader:
                    sequences = sequences.to(device)
                    attention_mask = attention_mask.to(device)
                    labels = labels.to(device)

                    logits = model(sequences, attention_mask)
                    loss = criterion(logits, labels)

                    val_loss += loss.item()

                    preds = torch.argmax(logits, dim=1)
                    val_preds.extend(preds.cpu().numpy())
                    val_labels.extend(labels.cpu().numpy())

            # Calculate metrics
            train_acc = accuracy_score(train_labels, train_preds)
            train_f1 = f1_score(train_labels, train_preds, average="binary")

            val_acc = accuracy_score(val_labels, val_preds)
            val_f1 = f1_score(val_labels, val_preds, average="binary")
            val_precision = precision_score(val_labels, val_preds, average="binary")
            val_recall = recall_score(val_labels, val_preds, average="binary")

            # Learning rate scheduling
            scheduler.step()

            # Print epoch results
            info(f"Epoch {epoch + 1}/{epochs}:")
            info(
                f"  Train Loss: {train_loss / len(train_loader):.4f}, Acc: {train_acc:.4f}, F1: {train_f1:.4f}"
            )
            info(
                f"  Val Loss: {val_loss / len(val_loader):.4f}, Acc: {val_acc:.4f}, F1: {val_f1:.4f}"
            )
            info(f"  Val Precision: {val_precision:.4f}, Recall: {val_recall:.4f}")

            # Save best model
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                torch.save(model.state_dict(), output_model_path)
                success(f"New best model saved with F1: {val_f1:.4f}")

        success(f"✅ Training completed! Best validation F1: {best_val_f1:.4f}")
        success(f"📁 Model saved to: {output_model_path}")

        return True

    except Exception as e:
        error(f"Training failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train LSTM model on pre-computed embeddings for malware detection"
    )
    parser.add_argument(
        "csv_path",
        type=str,
        help="Path to CSV file with pre-computed embeddings from preprocess_rl.py",
    )
    parser.add_argument(
        "--output-model",
        type=str,
        default="malware_lstm_model.pth",
        help="Path to save trained model (default: malware_lstm_model.pth)",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=10,
        help="Number of training epochs (default: 10)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Batch size for training (default: 16)",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=0.001,
        help="Learning rate for optimizer (default: 0.001)",
    )
    parser.add_argument(
        "--hidden-dim",
        type=int,
        default=128,
        help="Hidden dimension of LSTM (default: 128)",
    )
    parser.add_argument(
        "--num-layers",
        type=int,
        default=2,
        help="Number of LSTM layers (default: 2)",
    )
    parser.add_argument(
        "--dropout",
        type=float,
        default=0.3,
        help="Dropout rate (default: 0.3)",
    )
    parser.add_argument(
        "--max-benign-samples",
        type=int,
        default=10,
        help="Maximum benign samples per sequence (default: 10)",
    )
    parser.add_argument(
        "--device",
        type=str,
        default="auto",
        choices=["auto", "cuda", "cpu"],
        help="Device to use for training (default: auto)",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)

    success_result = train_lstm_model(
        csv_path=args.csv_path,
        output_model_path=args.output_model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
        dropout=args.dropout,
        max_benign_samples=args.max_benign_samples,
        device=args.device,
    )

    exit(0 if success_result else 1)
