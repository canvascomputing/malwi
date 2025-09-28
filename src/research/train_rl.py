import argparse
import numpy as np
import pandas as pd
import torch
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict
from transformers import AutoTokenizer
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv

from research.rl.package_environment import PackageEnv
from research.rl.embedding_environment import EmbeddingPackageEnv
from research.rl.policy import LSTMDistilBertActorCriticPolicy
from research.rl.embedding_policy import LSTMEmbeddingPolicy
from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)


def load_and_organize_embeddings(
    csv_path: str,
    test_split: float = 0.0,
    random_seed: int = 42,
) -> Tuple[
    Dict[str, List[np.ndarray]],
    List[np.ndarray],
    List[int],
    Dict[str, List[np.ndarray]],
    List[np.ndarray],
    List[int],
]:
    """
    Load CSV with embeddings and organize into malicious packages and benign samples.

    Args:
        csv_path: Path to training CSV with embeddings
        test_split: Fraction of data to hold out for testing (0.0-1.0)
        random_seed: Random seed for reproducible splits

    Returns:
        - train_malicious_packages: Training set malicious package embeddings
        - train_benign_embeddings: Training set benign embeddings
        - train_benign_labels: Training set benign labels
        - test_malicious_packages: Test set malicious package embeddings
        - test_benign_embeddings: Test set benign embeddings
        - test_benign_labels: Test set benign labels
    """
    df = pd.read_csv(csv_path)

    if "embedding" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain 'embedding' and 'label' columns")

    if "package" not in df.columns:
        warning("'package' column not found, using empty package names")
        df["package"] = ""

    malicious_packages = defaultdict(list)
    benign_embeddings = []
    benign_labels = []

    for idx, row in df.iterrows():
        embedding_str = row["embedding"]
        label_data = row["label"]
        package_data = row.get("package", "")

        if (
            pd.isna(embedding_str)
            or not isinstance(embedding_str, str)
            or not embedding_str.strip()
        ):
            continue

        embedding = np.fromstring(embedding_str, sep=",", dtype=np.float32)

        if label_data == "malicious":
            package_name = (
                package_data
                if package_data and not pd.isna(package_data)
                else "unknown"
            )
            malicious_packages[package_name].append(embedding)
        elif label_data == "benign":
            benign_embeddings.append(embedding)
            benign_labels.append(0)

    if test_split <= 0.0:
        return (
            dict(malicious_packages),
            benign_embeddings,
            benign_labels,
            {},
            [],
            [],
        )

    rng = np.random.RandomState(random_seed)

    package_names = list(malicious_packages.keys())
    rng.shuffle(package_names)

    n_test_packages = max(1, int(len(package_names) * test_split))
    test_package_names = package_names[:n_test_packages]
    train_package_names = package_names[n_test_packages:]

    train_malicious = {pkg: malicious_packages[pkg] for pkg in train_package_names}
    test_malicious = {pkg: malicious_packages[pkg] for pkg in test_package_names}

    n_test_benign = max(1, int(len(benign_embeddings) * test_split))
    benign_indices = np.arange(len(benign_embeddings))
    rng.shuffle(benign_indices)

    test_benign_indices = benign_indices[:n_test_benign]
    train_benign_indices = benign_indices[n_test_benign:]

    train_benign = [benign_embeddings[i] for i in train_benign_indices]
    train_benign_labels = [benign_labels[i] for i in train_benign_indices]

    test_benign = [benign_embeddings[i] for i in test_benign_indices]
    test_benign_labels = [benign_labels[i] for i in test_benign_indices]

    return (
        train_malicious,
        train_benign,
        train_benign_labels,
        test_malicious,
        test_benign,
        test_benign_labels,
    )


def load_and_organize_data(
    csv_path: str,
    test_split: float = 0.0,
    random_seed: int = 42,
) -> Tuple[
    Dict[str, List[str]],
    List[str],
    List[int],
    Dict[str, List[str]],
    List[str],
    List[int],
]:
    """
    Load CSV and organize into malicious packages and benign samples with train/test split.

    Args:
        csv_path: Path to training CSV
        test_split: Fraction of data to hold out for testing (0.0-1.0)
        random_seed: Random seed for reproducible splits

    Returns:
        - train_malicious_packages: Training set malicious packages
        - train_benign_samples: Training set benign samples
        - train_benign_labels: Training set benign labels
        - test_malicious_packages: Test set malicious packages (empty if test_split=0)
        - test_benign_samples: Test set benign samples
        - test_benign_labels: Test set benign labels
    """
    df = pd.read_csv(csv_path)

    if "tokens" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain 'tokens' and 'label' columns")

    if "package" not in df.columns:
        warning("'package' column not found, using empty package names")
        df["package"] = ""

    malicious_packages = defaultdict(list)
    benign_samples = []
    benign_labels = []

    for idx, row in df.iterrows():
        tokens_data = row["tokens"]
        label_data = row["label"]
        package_data = row.get("package", "")

        if (
            pd.isna(tokens_data)
            or not isinstance(tokens_data, str)
            or not tokens_data.strip()
        ):
            continue

        tokens = tokens_data.strip()

        if label_data == "malicious":
            package_name = (
                package_data
                if package_data and not pd.isna(package_data)
                else "unknown"
            )
            malicious_packages[package_name].append(tokens)
        elif label_data == "benign":
            benign_samples.append(tokens)
            benign_labels.append(0)

    if test_split <= 0.0:
        return (
            dict(malicious_packages),
            benign_samples,
            benign_labels,
            {},
            [],
            [],
        )

    rng = np.random.RandomState(random_seed)

    package_names = list(malicious_packages.keys())
    rng.shuffle(package_names)

    n_test_packages = max(1, int(len(package_names) * test_split))
    test_package_names = package_names[:n_test_packages]
    train_package_names = package_names[n_test_packages:]

    train_malicious = {pkg: malicious_packages[pkg] for pkg in train_package_names}
    test_malicious = {pkg: malicious_packages[pkg] for pkg in test_package_names}

    n_test_benign = max(1, int(len(benign_samples) * test_split))
    benign_indices = np.arange(len(benign_samples))
    rng.shuffle(benign_indices)

    test_benign_indices = benign_indices[:n_test_benign]
    train_benign_indices = benign_indices[n_test_benign:]

    train_benign = [benign_samples[i] for i in train_benign_indices]
    train_benign_labels = [benign_labels[i] for i in train_benign_indices]

    test_benign = [benign_samples[i] for i in test_benign_indices]
    test_benign_labels = [benign_labels[i] for i in test_benign_indices]

    return (
        train_malicious,
        train_benign,
        train_benign_labels,
        test_malicious,
        test_benign,
        test_benign_labels,
    )


def make_env(code_sample: str, label: int, tokenizer, device):
    """Create a single environment instance."""

    def _init():
        return CodeSampleEnv(
            code_sample=code_sample, label=label, tokenizer=tokenizer, device=device
        )

    return _init


def train_rl_agent(args):
    progress("Starting RL training with Stable-Baselines3 PPO...")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    info(f"Using device: {device}")

    info(f"Loading tokenizer from {args.tokenizer_path}...")
    tokenizer = AutoTokenizer.from_pretrained(str(args.tokenizer_path))
    success(f"Tokenizer loaded with vocab size: {len(tokenizer)}")

    info(f"Loading training data from {args.training_csv}...")
    (
        malicious_packages,
        benign_samples,
        benign_labels,
        test_malicious_packages,
        test_benign_samples,
        test_benign_labels,
    ) = load_and_organize_data(
        args.training_csv, test_split=args.test_split, random_seed=args.seed
    )

    info(f"Loaded {len(malicious_packages)} malicious packages (training)")
    info(f"Loaded {len(benign_samples)} benign samples (training)")

    if args.test_split > 0:
        info(f"Loaded {len(test_malicious_packages)} malicious packages (test)")
        info(f"Loaded {len(test_benign_samples)} benign samples (test)")

    total_malicious_files = sum(len(files) for files in malicious_packages.values())
    info(f"Total malicious files across all packages: {total_malicious_files}")

    if len(malicious_packages) == 0 or len(benign_samples) == 0:
        error("Need both malicious packages and benign samples for training")
        return

    package_names = list(malicious_packages.keys())
    info(
        f"Malicious packages: {package_names[:10]}..."
        if len(package_names) > 10
        else f"Malicious packages: {package_names}"
    )

    info(f"Creating PPO model with LSTM DistilBERT policy...")

    dummy_env = PackageEnv(
        code_samples=[benign_samples[0]],
        label=0,
        tokenizer=tokenizer,
        device=device,
        max_length=512,
    )
    vec_env = DummyVecEnv([lambda: dummy_env])

    model = PPO(
        LSTMDistilBertActorCriticPolicy,
        vec_env,
        policy_kwargs={
            "distilbert_model_path": args.distilbert_model_path,
            "lstm_hidden_size": 256,
            "lstm_num_layers": 1,
        },
        learning_rate=args.learning_rate,
        n_steps=args.n_steps,
        batch_size=args.batch_size,
        n_epochs=args.ppo_epochs,
        gamma=args.gamma,
        gae_lambda=0.95,
        clip_range=0.2,
        ent_coef=0.01,
        verbose=1,
        device=device,
    )

    success("PPO model created successfully")

    info(f"Starting training for {args.epochs} epochs...")
    info(
        f"PPO Parameters: learning_rate={args.learning_rate}, n_steps={args.n_steps}, batch_size={args.batch_size}"
    )
    info(
        f"Benign samples per package range: {args.min_benign_samples} to {args.max_benign_samples}"
    )

    rng = np.random.RandomState(42)
    total_timesteps = 0

    for epoch in range(args.epochs):
        progress(f"Epoch {epoch + 1}/{args.epochs}")

        shuffled_packages = rng.permutation(package_names).tolist()

        for pkg_idx, package_name in enumerate(shuffled_packages):
            package_files = malicious_packages[package_name]

            info(
                f"  📦 Package {pkg_idx + 1}/{len(shuffled_packages)}: {package_name} ({len(package_files)} samples)"
            )

            info(
                f"     🔴 Training on malicious package (all {len(package_files)} samples collectively)"
            )
            env = PackageEnv(
                code_samples=package_files,
                label=1,
                tokenizer=tokenizer,
                device=device,
                max_length=512,
            )
            vec_env = DummyVecEnv([lambda e=env: e])
            model.set_env(vec_env)

            model.policy.reset_lstm_states()

            model.learn(
                total_timesteps=args.n_steps,
                reset_num_timesteps=False,
                progress_bar=False,
            )
            total_timesteps += args.n_steps

            n_benign = rng.randint(args.min_benign_samples, args.max_benign_samples + 1)
            selected_benign_indices = rng.choice(
                len(benign_samples),
                size=min(n_benign, len(benign_samples)),
                replace=False,
            )

            info(f"     🟢 Training on {n_benign} benign samples")

            for benign_count, benign_idx in enumerate(selected_benign_indices):
                model.policy.reset_lstm_states()

                info(f"        Benign sample {benign_count + 1}/{n_benign}")
                env = PackageEnv(
                    code_samples=[benign_samples[benign_idx]],
                    label=0,
                    tokenizer=tokenizer,
                    device=device,
                    max_length=512,
                )
                vec_env = DummyVecEnv([lambda e=env: e])
                model.set_env(vec_env)

                model.learn(
                    total_timesteps=args.n_steps,
                    reset_num_timesteps=False,
                    progress_bar=False,
                )
                total_timesteps += args.n_steps

            info(f"     ✓ Package complete - Total timesteps: {total_timesteps:,}")

        success(f"Epoch {epoch + 1} completed - Total timesteps: {total_timesteps}")

    output_path = Path(args.output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    model_save_path = output_path / "ppo_malware_agent"
    info(f"Saving PPO model to {model_save_path}...")
    model.save(model_save_path)
    success(f"PPO model saved to {model_save_path}")

    test_metrics = {}
    if args.test_split > 0 and (
        len(test_malicious_packages) > 0 or len(test_benign_samples) > 0
    ):
        progress("Evaluating on test set...")

        correct = 0
        total = 0
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0

        for package_name, package_files in test_malicious_packages.items():
            env = PackageEnv(
                code_samples=package_files,
                label=1,
                tokenizer=tokenizer,
                device=device,
                max_length=512,
            )
            vec_env = DummyVecEnv([lambda e=env: e])
            model.set_env(vec_env)

            model.policy.reset_lstm_states()

            obs, _ = env.reset()
            done = False
            prediction = None

            while not done:
                action, _ = model.predict(obs, deterministic=True)
                obs, reward, terminated, truncated, info_dict = env.step(action)
                done = terminated or truncated

                if "prediction" in info_dict:
                    prediction = info_dict["prediction"]

            if prediction is not None:
                total += 1
                if prediction == 1:
                    correct += 1
                    true_positives += 1
                else:
                    false_negatives += 1

        for benign_idx in range(len(test_benign_samples)):
            env = PackageEnv(
                code_samples=[test_benign_samples[benign_idx]],
                label=0,
                tokenizer=tokenizer,
                device=device,
                max_length=512,
            )
            vec_env = DummyVecEnv([lambda e=env: e])
            model.set_env(vec_env)

            model.policy.reset_lstm_states()

            obs, _ = env.reset()
            done = False
            prediction = None

            while not done:
                action, _ = model.predict(obs, deterministic=True)
                obs, reward, terminated, truncated, info_dict = env.step(action)
                done = terminated or truncated

                if "prediction" in info_dict:
                    prediction = info_dict["prediction"]

            if prediction is not None:
                total += 1
                if prediction == 0:
                    correct += 1
                    true_negatives += 1
                else:
                    false_positives += 1

        accuracy = correct / total if total > 0 else 0.0
        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0.0
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0
            else 0.0
        )
        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        test_metrics = {
            "test_accuracy": accuracy,
            "test_precision": precision,
            "test_recall": recall,
            "test_f1": f1,
            "test_true_positives": true_positives,
            "test_false_positives": false_positives,
            "test_true_negatives": true_negatives,
            "test_false_negatives": false_negatives,
            "test_total": total,
        }

        success(f"Test Set Results:")
        info(f"  Accuracy: {accuracy:.4f}")
        info(f"  Precision: {precision:.4f}")
        info(f"  Recall: {recall:.4f}")
        info(f"  F1 Score: {f1:.4f}")
        info(f"  True Positives: {true_positives}")
        info(f"  False Positives: {false_positives}")
        info(f"  True Negatives: {true_negatives}")
        info(f"  False Negatives: {false_negatives}")

    metrics = {
        "epochs": args.epochs,
        "malicious_packages": len(malicious_packages),
        "total_malicious_files": total_malicious_files,
        "benign_samples": len(benign_samples),
        "total_timesteps": total_timesteps,
        "learning_rate": args.learning_rate,
        "n_steps": args.n_steps,
        "batch_size": args.batch_size,
        "ppo_epochs": args.ppo_epochs,
        "gamma": args.gamma,
        "min_benign_samples": args.min_benign_samples,
        "max_benign_samples": args.max_benign_samples,
        **test_metrics,
    }

    metrics_path = output_path / "training_metrics.txt"
    with open(metrics_path, "w") as f:
        f.write("Stable-Baselines3 PPO Training Metrics\n")
        f.write("=" * 40 + "\n\n")
        for key, value in metrics.items():
            f.write(f"{key}: {value}\n")
    success(f"Training metrics saved to {metrics_path}")

    success("Training completed successfully!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train RL agent for malware detection with early exit using Stable-Baselines3"
    )
    parser.add_argument(
        "training_csv",
        type=str,
        help="Path to training CSV file with 'tokens' and 'label' columns",
    )
    parser.add_argument(
        "--distilbert-model-path",
        type=str,
        default="malwi_models",
        help="Path to pre-trained DistilBERT model directory",
    )
    parser.add_argument(
        "--tokenizer-path",
        type=str,
        default="malwi_models",
        help="Path to tokenizer directory",
    )
    parser.add_argument(
        "--output-path",
        type=str,
        default="malwi_models/rl",
        help="Output directory for RL agent and metrics",
    )
    parser.add_argument(
        "--epochs", type=int, default=3, help="Number of training epochs"
    )
    parser.add_argument(
        "--min-benign-samples",
        type=int,
        default=1,
        help="Minimum number of benign samples per malicious package",
    )
    parser.add_argument(
        "--max-benign-samples",
        type=int,
        default=5,
        help="Maximum number of benign samples per malicious package",
    )
    parser.add_argument(
        "--learning-rate", type=float, default=3e-4, help="Learning rate for PPO"
    )
    parser.add_argument(
        "--n-steps",
        type=int,
        default=2048,
        help="Number of steps to run for each environment per update",
    )
    parser.add_argument(
        "--batch-size", type=int, default=64, help="Minibatch size for PPO"
    )
    parser.add_argument(
        "--ppo-epochs",
        type=int,
        default=10,
        help="Number of epochs when optimizing the surrogate loss",
    )
    parser.add_argument("--gamma", type=float, default=0.99, help="Discount factor")
    parser.add_argument(
        "--test-split",
        type=float,
        default=0.2,
        help="Fraction of data to hold out for testing (default: 0.2 = 20%)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible train/test splits",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)
    train_rl_agent(args)
