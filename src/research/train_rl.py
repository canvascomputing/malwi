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

from research.rl.environment import CodeSampleEnv
from research.rl.policy import DistilBertActorCriticPolicy
from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)


def load_and_organize_data(
    csv_path: str,
) -> Tuple[Dict[str, List[str]], List[str], List[int]]:
    """
    Load CSV and organize into malicious packages and benign samples.

    Returns:
        - malicious_packages: Dict mapping package names to list of token strings
        - benign_samples: List of benign token strings
        - benign_labels: List of labels (all 0) for benign samples
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

    return dict(malicious_packages), benign_samples, benign_labels


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
    malicious_packages, benign_samples, benign_labels = load_and_organize_data(
        args.training_csv
    )

    info(f"Loaded {len(malicious_packages)} malicious packages")
    info(f"Loaded {len(benign_samples)} benign samples")

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

    info(f"Creating PPO model with DistilBERT policy...")

    dummy_env = CodeSampleEnv(
        code_sample=benign_samples[0], label=0, tokenizer=tokenizer, device=device
    )
    vec_env = DummyVecEnv([lambda: dummy_env])

    model = PPO(
        DistilBertActorCriticPolicy,
        vec_env,
        policy_kwargs={
            "distilbert_model_path": args.distilbert_model_path,
            "net_arch": [256, 256],
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

            for file_tokens in package_files:
                env = CodeSampleEnv(
                    code_sample=file_tokens, label=1, tokenizer=tokenizer, device=device
                )
                vec_env = DummyVecEnv([lambda e=env: e])
                model.set_env(vec_env)

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

            for benign_idx in selected_benign_indices:
                env = CodeSampleEnv(
                    code_sample=benign_samples[benign_idx],
                    label=0,
                    tokenizer=tokenizer,
                    device=device,
                )
                vec_env = DummyVecEnv([lambda e=env: e])
                model.set_env(vec_env)

                model.learn(
                    total_timesteps=args.n_steps,
                    reset_num_timesteps=False,
                    progress_bar=False,
                )
                total_timesteps += args.n_steps

            if (pkg_idx + 1) % 10 == 0:
                info(
                    f"  Package {pkg_idx + 1}/{len(shuffled_packages)} - Total timesteps: {total_timesteps}"
                )

        success(f"Epoch {epoch + 1} completed - Total timesteps: {total_timesteps}")

    output_path = Path(args.output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    model_save_path = output_path / "ppo_malware_agent"
    info(f"Saving PPO model to {model_save_path}...")
    model.save(model_save_path)
    success(f"PPO model saved to {model_save_path}")

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

    args = parser.parse_args()
    configure_messaging(quiet=False)
    train_rl_agent(args)
