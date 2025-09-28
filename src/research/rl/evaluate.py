import argparse
import torch
from pathlib import Path
from typing import List
from transformers import AutoTokenizer
from stable_baselines3 import PPO

from research.rl.package_environment import PackageEnv
from common.messaging import configure_messaging, info, success, error


def evaluate_samples(
    model: PPO,
    code_samples: List[str],
    tokenizer: AutoTokenizer,
    device: torch.device,
    true_label: int = None,
) -> dict:
    """
    Evaluate a package (list of code samples) using the trained RL agent.

    Args:
        model: Trained PPO model
        code_samples: List of code sample strings (e.g., from one package)
        tokenizer: Tokenizer instance
        device: CPU or CUDA device
        true_label: Optional true label (0=benign, 1=malicious)

    Returns:
        Dictionary with evaluation results
    """
    env = PackageEnv(
        code_samples=code_samples,
        label=true_label if true_label is not None else 0,
        tokenizer=tokenizer,
        device=device,
        max_length=512,
    )

    model.policy.reset_lstm_states()

    obs, info_dict = env.reset()
    done = False
    steps = 0
    final_action = None

    while not done:
        action, _states = model.predict(obs, deterministic=True)
        obs, reward, terminated, truncated, info_dict = env.step(action)

        steps += 1
        done = terminated or truncated

        if action in [0, 1]:
            final_action = action
        elif done and "prediction" in info_dict:
            final_action = info_dict["prediction"]

    action_map = {0: "BENIGN", 1: "MALICIOUS", 2: "CONTINUE"}

    result = {
        "prediction": action_map.get(final_action, "UNKNOWN"),
        "prediction_label": final_action,
        "samples_processed": steps,
        "total_samples": env.num_samples,
        "early_exit": steps < env.num_samples,
    }

    if true_label is not None:
        result["true_label"] = "BENIGN" if true_label == 0 else "MALICIOUS"
        result["correct"] = final_action == true_label

    return result


def main(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    info(f"Using device: {device}")

    info(f"Loading tokenizer from {args.tokenizer_path}...")
    tokenizer = AutoTokenizer.from_pretrained(str(args.tokenizer_path))
    success(f"Tokenizer loaded with vocab size: {len(tokenizer)}")

    info(f"Loading trained PPO model from {args.model_path}...")
    model = PPO.load(args.model_path, device=device)
    success("PPO model loaded successfully")

    code_samples = []

    if args.input_file:
        info(f"Reading code sample from {args.input_file}...")
        with open(args.input_file, "r") as f:
            code_samples = [f.read()]
    elif args.input_dir:
        info(f"Reading code samples from directory {args.input_dir}...")
        input_path = Path(args.input_dir)
        for file_path in sorted(input_path.glob("**/*.py")):
            with open(file_path, "r") as f:
                code_samples.append(f.read())
        info(f"Found {len(code_samples)} code samples")
    elif args.code_sample:
        code_samples = [args.code_sample]

    if not code_samples:
        error(
            "No code samples provided. Use --code-sample, --input-file, or --input-dir"
        )
        return

    true_label = None
    if args.true_label is not None:
        if args.true_label.lower() == "benign":
            true_label = 0
        elif args.true_label.lower() == "malicious":
            true_label = 1

    info(f"Evaluating {len(code_samples)} code sample(s)...")
    result = evaluate_samples(
        model=model,
        code_samples=code_samples,
        tokenizer=tokenizer,
        device=device,
        true_label=true_label,
    )

    print("\n" + "=" * 50)
    print("RL Agent Evaluation Results (LSTM Memory)")
    print("=" * 50)
    print(f"Total samples in package: {len(code_samples)}")
    print(f"Prediction: {result['prediction']}")
    print(f"Samples processed: {result['samples_processed']}/{result['total_samples']}")
    print(f"Early exit: {result['early_exit']}")

    if "true_label" in result:
        print(f"True label: {result['true_label']}")
        print(f"Correct: {result['correct']}")

    print("=" * 50 + "\n")

    success("Evaluation completed!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate trained PPO agent on code samples with early exit"
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="malwi_models/rl/ppo_malware_agent.zip",
        help="Path to trained PPO model checkpoint",
    )
    parser.add_argument(
        "--tokenizer-path",
        type=str,
        default="malwi_models",
        help="Path to tokenizer directory",
    )
    parser.add_argument(
        "--code-sample", type=str, help="Single code sample string to evaluate"
    )
    parser.add_argument(
        "--input-file", type=str, help="Path to file containing a single code sample"
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        help="Path to directory containing multiple code samples (package)",
    )
    parser.add_argument(
        "--true-label",
        type=str,
        choices=["benign", "malicious"],
        help="True label of the sample(s) (optional, for accuracy checking)",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)
    main(args)
