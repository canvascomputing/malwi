import argparse
import torch
from pathlib import Path
from transformers import AutoTokenizer
from stable_baselines3 import PPO

from research.rl.environment import CodeSampleEnv, CHUNK_SIZE, MAX_CHUNKS
from common.messaging import configure_messaging, info, success, error


def evaluate_sample(
    model: PPO,
    code_sample: str,
    tokenizer: AutoTokenizer,
    device: torch.device,
    true_label: int = None,
) -> dict:
    env = CodeSampleEnv(
        code_sample=code_sample,
        label=true_label if true_label is not None else 0,
        tokenizer=tokenizer,
        device=device,
    )

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
        "chunks_processed": steps,
        "total_chunks": env.num_chunks,
        "early_exit": steps < env.num_chunks,
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

    if args.input_file:
        info(f"Reading code sample from {args.input_file}...")
        with open(args.input_file, "r") as f:
            code_sample = f.read()
    else:
        code_sample = args.code_sample

    if not code_sample:
        error("No code sample provided. Use --code-sample or --input-file")
        return

    true_label = None
    if args.true_label is not None:
        if args.true_label.lower() == "benign":
            true_label = 0
        elif args.true_label.lower() == "malicious":
            true_label = 1

    info("Evaluating code sample...")
    result = evaluate_sample(
        model=model,
        code_sample=code_sample,
        tokenizer=tokenizer,
        device=device,
        true_label=true_label,
    )

    print("\n" + "=" * 50)
    print("PPO Agent Evaluation Results")
    print("=" * 50)
    print(f"Prediction: {result['prediction']}")
    print(f"Chunks processed: {result['chunks_processed']}/{result['total_chunks']}")
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
        "--code-sample", type=str, help="Code sample string to evaluate"
    )
    parser.add_argument(
        "--input-file", type=str, help="Path to file containing code sample"
    )
    parser.add_argument(
        "--true-label",
        type=str,
        choices=["benign", "malicious"],
        help="True label of the sample (optional, for accuracy checking)",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)
    main(args)
