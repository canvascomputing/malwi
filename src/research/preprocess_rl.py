"""
Preprocess training data for RL by computing DistilBERT embeddings.

This module pre-computes embeddings for all code samples to enable fast RL training
without repeated DistilBERT inference.
"""

import argparse
import pandas as pd
import torch
from pathlib import Path
from transformers import AutoTokenizer, DistilBertModel

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)


def preprocess_rl_embeddings(
    input_csv: str,
    output_csv: str,
    distilbert_model_path: str,
    batch_size: int = 32,
) -> bool:
    """
    Preprocess training data by computing DistilBERT embeddings.

    Args:
        input_csv: Path to training CSV with 'tokens' column
        output_csv: Path to output CSV with 'embedding' column
        distilbert_model_path: Path to pre-trained DistilBERT model
        batch_size: Batch size for embedding computation

    Returns:
        True if preprocessing succeeded, False otherwise
    """
    try:
        # Validate input file
        if not Path(input_csv).exists():
            error(f"Input CSV not found: {input_csv}")
            return False

        # Validate model path
        if not Path(distilbert_model_path).exists():
            error(f"DistilBERT model not found: {distilbert_model_path}")
            return False

        # Load DistilBERT model and tokenizer
        progress("Loading DistilBERT model and tokenizer...")
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        info(f"Using device: {device}")

        tokenizer = AutoTokenizer.from_pretrained(distilbert_model_path)
        model = DistilBertModel.from_pretrained(distilbert_model_path)
        model.to(device)
        model.eval()

        success(f"Model loaded with hidden size: {model.config.hidden_size}")

        # Load CSV
        progress(f"Loading training data from {input_csv}...")
        df = pd.read_csv(input_csv)

        if "tokens" not in df.columns or "label" not in df.columns:
            error("CSV must contain 'tokens' and 'label' columns")
            return False

        info(f"Loaded {len(df)} samples")

        # Compute embeddings
        progress("Computing DistilBERT embeddings...")
        embeddings = [""] * len(df)  # Pre-allocate with empty strings

        for i in range(0, len(df), batch_size):
            batch_df = df.iloc[i : i + batch_size]
            batch_tokens_raw = batch_df["tokens"].tolist()

            # Filter out invalid tokens and convert to strings, tracking indices
            valid_indices = []
            batch_tokens = []
            for idx, token in enumerate(batch_tokens_raw):
                if token and not pd.isna(token) and str(token).strip():
                    valid_indices.append(i + idx)
                    batch_tokens.append(str(token))

            if not batch_tokens:
                continue

            # Tokenize batch
            encoded = tokenizer(
                batch_tokens,
                return_tensors="pt",
                truncation=True,
                padding="max_length",
                max_length=512,
            )

            # Move to device
            input_ids = encoded["input_ids"].to(device)
            attention_mask = encoded["attention_mask"].to(device)

            # Get embeddings
            with torch.no_grad():
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                cls_embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()

            # Store embeddings at their original indices
            for emb_idx, df_idx in enumerate(valid_indices):
                embeddings[df_idx] = ",".join(map(str, cls_embeddings[emb_idx]))

            if (i + batch_size) % 1000 == 0:
                info(f"   Processed {min(i + batch_size, len(df))}/{len(df)} samples")

        # Remove rows with empty embeddings
        df["embedding"] = embeddings
        df_with_embeddings = df[df["embedding"] != ""].copy()

        success(
            f"Computed embeddings for {len(df_with_embeddings)} samples "
            f"(skipped {len(df) - len(df_with_embeddings)} invalid samples)"
        )

        # Save to new CSV
        progress(f"Saving embeddings to {output_csv}...")
        df_with_embeddings.to_csv(output_csv, index=False)

        success(f"✅ RL preprocessing completed successfully!")
        info(f"📁 Output saved to: {output_csv}")
        info(f"📊 Total samples: {len(df_with_embeddings)}")
        info(f"💾 File size: {Path(output_csv).stat().st_size / 1024 / 1024:.1f} MB")

        return True

    except Exception as e:
        error(f"RL preprocessing failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Preprocess training data for RL by computing DistilBERT embeddings"
    )
    parser.add_argument(
        "input_csv",
        type=str,
        help="Path to input CSV file with 'tokens' and 'label' columns",
    )
    parser.add_argument(
        "--output-csv",
        type=str,
        default="training_rl_embeddings.csv",
        help="Path to output CSV file (default: training_rl_embeddings.csv)",
    )
    parser.add_argument(
        "--distilbert-model-path",
        type=str,
        default="malwi_models",
        help="Path to pre-trained DistilBERT model directory (default: malwi_models)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="Batch size for embedding computation (default: 32)",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)

    success_result = preprocess_rl_embeddings(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        distilbert_model_path=args.distilbert_model_path,
        batch_size=args.batch_size,
    )

    exit(0 if success_result else 1)
