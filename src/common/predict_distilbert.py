import logging
import os
import sys
from typing import Dict, Any, Optional, List
import threading

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, DistilBertForSequenceClassification

# Disable tokenizers parallelism to avoid warnings in multiprocessing contexts
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Version-specific model repositories
from malwi._version import __version__


def get_model_config_for_version(version: str) -> Dict[str, str]:
    """Get the appropriate model repository and revision for a given malwi version."""
    # Map malwi versions to model configurations
    # IMPORTANT: Use actual commit hashes, not tags, to ensure reproducibility
    VERSION_TO_MODEL_CONFIG = {
        "0.0.21": {
            "repo": "schirrmacher/malwi",
            "revision": "21f808cda19f6a465bbdd568960f6b0291321cdf",  # Pinned: 2025-08-14
        },
        "0.0.23": {
            "repo": "schirrmacher/malwi",
            "revision": "fcc6037664c00c9b1b1890b733b5898042e945c6",  # Pinned: 2025-08-19, F1=0.953
        },
        # Future versions will be added here as they are released
        # "0.0.24": {
        #     "repo": "schirrmacher/malwi",
        #     "revision": "COMMIT_HASH"  # Pin when releasing
        # },
        # Fallback for development/unreleased versions
        "default": {
            "repo": "schirrmacher/malwi",
            "revision": "main",  # Latest for development
        },
    }

    # Extract major.minor.patch from version
    base_version = ".".join(__version__.split(".")[:3])
    return VERSION_TO_MODEL_CONFIG.get(base_version, VERSION_TO_MODEL_CONFIG["default"])


# Get model configuration for current version
MODEL_CONFIG = get_model_config_for_version(__version__)
HF_REPO_NAME = MODEL_CONFIG["repo"]
HF_MODEL_REVISION = MODEL_CONFIG["revision"]
HF_TOKENIZER_NAME = HF_REPO_NAME
HF_MODEL_NAME = HF_REPO_NAME

HF_TOKENIZER_INSTANCE = None
HF_MODEL_INSTANCE = None
HF_DEVICE_INSTANCE = None
HF_DEVICE_IDS = None  # List of GPU device IDs
USE_MULTI_GPU = False

# Thread-local storage for tokenizers to avoid "Already borrowed" errors
_thread_local = threading.local()

# Singleton lock for model initialization
_model_init_lock = threading.Lock()
_models_initialized = False

# Higher == Faster
WINDOW_STRIDE = 384


def _ensure_models_initialized():
    """Ensure models are initialized exactly once (singleton pattern)."""
    global _models_initialized
    if not _models_initialized:
        with _model_init_lock:
            # Double-check after acquiring lock
            if not _models_initialized:
                initialize_models()
                _models_initialized = True


def get_thread_tokenizer():
    """Get a thread-local tokenizer instance to avoid 'Already borrowed' errors."""
    if not hasattr(_thread_local, "tokenizer"):
        # Ensure models are initialized (thread-safe singleton)
        _ensure_models_initialized()

        # Create a new tokenizer instance for this thread
        actual_tokenizer_path = getattr(
            _thread_local, "tokenizer_path", HF_TOKENIZER_NAME
        )
        _thread_local.tokenizer = AutoTokenizer.from_pretrained(
            actual_tokenizer_path, revision=HF_MODEL_REVISION, trust_remote_code=True
        )
    return _thread_local.tokenizer


def initialize_models(
    model_path: Optional[str] = None, tokenizer_path: Optional[str] = None
):
    logging.getLogger("transformers").setLevel(logging.ERROR)
    global \
        HF_TOKENIZER_INSTANCE, \
        HF_MODEL_INSTANCE, \
        HF_DEVICE_INSTANCE, \
        HF_MODEL_NAME, \
        HF_TOKENIZER_NAME, \
        HF_DEVICE_IDS, \
        USE_MULTI_GPU, \
        _models_initialized

    if HF_MODEL_INSTANCE is not None:
        return

    actual_tokenizer_path = tokenizer_path if tokenizer_path else HF_TOKENIZER_NAME
    actual_model_path = model_path if model_path else HF_MODEL_NAME

    # Store tokenizer path for thread-local instances
    _thread_local.tokenizer_path = actual_tokenizer_path

    try:
        HF_TOKENIZER_INSTANCE = AutoTokenizer.from_pretrained(
            actual_tokenizer_path, revision=HF_MODEL_REVISION, trust_remote_code=True
        )
        HF_MODEL_INSTANCE = DistilBertForSequenceClassification.from_pretrained(
            actual_model_path, revision=HF_MODEL_REVISION, trust_remote_code=True
        )

        # Setup device configuration for single or multi-GPU
        if torch.cuda.is_available():
            gpu_count = torch.cuda.device_count()
            if gpu_count > 1:
                # Multi-GPU setup
                HF_DEVICE_IDS = list(range(gpu_count))
                HF_DEVICE_INSTANCE = torch.device(f"cuda:{HF_DEVICE_IDS[0]}")
                HF_MODEL_INSTANCE = torch.nn.DataParallel(
                    HF_MODEL_INSTANCE, device_ids=HF_DEVICE_IDS
                )
                USE_MULTI_GPU = True
            else:
                # Single GPU setup
                HF_DEVICE_INSTANCE = torch.device("cuda:0")
                HF_DEVICE_IDS = [0]
                USE_MULTI_GPU = False
        elif torch.backends.mps.is_available():
            # Apple Silicon GPU setup
            HF_DEVICE_INSTANCE = torch.device("mps")
            HF_DEVICE_IDS = None
            USE_MULTI_GPU = False
        else:
            # CPU fallback
            HF_DEVICE_INSTANCE = torch.device("cpu")
            HF_DEVICE_IDS = None
            USE_MULTI_GPU = False

        HF_MODEL_INSTANCE.to(HF_DEVICE_INSTANCE)
        HF_MODEL_INSTANCE.eval()

        # Mark models as successfully initialized
        _models_initialized = True
    except Exception as e:
        logging.error(f"Failed to load HF model/tokenizer: {e}")
        HF_TOKENIZER_INSTANCE = HF_MODEL_INSTANCE = HF_DEVICE_INSTANCE = None
        _models_initialized = False


def _get_windowed_predictions(
    input_ids: torch.Tensor, attention_mask: torch.Tensor
) -> List[Dict[str, Any]]:
    """
    Run inference on multiple sliding windows of a single long input.
    """
    window_results = []
    max_length = get_thread_tokenizer().model_max_length
    num_tokens = attention_mask.sum().item()

    # The loop correctly iterates through all valid starting positions.
    for i in range(0, num_tokens, WINDOW_STRIDE):
        start_idx = i
        end_idx = i + max_length

        window_input_ids = input_ids[0, start_idx:end_idx]
        window_attention_mask = attention_mask[0, start_idx:end_idx]

        padding_needed = max_length - len(window_input_ids)
        if padding_needed > 0:
            pad_tensor = torch.tensor(
                [get_thread_tokenizer().pad_token_id] * padding_needed,
                device=HF_DEVICE_INSTANCE,
            )
            window_input_ids = torch.cat([window_input_ids, pad_tensor])

            mask_pad_tensor = torch.tensor(
                [0] * padding_needed, device=HF_DEVICE_INSTANCE
            )
            window_attention_mask = torch.cat([window_attention_mask, mask_pad_tensor])

        model_inputs = {
            "input_ids": window_input_ids.unsqueeze(0),
            "attention_mask": window_attention_mask.unsqueeze(0),
        }

        with torch.no_grad():
            outputs = HF_MODEL_INSTANCE(**model_inputs)

        if hasattr(outputs, "logits"):
            logits = outputs.logits
            probabilities = F.softmax(logits, dim=-1).cpu()[0]

            # Get label mapping from model config
            if (
                hasattr(HF_MODEL_INSTANCE.config, "id2label")
                and HF_MODEL_INSTANCE.config.id2label
                and not any(
                    k.startswith("LABEL_")
                    for k in HF_MODEL_INSTANCE.config.id2label.values()
                )
            ):
                label_map = HF_MODEL_INSTANCE.config.id2label
            else:
                # Fallback for backward compatibility with binary models
                label_map = {0: "benign", 1: "malicious"}

            # Create labels dictionary with confidence scores
            labels_dict = {}
            for idx, prob in enumerate(probabilities.tolist()):
                if idx in label_map:
                    label_name = label_map[idx]
                    labels_dict[label_name] = prob

            # Get the highest confidence label
            prediction_idx = torch.argmax(probabilities).item()
            predicted_label = label_map.get(prediction_idx, f"unknown_{prediction_idx}")

            window_results.append(
                {
                    "window_index": len(window_results),
                    "index": prediction_idx,
                    "label": predicted_label,
                    "probabilities": probabilities.tolist(),
                    "labels": labels_dict,
                }
            )

        # --- THIS BLOCK IS REMOVED ---
        # if end_idx >= num_tokens:
        #     break

    return window_results


def get_node_text_prediction(text_input: str) -> Dict[str, Any]:
    prediction_debug_info: Dict[str, Any] = {
        "tokenization_performed": False,
        "windowing_performed": False,
        "window_count": 0,
        "aggregation_strategy": "N/A",
        "original_text_snippet": (
            text_input[:200] + "..." if isinstance(text_input, str) else ""
        ),
    }

    if not isinstance(text_input, str):
        return {
            "status": "error",
            "message": "Input_Error_Invalid_Text_Input_Type",
            "prediction_debug": prediction_debug_info,
        }

    # Ensure models are initialized (singleton pattern)
    _ensure_models_initialized()

    if (
        HF_MODEL_INSTANCE is None
        or HF_TOKENIZER_INSTANCE is None
        or HF_DEVICE_INSTANCE is None
    ):
        return {
            "status": "error",
            "message": "Model_Not_Loaded",
            "prediction_debug": prediction_debug_info,
        }
    try:
        # Tokenize the entire input without truncation to check its length
        inputs = get_thread_tokenizer()(
            text_input,
            return_tensors="pt",
            padding=False,  # No padding yet
            truncation=False,  # No truncation yet
        )
        prediction_debug_info["tokenization_performed"] = True

        input_ids = inputs.get("input_ids").to(HF_DEVICE_INSTANCE)
        attention_mask = inputs.get("attention_mask").to(HF_DEVICE_INSTANCE)

        if input_ids is None or input_ids.numel() == 0:
            return {
                "status": "error",
                "message": "Input_Error_Empty_After_Tokenization",
                "prediction_debug": prediction_debug_info,
            }

        num_tokens = input_ids.shape[1]
        max_length = get_thread_tokenizer().model_max_length

        # --- Windowing Logic ---
        if num_tokens > max_length:
            prediction_debug_info["windowing_performed"] = True

            window_predictions = _get_windowed_predictions(input_ids, attention_mask)

            prediction_debug_info["window_count"] = len(window_predictions)
            prediction_debug_info["aggregation_strategy"] = "max_malicious_probability"
            prediction_debug_info["all_window_predictions"] = window_predictions

            if not window_predictions:
                return {
                    "status": "error",
                    "message": "Windowing_Error_No_Results",
                    "prediction_debug": prediction_debug_info,
                }

            # Aggregate results: find the window with highest confidence for any non-benign label
            # Strategy: if any part is malicious/suspicious, the whole is
            def get_max_threat_score(window):
                # Get maximum probability for non-benign labels
                probs = window["probabilities"]
                # Assume index 0 is benign (or check label map)
                if len(probs) > 1:
                    return max(probs[1:])  # Max of all non-benign labels
                return 0.0

            best_window = max(window_predictions, key=get_max_threat_score)

            return {
                "status": "success",
                "index": best_window["index"],
                "label": best_window["label"],
                "probabilities": best_window["probabilities"],
                "labels": best_window.get("labels", {}),
                "prediction_debug": prediction_debug_info,
            }

        # --- Single-Window Logic (input is not long) ---
        else:
            # The input is short enough, so we pad it to max_length and predict
            padded_inputs = get_thread_tokenizer()(
                text_input,
                return_tensors="pt",
                padding="max_length",
                truncation=True,
                max_length=max_length,
            )
            model_inputs = {
                "input_ids": padded_inputs["input_ids"].to(HF_DEVICE_INSTANCE),
                "attention_mask": padded_inputs["attention_mask"].to(
                    HF_DEVICE_INSTANCE
                ),
            }

            with torch.no_grad():
                outputs = HF_MODEL_INSTANCE(**model_inputs)

            if hasattr(outputs, "logits"):
                logits = outputs.logits
                probabilities = F.softmax(logits, dim=-1).cpu()[0]

                # Get label mapping from model config
                if (
                    hasattr(HF_MODEL_INSTANCE.config, "id2label")
                    and HF_MODEL_INSTANCE.config.id2label
                    and not any(
                        k.startswith("LABEL_")
                        for k in HF_MODEL_INSTANCE.config.id2label.values()
                    )
                ):
                    label_map = HF_MODEL_INSTANCE.config.id2label
                else:
                    # Fallback for backward compatibility with binary models
                    label_map = {0: "benign", 1: "malicious"}

                # Create labels dictionary with confidence scores
                labels_dict = {}
                for idx, prob in enumerate(probabilities.tolist()):
                    if idx in label_map:
                        label_name = label_map[idx]
                        labels_dict[label_name] = prob

                # Get the highest confidence label
                prediction_idx = torch.argmax(probabilities).item()
                predicted_label = label_map.get(
                    prediction_idx, f"unknown_{prediction_idx}"
                )

                return {
                    "status": "success",
                    "index": prediction_idx,
                    "label": predicted_label,
                    "probabilities": probabilities.tolist(),
                    "labels": labels_dict,
                    "prediction_debug": prediction_debug_info,
                }

            return {
                "status": "error",
                "message": "No_Logits",
                "prediction_debug": prediction_debug_info,
            }

    except Exception as e:
        logging.error(
            f"Exception during model inference for input '{text_input[:100]}...': {e}",
            exc_info=True,
        )
        return {
            "status": "error",
            "message": f"Inference_Err: {str(e)}",
            "prediction_debug": prediction_debug_info,
        }


def get_model_version_string(base_version: str) -> str:
    """Get complete version string including model information."""
    from malwi._version import __model_commit__

    try:
        # Start with base version and model commit
        version_parts = [f"v{base_version}", f"model: {__model_commit__}"]

        if HF_MODEL_INSTANCE is not None:
            try:
                # Add device information
                if USE_MULTI_GPU and HF_DEVICE_IDS:
                    version_parts.append(f"GPU x{len(HF_DEVICE_IDS)}")
                elif torch.cuda.is_available():
                    version_parts.append("GPU")
                elif torch.backends.mps.is_available():
                    version_parts.append("MPS")
                else:
                    version_parts.append("CPU")

                # Add Python version
                python_version = f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                version_parts.append(python_version)

            except Exception:
                # Fallback device info
                version_parts.append("CPU")
                python_version = f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                version_parts.append(python_version)
        else:
            # Add basic Python info when models aren't loaded
            python_version = f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            version_parts.append(python_version)

        # Join with commas
        version_str = ", ".join(version_parts)

    except Exception:
        # Fallback to basic version if everything fails
        python_version = f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        version_str = f"v{base_version}, model: {__model_commit__}, {python_version}"

    return version_str
