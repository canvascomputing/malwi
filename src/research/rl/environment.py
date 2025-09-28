import torch
import gymnasium as gym
import numpy as np
from typing import Tuple, Optional, Dict, Any
from transformers import PreTrainedTokenizer


CHUNK_SIZE = 128
MAX_CHUNKS = 32
REWARD_CORRECT = 10.0
REWARD_INCORRECT = -10.0
COST_PER_STEP = -0.1


class CodeSampleEnv(gym.Env):
    """Gymnasium environment for malware detection with early exit."""

    metadata = {"render_modes": []}

    def __init__(
        self,
        code_sample: str,
        label: int,
        tokenizer: PreTrainedTokenizer,
        device: torch.device,
    ):
        super().__init__()

        self.tokenizer = tokenizer
        self.device = device
        self.label = label

        tokens = tokenizer(
            code_sample, return_tensors="pt", truncation=False, padding=False
        )

        self.full_input_ids = tokens["input_ids"][0]
        self.full_attention_mask = tokens["attention_mask"][0]

        total_tokens = len(self.full_input_ids)
        self.num_chunks = (total_tokens + CHUNK_SIZE - 1) // CHUNK_SIZE

        self.current_chunk_index = 0
        self.done = False

        self.action_space = gym.spaces.Discrete(3)

        self.observation_space = gym.spaces.Dict(
            {
                "input_ids": gym.spaces.Box(
                    low=0,
                    high=tokenizer.vocab_size,
                    shape=(CHUNK_SIZE,),
                    dtype=np.int64,
                ),
                "attention_mask": gym.spaces.Box(
                    low=0, high=1, shape=(CHUNK_SIZE,), dtype=np.int64
                ),
            }
        )

    def _get_obs(self) -> Dict[str, np.ndarray]:
        start_idx = self.current_chunk_index * CHUNK_SIZE
        end_idx = start_idx + CHUNK_SIZE

        chunk_input_ids = self.full_input_ids[start_idx:end_idx]
        chunk_attention_mask = self.full_attention_mask[start_idx:end_idx]

        current_length = len(chunk_input_ids)
        if current_length < CHUNK_SIZE:
            padding_length = CHUNK_SIZE - current_length
            pad_token_id = self.tokenizer.pad_token_id

            pad_ids = torch.full(
                (padding_length,), pad_token_id, dtype=chunk_input_ids.dtype
            )
            chunk_input_ids = torch.cat([chunk_input_ids, pad_ids])

            pad_mask = torch.zeros(padding_length, dtype=chunk_attention_mask.dtype)
            chunk_attention_mask = torch.cat([chunk_attention_mask, pad_mask])

        return {
            "input_ids": chunk_input_ids.cpu().numpy(),
            "attention_mask": chunk_attention_mask.cpu().numpy(),
        }

    def reset(
        self, seed: Optional[int] = None, options: Optional[dict] = None
    ) -> Tuple[Dict[str, np.ndarray], Dict[str, Any]]:
        super().reset(seed=seed)

        self.current_chunk_index = 0
        self.done = False

        obs = self._get_obs()
        info = {"num_chunks": self.num_chunks, "true_label": self.label}

        return obs, info

    def step(
        self, action: int
    ) -> Tuple[Dict[str, np.ndarray], float, bool, bool, Dict[str, Any]]:
        if self.done:
            obs = self._get_obs()
            return obs, 0.0, True, False, {}

        if action == 0:
            self.done = True
            correct = action == self.label
            reward = REWARD_CORRECT if correct else REWARD_INCORRECT
            obs = self._get_obs()
            info = {"prediction": action, "correct": correct}
            return obs, reward, True, False, info

        elif action == 1:
            self.done = True
            correct = action == self.label
            reward = REWARD_CORRECT if correct else REWARD_INCORRECT
            obs = self._get_obs()
            info = {"prediction": action, "correct": correct}
            return obs, reward, True, False, info

        elif action == 2:
            self.current_chunk_index += 1

            if (
                self.current_chunk_index >= MAX_CHUNKS
                or self.current_chunk_index >= self.num_chunks
            ):
                self.done = True

                predicted_label = 0

                correct = predicted_label == self.label
                reward = REWARD_CORRECT if correct else REWARD_INCORRECT
                obs = self._get_obs()
                info = {
                    "prediction": predicted_label,
                    "correct": correct,
                    "forced_decision": True,
                }
                return obs, reward, True, False, info
            else:
                reward = COST_PER_STEP
                obs = self._get_obs()
                info = {"chunk_index": self.current_chunk_index}
                return obs, reward, False, False, info

        else:
            raise ValueError(f"Invalid action: {action}. Must be 0, 1, or 2.")
