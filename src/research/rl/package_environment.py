import torch
import gymnasium as gym
import numpy as np
from typing import Tuple, Optional, Dict, Any, List
from transformers import PreTrainedTokenizer


REWARD_CORRECT = 10.0
REWARD_INCORRECT = -10.0
COST_PER_SAMPLE = -0.1


class PackageEnv(gym.Env):
    """
    Gymnasium environment for malware package detection with early exit.

    The agent processes code samples from a malicious package sequentially.
    After each sample, it can:
    - Action 0: CLASSIFY_BENIGN (stop, predict benign)
    - Action 1: CLASSIFY_MALICIOUS (stop, predict malicious)
    - Action 2: CONTINUE (read next sample)

    Key differences from old environment:
    - No chunking - DistilBERT handles full samples with windowing
    - Sequential memory - LSTM remembers previous samples
    - Package-level decisions - agent sees multiple related samples
    """

    metadata = {"render_modes": []}

    def __init__(
        self,
        code_samples: List[str],
        label: int,
        tokenizer: PreTrainedTokenizer,
        device: torch.device,
        max_length: int = 512,
    ):
        super().__init__()

        self.tokenizer = tokenizer
        self.device = device
        self.label = label
        self.max_length = max_length
        self.code_samples = code_samples

        self.num_samples = len(code_samples)
        self.current_sample_index = 0
        self.done = False

        self.action_space = gym.spaces.Discrete(3)

        self.observation_space = gym.spaces.Dict(
            {
                "input_ids": gym.spaces.Box(
                    low=0,
                    high=tokenizer.vocab_size,
                    shape=(max_length,),
                    dtype=np.int64,
                ),
                "attention_mask": gym.spaces.Box(
                    low=0, high=1, shape=(max_length,), dtype=np.int64
                ),
            }
        )

    def _get_obs(self) -> Dict[str, np.ndarray]:
        """Get observation for current code sample."""
        if self.current_sample_index >= self.num_samples:
            self.current_sample_index = self.num_samples - 1

        current_code = self.code_samples[self.current_sample_index]

        tokens = self.tokenizer(
            current_code,
            return_tensors="pt",
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
        )

        return {
            "input_ids": tokens["input_ids"][0].cpu().numpy(),
            "attention_mask": tokens["attention_mask"][0].cpu().numpy(),
        }

    def reset(
        self, seed: Optional[int] = None, options: Optional[dict] = None
    ) -> Tuple[Dict[str, np.ndarray], Dict[str, Any]]:
        super().reset(seed=seed)

        self.current_sample_index = 0
        self.done = False

        obs = self._get_obs()
        info = {
            "num_samples": self.num_samples,
            "true_label": self.label,
            "current_sample": 0,
        }

        return obs, info

    def step(
        self, action: int
    ) -> Tuple[Dict[str, np.ndarray], float, bool, bool, Dict[str, Any]]:
        """
        Take action on current sample.

        Actions:
        - 0: CLASSIFY_BENIGN - predict benign and end episode
        - 1: CLASSIFY_MALICIOUS - predict malicious and end episode
        - 2: CONTINUE - move to next sample (costs -0.1)
        """
        if self.done:
            obs = self._get_obs()
            return obs, 0.0, True, False, {}

        if action == 0:
            self.done = True
            correct = action == self.label
            reward = REWARD_CORRECT if correct else REWARD_INCORRECT
            obs = self._get_obs()
            info = {
                "prediction": action,
                "correct": correct,
                "samples_seen": self.current_sample_index + 1,
            }
            return obs, reward, True, False, info

        elif action == 1:
            self.done = True
            correct = action == self.label
            reward = REWARD_CORRECT if correct else REWARD_INCORRECT
            obs = self._get_obs()
            info = {
                "prediction": action,
                "correct": correct,
                "samples_seen": self.current_sample_index + 1,
            }
            return obs, reward, True, False, info

        elif action == 2:
            self.current_sample_index += 1

            if self.current_sample_index >= self.num_samples:
                self.done = True

                predicted_label = 0

                correct = predicted_label == self.label
                reward = REWARD_CORRECT if correct else REWARD_INCORRECT
                obs = self._get_obs()
                info = {
                    "prediction": predicted_label,
                    "correct": correct,
                    "forced_decision": True,
                    "samples_seen": self.num_samples,
                }
                return obs, reward, True, False, info
            else:
                reward = COST_PER_SAMPLE
                obs = self._get_obs()
                info = {
                    "current_sample": self.current_sample_index,
                    "samples_seen": self.current_sample_index + 1,
                }
                return obs, reward, False, False, info

        else:
            raise ValueError(f"Invalid action: {action}. Must be 0, 1, or 2.")
