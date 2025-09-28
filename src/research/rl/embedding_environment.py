import torch
import gymnasium as gym
import numpy as np
from typing import Tuple, Optional, Dict, Any, List


REWARD_CORRECT = 10.0
REWARD_INCORRECT = -10.0
COST_PER_SAMPLE = -0.1


class EmbeddingPackageEnv(gym.Env):
    """
    Gymnasium environment for malware package detection with pre-computed embeddings.

    The agent processes pre-computed DistilBERT embeddings from code samples sequentially.
    After each sample, it can:
    - Action 0: CLASSIFY_BENIGN (stop, predict benign)
    - Action 1: CLASSIFY_MALICIOUS (stop, predict malicious)
    - Action 2: CONTINUE (read next sample)

    Key advantages:
    - No DistilBERT inference during training (10-50x faster)
    - Lower GPU memory usage
    - Embeddings are pre-computed and loaded from disk
    """

    metadata = {"render_modes": []}

    def __init__(
        self,
        embeddings: List[np.ndarray],
        label: int,
        device: torch.device,
    ):
        super().__init__()

        self.embeddings = embeddings
        self.label = label
        self.device = device

        self.num_samples = len(embeddings)
        self.current_sample_index = 0
        self.done = False

        self.action_space = gym.spaces.Discrete(3)

        embedding_dim = embeddings[0].shape[0] if len(embeddings) > 0 else 256
        self.observation_space = gym.spaces.Box(
            low=-np.inf,
            high=np.inf,
            shape=(embedding_dim,),
            dtype=np.float32,
        )

    def _get_obs(self) -> np.ndarray:
        """Get observation for current embedding."""
        if self.current_sample_index >= self.num_samples:
            self.current_sample_index = self.num_samples - 1

        return self.embeddings[self.current_sample_index]

    def reset(
        self, seed: Optional[int] = None, options: Optional[dict] = None
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
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

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
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
