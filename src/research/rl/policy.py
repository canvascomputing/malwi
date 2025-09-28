import torch
import torch.nn as nn
import gymnasium as gym
from typing import Dict, List, Tuple, Type, Optional, Any
from stable_baselines3.common.policies import ActorCriticPolicy
from stable_baselines3.common.torch_layers import BaseFeaturesExtractor
from transformers import DistilBertModel


class DistilBertFeatureExtractor(BaseFeaturesExtractor):
    """
    Feature extractor using frozen DistilBERT for code representation.
    Extracts [CLS] token embeddings from the last hidden layer.
    """

    def __init__(
        self,
        observation_space: gym.spaces.Dict,
        distilbert_model_path: str,
        features_dim: int = 256,
    ):
        super().__init__(observation_space, features_dim)

        self.distilbert = DistilBertModel.from_pretrained(distilbert_model_path)

        for param in self.distilbert.parameters():
            param.requires_grad = False

        self.distilbert.eval()

        hidden_size = self.distilbert.config.hidden_size

    @property
    def features_dim(self) -> int:
        return self.distilbert.config.hidden_size

    def forward(self, observations: Dict[str, torch.Tensor]) -> torch.Tensor:
        input_ids = observations["input_ids"].long()
        attention_mask = observations["attention_mask"].long()

        with torch.no_grad():
            outputs = self.distilbert(
                input_ids=input_ids, attention_mask=attention_mask
            )

        last_hidden_state = outputs.last_hidden_state

        cls_embeddings = last_hidden_state[:, 0, :]

        return cls_embeddings


class DistilBertActorCriticPolicy(ActorCriticPolicy):
    """
    Custom Actor-Critic policy using DistilBERT feature extraction.
    Compatible with Stable-Baselines3 PPO.
    """

    def __init__(
        self,
        observation_space: gym.spaces.Dict,
        action_space: gym.spaces.Discrete,
        lr_schedule,
        distilbert_model_path: str = "malwi_models",
        *args,
        **kwargs,
    ):
        self.distilbert_model_path = distilbert_model_path

        kwargs["features_extractor_class"] = DistilBertFeatureExtractor
        kwargs["features_extractor_kwargs"] = {
            "distilbert_model_path": distilbert_model_path
        }

        super().__init__(observation_space, action_space, lr_schedule, *args, **kwargs)
