import torch
import torch.nn as nn
import gymnasium as gym
from typing import Dict, List, Tuple, Type, Optional, Any
from stable_baselines3.common.policies import ActorCriticPolicy
from stable_baselines3.common.torch_layers import BaseFeaturesExtractor, FlattenExtractor
from stable_baselines3.common.distributions import CategoricalDistribution
from transformers import DistilBertModel


class DistilBertFeatureExtractor(BaseFeaturesExtractor):
    """
    Feature extractor using frozen DistilBERT for code representation.
    Extracts [CLS] token embeddings from the last hidden layer.
    DistilBERT handles windowing internally with max_length=512.
    """

    def __init__(
        self,
        observation_space: gym.spaces.Dict,
        distilbert_model_path: str,
        features_dim: int = 768,
    ):
        temp_model = DistilBertModel.from_pretrained(distilbert_model_path)
        actual_features_dim = temp_model.config.hidden_size

        super().__init__(observation_space, actual_features_dim)

        self.distilbert = temp_model
        for param in self.distilbert.parameters():
            param.requires_grad = False

        self.distilbert.eval()

        self._features_dim = actual_features_dim

    @property
    def features_dim(self) -> int:
        return self._features_dim

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


class LSTMDistilBertActorCriticPolicy(ActorCriticPolicy):
    """
    Custom Actor-Critic policy with LSTM memory.

    Architecture:
    1. DistilBERT processes each code sample → [CLS] embedding (frozen)
    2. LSTM maintains memory across samples in a package
    3. Actor-Critic networks make decisions based on LSTM output

    This allows the agent to remember previous samples when deciding on new ones.
    """

    def __init__(
        self,
        observation_space: gym.spaces.Dict,
        action_space: gym.spaces.Discrete,
        lr_schedule,
        distilbert_model_path: str = "malwi_models",
        lstm_hidden_size: int = 256,
        lstm_num_layers: int = 1,
        *args,
        **kwargs,
    ):
        self.distilbert_model_path = distilbert_model_path
        self.lstm_hidden_size = lstm_hidden_size
        self.lstm_num_layers = lstm_num_layers

        kwargs["features_extractor_class"] = DistilBertFeatureExtractor
        kwargs["features_extractor_kwargs"] = {
            "distilbert_model_path": distilbert_model_path
        }
        kwargs["net_arch"] = {"pi": [], "vf": []}
        kwargs["ortho_init"] = False

        super().__init__(observation_space, action_space, lr_schedule, *args, **kwargs)

        distilbert_size = self.features_extractor.features_dim

        if hasattr(self, 'mlp_extractor'):
            class IdentityMLP(nn.Module):
                def __init__(self, latent_dim):
                    super().__init__()
                    self.latent_dim_pi = latent_dim
                    self.latent_dim_vf = latent_dim

                def forward(self, features):
                    return features, features

                def forward_actor(self, features):
                    return features

                def forward_critic(self, features):
                    return features

            self.mlp_extractor = IdentityMLP(distilbert_size)

        self.lstm = nn.LSTM(
            input_size=distilbert_size,
            hidden_size=lstm_hidden_size,
            num_layers=lstm_num_layers,
            batch_first=True,
        )

        self.action_net = nn.Sequential(
            nn.Linear(lstm_hidden_size, 256), nn.ReLU(), nn.Linear(256, action_space.n)
        )

        self.value_net = nn.Sequential(
            nn.Linear(lstm_hidden_size, 256), nn.ReLU(), nn.Linear(256, 1)
        )

        self.lstm_hidden_state = None
        self.lstm_cell_state = None

    def reset_lstm_states(self):
        """Reset LSTM hidden states (call at episode start)."""
        self.lstm_hidden_state = None
        self.lstm_cell_state = None

    def extract_features(self, obs):
        """Extract features using only the DistilBERT feature extractor."""
        preprocessed_obs = self.obs_to_tensor(obs)[0] if not isinstance(obs, dict) else obs
        return self.features_extractor(preprocessed_obs)

    def _get_latent(self, obs):
        """
        Override to bypass mlp_extractor and use LSTM directly.
        This is called by parent class methods we're not overriding.
        """
        features = self.extract_features(obs)
        batch_size = features.shape[0]
        features = features.unsqueeze(1)

        if (
            self.lstm_hidden_state is None
            or self.lstm_hidden_state.shape[1] != batch_size
        ):
            device = features.device
            self.lstm_hidden_state = torch.zeros(
                self.lstm_num_layers, batch_size, self.lstm_hidden_size
            ).to(device)
            self.lstm_cell_state = torch.zeros(
                self.lstm_num_layers, batch_size, self.lstm_hidden_size
            ).to(device)

        lstm_out, (self.lstm_hidden_state, self.lstm_cell_state) = self.lstm(
            features, (self.lstm_hidden_state, self.lstm_cell_state)
        )

        self.lstm_hidden_state = self.lstm_hidden_state.detach()
        self.lstm_cell_state = self.lstm_cell_state.detach()

        lstm_out = lstm_out.squeeze(1)
        return lstm_out, lstm_out

    def _get_action_dist_from_latent(self, latent_pi):
        """Override to use custom action network."""
        mean_actions = self.action_net(latent_pi)
        return self.action_dist.proba_distribution(mean_actions)

    def _predict_values(self, latent_vf):
        """Override to use custom value network."""
        return self.value_net(latent_vf)

    def _predict(self, observation, deterministic=False):
        """Override prediction to use LSTM."""
        features = self.extract_features(observation)

        batch_size = features.shape[0]
        features = features.unsqueeze(1)

        if (
            self.lstm_hidden_state is None
            or self.lstm_hidden_state.shape[1] != batch_size
        ):
            device = features.device
            self.lstm_hidden_state = torch.zeros(
                self.lstm_num_layers, batch_size, self.lstm_hidden_size
            ).to(device)
            self.lstm_cell_state = torch.zeros(
                self.lstm_num_layers, batch_size, self.lstm_hidden_size
            ).to(device)

        lstm_out, (self.lstm_hidden_state, self.lstm_cell_state) = self.lstm(
            features, (self.lstm_hidden_state, self.lstm_cell_state)
        )

        lstm_out = lstm_out.squeeze(1)

        action_logits = self.action_net(lstm_out)
        distribution = self.action_dist.proba_distribution(action_logits)
        actions = distribution.get_actions(deterministic=deterministic)

        return actions

    def forward(self, obs, deterministic=False):
        """Forward pass with LSTM memory."""
        latent_pi, latent_vf = self._get_latent(obs)

        distribution = self._get_action_dist_from_latent(latent_pi)
        actions = distribution.get_actions(deterministic=deterministic)
        values = self._predict_values(latent_vf)
        log_prob = distribution.log_prob(actions)

        return actions, values, log_prob

    def evaluate_actions(self, obs, actions):
        """
        Evaluate actions for PPO update.
        Uses fresh LSTM states (not the persistent ones) for batch processing.
        """
        features = self.extract_features(obs)
        batch_size = features.shape[0]
        features = features.unsqueeze(1)

        device = features.device
        hidden = torch.zeros(
            self.lstm_num_layers, batch_size, self.lstm_hidden_size
        ).to(device)
        cell = torch.zeros(self.lstm_num_layers, batch_size, self.lstm_hidden_size).to(
            device
        )

        lstm_out, _ = self.lstm(features, (hidden, cell))
        lstm_out = lstm_out.squeeze(1)

        distribution = self._get_action_dist_from_latent(lstm_out)
        values = self._predict_values(lstm_out)
        log_prob = distribution.log_prob(actions)
        entropy = distribution.entropy()

        return values, log_prob, entropy
