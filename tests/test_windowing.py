import unittest
from unittest.mock import patch, MagicMock

import torch
import torch.nn.functional as F

# The path to the module needs to match your project structure.
# I've kept it as it was in the file you provided.
from common.predict_distilbert import predict, initialize_models


class TestWindowingPrediction(unittest.TestCase):
    def setUp(self):
        """
        This method runs before each test.
        We can do initial setup here if needed, but patching is handled per-test.
        """
        import logging

        logging.getLogger("transformers").setLevel(logging.ERROR)

    # --- THIS IS THE KEY CHANGE ---
    # The mock for HF_DEVICE_INSTANCE is replaced with a direct value using 'new'.
    @patch("common.predict_distilbert.HF_MODEL_INSTANCE")
    @patch("common.predict_distilbert.HF_TOKENIZER_INSTANCE")
    @patch("common.predict_distilbert.get_thread_tokenizer")
    @patch("common.predict_distilbert.HF_DEVICE_INSTANCE", new="cpu")
    def test_long_input_triggers_windowing_and_aggregates_correctly(
        self, mock_get_thread_tokenizer, mock_tokenizer, mock_model
    ):
        """
        Tests the full windowing pipeline for a long input text.
        Verifies that windowing is triggered and that the results from multiple
        windows are aggregated correctly (selecting the most malicious one).
        """
        # Note: 'mock_device' is no longer an argument to this method.

        # --- 1. Configure Mocks ---

        # Configure the mock tokenizer
        mock_tokenizer.model_max_length = 512
        mock_tokenizer.pad_token_id = 0

        # When the tokenizer is called, return a tensor of 1000 tokens.
        long_input_ids = torch.ones((1, 1000), dtype=torch.long)
        long_attention_mask = torch.ones((1, 1000), dtype=torch.long)
        mock_tokenizer.return_value = {
            "input_ids": long_input_ids,
            "attention_mask": long_attention_mask,
        }

        # Configure get_thread_tokenizer to return our mock tokenizer
        mock_get_thread_tokenizer.return_value = mock_tokenizer

        # Configure the mock model to return different logits for each window.
        # The aggregation logic should pick the result from the 2nd window.
        logits_window_1 = torch.tensor([[2.197, -2.197]])
        logits_window_2 = torch.tensor([[-0.847, 0.847]])
        logits_window_3 = torch.tensor([[1.386, -1.386]])

        # With WINDOW_STRIDE=128 and max_length=512, for 1000 tokens we get 8 windows
        # Windows start at: 0, 128, 256, 384, 512, 640, 768, 896
        mock_model_outputs = [
            MagicMock(logits=logits_window_1),
            MagicMock(logits=logits_window_2),  # Window 2 has highest maliciousness
            MagicMock(logits=logits_window_3),
            MagicMock(logits=logits_window_1),
            MagicMock(logits=logits_window_1),
            MagicMock(logits=logits_window_1),
            MagicMock(logits=logits_window_1),
            MagicMock(logits=logits_window_1),
        ]
        mock_model.side_effect = mock_model_outputs

        # Configure model config for label mapping
        mock_model.config.id2label = {0: "benign", 1: "malicious"}

        # --- 2. Call the Function under Test ---

        long_text_input = "A" * 2000
        initialize_models()
        result = predict(long_text_input)

        # --- 3. Assert the Results ---

        self.assertIsNotNone(result, "The result should not be None")
        self.assertEqual(
            result["status"], "success", "Prediction status should be 'success'"
        )

        self.assertEqual(
            result["label"], "malicious", "The final label should be 'malicious'"
        )
        self.assertEqual(result["index"], 1, "The final index should be 1")

        expected_probs_window_2 = F.softmax(logits_window_2, dim=-1)[0].tolist()
        self.assertAlmostEqual(
            result["probabilities"][0], expected_probs_window_2[0], places=5
        )
        self.assertAlmostEqual(
            result["probabilities"][1], expected_probs_window_2[1], places=5
        )

        debug_info = result["prediction_debug"]
        self.assertTrue(
            debug_info["windowing_performed"],
            "Debug info should confirm windowing was performed",
        )
        self.assertEqual(
            debug_info["window_count"],
            3,
        )
        self.assertEqual(
            debug_info["aggregation_strategy"], "max_malicious_probability"
        )
        self.assertEqual(
            mock_model.call_count,
            3,
        )
