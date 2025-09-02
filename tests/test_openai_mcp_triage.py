"""Test OpenAI MCP triage provider functionality."""

import os
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from common.malwi_object import MalwiObject
from common.triage import (
    OpenAITriageProvider,
    TRIAGE_BENIGN,
    TRIAGE_SUSPICIOUS,
    TRIAGE_SKIP,
)


class TestOpenAITriageProvider:
    """Test the OpenAI MCP triage provider."""

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}, clear=True)
    @patch("common.triage.OpenAI")
    def test_openai_mcp_initialization_default(self, mock_openai_class):
        """Test initialization with default settings."""
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client

        provider = OpenAITriageProvider()

        # Verify OpenAI client was created with correct parameters
        mock_openai_class.assert_called_once_with(
            api_key="test_key", base_url="https://api.openai.com/v1/"
        )
        assert provider.model == "gpt-4o-mini"

    @patch.dict(
        os.environ,
        {
            "OPENAI_API_KEY": "gemini_key",
            "OPENAI_BASE_URL": "https://generativelanguage.googleapis.com/v1beta/openai/",
            "OPENAI_MODEL": "gemini-2.5-flash",
        },
        clear=True,
    )
    @patch("common.triage.OpenAI")
    def test_openai_mcp_initialization_gemini(self, mock_openai_class):
        """Test initialization with Gemini settings."""
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client

        provider = OpenAITriageProvider()

        # Verify OpenAI client was created with Gemini parameters
        mock_openai_class.assert_called_once_with(
            api_key="gemini_key",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        )
        assert provider.model == "gemini-2.5-flash"

    def test_openai_mcp_no_api_key(self):
        """Test that initialization fails without API key."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(
                ValueError, match="OPENAI_API_KEY environment variable is required"
            ):
                OpenAITriageProvider()

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}, clear=True)
    @patch("common.triage.OpenAI")
    def test_classify_benign(self, mock_openai_class):
        """Test classifying an object as benign."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "benign"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_class.return_value = mock_client

        provider = OpenAITriageProvider()

        # Create test object
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="/test/file.py",
            file_source_code="def test(): pass",
            source_code="def test(): pass",
        )

        # Classify object
        result = provider.classify_object(obj, "file content")

        assert result == TRIAGE_BENIGN
        mock_client.chat.completions.create.assert_called_once()

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}, clear=True)
    @patch("common.triage.OpenAI")
    def test_classify_suspicious(self, mock_openai_class):
        """Test classifying an object as suspicious."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "suspicious"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_class.return_value = mock_client

        provider = OpenAITriageProvider()

        # Create test object
        obj = MalwiObject(
            name="malicious_function",
            language="python",
            file_path="/test/file.py",
            file_source_code="subprocess.run(['rm', '-rf', '/'])",
            source_code="subprocess.run(['rm', '-rf', '/'])",
        )

        # Classify object
        result = provider.classify_object(obj, "file content")

        assert result == TRIAGE_SUSPICIOUS

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}, clear=True)
    @patch("common.triage.OpenAI")
    def test_classify_skip(self, mock_openai_class):
        """Test classifying an object as skip."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "skip"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_class.return_value = mock_client

        provider = OpenAITriageProvider()

        # Create test object
        obj = MalwiObject(
            name="unclear_function",
            language="python",
            file_path="/test/file.py",
            file_source_code="def unclear(): pass",
            source_code="def unclear(): pass",
        )

        # Classify object
        result = provider.classify_object(obj, "file content")

        assert result == TRIAGE_SKIP

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}, clear=True)
    @patch("common.triage.OpenAI")
    def test_classify_unclear_response(self, mock_openai_class):
        """Test that unclear responses default to suspicious."""
        # Setup mock response with unclear text
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "I'm not sure about this"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_class.return_value = mock_client

        provider = OpenAITriageProvider()

        # Create test object
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="/test/file.py",
            file_source_code="def test(): pass",
            source_code="def test(): pass",
        )

        # Classify object - should default to suspicious
        result = provider.classify_object(obj, "file content")

        assert result == TRIAGE_SUSPICIOUS

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}, clear=True)
    @patch("common.triage.OpenAI")
    def test_classify_api_error(self, mock_openai_class):
        """Test that API errors return skip."""
        # Setup mock to raise exception
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API Error")
        mock_openai_class.return_value = mock_client

        provider = OpenAITriageProvider()

        # Create test object
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="/test/file.py",
            file_source_code="def test(): pass",
            source_code="def test(): pass",
        )

        # Classify object - should return skip on error
        result = provider.classify_object(obj, "file content")

        assert result == TRIAGE_SKIP

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}, clear=True)
    @patch("common.triage.OpenAI")
    def test_classify_none_content(self, mock_openai_class):
        """Test that None content returns suspicious."""
        # Setup mock response with None content
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = None

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_class.return_value = mock_client

        provider = OpenAITriageProvider()

        # Create test object
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="/test/file.py",
            file_source_code="def test(): pass",
            source_code="def test(): pass",
        )

        # Classify object - should return suspicious on None content
        result = provider.classify_object(obj, "file content")

        assert result == TRIAGE_SUSPICIOUS
