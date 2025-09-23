"""MCP-based triage functionality for malwi."""

import asyncio
import logging
import os
from typing import Protocol

# These third-party APIs are optional in the test environment. Import them
# lazily and default to ``None`` when the packages are missing so that the
# rest of the module can be imported without errors.
try:  # pragma: no cover - executed only when mistralai is installed
    from mistralai import Mistral
except Exception:  # pragma: no cover
    Mistral = None  # type: ignore

try:  # pragma: no cover - executed only when openai package is installed
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore

try:  # pragma: no cover - executed only when google-genai is installed
    from google import genai
except Exception:  # pragma: no cover
    genai = None  # type: ignore

from .malwi_object import MalwiObject


logger = logging.getLogger(__name__)


# Triage decision constants
TRIAGE_SUSPICIOUS = "suspicious"
TRIAGE_BENIGN = "benign"
TRIAGE_SKIP = "skip"
TRIAGE_QUIT = "quit"


def create_triage_prompt(obj: MalwiObject, file_content: str) -> str:
    return f"""You are a security software analyst reviewing random code of a large repository.

- the following code should be deeply analyzed for suspicious activities
- suspicious activities include:
    - exfiltration, networking, communication
    - obfuscation, encoding of payloads
    - access to sensitive information
```
{obj.source_code or file_content}
```

Please analyze the code for suspicious activities.

Based on your analysis, respond with exactly one of these options:
- "{TRIAGE_SUSPICIOUS}" - if this appears to be suspicious code
- "{TRIAGE_BENIGN}" - if this appears to be legitimate code

Respond with one word: {TRIAGE_SUSPICIOUS} or {TRIAGE_BENIGN}"""


class TriageProvider(Protocol):
    """Protocol for triage decision providers."""

    def classify_object(self, obj: MalwiObject, file_content: str) -> str:
        """
        Classify a malicious object.

        Returns one of:
        - "Suspicious (keep as malicious)"
        - "Benign (false positive)"
        - "Skip (unsure)"
        - "Quit (stop triaging)"
        """
        ...


class InteractiveTriageProvider:
    """Interactive triage using questionary."""

    def classify_object(self, obj: MalwiObject, file_content: str) -> str:
        import questionary

        # Display object information
        print(f"\n{'=' * 70}")
        print(f"File: {obj.file_path}")
        print(f"Object: {obj.name}")
        print(f"Maliciousness: {obj.maliciousness:.3f}" if obj.maliciousness else "N/A")
        print(f"Embedding count: {obj.embedding_count} tokens")
        print(f"{'=' * 70}")

        # Show source code
        if obj.source_code:
            print(obj.source_code)
        else:
            print(file_content)

        # Ask user to classify
        maliciousness_str = (
            f"{obj.maliciousness:.2f}" if obj.maliciousness is not None else "N/A"
        )

        return questionary.select(
            f"How would you classify this code (AI score: {maliciousness_str})?",
            choices=[
                TRIAGE_SUSPICIOUS,
                TRIAGE_BENIGN,
                TRIAGE_SKIP,
                TRIAGE_QUIT,
            ],
        ).ask()


class MistralTriageProvider:
    """Triage provider using Mistral AI for decisions."""

    def __init__(self):
        api_key = os.getenv("MISTRAL_API_KEY")
        if not api_key:
            raise ValueError("MISTRAL_API_KEY environment variable is required")
        self.client = Mistral(api_key=api_key)

    def triage_with_mistral(self, obj: MalwiObject, file_content: str) -> str:
        """Use Mistral to make triage decisions."""
        try:
            # Prepare the triage query
            query = create_triage_prompt(obj, file_content)

            # Call Mistral API
            response = self.client.chat.complete(
                model="mistral-medium-latest",
                messages=[{"role": "user", "content": query}],
                temperature=0.1,
            )

            # Extract response text
            response_text = response.choices[0].message.content

            # Parse the decision
            if TRIAGE_BENIGN in response_text:
                return TRIAGE_BENIGN
            elif TRIAGE_SUSPICIOUS in response_text:
                return TRIAGE_SUSPICIOUS
            elif TRIAGE_SKIP in response_text:
                return TRIAGE_SKIP
            else:
                # Default to suspicious if unclear
                return TRIAGE_SUSPICIOUS

        except Exception as e:
            logger.error(f"Mistral triage failed for {obj.name}: {e}")
            return TRIAGE_SKIP

    def classify_object(self, obj: MalwiObject, file_content: str) -> str:
        """Classify object using Mistral AI."""
        try:
            decision = self.triage_with_mistral(obj, file_content)

            logger.info(f"Mistral triage decision for {obj.name}: {decision}")

            return decision

        except Exception as e:
            logger.error(f"Triage failed for {obj.name}: {e}")
            return TRIAGE_SKIP


class GeminiTriageProvider:
    """Triage provider using Gemini API for decisions."""

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is required")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.0-flash-exp")

    def triage_with_gemini(self, obj: MalwiObject, file_content: str) -> str:
        """Use Gemini API to make triage decisions."""
        try:
            # Prepare the triage query
            query = create_triage_prompt(obj, file_content)

            # Call the Gemini model
            response = self.model.generate_content(
                query,
                generation_config=genai.GenerationConfig(
                    max_output_tokens=100,
                    temperature=0.1,
                ),
            )

            # Extract response text
            content = response.text
            if content is None:
                logger.warning(
                    f"Gemini returned None content for {obj.name}, defaulting to suspicious"
                )
                return TRIAGE_SUSPICIOUS
            response_text = content.lower().strip()

            # Parse the decision
            if TRIAGE_BENIGN in response_text:
                return TRIAGE_BENIGN
            elif TRIAGE_SUSPICIOUS in response_text:
                return TRIAGE_SUSPICIOUS
            elif TRIAGE_SKIP in response_text:
                return TRIAGE_SKIP
            else:
                # Default to suspicious if unclear
                logger.warning(
                    f"Unclear response from Gemini: {response_text}, defaulting to suspicious"
                )
                return TRIAGE_SUSPICIOUS

        except Exception as e:
            logger.error(f"Gemini triage failed for {obj.name}: {e}")
            return TRIAGE_SKIP

    def classify_object(self, obj: MalwiObject, file_content: str) -> str:
        """Classify object using Gemini API."""
        try:
            decision = self.triage_with_gemini(obj, file_content)

            logger.info(f"Gemini triage decision for {obj.name}: {decision}")

            return decision

        except Exception as e:
            logger.error(f"Triage failed for {obj.name}: {e}")
            return TRIAGE_SKIP


class OpenAITriageProvider:
    """Triage provider using OpenAI-compatible APIs (OpenAI, Gemini, etc.)."""

    def __init__(self):
        # Get API key and base URL from environment variables
        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("OPENAI_BASE_URL")

        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is required for OpenAI triage"
            )

        # Default to OpenAI's API if no base URL is provided
        if not base_url:
            base_url = "https://api.openai.com/v1/"

        self.client = OpenAI(api_key=api_key, base_url=base_url)

        # Get model from environment or use default
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

        logger.info(
            f"OpenAI provider initialized with base_url: {base_url}, model: {self.model}"
        )

    def triage_with_openai(self, obj: MalwiObject, file_content: str) -> str:
        """Use OpenAI-compatible API to make triage decisions."""
        try:
            # Prepare the triage query
            query = create_triage_prompt(obj, file_content)

            # Call OpenAI-compatible API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security analyst. Respond with one word: suspicious, benign, or skip.",
                    },
                    {"role": "user", "content": query},
                ],
                temperature=0.1,
            )

            # Extract response text
            logger.debug(f"OpenAI API response for {obj.name}: {response}")

            if not response.choices or len(response.choices) == 0:
                logger.warning(
                    f"OpenAI returned no choices for {obj.name}, defaulting to suspicious"
                )
                return TRIAGE_SUSPICIOUS

            choice = response.choices[0]
            if not hasattr(choice, "message") or not choice.message:
                logger.warning(
                    f"OpenAI returned no message for {obj.name}, defaulting to suspicious"
                )
                return TRIAGE_SUSPICIOUS

            content = choice.message.content
            if content is None:
                logger.warning(
                    f"OpenAI returned None content for {obj.name}, defaulting to suspicious. Full response: {response}"
                )
                return TRIAGE_SUSPICIOUS
            response_text = content.lower().strip()

            # Parse the decision
            if TRIAGE_BENIGN in response_text:
                return TRIAGE_BENIGN
            elif TRIAGE_SUSPICIOUS in response_text:
                return TRIAGE_SUSPICIOUS
            elif TRIAGE_SKIP in response_text:
                return TRIAGE_SKIP
            else:
                # Default to suspicious if unclear
                logger.warning(
                    f"Unclear response from OpenAI: {response_text}, defaulting to suspicious"
                )
                return TRIAGE_SUSPICIOUS

        except Exception as e:
            logger.error(f"OpenAI triage failed for {obj.name}: {e}")
            return TRIAGE_SKIP

    def classify_object(self, obj: MalwiObject, file_content: str) -> str:
        """Classify object using OpenAI-compatible API."""
        try:
            decision = self.triage_with_openai(obj, file_content)

            logger.info(f"OpenAI triage decision for {obj.name}: {decision}")

            return decision

        except Exception as e:
            logger.error(f"Triage failed for {obj.name}: {e}")
            return TRIAGE_SKIP


def create_triage_provider(use_llm: bool = False, **llm_kwargs) -> TriageProvider:
    """Create appropriate triage provider."""
    if use_llm:
        # Check which API keys are available and prioritize accordingly
        openai_key = os.getenv("OPENAI_API_KEY")
        mistral_key = os.getenv("MISTRAL_API_KEY")
        gemini_key = os.getenv("GEMINI_API_KEY")

        if openai_key:
            return OpenAITriageProvider(**llm_kwargs)
        elif mistral_key:
            return MistralTriageProvider(**llm_kwargs)
        elif gemini_key:
            return GeminiTriageProvider(**llm_kwargs)
        else:
            raise ValueError(
                "Either OPENAI_API_KEY, MISTRAL_API_KEY or GEMINI_API_KEY environment variable is required for LLM triage"
            )
    else:
        return InteractiveTriageProvider()
