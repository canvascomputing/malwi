"""MCP-based triage functionality for malwi."""

import asyncio
import logging
import os
from typing import Protocol

from mistralai import Mistral

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from google import genai

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

Your final decision:"""


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
                max_tokens=100,
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


class GeminiMCPTriageProvider:
    """Triage provider using Gemini MCP for decisions."""

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is required")
        genai.configure(api_key=api_key)

    async def triage_with_gemini_mcp(self, obj: MalwiObject, file_content: str) -> str:
        """Use Gemini MCP to make triage decisions."""
        server_params = StdioServerParameters(
            command="uvx",
            args=["--from", "google-mcp", "google_mcp"],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Prepare the triage query
                query = create_triage_prompt(obj, file_content)

                # Call the Gemini model
                result = await session.call_tool(
                    "generate_text",
                    {
                        "prompt": query,
                        "model": "gemini-2.5-flash",
                        "max_tokens": 100,
                        "temperature": 0.1,
                    },
                )

                # Extract response text
                response_text = result.content[0].text

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

    def classify_object(self, obj: MalwiObject, file_content: str) -> str:
        """Classify object using Gemini MCP."""
        try:
            decision = asyncio.run(self.triage_with_gemini_mcp(obj, file_content))

            logger.info(f"Gemini MCP triage decision for {obj.name}: {decision}")

            return decision

        except Exception as e:
            logger.error(f"Gemini MCP triage failed for {obj.name}: {e}")
            return TRIAGE_SKIP


def create_triage_provider(use_mcp: bool = False, **mcp_kwargs) -> TriageProvider:
    """Create appropriate triage provider."""
    if use_mcp:
        # Check which API keys are available and prioritize accordingly
        mistral_key = os.getenv("MISTRAL_API_KEY")
        gemini_key = os.getenv("GEMINI_API_KEY")

        if mistral_key:
            return MistralTriageProvider(**mcp_kwargs)
        elif gemini_key:
            return GeminiMCPTriageProvider(**mcp_kwargs)
        else:
            raise ValueError(
                "Either MISTRAL_API_KEY or GEMINI_API_KEY environment variable is required for MCP triage"
            )
    else:
        return InteractiveTriageProvider()
