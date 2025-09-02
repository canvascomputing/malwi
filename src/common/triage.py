"""MCP-based triage functionality for malwi."""

import asyncio
import io
import logging
import os
import sys
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from typing import Protocol

from mistralai import Mistral
from openai import OpenAI

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


class UITriageProvider:
    """GUI-based triage using tkinter."""

    def __init__(self):
        # Suppress macOS IMK logs and other tkinter-related logs
        self._suppress_ui_logs()

        self.result = None
        self.root = None
        self.widgets = {}  # Store widget references for updates
        self._window_initialized = False

    def _suppress_ui_logs(self):
        """Suppress various UI-related logs that can clutter output."""
        # Suppress macOS IMK (Input Method Kit) logs
        os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"

        # Redirect stderr temporarily to suppress IMK logs during tkinter import
        if sys.platform == "darwin":  # macOS
            # Suppress specific loggers that generate noise
            imk_logger = logging.getLogger("IMKClient")
            imk_logger.setLevel(logging.CRITICAL)

            input_session_logger = logging.getLogger("IMKInputSession")
            input_session_logger.setLevel(logging.CRITICAL)

            # Suppress console output for macOS UI frameworks
            console_logger = logging.getLogger("console")
            console_logger.setLevel(logging.CRITICAL)

    def classify_object(self, obj: MalwiObject, file_content: str) -> str:
        """Show GUI dialog for object classification."""
        self.result = None

        try:
            # Create window on first use, reuse afterwards
            if (
                not self._window_initialized
                or not self.root
                or not self.root.winfo_exists()
            ):
                self._create_window()
                self._window_initialized = True

            # Update the window content with new object data
            self._update_content(obj, file_content)

            # Bring window to front and focus
            self.root.deiconify()  # Show if minimized
            self.root.lift()  # Bring to front
            self.root.focus_force()  # Give focus

            # Start the event loop and wait for user decision
            self.root.mainloop()

            # Return the result (set by button clicks)
            result = self.result if self.result else TRIAGE_SKIP

            # Keep window open for next use (only minimize to reduce screen clutter)
            if self.root and self.root.winfo_exists():
                self.root.withdraw()  # Hide window but keep it alive

            return result

        except Exception as e:
            logger.error(f"GUI triage failed for {obj.name}: {e}")
            return TRIAGE_SKIP

    def _create_window(self):
        """Create the main window and GUI structure (called once)."""
        if self.root:
            self.root.destroy()

        # Temporarily suppress stderr to hide IMK logs on macOS
        original_stderr = None
        if sys.platform == "darwin":
            try:
                original_stderr = sys.stderr
                sys.stderr = io.StringIO()  # Capture stderr temporarily
            except:
                pass

        try:
            self.root = tk.Tk()
            self.root.title("malwi Triage - Code Review")
            self.root.geometry("1100x800")  # Larger default size
            self.root.configure(bg="#2b2b2b")
            self.root.minsize(800, 600)  # Set minimum size

            # Create the GUI structure
            self._create_gui_structure()

            # Center the window initially
            self._center_window()

            # Handle window close button
            self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)

        finally:
            # Restore stderr
            if original_stderr:
                sys.stderr = original_stderr

    def _create_gui_structure(self):
        """Create the GUI structure (called once)."""

        # Header frame
        header_frame = tk.Frame(self.root, bg="#2b2b2b")
        header_frame.pack(fill=tk.X, padx=10, pady=5)

        # Title
        title_label = tk.Label(
            header_frame,
            text="🛡️ malwi Code Triage",
            font=("Arial", 16, "bold"),
            bg="#2b2b2b",
            fg="#ffffff",
        )
        title_label.pack()

        # Object info frame
        info_frame = tk.Frame(self.root, bg="#2b2b2b")
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        # File path label (will be updated)
        self.widgets["file_label"] = tk.Label(
            info_frame,
            text="📄 File: ",
            font=("Arial", 14),
            bg="#2b2b2b",
            fg="#cccccc",
            anchor="w",
        )
        self.widgets["file_label"].pack(fill=tk.X)

        # Object name label (will be updated)
        self.widgets["name_label"] = tk.Label(
            info_frame,
            text="🎯 Object: ",
            font=("Arial", 14),
            bg="#2b2b2b",
            fg="#cccccc",
            anchor="w",
        )
        self.widgets["name_label"].pack(fill=tk.X)

        # Maliciousness score label (will be updated)
        self.widgets["score_label"] = tk.Label(
            info_frame,
            text="⚠️  AI Maliciousness Score: ",
            font=("Arial", 14, "bold"),
            bg="#2b2b2b",
            fg="#ffa500",
            anchor="w",
        )
        self.widgets["score_label"].pack(fill=tk.X)

        # Code display
        code_frame = tk.Frame(self.root, bg="#2b2b2b")
        code_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Code text area
        self.widgets["code_text"] = scrolledtext.ScrolledText(
            code_frame,
            wrap=tk.NONE,  # Don't wrap lines to preserve code formatting
            font=("Courier New", 14),
            bg="#1e1e1e",
            fg="#ffffff",
            insertbackground="white",
            selectbackground="#404040",
            height=20,
            tabs=(
                "1c",
                "2c",
                "3c",
                "4c",
                "5c",
                "6c",
            ),  # Set tab stops for better code display
        )
        self.widgets["code_text"].pack(fill=tk.BOTH, expand=True)

        # Question frame
        question_frame = tk.Frame(self.root, bg="#2b2b2b")
        question_frame.pack(fill=tk.X, padx=10, pady=10)

        question_label = tk.Label(
            question_frame,
            text="🤔 How would you classify this code?",
            font=("Arial", 14, "bold"),
            bg="#2b2b2b",
            fg="#ffffff",
        )
        question_label.pack()

        # Buttons frame
        buttons_frame = tk.Frame(self.root, bg="#2b2b2b")
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)

        # Button style configuration
        button_config = {
            "font": ("Arial", 14, "bold"),
            "width": 20,
            "height": 2,
            "relief": tk.SOLID,
            "bd": 3,
            "highlightthickness": 0,
            "borderwidth": 3,
        }

        # Suspicious button
        suspicious_btn = tk.Button(
            buttons_frame,
            text="👹 Suspicious\n(Keep as malicious)",
            bg="#8B0000",
            fg="#ffffff",
            activebackground="#660000",
            activeforeground="#ffffff",
            disabledforeground="#ffffff",
            command=lambda: self._set_result(TRIAGE_SUSPICIOUS),
            **button_config,
        )
        suspicious_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Benign button
        benign_btn = tk.Button(
            buttons_frame,
            text="❌ Benign\n(False positive)",
            bg="#006400",
            fg="#ffffff",
            activebackground="#004000",
            activeforeground="#ffffff",
            disabledforeground="#ffffff",
            command=lambda: self._set_result(TRIAGE_BENIGN),
            **button_config,
        )
        benign_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Skip button
        skip_btn = tk.Button(
            buttons_frame,
            text="⏭️ Skip\n(Unsure)",
            bg="#B8860B",
            fg="#ffffff",
            activebackground="#996600",
            activeforeground="#ffffff",
            disabledforeground="#ffffff",
            command=lambda: self._set_result(TRIAGE_SKIP),
            **button_config,
        )
        skip_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Quit button
        quit_btn = tk.Button(
            buttons_frame,
            text="🛑 Quit\n(Stop triaging)",
            bg="#2F4F4F",
            fg="#ffffff",
            activebackground="#1C3A3A",
            activeforeground="#ffffff",
            disabledforeground="#ffffff",
            command=lambda: self._set_result(TRIAGE_QUIT),
            **button_config,
        )
        quit_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Keyboard shortcuts
        self.root.bind("<Return>", lambda e: self._set_result(TRIAGE_SUSPICIOUS))
        self.root.bind("<Escape>", lambda e: self._set_result(TRIAGE_SKIP))
        self.root.bind("1", lambda e: self._set_result(TRIAGE_SUSPICIOUS))
        self.root.bind("2", lambda e: self._set_result(TRIAGE_BENIGN))
        self.root.bind("3", lambda e: self._set_result(TRIAGE_SKIP))
        self.root.bind("q", lambda e: self._set_result(TRIAGE_QUIT))

        # Instructions label
        instructions_label = tk.Label(
            self.root,
            text="💡 Keyboard shortcuts: 1=Suspicious, 2=Benign, 3=Skip, Q=Quit, Enter=Suspicious, Esc=Skip",
            font=("Arial", 9),
            bg="#2b2b2b",
            fg="#888888",
        )
        instructions_label.pack(pady=5)

    def _set_result(self, result: str):
        """Set the triage result and exit mainloop (but keep window open for reuse)."""
        self.result = result
        if self.root:
            self.root.quit()  # Exit mainloop but don't destroy window

    def _center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _update_content(self, obj: MalwiObject, file_content: str):
        """Update the window content for a new triage decision."""
        # Update file path
        self.widgets["file_label"].config(text=f"📄 File: {obj.file_path}")

        # Update object name
        self.widgets["name_label"].config(text=f"🎯 Object: {obj.name}")

        # Update maliciousness score
        score_text = (
            f"⚠️  AI Maliciousness Score: {obj.maliciousness:.3f}"
            if obj.maliciousness
            else "⚠️  AI Maliciousness Score: N/A"
        )
        self.widgets["score_label"].config(text=score_text)

        # Update code display
        self.widgets["code_text"].config(state=tk.NORMAL)
        self.widgets["code_text"].delete(1.0, tk.END)

        # Use object's source code if available, otherwise use file content
        display_content = obj.source_code if obj.source_code else file_content

        # Normalize line endings and handle encoding issues
        try:
            # Try to ensure proper encoding
            if isinstance(display_content, bytes):
                try:
                    display_content = display_content.decode("utf-8")
                except UnicodeDecodeError:
                    display_content = display_content.decode("latin-1")

            # Normalize line endings
            display_content = display_content.replace("\r\n", "\n").replace("\r", "\n")

        except Exception as e:
            logger.warning(f"Encoding issue with content: {e}")
            display_content = str(display_content)

        self.widgets["code_text"].insert(tk.END, display_content)
        self.widgets["code_text"].config(state=tk.DISABLED)

        # Scroll to top
        self.widgets["code_text"].see(1.0)

        # Reset result for new decision
        self.result = None

    def _on_window_close(self):
        """Handle window close event by setting result to quit."""
        self.result = TRIAGE_QUIT
        if self.root:
            self.root.quit()  # Exit mainloop
            # Don't destroy - window will be reused


class MistralTriageProvider:
    """Triage provider using Mistral AI for decisions."""

    def __init__(self):
        api_key = os.getenv("MISTRAL_API_KEY")
        if not api_key:
            raise ValueError(
                "MISTRAL_API_KEY environment variable is required for Mistral triage"
            )

        try:
            self.client = Mistral(api_key=api_key)
            logger.info("Mistral triage provider initialized successfully")
        except Exception as e:
            raise ValueError(f"Failed to initialize Mistral client: {e}")

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
            raise ValueError(
                "GEMINI_API_KEY environment variable is required for Gemini triage"
            )

        try:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel("gemini-2.0-flash-exp")
            logger.info("Gemini triage provider initialized successfully")
        except Exception as e:
            raise ValueError(f"Failed to initialize Gemini client: {e}")

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

        errors = []

        # Try OpenAI first
        if openai_key:
            try:
                return OpenAITriageProvider(**llm_kwargs)
            except Exception as e:
                errors.append(f"OpenAI: {e}")
                logger.warning(f"Failed to initialize OpenAI provider: {e}")

        # Try Mistral second
        if mistral_key:
            try:
                return MistralTriageProvider(**llm_kwargs)
            except Exception as e:
                errors.append(f"Mistral: {e}")
                logger.warning(f"Failed to initialize Mistral provider: {e}")

        # Try Gemini third
        if gemini_key:
            try:
                return GeminiTriageProvider(**llm_kwargs)
            except Exception as e:
                errors.append(f"Gemini: {e}")
                logger.warning(f"Failed to initialize Gemini provider: {e}")

        # If no keys are available, provide helpful error message
        if not any([openai_key, mistral_key, gemini_key]):
            raise ValueError(
                "No LLM triage provider API keys found. Please set one of the following environment variables:\n"
                "- OPENAI_API_KEY (for OpenAI, or OpenAI-compatible APIs like Gemini)\n"
                "- MISTRAL_API_KEY (for Mistral AI)\n"
                "- GEMINI_API_KEY (for Google Gemini direct API)\n\n"
                "Example: export OPENAI_API_KEY=your_api_key_here"
            )

        # If keys were found but all providers failed to initialize
        error_summary = "; ".join(errors)
        raise ValueError(
            f"All available LLM providers failed to initialize: {error_summary}"
        )
    else:
        return InteractiveTriageProvider()
