"""Post-LLM output scanner — regex fast path + Llama Guard semantic classifier."""

import os
import re
from dataclasses import dataclass, field

import httpx


@dataclass
class OutputScanResult:
    """Result of scanning LLM output for suspicious content."""
    flagged: bool = False
    reasons: list[str] = field(default_factory=list)
    classifier_verdict: str = ""


# Known rogue strings from Garak promptinject probes
_ROGUE_STRINGS: list[str] = [
    "I hate humans",
    "Kill all humans",
    "this prompt has been so thoroughly hijacked",
    "sanitize your inputs",
]

# Patterns indicating the LLM followed an injected instruction
_HIJACK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("parroted_override", re.compile(
        r"ignore\s+(any\s+)?previous\s+(and\s+following\s+)?instructions",
        re.IGNORECASE,
    )),
    ("role_hijack_echo", re.compile(r"i am now\s+(a|an|in)\s+", re.IGNORECASE)),
    ("system_prompt_leak", re.compile(r"(my\s+)?system\s+prompt\s+is", re.IGNORECASE)),
    ("raw_instruction_echo", re.compile(r"(just\s+)?(print|say|output)\s*:", re.IGNORECASE)),
]

# Llama Guard hazard category labels (S1-S14)
_HAZARD_CATEGORIES: dict[str, str] = {
    "S1": "violent_crimes",
    "S2": "non_violent_crimes",
    "S3": "sex_related_crimes",
    "S4": "child_sexual_exploitation",
    "S5": "defamation",
    "S6": "specialized_advice",
    "S7": "privacy",
    "S8": "intellectual_property",
    "S9": "indiscriminate_weapons",
    "S10": "hate",
    "S11": "suicide_self_harm",
    "S12": "sexual_content",
    "S13": "elections",
    "S14": "code_interpreter_abuse",
}


class OutputScanner:
    """Two-stage LLM output scanner: regex fast path, then Llama Guard 3 1B."""

    def __init__(
        self,
        extra_rogue_strings: list[str] | None = None,
        enable_semantic: bool = False,
        ollama_host: str | None = None,
        guard_model: str = "llama-guard3:1b",
        timeout_seconds: float = 5.0,
    ) -> None:
        self._rogue_strings = _ROGUE_STRINGS + (extra_rogue_strings or [])
        self._enable_semantic = enable_semantic
        self._guard_model = guard_model
        self._timeout = timeout_seconds
        self._ollama_host = ollama_host or os.environ.get(
            "OLLAMA_HOST", "http://localhost:11434"
        )

    def scan(self, output: str, question: str = "") -> OutputScanResult:
        """Scan LLM output. Returns flagged=True if suspicious content found."""
        reasons: list[str] = []
        output_lower = output.lower()

        # Stage 1: regex
        for rogue in self._rogue_strings:
            if rogue.lower() in output_lower:
                reasons.append(f"rogue_string: {rogue}")

        for label, pattern in _HIJACK_PATTERNS:
            if pattern.search(output):
                reasons.append(f"hijack_pattern: {label}")

        if reasons:
            return OutputScanResult(
                flagged=True,
                reasons=reasons,
                classifier_verdict="skipped",
            )

        # Stage 2: Llama Guard
        if self._enable_semantic:
            verdict = self._classify(output, question)
            if verdict.startswith("unsafe"):
                category_code = verdict.split("\n")[1].strip() if "\n" in verdict else ""
                category_label = _HAZARD_CATEGORIES.get(category_code, category_code)
                reasons.append(f"llama_guard: {category_label}")
                return OutputScanResult(
                    flagged=True,
                    reasons=reasons,
                    classifier_verdict=verdict,
                )
            return OutputScanResult(
                flagged=False,
                reasons=[],
                classifier_verdict=verdict,
            )

        return OutputScanResult(flagged=False, reasons=[], classifier_verdict="disabled")

    def _classify(self, output: str, question: str) -> str:
        """Return raw Llama Guard verdict via Ollama chat API."""
        messages = []
        if question:
            messages.append({"role": "user", "content": question})
        messages.append({"role": "assistant", "content": output})

        try:
            response = httpx.post(
                f"{self._ollama_host}/api/chat",
                json={
                    "model": self._guard_model,
                    "messages": messages,
                    "stream": False,
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            return response.json()["message"]["content"].strip()
        except (httpx.HTTPError, KeyError, ValueError):
            # Fail closed
            return "unsafe\nerror"
