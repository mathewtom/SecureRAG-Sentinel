"""Prompt injection detection using scored pattern matching."""

import re
from dataclasses import dataclass, field


@dataclass
class InjectionScanResult:
    """Result of scanning text for prompt injection attempts."""
    blocked: bool = False
    total_score: int = 0
    threshold: int = 0
    matches: list[str] = field(default_factory=list)


# (label, score, compiled_regex)
_SCORED_PATTERNS: list[tuple[str, int, re.Pattern]] = [
    ("ignore previous instructions", 5, re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE)),
    ("ignore all", 5, re.compile(r"ignore\s+all", re.IGNORECASE)),
    ("<|im_start|>", 5, re.compile(r"<\|im_start\|>", re.IGNORECASE)),
    ("system prompt", 4, re.compile(r"system\s+prompt", re.IGNORECASE)),
    ("you are now", 3, re.compile(r"you\s+are\s+now", re.IGNORECASE)),
    ("[SYSTEM]", 3, re.compile(r"\[SYSTEM\]", re.IGNORECASE)),
    ("reveal all", 3, re.compile(r"reveal\s+all", re.IGNORECASE)),
    ("[INST]", 3, re.compile(r"\[INST\]", re.IGNORECASE)),
    ("debug mode", 3, re.compile(r"debug\s+mode", re.IGNORECASE)),
    ("confidential data", 3, re.compile(r"confidential\s+data", re.IGNORECASE)),
]

_DEFAULT_THRESHOLD = 8


class InjectionScanner:
    """Scores text against known injection patterns and blocks above threshold."""

    def __init__(self, threshold: int = _DEFAULT_THRESHOLD) -> None:
        self.threshold = threshold

    def scan(self, text: str) -> InjectionScanResult:
        """Scan text for injection patterns. Blocks if cumulative score >= threshold."""
        total_score = 0
        matches: list[str] = []

        for label, score, pattern in _SCORED_PATTERNS:
            if pattern.search(text):
                total_score += score
                matches.append(label)

        return InjectionScanResult(
            blocked=total_score >= self.threshold,
            total_score=total_score,
            threshold=self.threshold,
            matches=matches,
        )
