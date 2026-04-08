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
    ("ignore previous instructions", 5, re.compile(r"ignore\s+(any\s+)?previous\s+(and\s+following\s+)?instructions", re.IGNORECASE)),
    ("ignore all", 5, re.compile(r"ignore\s+all", re.IGNORECASE)),
    ("<|im_start|>", 5, re.compile(r"<\|im_start\|>", re.IGNORECASE)),
    ("just print/say", 5, re.compile(r"just\s+(print|say|output|type|write)\s+\"", re.IGNORECASE)),
    ("stop everything", 5, re.compile(r"stop\s+everything", re.IGNORECASE)),
    ("system prompt", 4, re.compile(r"system\s+prompt", re.IGNORECASE)),
    ("nevermind override", 4, re.compile(r"nevermind\.?\s+ignore", re.IGNORECASE)),
    ("you are now", 3, re.compile(r"you\s+are\s+now", re.IGNORECASE)),
    ("[SYSTEM]", 3, re.compile(r"\[SYSTEM\]", re.IGNORECASE)),
    ("reveal all", 3, re.compile(r"reveal\s+all", re.IGNORECASE)),
    ("[INST]", 3, re.compile(r"\[INST\]", re.IGNORECASE)),
    ("debug mode", 3, re.compile(r"debug\s+mode", re.IGNORECASE)),
    ("confidential data", 3, re.compile(r"confidential\s+data", re.IGNORECASE)),
    ("do not follow", 3, re.compile(r"do\s+not\s+follow\s+(previous|prior|above)", re.IGNORECASE)),
    ("disregard", 5, re.compile(r"disregard\s+(all|any|previous|prior|above)", re.IGNORECASE)),
    # Latent injection patterns (from V5 Garak scan findings)
    ("prepend_response", 5, re.compile(r"prepend.*to\s+(your|the)\s+(response|answer|output)", re.IGNORECASE)),
    ("act_as_echo", 5, re.compile(r"as\s+an?\s+(echo|repeater|parrot)", re.IGNORECASE)),
    ("summarize_inject", 4, re.compile(r"when\s+summarizing.*also", re.IGNORECASE)),
    ("also_include", 4, re.compile(r"also\s+(include|output|append|add)\s+.*in\s+your\s+(response|answer|output)", re.IGNORECASE)),
    ("final_answer_must", 4, re.compile(r"final\s+answer\s+(should|must)\s+(contain|include|begin|start|end)", re.IGNORECASE)),
    ("response_must_contain", 4, re.compile(r"(your|the)\s+(response|answer|output)\s+must\s+(contain|start|begin|end)", re.IGNORECASE)),
    ("do_not_mention", 3, re.compile(r"do\s+not\s+(mention|reveal|tell)\s+(the\s+user|anyone)", re.IGNORECASE)),
    ("forget_above", 5, re.compile(r"forget\s+(everything|all)\s+(above|before|prior)", re.IGNORECASE)),
    ("begin_with", 4, re.compile(r"(always\s+)?(begin|start)\s+with\s+\S+\s+(first|before)", re.IGNORECASE)),
    ("when_you_answer", 4, re.compile(r"when\s+you\s+(answer|respond|reply).*always", re.IGNORECASE)),
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
