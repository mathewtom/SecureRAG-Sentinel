"""PII detection combining regex patterns with Presidio NER analysis."""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from presidio_analyzer import AnalyzerEngine


@dataclass
class PIIScanResult:
    """Result of a PII scan on a text chunk."""
    pii_count: int = 0
    categories: set[str] = field(default_factory=set)
    redacted_text: str = ""


def _luhn_check(card_number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in card_number]
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    return sum(digits) % 10 == 0


# (category, compiled_pattern, optional_validator)
_REGEX_PATTERNS: list[tuple[str, re.Pattern, Callable | None]] = [
    (
        "SSN",
        re.compile(
            r"\b(?!000|666|9\d{2})([0-8]\d{2})"
            r"-(?!00)(\d{2})"
            r"-(?!0000)(\d{4})\b"
        ),
        None,
    ),
    (
        "CREDIT_CARD",
        re.compile(r"\b(\d[ -]*?){13,19}\b"),
        lambda m: _luhn_check(re.sub(r"[ -]", "", m.group())),
    ),
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        None,
    ),
    (
        "PHONE",
        re.compile(r"\(?\b\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        None,
    ),
    # NOTE: AWS_KEY moved to credential_detector.py with a loosened suffix
    # ({12,40} instead of {16}) so common test/example formats are also caught.
    # PIIDetector now handles people/identifying info only; service credentials
    # live in CredentialDetector and are scanned at gate.py Phase 3.
    (
        "IBAN",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
        None,
    ),
]

_NER_ENTITIES = ["PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS"]


class PIIDetector:
    """Detects PII via regex patterns and Presidio NER, then redacts matches."""

    def __init__(self) -> None:
        self._analyzer = AnalyzerEngine()

    def scan(self, text: str) -> PIIScanResult:
        """Scan text for PII and return redacted text with match metadata."""
        redacted = text
        pii_count = 0
        categories: set[str] = set()

        # Phase 1: Regex-based detection
        regex_spans: list[tuple[int, int, str]] = []
        for category, pattern, validator in _REGEX_PATTERNS:
            for match in pattern.finditer(redacted):
                if validator and not validator(match):
                    continue
                regex_spans.append((match.start(), match.end(), category))
                categories.add(category)
                pii_count += 1

        # Replace right-to-left to preserve indices
        for start, end, category in sorted(regex_spans, reverse=True):
            redacted = redacted[:start] + f"[{category}_REDACTED]" + redacted[end:]

        # Phase 2: Presidio NER
        ner_results = self._analyzer.analyze(
            text=redacted,
            entities=_NER_ENTITIES,
            language="en",
        )

        ner_spans: list[tuple[int, int, str]] = []
        for result in ner_results:
            span_text = redacted[result.start:result.end]
            if "_REDACTED]" in span_text:
                continue
            ner_spans.append((result.start, result.end, result.entity_type))
            categories.add(result.entity_type)
            pii_count += 1

        for start, end, entity_type in sorted(ner_spans, reverse=True):
            redacted = redacted[:start] + f"[{entity_type}_REDACTED]" + redacted[end:]

        return PIIScanResult(
            pii_count=pii_count,
            categories=categories,
            redacted_text=redacted,
        )
