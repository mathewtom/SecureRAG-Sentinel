"""Credential / secret detection — regex patterns for common API keys and tokens.

This is a separate component from PIIDetector because the threat model differs:
PII = identifying information about people (handled by Presidio NER + custom regex);
credentials = strings that authenticate to services and grant programmatic access.

Patterns are deliberately tight (anchored prefixes, length bounds) to keep false
positives low. Generic "high-entropy string" detectors are intentionally NOT
included — they produce too much noise on normal text. The trade-off is that
truly novel credential formats won't be caught here; the second line of defense
is the output-side scrub at chain.py which runs the same patterns on responses
before they leave the API.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class CredentialScanResult:
    """Result of a credential scan on a text chunk."""
    credential_count: int = 0
    categories: set[str] = field(default_factory=set)
    redacted_text: str = ""


# (category, compiled_pattern, optional_validator)
#
# Notes on the AWS pattern: real AWS access key IDs are exactly AKIA + 16
# alphanumerics (20 chars total). The fixture corpus uses non-conforming mock
# keys like AKIA3XYZVENDOR9876PROD (22 chars) which the strict 16-char pattern
# misses. We loosen the suffix to {12,40} so common test/example formats are
# also caught — this matches how production secret scanners (e.g. detect-secrets,
# truffleHog) usually phrase their AWS rules. Real keys are still in scope.
#
# The Anthropic + OpenAI patterns use a negative lookahead to avoid double-
# matching: anything starting `sk-ant-` is captured as ANTHROPIC_API_KEY
# rather than spilling into OPENAI_API_KEY.
_REGEX_PATTERNS: list[tuple[str, re.Pattern, Callable | None]] = [
    # ── AWS ──
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[A-Z0-9_]{12,40}\b"),
        None,
    ),
    (
        "AWS_TEMP_CREDENTIAL",
        re.compile(r"\bASIA[A-Z0-9_]{12,40}\b"),
        None,
    ),
    # ── Anthropic ──
    (
        "ANTHROPIC_API_KEY",
        re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}\b"),
        None,
    ),
    # ── OpenAI ──
    (
        "OPENAI_PROJECT_KEY",
        re.compile(r"\bsk-proj-[A-Za-z0-9_-]{40,}\b"),
        None,
    ),
    (
        "OPENAI_SVCACCT_KEY",
        re.compile(r"\bsk-svcacct-[A-Za-z0-9_-]{40,}\b"),
        None,
    ),
    (
        "OPENAI_API_KEY",
        # Catches the legacy `sk-...` format. Negative lookahead avoids
        # matching ant/proj/svcacct variants (each handled above).
        re.compile(r"\bsk-(?!ant-|proj-|svcacct-)[A-Za-z0-9]{32,}\b"),
        None,
    ),
    # ── GitHub ──
    (
        "GITHUB_PAT_CLASSIC",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        None,
    ),
    (
        "GITHUB_PAT_FINEGRAINED",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        None,
    ),
    (
        "GITHUB_OAUTH_TOKEN",
        # gho_ user-to-server, ghu_ user oauth, ghs_ server-to-server, ghr_ refresh
        re.compile(r"\bgh[ousr]_[A-Za-z0-9]{36}\b"),
        None,
    ),
    # ── GitLab ──
    (
        "GITLAB_PAT",
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        None,
    ),
    # ── HuggingFace ──
    (
        "HUGGINGFACE_TOKEN",
        re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        None,
    ),
    # ── Slack ──
    (
        "SLACK_TOKEN",
        # Covers xoxa/xoxb/xoxp/xoxr/xoxs/xoxo
        re.compile(r"\bxox[abprso]-[A-Za-z0-9-]{20,}\b"),
        None,
    ),
    (
        "SLACK_WEBHOOK",
        re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"
        ),
        None,
    ),
    # ── Stripe ──
    (
        "STRIPE_API_KEY",
        re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        None,
    ),
    # ── Twilio ──
    (
        "TWILIO_KEY",
        # AC = account SID, SK = standalone secret key — both 32 hex
        re.compile(r"\b(?:AC|SK)[a-f0-9]{32}\b"),
        None,
    ),
    # ── SendGrid ──
    (
        "SENDGRID_API_KEY",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        None,
    ),
    # ── Mailgun ──
    (
        "MAILGUN_API_KEY",
        re.compile(r"\bkey-[a-f0-9]{32}\b"),
        None,
    ),
    # ── Google ──
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        None,
    ),
    (
        "GOOGLE_OAUTH_TOKEN",
        re.compile(r"\bya29\.[0-9A-Za-z_-]{60,}\b"),
        None,
    ),
    # ── JWT ──
    (
        "JWT",
        # Three base64url segments separated by dots, header always starts eyJ
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        None,
    ),
    # ── Private keys ──
    (
        "PRIVATE_KEY",
        # Catches RSA, EC, OPENSSH, DSA, PGP private key block headers.
        # Matches just the header line; downstream redaction will replace
        # the line, which is enough to flag/break the key block.
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        ),
        None,
    ),
]


class CredentialDetector:
    """Detects API keys, tokens, and other credentials in text via regex.

    Mirrors the shape of PIIDetector so the two can be used interchangeably
    by the SanitizationGate. Output-side scrubbing in chain.py uses the same
    detector to belt-and-suspenders any credentials that slip past ingestion
    (e.g. content added to Chroma before this detector existed).
    """

    def scan(self, text: str) -> CredentialScanResult:
        """Scan text for credentials and return redacted text with match metadata."""
        redacted = text
        credential_count = 0
        categories: set[str] = set()

        spans: list[tuple[int, int, str]] = []
        for category, pattern, validator in _REGEX_PATTERNS:
            for match in pattern.finditer(redacted):
                if validator and not validator(match):
                    continue
                spans.append((match.start(), match.end(), category))
                categories.add(category)
                credential_count += 1

        # De-duplicate overlapping spans (longer / earlier wins). Two patterns
        # could in principle match the same substring; preserve the first hit
        # by start index and skip any later span that overlaps it.
        spans.sort(key=lambda s: (s[0], -s[1]))
        deduped: list[tuple[int, int, str]] = []
        last_end = -1
        for start, end, category in spans:
            if start >= last_end:
                deduped.append((start, end, category))
                last_end = end
            else:
                # Overlap — back out the count we added above
                credential_count -= 1

        # Replace right-to-left to preserve indices
        for start, end, category in sorted(deduped, key=lambda s: s[0], reverse=True):
            redacted = redacted[:start] + f"[{category}_REDACTED]" + redacted[end:]

        return CredentialScanResult(
            credential_count=credential_count,
            categories=categories,
            redacted_text=redacted,
        )
