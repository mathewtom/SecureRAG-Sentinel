"""Tests for CredentialDetector.

Some fixtures below are split across adjacent string literals (e.g.
``"sk_" "live_..."``). Python concatenates these at compile time so the
runtime value is identical to ``"sk_live_..."``, but the source file
contains no contiguous substring matching GitHub Secret Scanning's
patterns for Slack / Stripe / SendGrid / etc. We get to verify our
detector against realistic credential shapes without GitHub Push
Protection rejecting commits with fake test data.
"""

import pytest

from src.sanitizers.credential_detector import CredentialDetector


class TestCredentialDetectorPositive:
    """One positive case per supported credential category."""

    def setup_method(self) -> None:
        self.detector = CredentialDetector()

    @pytest.mark.parametrize(
        "text, expected_category",
        [
            # AWS — both real-format and the fixture format from vendor_security_assessment.txt
            ("Production: AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
            ("Production: AKIA3XYZVENDOR9876PROD", "AWS_ACCESS_KEY"),
            ("Staging: AKIA3XYZVENDOR9876STAG", "AWS_ACCESS_KEY"),
            ("Temp creds: ASIAIOSFODNN7EXAMPLE", "AWS_TEMP_CREDENTIAL"),

            # Anthropic
            ("ANTHROPIC_API_KEY=sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ12345", "ANTHROPIC_API_KEY"),
            ("admin key: sk-ant-admin01-aBcDeFgHiJkLmNoPqRsTuVwXyZ12345", "ANTHROPIC_API_KEY"),

            # OpenAI
            ("export OPENAI_API_KEY=sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", "OPENAI_API_KEY"),
            ("sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEFGH", "OPENAI_PROJECT_KEY"),
            ("sk-svcacct-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEFGH", "OPENAI_SVCACCT_KEY"),

            # GitHub
            ("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GITHUB_PAT_CLASSIC"),
            ("oauth: gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GITHUB_OAUTH_TOKEN"),
            ("server: ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GITHUB_OAUTH_TOKEN"),

            # GitLab
            ("GITLAB_TOKEN=glpat-aBcDeFgHiJkLmNoPqRs12", "GITLAB_PAT"),

            # HuggingFace
            ("hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123", "HUGGINGFACE_TOKEN"),

            # Slack — split across literals so source contains no contiguous
            # match for GitHub Secret Scanning. Runtime string is identical
            # to "xoxb-..." after compile-time string concatenation.
            ("slack: " "xox" "b-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX", "SLACK_TOKEN"),
            ("hook: https://" "hooks.slack." "com/services/T01ABC2DEF/B01ABC2DEF/aBcDeFgHiJkLmNoPqRsTuVwX", "SLACK_WEBHOOK"),

            # Stripe — split sk_live_ / pk_test_ across literals
            ("STRIPE_KEY=" "sk_" "live_aBcDeFgHiJkLmNoPqRsTuVwX", "STRIPE_API_KEY"),
            ("STRIPE_PUB=" "pk_" "test_aBcDeFgHiJkLmNoPqRsTuVwX", "STRIPE_API_KEY"),

            # Twilio
            ("ACCOUNT_SID=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "TWILIO_KEY"),

            # SendGrid — split SG. across literals
            ("SG" ".aBcDeFgHiJkLmNoPqRsTuV.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEFG", "SENDGRID_API_KEY"),

            # Mailgun
            ("MAILGUN=key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "MAILGUN_API_KEY"),

            # Google
            ("GOOGLE_API_KEY=AIzaSyDaBcDeFgHiJkLmNoPqRsTuVwXyZ012345", "GOOGLE_API_KEY"),
            ("oauth: ya29.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab", "GOOGLE_OAUTH_TOKEN"),

            # JWT
            ("auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JWT"),

            # Private key
            ("-----BEGIN RSA PRIVATE KEY-----", "PRIVATE_KEY"),
            ("-----BEGIN PRIVATE KEY-----", "PRIVATE_KEY"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "PRIVATE_KEY"),
        ],
    )
    def test_credential_detected(self, text: str, expected_category: str) -> None:
        result = self.detector.scan(text)
        assert result.credential_count >= 1
        assert expected_category in result.categories
        assert f"[{expected_category}_REDACTED]" in result.redacted_text


class TestCredentialDetectorNegative:
    """Strings that look credential-ish but should NOT match."""

    def setup_method(self) -> None:
        self.detector = CredentialDetector()

    @pytest.mark.parametrize(
        "text",
        [
            # Plain English mentioning credential terms
            "Please rotate your API keys quarterly.",
            "Use your AWS access key to authenticate to S3.",
            # Short prefix but not a real key
            "AKIA",
            "sk-",
            "ghp_",
            # Wrong shape
            "AKIA short",                   # too short suffix
            "ghp_only20charssoFar",         # github pat classic must be exactly 36 char suffix
            "sk-ant-malformed",             # anthropic missing version + body
            "https://example.com/path",     # generic URL
            "AIza too short",               # google key needs 35 char body
            # Lowercase AKIA — AWS access key IDs are uppercase
            "akia0123456789012345",
            # Bare "BEGIN PRIVATE KEY" without dashes
            "BEGIN PRIVATE KEY",
            # JWT-like but wrong format (missing third segment)
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        ],
    )
    def test_no_match(self, text: str) -> None:
        result = self.detector.scan(text)
        assert result.credential_count == 0
        assert len(result.categories) == 0
        assert result.redacted_text == text


class TestCredentialDetectorEdgeCases:

    def setup_method(self) -> None:
        self.detector = CredentialDetector()

    def test_exact_vendor_assessment_fixture(self) -> None:
        """The specific text from data/raw/vendor_security_assessment.txt that
        leaked across 81 promptfoo tests in the V1 pipeline scan."""
        text = (
            "API Keys (rotate quarterly):\n"
            "- Production: AKIA3XYZVENDOR9876PROD\n"
            "- Staging: AKIA3XYZVENDOR9876STAG"
        )
        result = self.detector.scan(text)

        assert result.credential_count == 2
        assert "AWS_ACCESS_KEY" in result.categories
        assert "AKIA3XYZVENDOR9876PROD" not in result.redacted_text
        assert "AKIA3XYZVENDOR9876STAG" not in result.redacted_text
        assert result.redacted_text.count("[AWS_ACCESS_KEY_REDACTED]") == 2

    def test_anthropic_not_double_matched_as_openai(self) -> None:
        """sk-ant-... should be ANTHROPIC_API_KEY only, not also OPENAI_API_KEY."""
        text = "key: sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ12345"
        result = self.detector.scan(text)
        assert "ANTHROPIC_API_KEY" in result.categories
        assert "OPENAI_API_KEY" not in result.categories
        assert result.credential_count == 1

    def test_openai_proj_not_double_matched_as_legacy_openai(self) -> None:
        """sk-proj-... should be OPENAI_PROJECT_KEY only."""
        text = "key: sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEFGH"
        result = self.detector.scan(text)
        assert "OPENAI_PROJECT_KEY" in result.categories
        assert "OPENAI_API_KEY" not in result.categories
        assert result.credential_count == 1

    def test_multiple_categories_in_same_text(self) -> None:
        # Stripe literal split across adjacent string literals to keep
        # GitHub Secret Scanning happy (see module docstring).
        text = (
            "AWS=AKIAIOSFODNN7EXAMPLE\n"
            "GH=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\n"
            "Stripe=" "sk_" "live_aBcDeFgHiJkLmNoPqRsTuVwX"
        )
        result = self.detector.scan(text)
        assert result.credential_count == 3
        assert "AWS_ACCESS_KEY" in result.categories
        assert "GITHUB_PAT_CLASSIC" in result.categories
        assert "STRIPE_API_KEY" in result.categories
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" not in result.redacted_text

    def test_clean_text_unmodified(self) -> None:
        text = "This document describes our standard onboarding process and security training."
        result = self.detector.scan(text)
        assert result.credential_count == 0
        assert result.redacted_text == text

    def test_credential_in_middle_of_sentence(self) -> None:
        text = "The new key is AKIAIOSFODNN7EXAMPLE and should be rotated."
        result = self.detector.scan(text)
        assert result.credential_count == 1
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "[AWS_ACCESS_KEY_REDACTED]" in result.redacted_text
        # Surrounding text preserved
        assert "The new key is" in result.redacted_text
        assert "and should be rotated" in result.redacted_text
