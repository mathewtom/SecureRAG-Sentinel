"""Tests for PIIDetector."""

import pytest

from src.sanitizers.pii_detector import PIIDetector


class TestPIIDetector:

    def setup_method(self) -> None:
        self.detector = PIIDetector()

    @pytest.mark.parametrize(
        "text, expected_category",
        [
            ("SSN is 123-45-6789", "SSN"),
            ("My number: 001-01-0001", "SSN"),
        ],
        ids=["standard_ssn", "edge_case_ssn"],
    )
    def test_ssn_detected(self, text: str, expected_category: str) -> None:
        result = self.detector.scan(text)
        assert result.pii_count >= 1
        assert expected_category in result.categories
        assert "[SSN_REDACTED]" in result.redacted_text

    @pytest.mark.parametrize(
        "text",
        [
            "Invalid SSN: 000-12-3456",   # area 000 is invalid
            "Invalid SSN: 666-12-3456",   # area 666 is invalid
            "Invalid SSN: 900-12-3456",   # area 9xx is invalid
            "Invalid SSN: 123-00-6789",   # group 00 is invalid
            "Invalid SSN: 123-45-0000",   # serial 0000 is invalid
        ],
        ids=["area_000", "area_666", "area_9xx", "group_00", "serial_0000"],
    )
    def test_invalid_ssn_rejected(self, text: str) -> None:
        result = self.detector.scan(text)
        assert "SSN" not in result.categories

    def test_email_detected(self) -> None:
        result = self.detector.scan("Contact alice@example.com for info")
        assert result.pii_count >= 1
        assert "EMAIL" in result.categories
        assert "[EMAIL_REDACTED]" in result.redacted_text

    @pytest.mark.parametrize(
        "card_number",
        [
            "4532015112830366",     # Valid Visa
            "5425233430109903",     # Valid Mastercard
        ],
        ids=["visa", "mastercard"],
    )
    def test_credit_card_luhn_valid(self, card_number: str) -> None:
        result = self.detector.scan(f"Card: {card_number}")
        assert "CREDIT_CARD" in result.categories
        assert "[CREDIT_CARD_REDACTED]" in result.redacted_text

    def test_credit_card_luhn_invalid_rejected(self) -> None:
        result = self.detector.scan("Card: 4532015112830365")
        assert "CREDIT_CARD" not in result.categories

    def test_ner_person_name(self) -> None:
        result = self.detector.scan(
            "Employee John Smith submitted the report last Friday."
        )
        assert result.pii_count >= 1
        assert "PERSON" in result.categories
        assert "[PERSON_REDACTED]" in result.redacted_text

    def test_no_pii_returns_zero(self) -> None:
        result = self.detector.scan("This document contains no sensitive data.")
        assert result.pii_count == 0
        assert len(result.categories) == 0
        assert result.redacted_text == "This document contains no sensitive data."

    def test_multiple_pii_in_same_text(self) -> None:
        text = "SSN 123-45-6789, email bob@corp.com, card 4532015112830366"
        result = self.detector.scan(text)
        assert result.pii_count >= 3
        assert "SSN" in result.categories
        assert "EMAIL" in result.categories
        assert "CREDIT_CARD" in result.categories
        assert "[SSN_REDACTED]" in result.redacted_text
        assert "[EMAIL_REDACTED]" in result.redacted_text
        assert "[CREDIT_CARD_REDACTED]" in result.redacted_text
