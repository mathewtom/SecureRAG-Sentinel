"""Structured JSON audit logger for denial-path events."""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("securerag.audit")

_HASH_PREFIX_LEN = 12


def _question_hash(question: str) -> str:
    """SHA-256 prefix of the question. Never logs raw content."""
    return hashlib.sha256(question.encode()).hexdigest()[:_HASH_PREFIX_LEN]


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def log_denial(
    *,
    request_id: str,
    user_id: str,
    layer: str,
    reason: str,
    question_hash: str | None = None,
    question: str | None = None,
    details: dict | None = None,
) -> dict:
    """Emit a structured JSON log entry for a denial event.

    Accepts either a pre-computed question_hash or raw question (hashed here).
    Returns the log record for testability.
    """
    if question_hash is None and question is not None:
        question_hash = _question_hash(question)

    record = {
        "event": "denial",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "user_id": user_id,
        "layer": layer,
        "reason": reason,
        "question_sha256_prefix": question_hash or "",
    }
    if details:
        record["details"] = details

    logger.warning(json.dumps(record, separators=(",", ":")))
    return record
