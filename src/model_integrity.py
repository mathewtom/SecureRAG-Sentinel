"""Model digest verification via Ollama /api/tags endpoint."""

import os

import httpx


class ModelDigestMismatch(Exception):
    """Raised when the Ollama model digest does not match the pinned value."""

    def __init__(self, model: str, expected: str, actual: str) -> None:
        self.model = model
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Model digest mismatch for {model}: "
            f"expected {expected}, got {actual}"
        )


def verify_model_digest(
    model: str,
    *,
    ollama_host: str | None = None,
    expected_digest: str | None = None,
) -> str:
    """Verify the Ollama model digest against a pinned value.

    If SECURERAG_MODEL_DIGEST is not set and no expected_digest is provided,
    verification is skipped (returns the actual digest for informational use).

    Returns the actual digest prefix.
    """
    host = ollama_host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    pinned = expected_digest or os.environ.get("SECURERAG_MODEL_DIGEST")

    response = httpx.get(f"{host}/api/tags", timeout=5.0)
    response.raise_for_status()

    actual_digest = ""
    for m in response.json().get("models", []):
        if m["name"] == model or m["name"].startswith(model.split(":")[0]):
            if m["name"] == model:
                actual_digest = m["digest"]
                break
            actual_digest = actual_digest or m["digest"]

    if not actual_digest:
        raise ModelDigestMismatch(model, pinned or "any", "not_found")

    if pinned and not actual_digest.startswith(pinned):
        raise ModelDigestMismatch(model, pinned, actual_digest[:len(pinned)])

    return actual_digest
