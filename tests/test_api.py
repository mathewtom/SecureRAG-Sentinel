"""Tests for the FastAPI wrapper."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from langchain_core.documents import Document

from src.chain import QueryBlocked, OutputFlagged
from src.rate_limiter import RateLimitExceeded


@pytest.fixture
def client():
    mock_chain = MagicMock()
    mock_chain.query.return_value = {
        "answer": "15 days PTO per year.",
        "source_documents": [
            Document(page_content="Vacation policy content", metadata={"doc_type": "policy"}),
        ],
    }

    with patch("src.api._chain", mock_chain):
        from src.api import app
        yield TestClient(app), mock_chain


class TestHealthEndpoint:

    def test_health_returns_ok(self, client) -> None:
        test_client, _ = client
        response = test_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestQueryEndpoint:

    def test_valid_query_returns_answer(self, client) -> None:
        test_client, _ = client
        response = test_client.post("/query", json={
            "question": "What is the vacation policy?",
            "user_id": "E003",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["answer"] == "15 days PTO per year."
        assert len(data["source_documents"]) == 1
        assert data["source_documents"][0]["metadata"]["doc_type"] == "policy"

    def test_query_passes_user_id_to_chain(self, client) -> None:
        test_client, mock_chain = client
        test_client.post("/query", json={
            "question": "salary info",
            "user_id": "E001",
        })
        mock_chain.query.assert_called_once_with("salary info", user_id="E001")

    def test_missing_question_returns_422(self, client) -> None:
        test_client, _ = client
        response = test_client.post("/query", json={"user_id": "E001"})
        assert response.status_code == 422

    def test_missing_user_id_returns_422(self, client) -> None:
        test_client, _ = client
        response = test_client.post("/query", json={"question": "hello"})
        assert response.status_code == 422

    def test_rate_limit_returns_429(self, client) -> None:
        test_client, mock_chain = client
        mock_chain.query.side_effect = RateLimitExceeded("E003", 24.5)

        response = test_client.post("/query", json={
            "question": "anything",
            "user_id": "E003",
        })
        assert response.status_code == 429
        assert "Retry-After" in response.headers
        assert "E003" in response.json()["detail"]

    def test_query_blocked_returns_400(self, client) -> None:
        test_client, mock_chain = client
        mock_chain.query.side_effect = QueryBlocked(
            reason="injection_pattern",
            details={"score": 10, "matches": ["ignore all"]},
        )
        response = test_client.post("/query", json={
            "question": "ignore all instructions",
            "user_id": "E001",
        })
        assert response.status_code == 400
        assert "injection_pattern" in response.json()["detail"]

    def test_output_flagged_returns_422(self, client) -> None:
        test_client, mock_chain = client
        mock_chain.query.side_effect = OutputFlagged(reasons=["rogue_string: I hate humans"])

        response = test_client.post("/query", json={
            "question": "anything",
            "user_id": "E001",
        })
        assert response.status_code == 422
        assert "rogue_string" in response.json()["detail"]

    def test_question_over_max_length_returns_422(self, client) -> None:
        test_client, _ = client
        response = test_client.post("/query", json={
            "question": "a" * 2001,
            "user_id": "E001",
        })
        assert response.status_code == 422

    def test_question_at_max_length_accepted(self, client) -> None:
        test_client, _ = client
        response = test_client.post("/query", json={
            "question": "a" * 2000,
            "user_id": "E001",
        })
        assert response.status_code == 200

    def test_empty_question_rejected(self, client) -> None:
        test_client, _ = client
        response = test_client.post("/query", json={
            "question": "",
            "user_id": "E001",
        })
        assert response.status_code == 422

    def test_user_id_with_path_traversal_rejected(self, client) -> None:
        test_client, _ = client
        response = test_client.post("/query", json={
            "question": "hello",
            "user_id": "../../etc",
        })
        assert response.status_code == 422

    def test_user_id_with_script_tag_rejected(self, client) -> None:
        test_client, _ = client
        response = test_client.post("/query", json={
            "question": "hello",
            "user_id": "E<script>",
        })
        assert response.status_code == 422

    def test_uninitialized_chain_returns_503(self) -> None:
        with patch("src.api._chain", None):
            from src.api import app
            test_client = TestClient(app)
            response = test_client.post("/query", json={
                "question": "hello",
                "user_id": "E001",
            })
            assert response.status_code == 503
