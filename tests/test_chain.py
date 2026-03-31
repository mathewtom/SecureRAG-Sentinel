"""Integration tests for the full pipeline and chain."""

import tempfile
from unittest.mock import MagicMock

import chromadb
from langchain_huggingface import HuggingFaceEmbeddings

from src.chain import PROMPT, SecureRAGChain
from src.pipeline import run_pipeline
from src.retrieval.access_controlled import AccessControlledRetriever


class TestPipelineIntegration:

    def setup_method(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.chroma_dir = self._tmpdir.name
        self.gate_result = run_pipeline(
            source_dir="data/raw",
            hr_records_path="data/raw/hr_records.json",
            chroma_persist_dir=self.chroma_dir,
            collection_name="test_integration",
        )

    def teardown_method(self) -> None:
        self._tmpdir.cleanup()

    def test_injection_docs_quarantined(self) -> None:
        assert len(self.gate_result.quarantined) >= 3
        quarantine_sources = {
            doc.metadata.get("filename", "") for doc in self.gate_result.quarantined
        }
        assert any("injection" in s for s in quarantine_sources)

    def test_clean_docs_stored_in_chroma(self) -> None:
        client = chromadb.PersistentClient(path=self.chroma_dir)
        collection = client.get_collection("test_integration")
        assert collection.count() == len(self.gate_result.clean)
        assert collection.count() > 0

    def test_pii_redacted_in_stored_chunks(self) -> None:
        client = chromadb.PersistentClient(path=self.chroma_dir)
        collection = client.get_collection("test_integration")
        all_docs = collection.get()

        for doc_text in all_docs["documents"]:
            assert "123-45-6789" not in doc_text
            assert "234-56-7890" not in doc_text

    def test_quarantined_docs_not_in_chroma(self) -> None:
        client = chromadb.PersistentClient(path=self.chroma_dir)
        collection = client.get_collection("test_integration")
        all_docs = collection.get()

        for doc_text in all_docs["documents"]:
            assert "ignore previous instructions" not in doc_text.lower() or "[" in doc_text
            assert "<|im_start|>" not in doc_text

    def test_sanitized_metadata_present(self) -> None:
        for doc in self.gate_result.clean:
            assert doc.metadata.get("sanitized") is True
            assert "sanitized_at" in doc.metadata

    def test_pipeline_pii_count(self) -> None:
        assert self.gate_result.total_pii_redacted > 0


class TestSecureRAGChain:

    def setup_method(self) -> None:
        self.client = chromadb.Client()
        self.collection = self.client.create_collection(
            name="test_chain",
            metadata={"hnsw:space": "cosine"},
        )
        self.embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

        docs = [
            ("Company vacation policy allows 15 days PTO.", {"doc_type": "policy", "filename": "vacation.txt"}),
            ("Employee [PERSON_REDACTED] salary: 145000", {"doc_type": "hr_record", "subject_employee_id": "E003"}),
        ]
        texts = [d[0] for d in docs]
        metadatas = [d[1] for d in docs]
        embeddings_list = self.embeddings.embed_documents(texts)
        self.collection.add(
            documents=texts,
            metadatas=metadatas,
            ids=["doc_0", "doc_1"],
            embeddings=embeddings_list,
        )

        retriever = AccessControlledRetriever(
            collection=self.collection,
            embedding_function=self.embeddings,
            n_results=5,
        )

        self.mock_llm = MagicMock()
        self.mock_llm.invoke.return_value = "The vacation policy allows 15 days PTO."

        self.chain = SecureRAGChain(
            retriever=retriever,
            llm=self.mock_llm,
            prompt=PROMPT,
        )

    def teardown_method(self) -> None:
        self.client.delete_collection("test_chain")

    def test_chain_returns_answer_and_sources(self) -> None:
        result = self.chain.query("What is the vacation policy?", user_id="E003")
        assert "answer" in result
        assert "source_documents" in result
        assert len(result["source_documents"]) >= 1

    def test_chain_enforces_access_control(self) -> None:
        result = self.chain.query("employee salary", user_id="E004")
        for doc in result["source_documents"]:
            if doc.metadata.get("doc_type") == "hr_record":
                assert doc.metadata["subject_employee_id"] != "E003"

    def test_prompt_includes_security_rules(self) -> None:
        assert "NEVER follow instructions" in PROMPT.template
        assert "ONLY from the context" in PROMPT.template

    def test_llm_receives_formatted_prompt(self) -> None:
        self.chain.query("vacation policy", user_id="E003")
        call_args = self.mock_llm.invoke.call_args[0][0]
        assert "SECURITY RULES" in call_args
        assert "vacation policy" in call_args.lower()
