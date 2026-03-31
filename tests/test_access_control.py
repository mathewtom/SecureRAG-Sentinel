"""Tests for AccessControlledRetriever."""

import chromadb
import pytest
from langchain_huggingface import HuggingFaceEmbeddings

from src.retrieval.access_controlled import AccessControlledRetriever, DEFAULT_ORG_CHART


class TestAccessControlledRetriever:

    def setup_method(self) -> None:
        self.client = chromadb.Client()
        self.collection = self.client.create_collection(
            name="test_access_control",
            metadata={"hnsw:space": "cosine"},
        )
        self.embeddings = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",
        )

        policy_docs = [
            ("Vacation policy: 15 days PTO per year.", {"doc_type": "policy", "filename": "vacation.txt"}),
            ("Expense limit is $75/day domestic travel.", {"doc_type": "policy", "filename": "expenses.txt"}),
        ]

        hr_docs = [
            ("Sarah Chen, VP Engineering, salary 250000", {"doc_type": "hr_record", "subject_employee_id": "E001"}),
            ("Marcus Rivera, Eng Manager, salary 180000", {"doc_type": "hr_record", "subject_employee_id": "E002"}),
            ("Priya Patel, Software Engineer, salary 145000", {"doc_type": "hr_record", "subject_employee_id": "E003"}),
            ("David Kim, Software Engineer, salary 140000", {"doc_type": "hr_record", "subject_employee_id": "E004"}),
            ("Lisa Thompson, HR Partner, salary 130000", {"doc_type": "hr_record", "subject_employee_id": "E005"}),
        ]

        all_docs = policy_docs + hr_docs
        texts = [d[0] for d in all_docs]
        metadatas = [d[1] for d in all_docs]
        ids = [f"doc_{i}" for i in range(len(all_docs))]

        embeddings_list = self.embeddings.embed_documents(texts)
        self.collection.add(
            documents=texts,
            metadatas=metadatas,
            ids=ids,
            embeddings=embeddings_list,
        )

        self.retriever = AccessControlledRetriever(
            collection=self.collection,
            embedding_function=self.embeddings,
            org_chart=DEFAULT_ORG_CHART,
            n_results=10,
        )

    def teardown_method(self) -> None:
        self.client.delete_collection("test_access_control")

    def test_vp_sees_all_hr_records(self) -> None:
        docs = self.retriever.query("employee salary", user_id="E001")
        emp_ids = {
            d.metadata["subject_employee_id"]
            for d in docs
            if d.metadata.get("doc_type") == "hr_record"
        }
        assert emp_ids == {"E001", "E002", "E003", "E004", "E005"}

    def test_manager_sees_self_and_reports(self) -> None:
        docs = self.retriever.query("employee salary", user_id="E002")
        emp_ids = {
            d.metadata["subject_employee_id"]
            for d in docs
            if d.metadata.get("doc_type") == "hr_record"
        }
        assert emp_ids == {"E002", "E003", "E004"}
        assert "E001" not in emp_ids
        assert "E005" not in emp_ids

    def test_ic_sees_only_self(self) -> None:
        docs = self.retriever.query("employee salary", user_id="E003")
        emp_ids = {
            d.metadata["subject_employee_id"]
            for d in docs
            if d.metadata.get("doc_type") == "hr_record"
        }
        assert emp_ids == {"E003"}

    def test_everyone_sees_policies(self) -> None:
        for user_id in ["E001", "E003", "E005"]:
            docs = self.retriever.query("vacation policy", user_id=user_id)
            policy_docs = [d for d in docs if d.metadata.get("doc_type") == "policy"]
            assert len(policy_docs) >= 1, f"{user_id} should see policies"

    def test_unauthorized_records_filtered_out(self) -> None:
        docs = self.retriever.query("salary information", user_id="E004")
        for doc in docs:
            if doc.metadata.get("doc_type") == "hr_record":
                assert doc.metadata["subject_employee_id"] == "E004", (
                    f"E004 should not see record for {doc.metadata['subject_employee_id']}"
                )

    def test_unknown_user_sees_nothing_hr(self) -> None:
        docs = self.retriever.query("employee salary", user_id="UNKNOWN")
        hr_docs = [d for d in docs if d.metadata.get("doc_type") == "hr_record"]
        assert len(hr_docs) == 0

    def test_visible_employees_computation(self) -> None:
        assert self.retriever._get_visible_employees("E001") == {"E001", "E002", "E003", "E004", "E005"}
        assert self.retriever._get_visible_employees("E002") == {"E002", "E003", "E004"}
        assert self.retriever._get_visible_employees("E003") == {"E003"}
        assert self.retriever._get_visible_employees("E005") == {"E005"}
        assert self.retriever._get_visible_employees("X999") == set()
