"""Tests for loader_factory and HRRecordLoader."""

import json
import tempfile
from pathlib import Path

import pytest
from langchain_core.documents import Document

from src.loaders.hr_record_loader import HRRecordLoader, _build_manager_chain, DEFAULT_ORG_CHART
from src.loaders.loader_factory import load_documents


class TestLoaderFactory:

    def setup_method(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmpdir.name)

    def teardown_method(self) -> None:
        self._tmpdir.cleanup()

    def test_loads_txt_files(self) -> None:
        (self.tmpdir / "doc.txt").write_text("Hello world")
        docs = load_documents(self.tmpdir)
        assert len(docs) == 1
        assert docs[0].page_content.strip() == "Hello world"

    def test_metadata_enrichment(self) -> None:
        (self.tmpdir / "report.txt").write_text("Q3 results")
        docs = load_documents(self.tmpdir, access_level="confidential")
        meta = docs[0].metadata
        assert meta["filename"] == "report.txt"
        assert meta["file_type"] == ".txt"
        assert meta["access_level"] == "confidential"
        assert meta["sanitized"] is False
        assert "ingested_at" in meta

    def test_unsupported_extension_skipped(self) -> None:
        (self.tmpdir / "image.png").write_bytes(b"\x89PNG")
        docs = load_documents(self.tmpdir)
        assert len(docs) == 0

    def test_bad_file_skipped_gracefully(self) -> None:
        bad_file = self.tmpdir / "bad.txt"
        bad_file.write_bytes(b"\x00\x01\x02\x03")
        (self.tmpdir / "good.txt").write_text("Valid content")
        docs = load_documents(self.tmpdir)
        assert any(d.metadata["filename"] == "good.txt" for d in docs)

    def test_nonexistent_directory_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_documents("/nonexistent/path/xyz")

    def test_loads_real_sample_data(self) -> None:
        docs = load_documents("data/raw")
        assert len(docs) >= 10


class TestHRRecordLoader:

    def setup_method(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmpdir.name)

    def teardown_method(self) -> None:
        self._tmpdir.cleanup()

    def _write_records(self, records: list[dict]) -> Path:
        path = self.tmpdir / "hr.json"
        path.write_text(json.dumps(records))
        return path

    def test_yields_one_doc_per_employee(self) -> None:
        path = self._write_records([
            {"employee_id": "E001", "name": "Alice", "title": "VP"},
            {"employee_id": "E002", "name": "Bob", "title": "Manager"},
        ])
        loader = HRRecordLoader(path)
        docs = loader.load()
        assert len(docs) == 2

    def test_metadata_contains_employee_id(self) -> None:
        path = self._write_records([
            {"employee_id": "E003", "name": "Charlie", "title": "IC"},
        ])
        loader = HRRecordLoader(path)
        docs = loader.load()
        assert docs[0].metadata["subject_employee_id"] == "E003"
        assert docs[0].metadata["doc_type"] == "hr_record"

    def test_manager_chain_built(self) -> None:
        path = self._write_records([
            {"employee_id": "E003", "name": "Priya", "title": "IC"},
        ])
        loader = HRRecordLoader(path)
        docs = loader.load()
        chain = docs[0].metadata["manager_chain"]
        assert chain == "E003,E002,E001"

    def test_page_content_excludes_employee_id(self) -> None:
        path = self._write_records([
            {"employee_id": "E001", "name": "Sarah", "salary": 250000},
        ])
        loader = HRRecordLoader(path)
        docs = loader.load()
        assert "employee_id" not in docs[0].page_content
        assert "name: Sarah" in docs[0].page_content

    def test_real_hr_records_file(self) -> None:
        loader = HRRecordLoader("data/raw/hr_records.json")
        docs = loader.load()
        assert len(docs) == 5
        emp_ids = {d.metadata["subject_employee_id"] for d in docs}
        assert emp_ids == {"E001", "E002", "E003", "E004", "E005"}


class TestManagerChain:

    def test_root_employee(self) -> None:
        chain = _build_manager_chain("E001", DEFAULT_ORG_CHART)
        assert chain == ["E001"]

    def test_mid_level(self) -> None:
        chain = _build_manager_chain("E002", DEFAULT_ORG_CHART)
        assert chain == ["E002", "E001"]

    def test_leaf_employee(self) -> None:
        chain = _build_manager_chain("E003", DEFAULT_ORG_CHART)
        assert chain == ["E003", "E002", "E001"]
