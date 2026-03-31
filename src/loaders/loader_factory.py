"""Generic document loader that walks a directory and picks loaders by extension."""

import logging
from datetime import datetime, timezone
from pathlib import Path

from langchain_community.document_loaders import (
    CSVLoader,
    PyPDFLoader,
    TextLoader,
)
from langchain_core.documents import Document

logger = logging.getLogger(__name__)

_LOADER_MAP: dict[str, type] = {
    ".txt": TextLoader,
    ".pdf": PyPDFLoader,
    ".csv": CSVLoader,
}


def load_documents(
    source_dir: str | Path,
    access_level: str = "internal",
) -> list[Document]:
    """Walk source_dir, load supported files, and enrich metadata.

    Unsupported extensions are skipped. Errors on individual files are
    logged and skipped (fail-closed).
    """
    source_path = Path(source_dir)
    if not source_path.is_dir():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    documents: list[Document] = []
    ingested_at = datetime.now(timezone.utc).isoformat()

    for file_path in sorted(source_path.rglob("*")):
        if file_path.is_dir():
            continue

        ext = file_path.suffix.lower()
        loader_cls = _LOADER_MAP.get(ext)

        if loader_cls is None:
            logger.warning("Unsupported file type %s, skipping: %s", ext, file_path)
            continue

        try:
            loader = loader_cls(str(file_path))
            file_docs = loader.load()
        except Exception as exc:
            logger.error("Failed to load %s: %s", file_path, exc)
            continue

        for doc in file_docs:
            doc.metadata.update({
                "filename": file_path.name,
                "file_type": ext,
                "access_level": access_level,
                "ingested_at": ingested_at,
                "sanitized": False,
            })
            documents.append(doc)

    return documents
