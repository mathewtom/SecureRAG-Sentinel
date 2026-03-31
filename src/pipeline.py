"""Ingestion pipeline: load → split → sanitize → embed → store."""

import logging
from pathlib import Path

import chromadb
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

from src.loaders.hr_record_loader import HRRecordLoader
from src.loaders.loader_factory import load_documents
from src.sanitizers.gate import GateResult, SanitizationGate

logger = logging.getLogger(__name__)

CHUNK_SIZE = 500
CHUNK_OVERLAP = 50
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
COLLECTION_NAME = "securerag"
CHROMA_PERSIST_DIR = "chroma_db"


def run_pipeline(
    source_dir: str | Path = "data/raw",
    hr_records_path: str | Path | None = "data/raw/hr_records.json",
    chroma_persist_dir: str | Path = CHROMA_PERSIST_DIR,
    collection_name: str = COLLECTION_NAME,
) -> GateResult:
    """Load, chunk, sanitize, embed, and store documents in ChromaDB."""
    logger.info("Loading documents from %s", source_dir)
    documents = load_documents(source_dir)

    if hr_records_path and Path(hr_records_path).exists():
        logger.info("Loading HR records from %s", hr_records_path)
        hr_loader = HRRecordLoader(hr_records_path)
        hr_docs = hr_loader.load()
        for doc in hr_docs:
            doc.metadata.setdefault("access_level", "restricted")
        documents.extend(hr_docs)
    elif hr_records_path:
        logger.warning("HR records path provided but not found: %s", hr_records_path)

    logger.info("Loaded %d documents total", len(documents))

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
    )
    chunks = splitter.split_documents(documents)
    logger.info("Split into %d chunks", len(chunks))

    gate = SanitizationGate()
    gate_result = gate.process(chunks)
    logger.info(
        "Gate results: %d clean, %d quarantined, %d PII redacted",
        len(gate_result.clean),
        len(gate_result.quarantined),
        gate_result.total_pii_redacted,
    )

    if gate_result.clean:
        embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
        client = chromadb.PersistentClient(path=str(chroma_persist_dir))

        try:
            client.delete_collection(collection_name)
        except (ValueError, Exception):
            pass

        collection = client.create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

        texts = [doc.page_content for doc in gate_result.clean]
        metadatas = []
        for doc in gate_result.clean:
            clean_meta = {}
            for k, v in doc.metadata.items():
                if isinstance(v, (str, int, float, bool)):
                    clean_meta[k] = v
                else:
                    clean_meta[k] = str(v)
            metadatas.append(clean_meta)
        ids = [f"chunk_{i}" for i in range(len(texts))]

        embedding_vectors = embeddings.embed_documents(texts)
        collection.add(
            documents=texts,
            metadatas=metadatas,
            ids=ids,
            embeddings=embedding_vectors,
        )
        logger.info("Stored %d chunks in ChromaDB collection '%s'", len(texts), collection_name)

    return gate_result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = run_pipeline()
    print(f"\nPipeline complete:")
    print(f"  Clean chunks:      {len(result.clean)}")
    print(f"  Quarantined:       {len(result.quarantined)}")
    print(f"  PII redacted:      {result.total_pii_redacted}")
