"""SanitizationGate — multi-scanner pipeline that filters documents before embedding."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from langchain_core.documents import Document
from langchain_core.runnables import RunnableLambda

from src.sanitizers.credential_detector import CredentialDetector
from src.sanitizers.injection_scanner import InjectionScanner
from src.sanitizers.pii_detector import PIIDetector

_INGESTION_EMBEDDING_THRESHOLD = 0.50


@dataclass
class GateResult:
    """Aggregated outcome of running all documents through the gate."""
    clean: list[Document] = field(default_factory=list)
    quarantined: list[Document] = field(default_factory=list)
    total_pii_redacted: int = 0
    total_credentials_stripped: int = 0


class SanitizationGate:
    """Four-phase scan pipeline: regex injection → embedding similarity → PII → credentials.

    Injection or embedding hits quarantine immediately and skip remaining scans.
    Clean documents are stamped with sanitized=True and a UTC timestamp.
    """

    def __init__(self, embedding_function=None) -> None:
        self._injection_scanner = InjectionScanner()
        self._pii_detector = PIIDetector()
        self._credential_detector = CredentialDetector()
        self._embedding_detector = None
        if embedding_function is not None:
            from src.sanitizers.embedding_detector import EmbeddingInjectionDetector
            self._embedding_detector = EmbeddingInjectionDetector(
                embedding_function=embedding_function,
                threshold=_INGESTION_EMBEDDING_THRESHOLD,
            )

    def process(self, documents: list[Document]) -> GateResult:
        """Run all documents through the scan pipeline."""
        result = GateResult()

        for doc in documents:
            # Phase 1: Regex injection — quarantine and short-circuit
            injection_result = self._injection_scanner.scan(doc.page_content)
            if injection_result.blocked:
                doc.metadata["quarantine_reason"] = "injection"
                doc.metadata["injection_score"] = injection_result.total_score
                doc.metadata["injection_matches"] = str(injection_result.matches)
                result.quarantined.append(doc)
                continue

            # Phase 1.5: Embedding similarity — catches latent injections that evade regex
            if self._embedding_detector is not None:
                embed_result = self._embedding_detector.scan(doc.page_content)
                if embed_result.blocked:
                    doc.metadata["quarantine_reason"] = "embedding_similarity"
                    doc.metadata["similarity_score"] = round(embed_result.max_similarity, 3)
                    doc.metadata["matched_pattern"] = embed_result.matched_pattern
                    result.quarantined.append(doc)
                    continue

            # Phase 2: PII — redact in-place
            pii_result = self._pii_detector.scan(doc.page_content)
            if pii_result.pii_count > 0:
                doc.page_content = pii_result.redacted_text
                doc.metadata["pii_redacted"] = True
                doc.metadata["pii_categories"] = str(pii_result.categories)
                doc.metadata["pii_count"] = pii_result.pii_count
                result.total_pii_redacted += pii_result.pii_count

            # Phase 3: Credential scan — redact API keys / tokens / private keys
            cred_result = self._credential_detector.scan(doc.page_content)
            if cred_result.credential_count > 0:
                doc.page_content = cred_result.redacted_text
                doc.metadata["credentials_redacted"] = True
                doc.metadata["credential_categories"] = str(cred_result.categories)
                doc.metadata["credential_count"] = cred_result.credential_count
                result.total_credentials_stripped += cred_result.credential_count

            doc.metadata["sanitized"] = True
            doc.metadata["sanitized_at"] = datetime.now(timezone.utc).isoformat()
            result.clean.append(doc)

        return result

    def as_runnable(self) -> RunnableLambda:
        """Wrap process() as a LangChain Runnable returning only clean docs."""
        def _run(documents: list[Document]) -> list[Document]:
            return self.process(documents).clean

        return RunnableLambda(_run)
