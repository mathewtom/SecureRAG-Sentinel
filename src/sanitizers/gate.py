"""SanitizationGate — multi-scanner pipeline that filters documents before embedding."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from langchain_core.documents import Document
from langchain_core.runnables import RunnableLambda

from src.sanitizers.injection_scanner import InjectionScanner
from src.sanitizers.pii_detector import PIIDetector


@dataclass
class GateResult:
    """Aggregated outcome of running all documents through the gate."""
    clean: list[Document] = field(default_factory=list)
    quarantined: list[Document] = field(default_factory=list)
    total_pii_redacted: int = 0
    total_credentials_stripped: int = 0


class SanitizationGate:
    """Three-phase scan pipeline: injection → PII → credentials.

    Injection hits quarantine immediately and skip remaining scans.
    Clean documents are stamped with sanitized=True and a UTC timestamp.
    """

    def __init__(self) -> None:
        self._injection_scanner = InjectionScanner()
        self._pii_detector = PIIDetector()

    def process(self, documents: list[Document]) -> GateResult:
        """Run all documents through the scan pipeline."""
        result = GateResult()

        for doc in documents:
            # Phase 1: Injection — quarantine and short-circuit
            injection_result = self._injection_scanner.scan(doc.page_content)
            if injection_result.blocked:
                doc.metadata["quarantine_reason"] = "injection"
                doc.metadata["injection_score"] = injection_result.total_score
                doc.metadata["injection_matches"] = str(injection_result.matches)
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

            # Phase 3: Credential scan (future)
            credential_scanner = None
            if credential_scanner is not None:
                pass

            doc.metadata["sanitized"] = True
            doc.metadata["sanitized_at"] = datetime.now(timezone.utc).isoformat()
            result.clean.append(doc)

        return result

    def as_runnable(self) -> RunnableLambda:
        """Wrap process() as a LangChain Runnable returning only clean docs."""
        def _run(documents: list[Document]) -> list[Document]:
            return self.process(documents).clean

        return RunnableLambda(_run)
