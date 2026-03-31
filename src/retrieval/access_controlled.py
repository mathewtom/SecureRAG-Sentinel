"""Access-controlled retriever — enforces org-chart-based visibility at query time."""

from functools import lru_cache

from chromadb import ClientAPI
from langchain_core.documents import Document


# employee_id → manager_id (None = top of hierarchy)
DEFAULT_ORG_CHART: dict[str, str | None] = {
    "E001": None,
    "E002": "E001",
    "E003": "E002",
    "E004": "E002",
    "E005": "E001",
}


class AccessControlledRetriever:
    """Filters ChromaDB results by org-chart visibility.

    Policies are visible to everyone. HR records are visible only to the
    subject and their management chain. Fail-closed: unknown users and
    untyped documents are excluded. Visibility is computed at query time,
    so org changes require zero re-indexing.
    """

    def __init__(
        self,
        collection,
        embedding_function,
        org_chart: dict[str, str | None] | None = None,
        n_results: int = 5,
    ) -> None:
        self._collection = collection
        self._embedding_function = embedding_function
        self._org_chart = org_chart or DEFAULT_ORG_CHART
        self._n_results = n_results
        self._reports: dict[str, set[str]] = {}
        for emp_id, manager_id in self._org_chart.items():
            if manager_id is not None:
                self._reports.setdefault(manager_id, set()).add(emp_id)

    def _get_visible_employees(self, user_id: str) -> set[str]:
        """Return employee IDs visible to user_id (self + transitive reports)."""
        if user_id not in self._org_chart:
            return set()

        visible = {user_id}
        queue = list(self._reports.get(user_id, []))

        while queue:
            emp = queue.pop()
            if emp not in visible:
                visible.add(emp)
                queue.extend(self._reports.get(emp, []))

        return visible

    def _build_where_filter(self, user_id: str) -> dict:
        """Build a ChromaDB where filter scoped to the user's visibility."""
        visible = self._get_visible_employees(user_id)
        visible_list = sorted(visible)

        return {
            "$or": [
                {"doc_type": {"$eq": "policy"}},
                {
                    "$and": [
                        {"doc_type": {"$eq": "hr_record"}},
                        {"subject_employee_id": {"$in": visible_list}},
                    ]
                },
            ]
        }

    def query(
        self,
        query_text: str,
        user_id: str,
    ) -> list[Document]:
        """Query the vector store with org-chart access control filtering."""
        visible = self._get_visible_employees(user_id)
        if not visible:
            return []

        query_embedding = self._embedding_function.embed_query(query_text)

        where_filter = self._build_where_filter(user_id)

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=self._n_results,
            where=where_filter,
        )

        # Convert ChromaDB results to LangChain Documents
        documents: list[Document] = []
        if results["documents"] and results["documents"][0]:
            for i, doc_text in enumerate(results["documents"][0]):
                metadata = {}
                if results["metadatas"] and results["metadatas"][0]:
                    metadata = results["metadatas"][0][i]
                documents.append(Document(
                    page_content=doc_text,
                    metadata=metadata,
                ))

        return documents
