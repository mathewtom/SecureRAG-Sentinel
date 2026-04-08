"""FastAPI wrapper for the SecureRAG chain."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.chain import build_chain, SecureRAGChain, QueryBlocked, OutputFlagged
from src.rate_limiter import RateLimitExceeded

_chain: SecureRAGChain | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _chain
    _chain = build_chain()
    yield


app = FastAPI(title="SecureRAG-Sentinel", lifespan=lifespan)


class QueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)
    user_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class SourceDocument(BaseModel):
    content: str
    metadata: dict


class QueryResponse(BaseModel):
    answer: str
    source_documents: list[SourceDocument]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "chain_loaded": _chain is not None}


@app.post("/query", response_model=QueryResponse)
def query(request: QueryRequest) -> QueryResponse:
    if _chain is None:
        raise HTTPException(status_code=503, detail="Chain not initialized")

    try:
        result = _chain.query(request.question, user_id=request.user_id)
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": str(int(exc.retry_after) + 1)},
        )
    except QueryBlocked as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Query blocked: {exc.reason}",
        )
    except OutputFlagged as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Response withheld: {', '.join(exc.reasons)}",
        )

    return QueryResponse(
        answer=result["answer"],
        source_documents=[
            SourceDocument(content=doc.page_content, metadata=doc.metadata)
            for doc in result["source_documents"]
        ],
    )
