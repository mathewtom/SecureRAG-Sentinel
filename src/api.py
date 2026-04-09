"""FastAPI wrapper for the SecureRAG chain."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.chain import build_chain, SecureRAGChain, QueryBlocked, OutputFlagged
from src.rate_limiter import RateLimitExceeded

# Hardcoded demo user identity. In production, an upstream proxy would
# authenticate the request and inject a verified user_id. We hardcode to
# a low-privilege Software Engineer (E003) so adversarial testing tools
# cannot self-elevate privileges via the request body.
DEMO_USER_ID = os.environ.get("SECURERAG_DEMO_USER", "E003")

_chain: SecureRAGChain | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _chain
    _chain = build_chain()
    yield


app = FastAPI(title="SecureRAG-Sentinel", lifespan=lifespan)


class QueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)


class SourceDocument(BaseModel):
    content: str
    metadata: dict


class QueryResponse(BaseModel):
    answer: str
    source_documents: list[SourceDocument]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "chain_loaded": _chain is not None, "demo_user": DEMO_USER_ID}


@app.post("/query", response_model=QueryResponse)
def query(request: QueryRequest) -> QueryResponse:
    if _chain is None:
        raise HTTPException(status_code=503, detail="Chain not initialized")

    try:
        result = _chain.query(request.question, user_id=DEMO_USER_ID)
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
