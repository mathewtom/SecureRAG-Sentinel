# SecureRAG-Sentinel

A security-hardened RAG pipeline that treats the LLM as an untrusted component. Documents are sanitized before they hit the vector store and access-controlled before they reach the model. Dockerized for one-command deployment. Built with LangChain, ChromaDB, Presidio, FastAPI, and Ollama (LLaMA 3.1 8B).

## Quick Start (Docker)

```bash
git clone https://github.com/mathewtom/SecureRAG-Sentinel.git
cd SecureRAG-Sentinel

# Start Ollama and pull the model
docker compose up ollama -d
docker compose exec ollama ollama pull llama3.1:8b

# Place documents in data/raw/, then ingest
docker compose run --rm pipeline

# Start the API
docker compose up api -d
```

The API serves on `http://localhost:8000`. Pipeline reads documents from `data/raw/` on your host (mounted read-only) and writes embeddings to a shared Docker volume that the API container reads from.

### Local Setup (without Docker)

Requires Python 3.12+ and [Ollama](https://ollama.com).

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

ollama pull llama3.1:8b
ollama serve
```

```bash
python -m src.pipeline                                    # ingest
uvicorn src.api:app --host 0.0.0.0 --port 8000           # serve
```

## Usage

Drop documents (`.txt`, `.pdf`, `.csv`) into `data/raw/`. HR records go in `data/raw/hr_records.json`. The pipeline loads, chunks, sanitizes, and embeds everything into ChromaDB. Injection attempts are quarantined and never stored. PII is redacted in-place before embedding.

To query via the API:

```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"question": "What is our vacation policy?", "user_id": "E003"}'
```

Or directly from Python:

```python
from src.chain import build_chain

chain = build_chain()
result = chain.query("What is our vacation policy?", user_id="E003")
```

The `user_id` determines what the retriever is allowed to return. An IC sees policies and their own HR record. A VP sees everything. Unknown users get nothing. Each user is rate-limited to 10 requests per 60-second window by default, configurable via `build_chain(max_requests=, window_seconds=)`.

### API Endpoints

- `GET /health` — liveness check
- `POST /query` — accepts `{"question": "...", "user_id": "..."}`, returns answer + source documents. Returns 429 with `Retry-After` header when rate-limited.

### Tests

Tests run without Ollama or Docker (the LLM is mocked, ChromaDB runs in-memory):

```bash
pytest tests/ -v
```

## How it works

There are two separate paths with ChromaDB sitting in the middle.

**Ingestion** runs once (or whenever you add docs). The loader factory walks `data/raw/` and picks a LangChain loader by file extension. HR records get a dedicated loader that yields one document per employee and stamps each with `subject_employee_id` and a manager chain. Everything gets chunked (500 chars, 50 overlap), then fed through the `SanitizationGate`.

The gate runs three scans in priority order. First, the injection scanner scores text against known prompt injection patterns (instruction overrides, ChatML tokens, role hijacking, etc.) — if the cumulative score hits the threshold, the chunk is quarantined and remaining scans are skipped. This short-circuit is intentional: an attacker could craft payloads that exploit downstream scanners, so adversarial content gets no further processing. Second, the PII detector combines regex patterns (SSN with prefix validation, credit card with Luhn check, email, phone, AWS keys, IBAN) with Presidio's NER engine for names and locations. Matches get replaced with `[SSN_REDACTED]`-style tags and the chunk continues through. Third slot is reserved for a credential scanner (not yet implemented).

Clean chunks are embedded with `all-MiniLM-L6-v2` and stored in ChromaDB.

**Querying** happens per request. The `AccessControlledRetriever` computes visibility from an org chart using BFS traversal, then builds a ChromaDB `$or` filter: policies are visible to everyone, HR records only to the subject and their management chain. This is enforced at the retriever, not the prompt — unauthorized chunks never leave the database, so there's nothing for the LLM to leak. Visibility is computed at query time so org changes require zero re-indexing.

Before retrieval runs, a per-user sliding-window rate limiter checks whether the caller has exceeded their request quota. This limits enumeration and brute-force data extraction attempts — a blocked request short-circuits before any embedding or LLM computation.

Retrieved chunks are formatted into a security-focused prompt that tells the model to answer only from context and never follow instructions embedded in documents. This is defense-in-depth, not a primary control — the 8B model's instruction-following is too weak to be a security boundary.

## Security mappings

### OWASP Top 10 for LLM Applications

**LLM01 (Prompt Injection)** — The injection scanner quarantines adversarial payloads at ingestion. Chunks containing override attempts, ChatML tokens, or role hijacking never reach the vector store.

**LLM02 (Insecure Output Handling)** — The prompt template constrains the LLM to context-only answers. Source documents are returned with every response for auditability.

**LLM03 (Training Data Poisoning)** — All documents pass through the full sanitization gate before embedding. Poisoned documents are quarantined at ingestion.

**LLM06 (Sensitive Information Disclosure)** — PII is redacted before embedding. Access control ensures HR records are only retrievable by authorized users in the management chain.

**LLM08 (Excessive Agency)** — The LLM has no tool use, no code execution, no write access. It receives context and produces text.

**LLM09 (Overreliance)** — Every response includes `source_documents` so users can verify claims against the original (redacted) chunks.

**LLM10 (Model Theft)** — Everything runs locally via Ollama. No data or weights leave the machine.

### MITRE ATLAS

**AML.T0051 (Prompt Injection)** — Scored regex patterns detect instruction overrides, ChatML token injection, and system prompt extraction. Adversarial chunks are quarantined before embedding.

**AML.T0054 (LLM Jailbreak)** — Multi-layer defense: injection patterns blocked at ingestion, prompt template constrains at inference. Neither layer is relied on alone.

**AML.T0020 (Erode ML Model Integrity)** — Documents are scanned and sanitized before entering the vector store. Poisoned content can't corrupt the retrieval index.

**AML.T0024 (Exfiltration via Inference API)** — Org-chart filtering at the retriever prevents unauthorized data from entering the LLM context. Per-user rate limiting restricts enumeration attempts. An IC can't extract VP-level records regardless of prompt or query volume.

**AML.T0043 (Craft Adversarial Data)** — Pattern validators (Luhn checksum, SSA prefix rules) catch adversarial inputs designed to bypass simple regex.

**AML.T0010 (Insert Backdoor)** — Backdoor instructions embedded in documents are caught by the scored pattern matcher at ingestion.

## License

MIT
