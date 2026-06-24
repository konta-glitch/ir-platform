"""
app/rag_engine.py — RAG (Retrieval-Augmented Generation) semantic search
over incident findings.

What this does
--------------
After the detection pipeline produces findings, this module:
  1. Embeds each finding's text into a ChromaDB vector store (local, in-memory
     per incident — no persistence needed between requests)
  2. Exposes a search() method that takes a natural-language query and returns
     the top-k semantically similar findings
  3. Exposes a query_llm() method that uses those top-k findings as context for
     a focused LLM answer (RAG pattern)

Why this is better than sending all 750 findings to the LLM
------------------------------------------------------------
Instead of 19 batches where Mixtral loses context and JSON-truncates, the
analyst asks a specific question ("show me all LSASS access") and gets a
focused LLM answer backed by the 10-20 most relevant findings — fast, coherent,
no truncation.

Embedding model
---------------
Uses sentence-transformers "all-MiniLM-L6-v2" by default — 22MB, runs on CPU,
no GPU needed, 384-dimensional vectors. If the model isn't installed, falls
back to a keyword BM25-style search so the feature degrades gracefully rather
than crashing.

Usage (from FastAPI route)
--------------------------
    from app.rag_engine import RAGEngine

    engine = RAGEngine(incident_id)
    engine.index_findings(findings)          # call once after detection pipeline

    # Semantic search — returns list of findings sorted by relevance
    results = engine.search("lsass credential dumping", top_k=10)

    # RAG answer — returns LLM response grounded in relevant findings
    answer = await engine.query_llm("What credential dumping techniques were used?", lm_client)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# ── Embedding backend (graceful degradation) ────────────────────────────────

class _EmbeddingBackend:
    """Try sentence-transformers; fall back to TF-IDF keyword vectors."""

    def __init__(self):
        self._model = None
        self._backend = "keyword"
        self._vocab: dict[str, int] = {}

        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._backend = "sentence-transformers"
            logger.info("RAG: using sentence-transformers (all-MiniLM-L6-v2)")
        except ImportError:
            logger.info("RAG: sentence-transformers not installed — using keyword fallback")
        except Exception as e:
            logger.warning(f"RAG: sentence-transformers load failed ({e}) — using keyword fallback")

    def encode(self, texts: list[str]) -> list[list[float]]:
        if self._backend == "sentence-transformers" and self._model:
            vecs = self._model.encode(texts, show_progress_bar=False)
            return [v.tolist() for v in vecs]
        return [self._keyword_vector(t) for t in texts]

    def _keyword_vector(self, text: str) -> list[float]:
        """Simple bag-of-words TF vector over the current vocabulary."""
        tokens = re.findall(r'\w+', text.lower())
        # Extend vocab
        for tok in tokens:
            if tok not in self._vocab:
                self._vocab[tok] = len(self._vocab)
        vec = [0.0] * max(len(self._vocab), 1)
        for tok in tokens:
            if tok in self._vocab:
                vec[self._vocab[tok]] += 1.0
        # L2 normalise
        norm = sum(x * x for x in vec) ** 0.5
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec

    @property
    def backend(self) -> str:
        return self._backend


# Singleton backend — shared across all RAGEngine instances (saves ~200ms load)
_EMBEDDING_BACKEND: _EmbeddingBackend | None = None

def _get_backend() -> _EmbeddingBackend:
    global _EMBEDDING_BACKEND
    if _EMBEDDING_BACKEND is None:
        _EMBEDDING_BACKEND = _EmbeddingBackend()
    return _EMBEDDING_BACKEND


# ── Vector store (in-memory, per incident) ──────────────────────────────────

class _VectorStore:
    """Minimal in-memory cosine-similarity store. No external dependencies."""

    def __init__(self):
        self._vectors: list[list[float]] = []
        self._docs: list[dict] = []

    def add(self, vectors: list[list[float]], docs: list[dict]) -> None:
        self._vectors.extend(vectors)
        self._docs.extend(docs)

    def query(self, query_vec: list[float], top_k: int) -> list[tuple[dict, float]]:
        if not self._vectors:
            return []
        scores = [_cosine(query_vec, v) for v in self._vectors]
        ranked = sorted(zip(self._docs, scores), key=lambda x: x[1], reverse=True)
        return ranked[:top_k]

    def __len__(self) -> int:
        return len(self._docs)


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two equal-length vectors."""
    min_len = min(len(a), len(b))
    if min_len == 0:
        return 0.0
    dot = sum(a[i] * b[i] for i in range(min_len))
    norm_a = sum(x * x for x in a[:min_len]) ** 0.5
    norm_b = sum(x * x for x in b[:min_len]) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ── RAG Engine ───────────────────────────────────────────────────────────────

class RAGEngine:
    """
    Per-incident RAG engine. Create one instance per incident, call
    index_findings() once, then call search() / query_llm() as needed.
    """

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self._store = _VectorStore()
        self._backend = _get_backend()
        self._indexed = False

    # ── Indexing ─────────────────────────────────────────────────────────────

    def index_findings(self, findings: list[dict]) -> None:
        """
        Convert findings to text, embed them, add to the vector store.
        Call this once after the detection pipeline finishes.
        """
        if not findings:
            return

        texts = [self._finding_to_text(f) for f in findings]
        batch_size = 64
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            batch_docs  = findings[i:i + batch_size]
            vectors = self._backend.encode(batch_texts)
            self._store.add(vectors, batch_docs)

        self._indexed = True
        logger.info(
            f"RAG [{self.incident_id}]: indexed {len(self._store)} findings "
            f"using {self._backend.backend}"
        )

    @staticmethod
    def _finding_to_text(f: dict) -> str:
        """Flatten a finding into a single string for embedding."""
        parts = [
            f.get("name", ""),
            f.get("description", ""),
            f.get("category", ""),
            f.get("mitre", ""),
            f.get("severity", ""),
        ]
        ev = f.get("evidence", {})
        if isinstance(ev, dict):
            parts.extend(str(v)[:100] for v in ev.values())
        elif isinstance(ev, str):
            parts.append(ev[:200])
        return " ".join(p for p in parts if p)

    # ── Search ────────────────────────────────────────────────────────────────

    def search(self, query: str, top_k: int = 15,
               min_score: float = 0.1) -> list[dict]:
        """
        Semantic search over indexed findings.

        Returns up to top_k findings sorted by cosine similarity to query,
        each augmented with a 'relevance_score' field (0-1).
        """
        if not self._indexed:
            logger.warning(f"RAG [{self.incident_id}]: search before index_findings()")
            return []

        query_vec = self._backend.encode([query])[0]
        results   = self._store.query(query_vec, top_k * 2)  # over-fetch, then filter

        output = []
        for doc, score in results:
            if score < min_score:
                continue
            augmented = {**doc, "relevance_score": round(score, 3)}
            output.append(augmented)
            if len(output) >= top_k:
                break

        logger.info(
            f"RAG [{self.incident_id}]: query={query!r:.40} "
            f"→ {len(output)} results (top score={output[0]['relevance_score'] if output else 0:.3f})"
        )
        return output

    # ── RAG answer via LLM ───────────────────────────────────────────────────

    async def query_llm(
        self,
        question: str,
        lm_client: Any,
        top_k: int = 15,
        max_context_chars: int = 6000,
    ) -> str:
        """
        Retrieve top-k relevant findings and use them as context for a
        focused LLM answer. Much faster and more coherent than sending all
        findings — the model sees only what's relevant to the question.
        """
        relevant = self.search(question, top_k=top_k)
        if not relevant:
            return "No relevant findings found for that query."

        # Build compact context
        context_lines = []
        total_chars = 0
        for f in relevant:
            line = (
                f"[{f.get('severity','?').upper()}] {f.get('name','?')} "
                f"(MITRE: {f.get('mitre','?')}) — {f.get('description','')[:200]}"
            )
            if total_chars + len(line) > max_context_chars:
                break
            context_lines.append(line)
            total_chars += len(line)

        context = "\n".join(context_lines)

        prompt = (
            f"You are an expert incident responder. Answer the following question "
            f"based ONLY on the forensic findings provided below. Be concise and "
            f"cite specific findings.\n\n"
            f"QUESTION: {question}\n\n"
            f"RELEVANT FINDINGS ({len(context_lines)} of {len(relevant)} retrieved):\n"
            f"{context}\n\n"
            f"ANSWER:"
        )

        try:
            response = await lm_client.complete(prompt)
            return response
        except Exception as e:
            logger.error(f"RAG [{self.incident_id}]: LLM query failed: {e}")
            # Return findings as fallback even if LLM is down
            return (
                f"LLM unavailable ({e}). Top {len(relevant)} relevant findings:\n\n"
                + "\n".join(
                    f"• [{f.get('severity','?').upper()}] {f.get('name','?')}"
                    for f in relevant
                )
            )

    # ── Convenience ──────────────────────────────────────────────────────────

    @property
    def is_indexed(self) -> bool:
        return self._indexed

    @property
    def finding_count(self) -> int:
        return len(self._store)


# ── Global registry (incident_id → RAGEngine) ────────────────────────────────
# Keeps engines alive for the lifetime of the process so subsequent API calls
# to the same incident don't re-index.

_REGISTRY: dict[str, RAGEngine] = {}


def get_engine(incident_id: str) -> RAGEngine:
    """Get or create a RAGEngine for the given incident."""
    if incident_id not in _REGISTRY:
        _REGISTRY[incident_id] = RAGEngine(incident_id)
    return _REGISTRY[incident_id]


def drop_engine(incident_id: str) -> None:
    """Remove an engine from the registry (call when incident is deleted)."""
    _REGISTRY.pop(incident_id, None)
