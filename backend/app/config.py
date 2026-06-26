from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # LM Studio (local LLM)
    lm_studio_base_url: str = "http://host.docker.internal:1234/v1"
    lm_studio_model: str = "qwen2.5-coder-14b-instruct-mlx"

    # Claude (optional, for knowledge gaps)
    anthropic_api_key: str = ""
    claude_model: str = "claude-sonnet-4-6"

    # General
    log_level: str = "INFO"
    data_dir: str = "/app/data"
    export_dir: str = "/app/exports"

    # ── Narrative pass (second LLM pass) ──
    # How many narrative batches run concurrently against the local LLM. The
    # batches are independent, so running them in parallel cuts wall-clock time
    # roughly N-fold. Cap it to what your LLM server can handle without
    # thrashing — LM Studio with one loaded model handles 2-4 well; raise if
    # you run a server that batches requests. 1 = old sequential behaviour.
    # ── LLM token budget ──
    # Max tokens the local LLM may generate per call. Reasoning models
    # (DeepSeek-R1, QwQ) spend a large share of this on their <think> block
    # BEFORE the answer, so a budget fine for a plain model leaves no room for
    # the actual JSON and you get an empty "received 0 chars" response. 16000
    # leaves headroom for reasoning + answer.
    llm_max_tokens: int = 16000

    # How many narrative batches run at once. On a LOCAL single-GPU LLM (e.g.
    # DeepSeek-R1 in LM Studio on an M-series Mac) concurrent calls share the
    # same GPU and slow each other down, so high concurrency is counter-
    # productive — 4 parallel batches each ran ~3-4x slower and some blew past
    # the timeout. 2 keeps a little overlap without thrashing the GPU. Raise it
    # only if you're pointing at a backend that genuinely serves requests in
    # parallel (vLLM, a hosted API).
    narrative_concurrency: int = 2
    # Findings per narrative batch. Smaller = more, shorter prompts (more
    # parallelism, less chance of hitting the model's output limit mid-JSON).
    narrative_batch_size: int = 20
    # Reasoning models (DeepSeek-R1, QwQ) burn most of their token budget on a
    # <think> block. For the NARRATIVE pass that's wasteful — the task is to
    # format findings into JSON, not to reason for thousands of tokens — and it
    # exhausts the budget so the JSON never gets emitted (empty content). When
    # true, append a no-think directive to the narrative prompt so the model
    # answers directly. The primary analysis pass still reasons normally.
    narrative_disable_thinking: bool = True
    # Default per-call timeout (seconds) for LLM calls. The 300s httpx default
    # cuts off slow reasoning models (DeepSeek-R1 spends ~170s just thinking on
    # the main analysis pass, plus prompt processing + generation). This is the
    # baseline used by the primary analysis and enrichment passes; the
    # narrative pass uses its own (longer) narrative_timeout below.
    llm_timeout: float = 600.0

    # Per-call timeout (seconds) for the narrative LLM calls. Reasoning models
    # are slow, and even at concurrency=2 a heavy batch can take ~10 min, so
    # this is a generous safety margin above the typical batch time. Pair it
    # with low narrative_concurrency — the timeout catches stragglers, it isn't
    # a substitute for not thrashing the GPU.
    narrative_timeout: float = 900.0
    # After per-batch narratives are written, run ONE more pass that reads the
    # batch narratives + key findings and writes a single coherent incident
    # story — so related activity split across batches reads as one attack, not
    # N stitched-together sections. The per-batch results are kept as a fallback
    # if synthesis fails or is disabled. Off → the old concatenated-sections
    # behaviour. One extra LLM call (small prompt: it summarises summaries).
    narrative_synthesize: bool = True
    # Severities sent to the narrative pass. IR default is ALL — nothing is
    # dropped. Set to "critical,high" to speed up at the cost of coverage.
    narrative_severities: str = "critical,high,medium,low,info"

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
