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

    narrative_concurrency: int = 4
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
    # Per-call timeout (seconds) for the narrative LLM calls. Reasoning models
    # are slow, so the default 300s can cut them off mid-generation. Bumped for
    # the narrative pass specifically.
    narrative_timeout: float = 600.0
    # Severities sent to the narrative pass. IR default is ALL — nothing is
    # dropped. Set to "critical,high" to speed up at the cost of coverage.
    narrative_severities: str = "critical,high,medium,low,info"

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
