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
    narrative_concurrency: int = 4
    # Findings per narrative batch. Smaller = more, shorter prompts (more
    # parallelism, less chance of hitting the model's output limit mid-JSON).
    narrative_batch_size: int = 20
    # Severities sent to the narrative pass. IR default is ALL — nothing is
    # dropped. Set to "critical,high" to speed up at the cost of coverage.
    narrative_severities: str = "critical,high,medium,low,info"

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
