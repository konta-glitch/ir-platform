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

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
