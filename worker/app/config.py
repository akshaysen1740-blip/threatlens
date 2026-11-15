"""Worker configuration, loaded from environment variables."""
import os
import socket
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379"))
    jobs_stream: str = field(default_factory=lambda: os.getenv("JOBS_STREAM", "scan:jobs"))
    events_stream: str = field(default_factory=lambda: os.getenv("EVENTS_STREAM", "scan:events"))
    dlq_stream: str = field(default_factory=lambda: os.getenv("DLQ_STREAM", "scan:dlq"))
    jobs_group: str = field(default_factory=lambda: os.getenv("JOBS_GROUP", "workers"))
    consumer_name: str = field(default_factory=lambda: os.getenv("CONSUMER_NAME") or socket.gethostname())

    max_attempts: int = field(default_factory=lambda: int(os.getenv("MAX_ATTEMPTS", "3")))
    scan_timeout_seconds: float = field(default_factory=lambda: float(os.getenv("SCAN_TIMEOUT_SECONDS", "45")))
    claim_idle_ms: int = field(default_factory=lambda: int(os.getenv("CLAIM_IDLE_MS", "60000")))
    enable_network_checks: bool = field(default_factory=lambda: _bool("ENABLE_NETWORK_CHECKS", True))

    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "none").strip().lower())
    llm_api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", "").strip())
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "").strip())
    llm_timeout_seconds: float = field(default_factory=lambda: float(os.getenv("LLM_TIMEOUT_SECONDS", "20")))

    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO").upper())
