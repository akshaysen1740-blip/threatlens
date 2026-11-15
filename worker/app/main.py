import logging
import signal

from .config import Settings
from .worker import Worker


def main() -> None:
    settings = Settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s [worker:%(name)s] %(message)s",
    )
    provider = settings.llm_provider if settings.llm_api_key else "none (rule-based explanations)"
    logging.getLogger(__name__).info(
        "Starting ThreatLens worker | AI provider: %s | network checks: %s",
        provider, settings.enable_network_checks,
    )

    worker = Worker(settings)
    signal.signal(signal.SIGTERM, worker.stop)
    signal.signal(signal.SIGINT, worker.stop)
    worker.run()


if __name__ == "__main__":
    main()
