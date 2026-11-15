"""
Redis Streams consumer.

Job lifecycle:
  1. Read a job from the jobs stream through a consumer group (each job goes to one worker).
  2. Publish 'scanning', run the scan with a timeout.
  3. Success  -> publish 'done' with the result.
     Failure  -> re-queue with attempt + 1 and publish 'queued',
                 or after MAX_ATTEMPTS move it to the dead-letter stream and publish 'failed'.
  4. XACK the job so it is not delivered again.

If a worker crashes mid-job, the job stays pending in Redis and another worker
reclaims it with XAUTOCLAIM after CLAIM_IDLE_MS.
"""
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import datetime, timezone

import redis

from .config import Settings
from .scanner import PermanentError, run_scan

log = logging.getLogger(__name__)

RECLAIM_EVERY_SECONDS = 30
STREAM_MAXLEN = 10_000


class Worker:
    def __init__(self, settings: Settings, client: "redis.Redis | None" = None):
        self.settings = settings
        self.redis = client or redis.Redis.from_url(settings.redis_url, decode_responses=True)
        self.running = True
        self.executor = ThreadPoolExecutor(max_workers=2)

    # ---------- setup ----------
    def ensure_group(self) -> None:
        try:
            self.redis.xgroup_create(self.settings.jobs_stream, self.settings.jobs_group, id="0", mkstream=True)
            log.info("Created consumer group %s on %s", self.settings.jobs_group, self.settings.jobs_stream)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    # ---------- publishing ----------
    def publish_event(self, job: dict, status: str, attempt: int, **extra: str) -> None:
        fields = {
            "scanId": job.get("scanId", ""),
            "userId": job.get("userId", ""),
            "status": status,
            "attempt": str(attempt),
            "at": datetime.now(timezone.utc).isoformat(),
            **extra,
        }
        self.redis.xadd(self.settings.events_stream, fields, maxlen=STREAM_MAXLEN, approximate=True)

    def requeue(self, job: dict, attempt: int, error: str) -> None:
        retry = {**job, "attempt": str(attempt), "lastError": error}
        self.redis.xadd(self.settings.jobs_stream, retry, maxlen=STREAM_MAXLEN, approximate=True)

    def dead_letter(self, job: dict, error: str) -> None:
        entry = {**job, "error": error, "failedAt": datetime.now(timezone.utc).isoformat()}
        self.redis.xadd(self.settings.dlq_stream, entry, maxlen=STREAM_MAXLEN, approximate=True)

    # ---------- processing ----------
    def handle(self, message_id: str, job: dict) -> None:
        attempt = int(job.get("attempt", "1") or 1)
        scan_id = job.get("scanId")
        try:
            if not scan_id or not job.get("userId"):
                raise PermanentError("Job is missing scanId or userId")
            payload = json.loads(job.get("payload") or "{}")

            log.info("Scanning %s (type=%s, attempt=%d)", scan_id, job.get("type"), attempt)
            self.publish_event(job, "scanning", attempt)

            future = self.executor.submit(run_scan, self.settings, job.get("type", ""), payload)
            result = future.result(timeout=self.settings.scan_timeout_seconds)

            self.publish_event(job, "done", attempt, result=json.dumps(result))
            log.info("Scan %s done: %s (%s/100)", scan_id, result["verdict"], result["riskScore"])

        except Exception as exc:
            error = "Scan timed out" if isinstance(exc, FuturesTimeout) else (str(exc) or type(exc).__name__)[:500]
            retryable = not isinstance(exc, (PermanentError, json.JSONDecodeError))

            if retryable and attempt < self.settings.max_attempts:
                log.warning("Scan %s failed (attempt %d/%d), retrying: %s",
                            scan_id, attempt, self.settings.max_attempts, error)
                time.sleep(min(2 ** attempt, 10))  # simple backoff before the retry
                self.requeue(job, attempt + 1, error)
                self.publish_event(job, "queued", attempt + 1, error=f"Retrying after error: {error}")
            else:
                log.error("Scan %s failed permanently: %s", scan_id, error)
                self.dead_letter(job, error)
                self.publish_event(job, "failed", attempt, error=error)
        finally:
            self.redis.xack(self.settings.jobs_stream, self.settings.jobs_group, message_id)

    def reclaim_stale(self) -> None:
        """Takes over jobs that another (probably crashed) worker read but never acknowledged."""
        _next, messages, *_ = self.redis.xautoclaim(
            self.settings.jobs_stream,
            self.settings.jobs_group,
            self.settings.consumer_name,
            min_idle_time=self.settings.claim_idle_ms,
            start_id="0-0",
            count=10,
        )
        for message_id, fields in messages:
            if fields:
                log.warning("Reclaimed stale job %s", message_id)
                self.handle(message_id, fields)
            else:  # entry was trimmed from the stream
                self.redis.xack(self.settings.jobs_stream, self.settings.jobs_group, message_id)

    def run(self) -> None:
        self.ensure_group()
        log.info("Worker '%s' listening on %s", self.settings.consumer_name, self.settings.jobs_stream)
        last_reclaim = 0.0

        while self.running:
            try:
                if time.monotonic() - last_reclaim > RECLAIM_EVERY_SECONDS:
                    self.reclaim_stale()
                    last_reclaim = time.monotonic()

                response = self.redis.xreadgroup(
                    self.settings.jobs_group,
                    self.settings.consumer_name,
                    {self.settings.jobs_stream: ">"},
                    count=1,
                    block=5000,
                )
                for _stream, messages in response or []:
                    for message_id, fields in messages:
                        self.handle(message_id, fields)

            except redis.ConnectionError as exc:
                log.error("Redis connection error: %s (retrying in 3s)", exc)
                time.sleep(3)

        self.executor.shutdown(wait=False, cancel_futures=True)
        log.info("Worker stopped")

    def stop(self, *_args) -> None:
        log.info("Stop requested, finishing current job...")
        self.running = False
