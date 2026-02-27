"""
RQ job functions — thin HTTP callers only.

Every job delegates its business logic to a worker callback endpoint on the
API service (app/api/v1/worker_callbacks.py).  Jobs are only responsible for:
  1. POSTing to the right callback URL via httpx
  2. Retry / back-off policy (via RQ Retry passed at enqueue time)
  3. Mapping terminal HTTP errors (409, 422) to non-retriable outcomes
     (caught exceptions are NOT re-raised so RQ won't retry them)

Inter-service auth : X-Internal-Secret header + INTERNAL_API_SECRET env var
Callback base URL  : INTERNAL_API_URL env var
                     Railway prod → http://<service>.railway.internal:<PORT>
                     Local dev    → http://api:8000  (Docker Compose service name)
"""
import uuid
from typing import Any, Dict, Optional

import httpx
import structlog

from app.core.config import settings
from app.services.jobs.task_exceptions import (
    DuplicatePDFError,
    NoHoldingsFoundError,
    PDFDownloadError,
)

logger = structlog.get_logger()

# Exponential-backoff intervals (seconds) for retriable jobs: 10s, 30s, 60s, 2m, 5m
_RETRY_INTERVALS = [10, 30, 60, 120, 300]


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _post_internal(path: str, body: Dict[str, Any], *, trace_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Synchronous POST to an internal worker-callback endpoint.

    Raises:
        DuplicatePDFError / NoHoldingsFoundError — on 409 (terminal, no retry)
        PDFDownloadError                         — on 5xx  (retriable)
        HTTPException                            — on 422  (terminal, no retry)
    """
    base_url = (settings.internal_api_url or "http://localhost:8000").rstrip("/")
    url = f"{base_url}/api/v1/worker{path}"
    headers = {
        "X-Internal-Secret": settings.internal_api_secret or "",
        "Content-Type": "application/json",
    }
    if trace_id:
        headers["X-Trace-Id"] = trace_id

    log = logger.bind(path=path, trace_id=trace_id)

    with httpx.Client(timeout=300) as client:
        resp = client.post(url, json=body, headers=headers)

    data: Dict[str, Any] = {}
    try:
        data = resp.json()
    except Exception:
        data = {"detail": resp.text}

    if resp.status_code in (200, 201):
        return data

    if resp.status_code == 409:
        code = data.get("error_code", "CONFLICT")
        msg = data.get("error_message", str(data))
        log.warning("worker_callback_terminal_conflict", status=409, error_code=code)
        if "DUPLICATE" in code:
            raise DuplicatePDFError(msg, existing_snapshot_id=None, user_id=body.get("user_id"), task_id=None)
        raise NoHoldingsFoundError(msg, user_id=body.get("user_id"), task_id=None)

    if resp.status_code == 422:
        code = data.get("error_code", "VALIDATION_ERROR")
        msg = data.get("error_message", str(data))
        log.warning("worker_callback_terminal_validation", status=422, error_code=code)
        raise NoHoldingsFoundError(msg, user_id=body.get("user_id"), task_id=None)

    # 5xx or anything else → retriable
    log.error("worker_callback_retriable_error", status=resp.status_code, body=data)
    raise PDFDownloadError(
        f"Worker callback {path} returned {resp.status_code}: {data.get('detail', '')}",
        user_id=body.get("user_id"),
        task_id=None,
    )


# ---------------------------------------------------------------------------
# Job functions
# ---------------------------------------------------------------------------

def parse_pdf_task(pdf_url: str, pdf_hash: str, user_id: str, file_id: Optional[str] = None) -> Dict[str, Any]:
    """POST /api/v1/worker/parse-pdf — full PDF parse + snapshot pipeline.

    Enqueue with Retry(max=5, interval=_RETRY_INTERVALS) for PDFDownloadError.
    Terminal errors (DuplicatePDFError, NoHoldingsFoundError) are caught and
    logged — NOT re-raised so RQ will not retry them.
    """
    trace_id = str(uuid.uuid4())
    structlog.contextvars.bind_contextvars(trace_id=trace_id)
    try:
        return _post_internal(
            "/parse-pdf",
            {"pdf_url": pdf_url, "pdf_hash": pdf_hash, "user_id": user_id, "file_id": file_id, "trace_id": trace_id},
            trace_id=trace_id,
        )
    except (DuplicatePDFError, NoHoldingsFoundError) as exc:
        logger.warning("parse_pdf_task_terminal", error=str(exc), user_id=user_id)
        return {"success": False, "terminal": True, "error": str(exc)}


def process_portfolio_task(portfolio_id: str) -> Dict[str, Any]:
    """Stub — no market data integration yet."""
    logger.info("process_portfolio_task_noop", portfolio_id=portfolio_id)
    return {"success": True, "portfolio_id": portfolio_id, "processed": True}


def reconcile_transactions_task(snapshot_id: str, user_id: str) -> Dict[str, Any]:
    """POST /api/v1/worker/reconcile-transactions.

    Enqueue with Retry(max=3, interval=_RETRY_INTERVALS[:3]) for PDFDownloadError.
    """
    trace_id = str(uuid.uuid4())
    structlog.contextvars.bind_contextvars(trace_id=trace_id)
    return _post_internal(
        "/reconcile-transactions",
        {"snapshot_id": snapshot_id, "user_id": user_id, "trace_id": trace_id},
        trace_id=trace_id,
    )


def calculate_refresh_due_task(user_id: str) -> Dict[str, Any]:
    """POST /api/v1/worker/calculate-refresh-due."""
    return _post_internal("/calculate-refresh-due", {"user_id": user_id})


def check_portfolio_staleness_task() -> Dict[str, Any]:
    """POST /api/v1/worker/jobs/check-portfolio-staleness (scheduled)."""
    return _post_internal("/jobs/check-portfolio-staleness", {})


def cleanup_expired_sessions_task() -> Dict[str, Any]:
    """POST /api/v1/worker/jobs/cleanup-expired-sessions (scheduled)."""
    return _post_internal("/jobs/cleanup-expired-sessions", {})


def retry_failed_reconciliations_task() -> Dict[str, Any]:
    """POST /api/v1/worker/jobs/retry-failed-reconciliations (scheduled)."""
    return _post_internal("/jobs/retry-failed-reconciliations", {})


def send_access_reminders_task() -> Dict[str, Any]:
    """POST /api/v1/worker/jobs/send-access-reminders (scheduled)."""
    return _post_internal("/jobs/send-access-reminders", {})


def sync_gmail_task(user_id: str, sync_type: str = "incremental") -> Dict[str, Any]:
    """POST /api/v1/worker/sync-gmail."""
    trace_id = str(uuid.uuid4())
    return _post_internal(
        "/sync-gmail",
        {"user_id": user_id, "sync_type": sync_type, "trace_id": trace_id},
        trace_id=trace_id,
    )


# ---------------------------------------------------------------------------
# Utility (called synchronously from API routes)
# ---------------------------------------------------------------------------

def get_task_status(task_id: str) -> Dict[str, Any]:
    """Fetch job status from RQ via Job.fetch."""
    from rq.job import Job
    from rq.exceptions import NoSuchJobError
    from app.core.rq_app import redis_conn

    try:
        job = Job.fetch(task_id, connection=redis_conn)
    except NoSuchJobError:
        return {"state": "PENDING", "status": "Task is waiting to be processed", "task_id": task_id}

    status = job.get_status()

    if status.value in ("queued", "started", "deferred", "scheduled"):
        state = status.value.upper()
        return {"state": state, "status": f"Task is {status.value}", "task_id": task_id}

    if status.value == "finished":
        return {"state": "SUCCESS", "status": "Task completed successfully", "result": job.result, "task_id": task_id}

    if status.value == "failed":
        exc_info = job.exc_info or ""
        return {"state": "FAILURE", "status": "Task failed", "error": str(exc_info), "task_id": task_id}

    return {"state": status.value.upper(), "status": f"Unknown state: {status.value}", "task_id": task_id}
