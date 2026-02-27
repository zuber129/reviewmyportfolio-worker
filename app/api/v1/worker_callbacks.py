"""
Worker callback endpoints — invoked exclusively by RQ workers.

RQ jobs are thin HTTP callers. All business logic lives here and in the
service layer (app/services/). This keeps DB/cache access, error handling, and
domain logic consolidated in the API process.

Security: every request must carry  X-Internal-Secret: <INTERNAL_API_SECRET>.
          Missing or wrong secret → HTTP 403.

URL prefix: /api/v1/worker/...
"""
import base64
import re
from datetime import date, datetime
from typing import Any, Dict, Optional

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.config import settings
from app.core.exceptions import DuplicatePANError, MissingPANError, MultiplePANError
from app.infrastructure.supabase_client import supabase_client
from app.services.integrations.file_validator import file_validator
from app.services.integrations.malware_scanner import malware_scanner
from app.services.pdf.exceptions import PDFValidationError
from app.services.pdf.parser import pdf_parser
from app.services.social.reputation_service import ReputationService
from app.services.jobs.task_exceptions import (
    DuplicatePDFError,
    NoHoldingsFoundError,
    PDFDownloadError,
    SnapshotSaveError,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/worker", tags=["Worker Callbacks"])


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def _require_worker_secret(x_internal_secret: str = Header(...)) -> None:
    if not settings.internal_api_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="INTERNAL_API_SECRET is not configured on the API service",
        )
    if x_internal_secret != settings.internal_api_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid worker secret",
        )


# ---------------------------------------------------------------------------
# Request schemas (one per endpoint, kept minimal)
# ---------------------------------------------------------------------------

class ParsePdfRequest(BaseModel):
    pdf_url: str
    pdf_hash: str
    user_id: str
    file_id: Optional[str] = None
    trace_id: Optional[str] = None


class ReconcileTransactionsRequest(BaseModel):
    snapshot_id: str
    user_id: str
    trace_id: Optional[str] = None


class CalculateRefreshDueRequest(BaseModel):
    user_id: str


class SyncGmailRequest(BaseModel):
    user_id: str
    sync_type: str = "incremental"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

async def _extract_statement_date(pdf_bytes: bytes) -> date:
    """Try to pull the statement date from the PDF; fall back to today."""
    try:
        import fitz  # PyMuPDF

        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        first_page = doc[0].get_text()

        patterns = [
            r"as\s+of\s+(\d{1,2}[-/]\w{3}[-/]\d{4})",
            r"as\s+on\s+(\d{1,2}[-/]\w{3}[-/]\d{4})",
            r"date[:\s]+(\d{1,2}[-/]\d{1,2}[-/]\d{4})",
            r"statement\s+date[:\s]+(\d{1,2}[-/]\w{3}[-/]\d{4})",
        ]

        for pattern in patterns:
            match = re.search(pattern, first_page, re.IGNORECASE)
            if match:
                for fmt in ["%d-%b-%Y", "%d/%m/%Y", "%d-%m-%Y"]:
                    try:
                        parsed = datetime.strptime(match.group(1), fmt).date()
                        doc.close()
                        logger.info("statement_date_extracted", date=parsed.isoformat(), method="text_parsing")
                        return parsed
                    except ValueError:
                        continue

        metadata = doc.metadata
        if metadata and metadata.get("creationDate"):
            m = re.match(r"D:(\d{8})", metadata["creationDate"])
            if m:
                parsed = datetime.strptime(m.group(1), "%Y%m%d").date()
                doc.close()
                logger.info("statement_date_extracted", date=parsed.isoformat(), method="pdf_metadata")
                return parsed

        doc.close()
    except Exception as exc:
        logger.warning("statement_date_extraction_failed", error=str(exc))

    today = date.today()
    logger.info("statement_date_extracted", date=today.isoformat(), method="fallback_today")
    return today


# ---------------------------------------------------------------------------
# PDF parsing + snapshot creation
# ---------------------------------------------------------------------------

@router.post("/parse-pdf", dependencies=[Depends(_require_worker_secret)])
async def parse_pdf(req: ParsePdfRequest) -> JSONResponse:
    """
    Full PDF parse → snapshot pipeline triggered by parse_pdf_task.

    Failure modes:
      422  — terminal validation failure (bad file, malware, missing PAN) — worker must NOT retry
      409  — duplicate PDF or cross-user PAN conflict — worker must NOT retry
      500  — transient error (download failed, DB down, etc.) — worker SHOULD retry
    """
    if req.trace_id:
        structlog.contextvars.bind_contextvars(trace_id=req.trace_id)

    file_id, user_id, pdf_url, pdf_hash = req.file_id, req.user_id, req.pdf_url, req.pdf_hash

    async def _fail_file(code: str, message: str, details: Optional[Dict] = None) -> None:
        if file_id:
            try:
                await supabase_client.update_file_status(
                    file_id=file_id,
                    status="failed",
                    error_code=code,
                    error_message=message,
                    error_details=details or {},
                    processing_completed_at="now()",
                )
            except Exception as e:
                logger.warning("file_status_update_failed", error=str(e))

    try:
        # 1. Mark validating
        if file_id:
            await supabase_client.update_file_status(
                file_id=file_id, status="validating", processing_started_at="now()"
            )

        # 2. Download
        pdf_bytes = await supabase_client.download_from_storage(
            bucket="portfolio-documents",
            path=pdf_url.split("portfolio-documents/")[-1],
        )
        if not pdf_bytes:
            raise PDFDownloadError("Failed to download PDF from storage", user_id=user_id, task_id=None)

        # 3. File validation (magic bytes, size, structure)
        try:
            file_validator.validate_all(pdf_bytes, filename=pdf_url.split("/")[-1])
        except PDFValidationError as e:
            await _fail_file(e.error_code, e.message)
            return JSONResponse(status_code=422, content={"success": False, "error_code": e.error_code, "error_message": e.message})

        # 4. Malware scan
        if file_id:
            await supabase_client.update_file_status(file_id=file_id, status="scanning")
        scan = malware_scanner.scan_pdf(pdf_bytes)
        if not scan["clean"]:
            threat_str = ", ".join(scan["threats"])
            logger.error("malware_detected", threats=scan["threats"], user_id=user_id)
            await _fail_file("MALWARE_DETECTED", f"File contains malicious content: {threat_str}")
            return JSONResponse(status_code=422, content={"success": False, "error_code": "MALWARE_DETECTED", "error_message": threat_str})

        # 5. Parse PDF
        if file_id:
            await supabase_client.update_file_status(file_id=file_id, status="parsing")
        pdf_base64 = base64.b64encode(pdf_bytes).decode("utf-8")
        try:
            portfolio_data = await pdf_parser.parse_pdf(pdf_base64, use_openai_fallback=True)
        except PDFValidationError as e:
            await _fail_file(e.error_code, e.message)
            return JSONResponse(status_code=422, content={"success": False, "error_code": e.error_code, "error_message": e.message})

        if not portfolio_data:
            raise NoHoldingsFoundError("No holdings found in PDF", user_id=user_id, task_id=None)

        statement_date = await _extract_statement_date(pdf_bytes)

        # 6. PII (PAN) validation
        pii_hash = getattr(portfolio_data, "pii_hash", None)
        if not pii_hash:
            raise MissingPANError(details={"user_id": user_id, "reason": "PAN not found in CAS statement"})

        existing_by_pan = await supabase_client.check_pii_hash_exists(pii_hash)
        if existing_by_pan and existing_by_pan["user_id"] != user_id:
            raise DuplicatePANError(pan_hash=pii_hash, details={"user_id": user_id})

        user_current_pan = await supabase_client.get_user_pii_hash(user_id)
        if user_current_pan and user_current_pan != pii_hash:
            raise MultiplePANError(details={"user_id": user_id})

        # 7. Duplicate PDF check
        existing_snapshot = await supabase_client.check_snapshot_exists(user_id=user_id, pdf_hash=pdf_hash)
        if existing_snapshot:
            raise DuplicatePDFError(
                f"This statement was already uploaded on {existing_snapshot.get('upload_time')}",
                existing_snapshot_id=existing_snapshot["id"],
                user_id=user_id,
                task_id=None,
            )

        # 8. Build and persist snapshot
        holdings_list = [
            (h.model_dump() if hasattr(h, "model_dump") else dict(h))
            for h in (portfolio_data.holdings or [])
        ]
        snapshot_dict: Dict[str, Any] = {
            "user_id": user_id,
            "pdf_url": pdf_url,
            "pdf_hash": pdf_hash,
            "statement_date": statement_date.isoformat(),
            "holdings": holdings_list,
            "total_value": float(portfolio_data.total_value) if portfolio_data.total_value else None,
            "xirr": float(portfolio_data.xirr) if portfolio_data.xirr else None,
            "risk_level": None,
            "holding_count": len(holdings_list),
            "title": getattr(portfolio_data, "title", None) or f"Portfolio Snapshot {statement_date}",
            "extraction_method": "pymupdf",
        }

        saved = await supabase_client.create_portfolio_snapshot(snapshot_dict)
        if not saved or saved.get("error"):
            raise SnapshotSaveError(
                (saved.get("error") if saved else None) or "Failed to save snapshot",
                user_id=user_id,
                task_id=None,
            )

        # 9. Persist transactions (non-fatal)
        transactions = [
            (t.model_dump() if hasattr(t, "model_dump") else dict(t))
            for t in (getattr(portfolio_data, "transactions", None) or [])
        ]
        if transactions:
            try:
                await supabase_client.create_portfolio_transactions(
                    snapshot_id=saved["id"], user_id=user_id, transactions=transactions
                )
            except Exception as e:
                logger.warning("transaction_save_failed", snapshot_id=saved["id"], error=str(e))

        # 10. Reputation update (non-fatal)
        try:
            await ReputationService.trigger_reputation_update(user_id, supabase_client)
        except Exception as e:
            logger.warning("reputation_update_failed", user_id=user_id, error=str(e))

        # 11. Mark completed
        if file_id:
            await supabase_client.update_file_status(
                file_id=file_id,
                status="completed",
                snapshot_id=saved["id"],
                processing_completed_at="now()",
            )

        logger.info("parse_pdf_completed", user_id=user_id, snapshot_id=saved["id"], holdings=len(holdings_list))
        return JSONResponse(content={
            "success": True,
            "snapshot_id": saved["id"],
            "statement_date": statement_date.isoformat(),
            "holdings_count": len(holdings_list),
            "total_value": snapshot_dict["total_value"],
            "xirr": snapshot_dict["xirr"],
            "file_id": file_id,
        })

    except (MissingPANError, DuplicatePANError, MultiplePANError) as e:
        code = type(e).__name__.upper()
        await _fail_file(code, str(e), getattr(e, "details", {}))
        return JSONResponse(status_code=422, content={"success": False, "error_code": code, "error_message": str(e)})

    except (DuplicatePDFError, NoHoldingsFoundError) as e:
        code = type(e).__name__.upper()
        await _fail_file(code, str(e))
        return JSONResponse(status_code=409, content={"success": False, "error_code": code, "error_message": str(e)})

    except PDFDownloadError as e:
        logger.error("pdf_download_failed", user_id=user_id, error=str(e))
        raise HTTPException(status_code=500, detail={"error_code": "PDF_DOWNLOAD_ERROR", "error_message": str(e)})

    except Exception as e:
        code = getattr(e, "error_code", "INTERNAL_ERROR")
        msg = getattr(e, "message", str(e))
        logger.error("parse_pdf_failed", user_id=user_id, error=str(e), exc_info=True)
        await _fail_file(code, msg, {"exception_type": type(e).__name__})
        raise HTTPException(status_code=500, detail={"error_code": code, "error_message": msg})


# ---------------------------------------------------------------------------
# Transaction reconciliation
# ---------------------------------------------------------------------------

@router.post("/reconcile-transactions", dependencies=[Depends(_require_worker_secret)])
async def reconcile_transactions(req: ReconcileTransactionsRequest) -> JSONResponse:
    """Triggered by reconcile_transactions_task."""
    if req.trace_id:
        structlog.contextvars.bind_contextvars(trace_id=req.trace_id)

    from app.services.finance.transaction_reconciliation import reconciliation_service

    try:
        result = await reconciliation_service.reconcile_snapshot(req.snapshot_id, req.user_id)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error("reconcile_transactions_failed", snapshot_id=req.snapshot_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Portfolio refresh-due recalculation
# ---------------------------------------------------------------------------

@router.post("/calculate-refresh-due", dependencies=[Depends(_require_worker_secret)])
async def calculate_refresh_due(req: CalculateRefreshDueRequest) -> JSONResponse:
    """Triggered by calculate_refresh_due_task after a successful upload."""
    from app.services.jobs.refresh_due_calculator import update_profile_refresh_due

    try:
        success = await update_profile_refresh_due(req.user_id)
        return JSONResponse(content={"success": success})
    except Exception as e:
        logger.error("calculate_refresh_due_failed", user_id=req.user_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Scheduled / beat jobs
# ---------------------------------------------------------------------------

@router.post("/jobs/check-portfolio-staleness", dependencies=[Depends(_require_worker_secret)])
async def check_portfolio_staleness() -> JSONResponse:
    """Daily beat job: mark stale portfolios as requiring refresh."""
    from app.services.jobs.portfolio_staleness_job import check_portfolio_staleness_job

    try:
        await check_portfolio_staleness_job()
        return JSONResponse(content={"success": True})
    except Exception as e:
        logger.error("check_portfolio_staleness_failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/jobs/cleanup-expired-sessions", dependencies=[Depends(_require_worker_secret)])
async def cleanup_expired_sessions() -> JSONResponse:
    """Hourly beat job: remove expired rows from auth_sessions."""
    from app.services.jobs.portfolio_staleness_job import cleanup_expired_sessions_job

    try:
        await cleanup_expired_sessions_job()
        return JSONResponse(content={"success": True})
    except Exception as e:
        logger.error("cleanup_expired_sessions_failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/jobs/retry-failed-reconciliations", dependencies=[Depends(_require_worker_secret)])
async def retry_failed_reconciliations() -> JSONResponse:
    """Daily scheduled job: re-queue snapshots with failed reconciliation."""
    from app.services.jobs.tasks import reconcile_transactions_task
    from app.core.rq_app import portfolio_processing_queue
    from rq import Retry

    try:
        result = (
            supabase_client.client
            .table("portfolio_transactions")
            .select("snapshot_id, user_id")
            .eq("reconciliation_status", "failed")
            .execute()
        )
        if not result.data:
            return JSONResponse(content={"retried": 0})

        seen: set = set()
        retried = 0
        for row in result.data:
            key = (row["snapshot_id"], row["user_id"])
            if key not in seen:
                seen.add(key)
                portfolio_processing_queue.enqueue(
                    reconcile_transactions_task,
                    row["snapshot_id"],
                    row["user_id"],
                    retry=Retry(max=3, interval=[10, 30, 60]),
                    job_timeout=300,
                )
                retried += 1

        logger.info("retry_failed_reconciliations_completed", retried=retried)
        return JSONResponse(content={"retried": retried})
    except Exception as e:
        logger.error("retry_failed_reconciliations_failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/jobs/send-access-reminders", dependencies=[Depends(_require_worker_secret)])
async def send_access_reminders() -> JSONResponse:
    """Daily beat job: send portfolio access reminder emails."""
    from app.services.jobs.access_reminder_job import send_access_reminders as _send_reminders

    try:
        result = await _send_reminders()
        return JSONResponse(content=result)
    except Exception as e:
        logger.error("send_access_reminders_failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Gmail sync
# ---------------------------------------------------------------------------

@router.post("/sync-gmail", dependencies=[Depends(_require_worker_secret)])
async def sync_gmail(req: SyncGmailRequest) -> JSONResponse:
    """
    Triggered by sync_gmail_task. Delegates to app/services/gmail_sync.py.
    Note: Gmail feature is pending Google OAuth verification; this endpoint
    exists so the architecture is complete when the feature is enabled.
    """
    if req.trace_id:
        structlog.contextvars.bind_contextvars(trace_id=req.trace_id)

    from app.services.integrations.gmail_sync import sync_gmail_for_user

    try:
        result = await sync_gmail_for_user(user_id=req.user_id, sync_type=req.sync_type)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error("sync_gmail_failed", user_id=req.user_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
