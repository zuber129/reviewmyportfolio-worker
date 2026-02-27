"""
Gmail sync business logic — moved here from Celery tasks.

Called by the worker callback endpoint POST /api/v1/worker/sync-gmail.
Feature is currently disabled pending Google OAuth verification.
"""
import base64
import hashlib
from datetime import datetime
from typing import Any, Dict

import structlog

from app.infrastructure.supabase_client import supabase_client
from app.utils.encryption import decrypt_token, encrypt_token

logger = structlog.get_logger()


async def sync_gmail_for_user(user_id: str, sync_type: str = "incremental") -> Dict[str, Any]:
    """
    Full Gmail sync pipeline for a user.

    Steps:
      1. Load Gmail account + refresh OAuth token if expired
      2. Scan inbox for CAS emails
      3. Download PDF attachments, deduplicate, upload to storage
      4. Enqueue parse_pdf_task for each new PDF
      5. Update sync log and account history ID

    Args:
        user_id:   Supabase user ID
        sync_type: "initial" | "incremental" | "manual"

    Returns:
        Dict with emails_scanned / pdfs_processed / duration_ms
    """
    from app.services.integrations.gmail_client import gmail_client
    from app.services.jobs.tasks import parse_pdf_task

    start_time = datetime.utcnow()

    gmail_account = await supabase_client.get_gmail_account(user_id)
    if not gmail_account:
        logger.error("gmail_account_not_found", user_id=user_id)
        return {"success": False, "error": "Gmail account not found"}

    sync_log = await supabase_client.create_gmail_sync_log({
        "gmail_account_id": gmail_account["id"],
        "user_id": user_id,
        "sync_type": sync_type,
        "status": "started",
    })

    logger.info("gmail_sync_started", user_id=user_id, sync_type=sync_type, sync_log_id=sync_log["id"])

    try:
        # Refresh token if expired
        token_expires_at = datetime.fromisoformat(
            gmail_account["token_expires_at"].replace("Z", "+00:00")
        )
        if datetime.utcnow() >= token_expires_at:
            logger.info("gmail_token_refreshing", user_id=user_id)
            access_token, new_expires_at = await gmail_client.refresh_access_token(
                gmail_account["encrypted_refresh_token"]
            )
            await supabase_client.update_gmail_account(user_id, {
                "encrypted_access_token": encrypt_token(access_token),
                "token_expires_at": new_expires_at.isoformat(),
            })
        else:
            access_token = decrypt_token(gmail_account["encrypted_access_token"])

        days_back = 180 if sync_type == "initial" else 30
        cas_emails, new_history_id = await gmail_client.scan_for_cas_emails(
            access_token,
            last_history_id=gmail_account.get("last_history_id"),
            days_back=days_back,
        )

        logger.info("gmail_cas_emails_found", user_id=user_id, count=len(cas_emails))

        pdfs_downloaded = 0
        pdfs_processed = 0

        for email_data in cas_emails:
            try:
                cas_email = await supabase_client.create_gmail_cas_email({
                    "gmail_account_id": gmail_account["id"],
                    "user_id": user_id,
                    **email_data,
                })

                attachments = await gmail_client.download_pdf_attachments(
                    access_token, email_data["gmail_message_id"]
                )
                pdfs_downloaded += len(attachments)

                for filename, pdf_bytes in attachments:
                    try:
                        pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()

                        existing = await supabase_client.check_file_hash_exists(user_id, pdf_hash)
                        if existing:
                            logger.info("gmail_pdf_duplicate_skipped", user_id=user_id, filename=filename)
                            continue

                        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                        file_key = f"{user_id}/gmail_{timestamp}_{filename}"

                        await supabase_client.upload_to_storage(
                            bucket="portfolio-documents",
                            path=file_key,
                            file_bytes=pdf_bytes,
                        )

                        file_record = await supabase_client.create_portfolio_file({
                            "user_id": user_id,
                            "storage_path": file_key,
                            "storage_bucket": "portfolio-documents",
                            "file_size_bytes": len(pdf_bytes),
                            "file_hash": pdf_hash,
                            "original_filename": filename,
                            "mime_type": "application/pdf",
                            "source": "gmail",
                            "file_status": "uploaded",
                        })

                        # Enqueue parse — thin job will call the worker callback
                        pdf_url = f"portfolio-documents/{file_key}"
                        from app.core.rq_app import pdf_parsing_queue
                        from rq import Retry
                        pdf_parsing_queue.enqueue(
                            parse_pdf_task,
                            pdf_url=pdf_url,
                            pdf_hash=pdf_hash,
                            user_id=user_id,
                            file_id=file_record["id"],
                            retry=Retry(max=5, interval=[10, 30, 60, 120, 300]),
                            job_timeout=300,
                        )

                        await supabase_client.update_gmail_cas_email(
                            cas_email["id"], {"portfolio_file_id": file_record["id"]}
                        )

                        pdfs_processed += 1
                        logger.info("gmail_pdf_queued", user_id=user_id, filename=filename)

                    except Exception as e:
                        logger.error("gmail_pdf_processing_failed", user_id=user_id, filename=filename, error=str(e))
                        continue

                await supabase_client.update_gmail_cas_email(
                    cas_email["id"],
                    {"processed": True, "processed_at": datetime.utcnow().isoformat()},
                )

            except Exception as e:
                logger.error(
                    "gmail_email_processing_failed",
                    user_id=user_id,
                    email_id=email_data.get("gmail_message_id"),
                    error=str(e),
                )
                continue

        await supabase_client.update_gmail_account(user_id, {
            "last_sync_at": datetime.utcnow().isoformat(),
            "last_history_id": new_history_id,
            "status": "active",
        })

        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        await supabase_client.update_gmail_sync_log(sync_log["id"], {
            "status": "completed",
            "emails_scanned": len(cas_emails),
            "cas_emails_found": len(cas_emails),
            "pdfs_downloaded": pdfs_downloaded,
            "pdfs_processed": pdfs_processed,
            "completed_at": datetime.utcnow().isoformat(),
            "duration_ms": duration_ms,
        })

        logger.info(
            "gmail_sync_completed",
            user_id=user_id,
            cas_emails=len(cas_emails),
            pdfs_processed=pdfs_processed,
            duration_ms=duration_ms,
        )
        return {
            "success": True,
            "emails_scanned": len(cas_emails),
            "pdfs_processed": pdfs_processed,
            "duration_ms": duration_ms,
        }

    except Exception as e:
        logger.error("gmail_sync_failed", user_id=user_id, error=str(e), exc_info=True)
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        await supabase_client.update_gmail_sync_log(sync_log["id"], {
            "status": "failed",
            "error_message": str(e),
            "completed_at": datetime.utcnow().isoformat(),
            "duration_ms": duration_ms,
        })
        return {"success": False, "error": str(e)}
