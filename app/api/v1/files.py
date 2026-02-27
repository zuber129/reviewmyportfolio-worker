"""
API endpoints for portfolio file tracking and management.
"""
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing import Optional

from app.api.dependencies import get_current_user
from app.domain.schemas import (
    PortfolioFile,
    FileUploadHistoryResponse,
)
from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger()

router = APIRouter(prefix="/files", tags=["Files"])


@router.get("", response_model=FileUploadHistoryResponse)
async def list_user_files(
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    include_deleted: bool = Query(False, description="Include soft-deleted files"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: dict = Depends(get_current_user),
):
    """
    List all files uploaded by the current user with pagination and filtering.
    
    Query Parameters:
    - status: Filter by processing status (uploaded, validating, scanning, parsing, completed, failed)
    - include_deleted: Include soft-deleted files (default: false)
    - page: Page number (default: 1)
    - page_size: Items per page (default: 20, max: 100)
    """
    try:
        offset = (page - 1) * page_size
        
        files = await supabase_client.get_user_files(
            user_id=current_user["id"],
            status=status_filter,
            include_deleted=include_deleted,
            offset=offset,
            limit=page_size,
        )
        
        total = await supabase_client.count_user_files(
            user_id=current_user["id"],
            status=status_filter,
            include_deleted=include_deleted,
        )
        
        logger.info(
            "user_files_listed",
            user_id=current_user["id"],
            count=len(files),
            total=total,
            page=page,
        )
        
        return {
            "files": files,
            "total": total,
            "page": page,
            "page_size": page_size,
        }
    except Exception as e:
        logger.error(
            "list_user_files_error",
            user_id=current_user["id"],
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list files: {str(e)}",
        )


@router.get("/{file_id}", response_model=PortfolioFile)
async def get_file_details(
    file_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Get detailed information about a specific file.
    
    Returns full file record including error details, processing status, and metadata.
    """
    try:
        file_record = await supabase_client.get_file_by_id(file_id)
        
        # Verify ownership
        if file_record["user_id"] != current_user["id"]:
            logger.warning(
                "unauthorized_file_access_attempt",
                user_id=current_user["id"],
                file_id=file_id,
                owner_id=file_record["user_id"],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this file",
            )
        
        logger.info(
            "file_details_retrieved",
            user_id=current_user["id"],
            file_id=file_id,
            status=file_record["status"],
        )
        
        return file_record
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "get_file_details_error",
            user_id=current_user["id"],
            file_id=file_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {str(e)}",
        )


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file(
    file_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Soft delete a file record.
    
    This marks the file as deleted but doesn't remove it from storage immediately.
    The retention policy will clean up old files after 6 months.
    """
    try:
        # Get file to verify ownership
        file_record = await supabase_client.get_file_by_id(file_id)
        
        if file_record["user_id"] != current_user["id"]:
            logger.warning(
                "unauthorized_file_delete_attempt",
                user_id=current_user["id"],
                file_id=file_id,
                owner_id=file_record["user_id"],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to delete this file",
            )
        
        # Soft delete
        await supabase_client.soft_delete_file(
            file_id=file_id,
            delete_reason="user_requested",
        )
        
        logger.info(
            "file_deleted",
            user_id=current_user["id"],
            file_id=file_id,
        )
        
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "delete_file_error",
            user_id=current_user["id"],
            file_id=file_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete file: {str(e)}",
        )


from pydantic import BaseModel
from app.state_machines.upload_flow import UploadFlowMachine

class UnlockRequest(BaseModel):
    password: str

@router.post("/{file_id}/unlock")
async def unlock_password_protected_file(
    file_id: str,
    request: UnlockRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Unlock and reprocess a password-protected PDF file.
    
    Uses state machine to manage unlock attempts and transitions.
    Only works for files with error_code='PASSWORD_PROTECTED'.
    """
    try:
        file_record = await supabase_client.get_file_by_id(file_id)
        
        # Convert to dict if it's a Pydantic model
        if hasattr(file_record, 'model_dump'):
            file_record = file_record.model_dump()
        elif hasattr(file_record, 'dict'):
            file_record = file_record.dict()
        
        sm = UploadFlowMachine(model=file_record, user_id=current_user["id"])
        
        if not sm.is_owner(current_user["id"]):
            logger.warning(
                "unauthorized_file_unlock_attempt",
                user_id=current_user["id"],
                file_id=file_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to unlock this file",
            )
        
        if file_record["error_code"] != "PASSWORD_PROTECTED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File is not password-protected (error_code: {file_record['error_code']})",
            )
        
        if not sm.can_unlock():
            sm.max_unlock_attempts()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=sm.model["error_message"],
            )
        
        import fitz
        
        encrypted_pdf_bytes = supabase_client.client.storage.from_(
            file_record["storage_bucket"]
        ).download(file_record["storage_path"])
        
        doc = fitz.open(stream=encrypted_pdf_bytes, filetype="pdf")
        
        if not doc.is_encrypted:
            doc.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PDF is not encrypted",
            )
        
        auth_result = doc.authenticate(request.password)
        
        if not auth_result:
            doc.close()
            sm.password_incorrect()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=sm.error_message,
            )
        
        decrypted_pdf_bytes = doc.tobytes()
        doc.close()
        
        supabase_client.client.storage.from_(file_record["storage_bucket"]).update(
            file_record["storage_path"],
            decrypted_pdf_bytes,
            {"content-type": "application/pdf"}
        )
        
        logger.info(
            "pdf_decrypted_and_reuploaded",
            user_id=current_user["id"],
            file_id=file_id,
            original_size=len(encrypted_pdf_bytes),
            decrypted_size=len(decrypted_pdf_bytes),
        )
        
        sm.password_provided()
        
        from app.services.jobs.tasks import parse_pdf_task
        from app.core.rq_app import pdf_parsing_queue
        from rq import Retry
        
        pdf_url = supabase_client.client.storage.from_(
            file_record["storage_bucket"]
        ).get_public_url(file_record["storage_path"])
        
        task = pdf_parsing_queue.enqueue(
            parse_pdf_task,
            pdf_url=pdf_url,
            pdf_hash=file_record["file_hash"],
            user_id=current_user["id"],
            file_id=file_id,
            retry=Retry(max=5, interval=[10, 30, 60, 120, 300]),
            job_timeout=300,
        )
        
        await supabase_client.update_file_status(
            file_id=file_id,
            celery_task_id=task.id,
        )
        
        logger.info(
            "password_unlock_initiated",
            user_id=current_user["id"],
            file_id=file_id,
            task_id=task.id,
        )
        
        return sm.get_flow_info()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "unlock_file_error",
            user_id=current_user["id"],
            file_id=file_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unlock file: {str(e)}",
        )


@router.post("/{file_id}/retry")
async def retry_failed_file(
    file_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Retry processing a failed file upload.
    
    Uses state machine to manage retry attempts and transitions.
    Only works for files with status='failed' and retry_count < 3.
    """
    try:
        file_record = await supabase_client.get_file_by_id(file_id)
        
        sm = UploadFlowMachine(model=file_record, user_id=current_user["id"])
        
        if not sm.is_owner(current_user["id"]):
            logger.warning(
                "unauthorized_file_retry_attempt",
                user_id=current_user["id"],
                file_id=file_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to retry this file",
            )
        
        if file_record["status"] != "failed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot retry file with status '{file_record['status']}'. Only failed files can be retried.",
            )
        
        if not sm.can_retry():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum retry limit (3) reached for this file",
            )
        
        sm.retry_from_failed()
        
        from app.services.jobs.tasks import parse_pdf_task
        from app.core.rq_app import pdf_parsing_queue
        from rq import Retry
        
        pdf_url = supabase_client.client.storage.from_(
            file_record["storage_bucket"]
        ).get_public_url(file_record["storage_path"])
        
        task = pdf_parsing_queue.enqueue(
            parse_pdf_task,
            pdf_url=pdf_url,
            pdf_hash=file_record["file_hash"],
            user_id=current_user["id"],
            file_id=file_id,
            retry=Retry(max=5, interval=[10, 30, 60, 120, 300]),
            job_timeout=300,
        )
        
        await supabase_client.update_file_status(
            file_id=file_id,
            celery_task_id=task.id,
            last_retry_at="now()",
        )
        
        logger.info(
            "file_retry_initiated",
            user_id=current_user["id"],
            file_id=file_id,
            task_id=task.id,
            retry_count=sm.model.get("retry_count", 0),
        )
        
        return sm.get_flow_info()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "retry_file_error",
            user_id=current_user["id"],
            file_id=file_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retry file: {str(e)}",
        )
