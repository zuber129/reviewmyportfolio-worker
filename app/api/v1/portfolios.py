import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import structlog
from app.api.dependencies import get_current_user, get_optional_user
from app.services.auth.auth_session_service import restore_all_user_sessions
from app.core.exceptions import (
    AccessBlockedError,
    PortfolioNotFoundError,
    ShareToBrowseRequiredError,
)
from app.domain.schemas import (
    ErrorResponse,
    Holding,
    Opinion,
    OpinionCreate,
    PaginationMeta,
    Portfolio,
    PortfolioCreate,
    PortfolioFeedRequest,
    PortfolioFeedResponse,
    PortfolioStatusResponse,
    ProcessPortfolioRequest,
    PublicPortfolio,
    PublicUserProfile,
    Report,
    ReportCreate,
    Review,
    ReviewCreate,
    UploadTaskResponse,
    UploadUrlResponse,
)
from app.infrastructure.redis_client import redis_client
from app.infrastructure.supabase_client import supabase_client
from app.services.jobs.feed_cache_service import feed_cache_service
from app.services.integrations.malware_scanner import malware_scanner
from app.services.auth.moderation_service import moderation_service
from app.services.pdf.exceptions import ERROR_MESSAGES, MalwareDetectedError
from app.services.pdf.parser import pdf_parser
from app.services.jobs.tasks import get_task_status, parse_pdf_task
from app.core.rq_app import pdf_parsing_queue
from rq import Retry
from app.services.social.trending_service import TrendingService
from app.utils.sanitize import sanitize_html, sanitize_plain_text
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

logger = structlog.get_logger()
router = APIRouter(prefix="/portfolios", tags=["Portfolios"])


# Privacy helper functions
def _to_public_portfolio(portfolio_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform portfolio data to public format by removing user_id.
    Preserves all other fields including owner information.
    """
    public_data = portfolio_data.copy()
    # Remove user_id for privacy
    public_data.pop("user_id", None)

    # Transform owner to public profile if present
    if "owner" in public_data and public_data["owner"]:
        owner = public_data["owner"]
        public_data["owner"] = {
            "username": owner.get("username"),
            "avatar_url": owner.get("avatar_url"),
            "bio": owner.get("bio"),
            "badges": owner.get("badges", []),
        }

    return public_data


def _to_public_user_profile(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Transform user profile to public format by removing user_id and PII."""
    return {
        "username": user_data.get("username"),
        "avatar_url": user_data.get("avatar_url"),
        "bio": user_data.get("bio"),
        "badges": user_data.get("badges", []),
    }


@router.get("/pending")
async def get_pending_uploads(current_user: dict = Depends(get_current_user)):
    """
    Get user's pending/processing portfolio uploads.
    Returns uploads that are still being processed in the background.
    """
    try:
        # Fetch user's portfolio files that are still processing
        pending = await supabase_client.get_pending_portfolio_files(current_user["id"])  # type: ignore[attr-defined]
        
        uploads = []
        for file in pending:
            uploads.append({
                "id": file.get("snapshot_id") or file.get("id"),
                "title": file.get("title", "Untitled Portfolio"),
                "file_name": file.get("original_filename", "portfolio.pdf"),
                "status": "completed" if file.get("status") == "completed" else "failed" if file.get("status") == "failed" else "processing",
                "file_status": file.get("file_status", "uploaded"),
                "progress": 0,  # Will be calculated by frontend based on file_status
                "started_at": file.get("uploaded_at") or file.get("created_at"),
                "error": file.get("error_message"),
            })
        
        return {"uploads": uploads}
    except Exception as e:
        logger.error("failed_to_fetch_pending_uploads", user_id=current_user["id"], error=str(e))
        return {"uploads": []}


@router.get("/upload-url")
async def get_upload_url(current_user: dict = Depends(get_current_user)):
    """
    Generate a presigned URL for direct PDF upload to storage.
    This implements secure file upload best practices by:
    1. Avoiding file upload through application server (reduces load)
    2. Eliminating base64 encoding overhead (~33% size reduction)
    3. Enabling parallel uploads and better scalability
    4. Using short-lived signed URLs (5 min expiry)
    5. Using meaningful timestamps for debugging
    """
    try:
        # Generate meaningful file path with timestamp
        import datetime
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        file_key = f"{current_user['id']}/{timestamp}_portfolio.pdf"

        # Create presigned URL (expires in 5 minutes)
        presigned_url = await supabase_client.create_presigned_upload_url(
            bucket="portfolio-documents", path=file_key, expires_in=300
        )

        if not presigned_url:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate upload URL",
            )

        # Fix for Docker: Replace host.docker.internal with 127.0.0.1
        # so frontend (running on host) can access the URL
        presigned_url_fixed = presigned_url.replace("host.docker.internal", "127.0.0.1")

        logger.info(
            "upload_url_generated",
            user_id=current_user["id"],
            file_key=file_key,
            original_url=presigned_url,
            fixed_url=presigned_url_fixed,
        )

        return {
            "upload_url": presigned_url_fixed,
            "file_key": file_key,
            "bucket": "portfolio-documents",
            "expires_in": 300,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "upload_url_generation_error", user_id=current_user["id"], error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate upload URL: {str(e)}",
        )


@router.post("/process")
async def process_portfolio(
    request: ProcessPortfolioRequest, current_user: dict = Depends(get_current_user)
):
    """
    Process a PDF that was uploaded directly to storage via presigned URL.
    This is called after the frontend uploads the file to storage.
    Creates a placeholder portfolio immediately so user can track status.

    Args:
        request: ProcessPortfolioRequest containing file_key, title, description, is_public
        current_user: Authenticated user from dependency
    """
    try:
        # Download PDF from storage to calculate hash (for deduplication)
        logger.info(
            "portfolio_pdf_download_started",
            user_id=current_user["id"],
            file_key=request.file_key,
            original_filename=request.original_filename,
        )
        
        pdf_bytes = await supabase_client.download_from_storage(
            bucket="portfolio-documents", path=request.file_key
        )

        if not pdf_bytes:
            logger.error(
                "portfolio_pdf_not_found",
                user_id=current_user["id"],
                file_key=request.file_key,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Uploaded file not found in storage",
            )

        # Validate file size (1MB limit)
        if len(pdf_bytes) > 1 * 1024 * 1024:
            logger.error(
                "portfolio_pdf_too_large",
                user_id=current_user["id"],
                size_bytes=len(pdf_bytes),
                file_key=request.file_key,
            )
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="PDF file too large (max 1MB)",
            )

        # Validate PDF
        if not pdf_bytes.startswith(b"%PDF"):
            logger.error(
                "portfolio_invalid_pdf_format",
                user_id=current_user["id"],
                file_key=request.file_key,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid PDF file"
            )

        # Scan for malware/viruses
        scan_result = malware_scanner.scan_pdf(pdf_bytes)
        
        if not scan_result["clean"]:
            logger.error(
                "malware_detected_in_upload",
                user_id=current_user["id"],
                threats=scan_result["threats"],
                file_key=request.file_key,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "MALWARE_DETECTED",
                    "message": ERROR_MESSAGES["MALWARE_DETECTED"]["message"],
                    "threats": scan_result["threats"],
                },
            )
        
        logger.info(
            "malware_scan_passed",
            user_id=current_user["id"],
            scan_time=scan_result["scan_time"],
            scanner_available=scan_result["scanner_available"],
        )

        # Calculate SHA-256 hash for deduplication
        pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()

        # Early deduplication check - fail fast if file already processed
        existing_file = await supabase_client.check_file_hash_exists(
            user_id=current_user["id"], file_hash=pdf_hash
        )
        
        if existing_file:
            logger.info(
                "duplicate_file_upload_blocked",
                user_id=current_user["id"],
                file_hash=pdf_hash,
                existing_file_id=existing_file["id"],
                existing_uploaded_at=existing_file["uploaded_at"],
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error_code": "DUPLICATE_FILE",
                    "message": f"This statement was already uploaded on {existing_file['uploaded_at']}",
                    "existing_file_id": existing_file["id"],
                    "existing_snapshot_id": existing_file.get("snapshot_id"),
                },
            )

        # Get public URL for the file
        pdf_url = supabase_client.client.storage.from_(
            "portfolio-documents"
        ).get_public_url(request.file_key)

        # Create file tracking record
        file_record = await supabase_client.create_portfolio_file(
            {
                "user_id": current_user["id"],
                "storage_path": request.file_key,
                "storage_bucket": "portfolio-documents",
                "file_size_bytes": len(pdf_bytes),
                "file_hash": pdf_hash,
                "original_filename": request.original_filename,
                "mime_type": "application/pdf",
                "status": "uploaded",
            }
        )
        
        file_id = file_record["id"]
        logger.info(
            "file_tracking_record_created",
            file_id=file_id,
            user_id=current_user["id"],
            file_hash=pdf_hash,
        )

        # Create placeholder portfolio immediately with "processing" status
        placeholder_data = {
            "title": request.title or "Untitled Portfolio",
            "description": request.description,
            "investment_thesis": request.investment_thesis,
            "is_public": request.is_public or False,
            "pdf_processing_status": "processing",
            "pdf_url": pdf_url,
            "file_id": file_id,
            "total_value": 0,
            "xirr": 0,
            "holding_count": 0,
            "holdings_last_updated_at": datetime.now(timezone.utc).isoformat(),
        }

        portfolio = await supabase_client.create_portfolio(
            user_id=current_user["id"], data=placeholder_data
        )

        if not portfolio:
            logger.error(
                "portfolio_creation_failed",
                user_id=current_user["id"],
                file_key=request.file_key,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create portfolio",
            )

        portfolio_id = str(portfolio["id"])
        logger.info(
            "portfolio_created",
            user_id=current_user["id"],
            portfolio_id=portfolio_id,
            file_key=request.file_key,
        )

        # Restore all user sessions after portfolio upload (186-day rule)
        try:
            await restore_all_user_sessions(current_user["id"], supabase_client)
        except Exception as e:
            logger.warning("restore_sessions_failed", user_id=current_user["id"], error=str(e))

        # Enqueue parsing task with file_id for tracking
        task = pdf_parsing_queue.enqueue(
            parse_pdf_task,
            pdf_url=pdf_url,
            pdf_hash=pdf_hash,
            user_id=current_user["id"],
            file_id=file_id,
            retry=Retry(max=5, interval=[10, 30, 60, 120, 300]),
            job_timeout=300,
        )

        # Update file record with rq job id
        await supabase_client.update_file_status(
            file_id=file_id,
            status="uploaded",
            celery_task_id=task.id,
        )

        logger.info(
            "portfolio_processing_started",
            user_id=current_user["id"],
            portfolio_id=portfolio_id,
            task_id=task.id,
            file_id=file_id,
            file_key=request.file_key,
            pdf_hash=pdf_hash,
        )

        return {
            "portfolio_id": portfolio_id,
            "task_id": task.id,
            "file_id": file_id,
            "status": "processing",
            "message": "PDF processing started",
            "file_key": request.file_key,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "portfolio_processing_error", user_id=current_user["id"], error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Processing failed: {str(e)}",
        )


@router.get("/task/{task_id}")
async def get_upload_task_status(
    task_id: str, current_user: dict = Depends(get_current_user)
):
    """
    Check the status of a portfolio upload task.
    Returns structured error information if parsing failed.
    """
    try:
        task_status = get_task_status(task_id)

        # If task succeeded but contains error_code (validation error)
        if task_status.get("state") == "SUCCESS" and task_status.get("result", {}).get(
            "error_code"
        ):
            result = task_status["result"]
            error_code = result["error_code"]

            # Get user-friendly message
            error_info = ERROR_MESSAGES.get(
                error_code, ERROR_MESSAGES["INTERNAL_ERROR"]
            )

            return {
                "state": "FAILED",
                "status": "Validation failed",
                "error_code": error_code,
                "error_title": error_info["title"],
                "error_message": error_info["message"],
                "error_help": error_info["help"],
                "task_id": task_id,
            }

        return task_status
    except Exception as e:
        logger.error("task_status_error", task_id=task_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get task status",
        )


@router.get("/feed", response_model=PortfolioFeedResponse)
async def get_portfolio_feed(
    page: int = 1,
    page_size: int = 20,
    # Portfolio filters
    portfolio_size_min: Optional[float] = None,
    portfolio_size_max: Optional[float] = None,
    xirr_min: Optional[float] = None,
    xirr_max: Optional[float] = None,
    risk_level: Optional[str] = None,  # Will convert to list
    holding_count_min: Optional[int] = None,
    holding_count_max: Optional[int] = None,
    # Sorting
    sort_by: str = "created_at",
    sort_order: str = "desc",
    # Auth - REQUIRED for access control
    current_user: dict = Depends(get_current_user),
):
    """
    Get paginated portfolio feed with advanced filtering and sorting.

    **Access Control**:
    - Users who have never uploaded a portfolio cannot browse (share to browse).
    - Users with blocked status (75+ days since last upload) cannot browse.
    - Users with restricted status (61-74 days) can still browse with warnings.

    Filters:
    - portfolio_size_min/max: Filter by portfolio value range
    - xirr_min/max: Filter by XIRR percentage range
    - risk_level: Filter by risk level (conservative, moderate, aggressive)
    - holding_count_min/max: Filter by number of holdings

    Sorting:
    - sort_by: created_at (default), xirr, portfolio_size, holding_count
    - sort_order: desc (default) or asc

    Pagination:
    - page: Page number (default: 1)
    - page_size: Items per page (default: 20, max: 100)
    """
    try:
        # ACCESS CONTROL: Check if user can browse feed
        from app.utils.access_control import compute_access_status

        # Get user profile to check access status
        profile = await supabase_client.get_user_profile(current_user["id"])
        last_upload = profile.get("last_portfolio_upload_at") or profile.get(
            "last_upload_date"
        )

        # Parse if string
        if isinstance(last_upload, str):
            from datetime import datetime, timezone

            last_upload = datetime.fromisoformat(last_upload.replace("Z", "+00:00"))

        # Compute access status
        access_result = compute_access_status(last_upload)

        # Enforce access control
        if not access_result.has_ever_uploaded:
            # Never uploaded - must upload first ("share to browse")
            logger.warning("feed_access_denied_no_upload", user_id=current_user["id"])
            raise ShareToBrowseRequiredError()

        if access_result.status == "blocked":
            # Blocked - must upload to restore access
            logger.warning(
                "feed_access_denied_blocked",
                user_id=current_user["id"],
                days_since_upload=access_result.days_since_last_upload,
            )
            raise AccessBlockedError(
                days_since_upload=access_result.days_since_last_upload
            )

        # Active or restricted - allow access
        # (restricted users see warnings in frontend, but can still browse)
        # Validate page_size
        if page_size > 100:
            page_size = 100
        if page_size < 1:
            page_size = 20

        # Convert risk_level to list if provided (for multi-select support)
        risk_level_list = [risk_level] if risk_level else None

        # Check if cache is populated (fallback to DB if not)
        total_count = await feed_cache_service.get_total_count()

        if total_count == 0:
            # Cache not populated, fallback to database
            logger.warning("feed_cache_empty_fallback_to_db")

            # Build filters for database query
            filters: Dict[str, Any] = {}
            if risk_level:
                filters["risk_level"] = risk_level
            if xirr_min:
                filters["min_xirr"] = xirr_min
            if xirr_max:
                filters["max_xirr"] = xirr_max

            # Calculate offset for database query
            offset = (page - 1) * page_size

            # Get portfolios from database
            portfolios = await supabase_client.get_portfolios_feed(
                offset=offset, limit=page_size, filters=filters
            )

            # Populate cache and add reaction data for each portfolio
            for portfolio in portfolios:
                if "id" in portfolio and "created_at" in portfolio:
                    # Get holding count from holdings if available
                    holdings = portfolio.get("holdings", [])
                    portfolio["holding_count"] = len(holdings) if holdings else 0

                    # Add reaction data
                    portfolio_id = portfolio["id"]
                    reaction_count = await supabase_client.get_reaction_count(
                        portfolio_id
                    )
                    portfolio["reaction_count"] = reaction_count

                    if current_user:
                        is_reacted = await supabase_client.check_user_reacted(
                            portfolio_id=portfolio_id, user_id=current_user["id"]
                        )
                        portfolio["is_reacted"] = is_reacted
                    else:
                        portfolio["is_reacted"] = False

                    # Populate cache asynchronously
                    await feed_cache_service.populate_feed_cache(
                        portfolio_id=str(portfolio["id"]),
                        portfolio_data=portfolio,
                        created_at=portfolio["created_at"],
                    )

            # Transform to public format (strip user_id for privacy)
            public_portfolios = [_to_public_portfolio(p) for p in portfolios]

            # Return database results
            return {
                "portfolios": public_portfolios,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": len(portfolios) + offset,
                    "total_pages": -1,  # Unknown without count query
                    "has_previous": page > 1,
                    "has_next": len(portfolios) == page_size,
                },
                "source": "database",
            }

        # Use cache service for filtered and sorted feed
        result = await feed_cache_service.get_feed(
            page=page,
            page_size=page_size,
            portfolio_size_min=portfolio_size_min,
            portfolio_size_max=portfolio_size_max,
            xirr_min=xirr_min,
            xirr_max=xirr_max,
            risk_level=risk_level_list,
            holding_count_min=holding_count_min,
            holding_count_max=holding_count_max,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        # Add reaction data to each portfolio
        if result.get("portfolios"):
            portfolio_ids = [p["id"] for p in result["portfolios"]]

            # Get reaction counts for all portfolios
            for portfolio in result["portfolios"]:
                portfolio_id = portfolio["id"]

                # Get reaction count
                reaction_count = await supabase_client.get_reaction_count(portfolio_id)
                portfolio["reaction_count"] = reaction_count

                # Get user's reaction status if authenticated
                if current_user:
                    is_reacted = await supabase_client.check_user_reacted(
                        portfolio_id=portfolio_id, user_id=current_user["id"]
                    )
                    portfolio["is_reacted"] = is_reacted
                else:
                    portfolio["is_reacted"] = False

            # Transform all portfolios to public format (strip user_id for privacy)
            result["portfolios"] = [
                _to_public_portfolio(p) for p in result["portfolios"]
            ]

        # Add source indicator
        result["source"] = "cache"

        logger.info(
            "portfolio_feed_served",
            page=page,
            count=len(result["portfolios"]),
            source="cache",
            filters_applied=bool(
                any(
                    [
                        portfolio_size_min,
                        portfolio_size_max,
                        xirr_min,
                        xirr_max,
                        risk_level,
                        holding_count_min,
                        holding_count_max,
                    ]
                )
            ),
        )

        return result

    except (ShareToBrowseRequiredError, AccessBlockedError):
        # Re-raise access control exceptions so they're handled by FastAPI exception handlers
        raise
    except Exception as e:
        logger.error("portfolio_feed_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch portfolio feed",
        )


@router.post(
    "/{portfolio_id}/review", response_model=Review, status_code=status.HTTP_201_CREATED
)
async def add_portfolio_review(
    portfolio_id: str,
    request: ReviewCreate,
    current_user: dict = Depends(get_current_user),
):
    """
    Add a review to a portfolio.
    Users can review other users' portfolios but not their own.
    """
    try:
        # Check if portfolio exists
        # This would be a Supabase query
        # For now, we'll assume it exists

        # Create the review
        review = await supabase_client.create_portfolio_review(
            portfolio_id=portfolio_id,
            user_id=current_user["id"],
            rating=request.rating,
            content=request.content,
            review_type=request.review_type,
        )

        if not review:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create review",
            )

        # Invalidate portfolio in feed cache (review counts may have changed)
        # For now, just invalidate the portfolio data, not the whole feed
        await redis_client.delete(f"portfolio:{portfolio_id}")

        logger.info(
            "review_created",
            portfolio_id=portfolio_id,
            user_id=current_user["id"],
            rating=request.rating,
        )

        return Review(**review)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("review_create_error", portfolio_id=portfolio_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add review",
        )


@router.get("/{portfolio_id}", response_model=PublicPortfolio)
async def get_portfolio(
    portfolio_id: str, current_user: dict = Depends(get_current_user)
):
    """
    Get a specific portfolio by ID.

    **Access Control**:
    - Users who have never uploaded a portfolio cannot view details (share to browse).
    - Users with blocked status (75+ days since last upload) cannot view details.
    - Users with restricted status (61-74 days) can still view with warnings.
    - Private portfolios require ownership.

    Returns PublicPortfolio (excludes user_id for privacy).
    """
    try:
        # ACCESS CONTROL: Check if user can browse portfolio details
        from app.utils.access_control import compute_access_status

        # Get user profile to check access status
        profile = await supabase_client.get_user_profile(current_user["id"])
        last_upload = profile.get("last_portfolio_upload_at") or profile.get(
            "last_upload_date"
        )

        # Parse if string
        if isinstance(last_upload, str):
            from datetime import datetime, timezone

            last_upload = datetime.fromisoformat(last_upload.replace("Z", "+00:00"))

        # Compute access status
        access_result = compute_access_status(last_upload)

        # Enforce access control (same as feed)
        if not access_result.has_ever_uploaded:
            logger.warning(
                "portfolio_detail_access_denied_no_upload",
                user_id=current_user["id"],
                portfolio_id=portfolio_id,
            )
            raise ShareToBrowseRequiredError()

        if access_result.status == "blocked":
            logger.warning(
                "portfolio_detail_access_denied_blocked",
                user_id=current_user["id"],
                portfolio_id=portfolio_id,
                days_since_upload=access_result.days_since_last_upload,
            )
            raise AccessBlockedError(
                days_since_upload=access_result.days_since_last_upload
            )
        # Check cache first
        cache_key = f"portfolio:{portfolio_id}"
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            logger.info("portfolio_cache_hit", portfolio_id=portfolio_id)
            # Transform to public response (strip user_id)
            public_data = _to_public_portfolio(cached_data)
            return PublicPortfolio(**public_data)

        # Fetch from database
        portfolio_data = await supabase_client.get_portfolio(portfolio_id)

        # Check visibility and access control
        visibility = portfolio_data.get("visibility", "public")
        if visibility == "private":
            # Private portfolio - check if user is owner
            if not current_user or current_user.get("id") != portfolio_data.get(
                "user_id"
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Private portfolio"
                )

        # Fetch user profile for owner info
        user_profile = await supabase_client.get_user_profile(portfolio_data["user_id"])

        # Enhance portfolio data with full owner profile
        portfolio_data["owner"] = user_profile

        # Cache for 10 minutes
        await redis_client.set(cache_key, portfolio_data, expire=600)

        logger.info(
            "portfolio_fetched", portfolio_id=portfolio_id, visibility=visibility
        )

        # Transform to public response (strip user_id)
        public_data = _to_public_portfolio(portfolio_data)
        return PublicPortfolio(**public_data)

    except PortfolioNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Portfolio not found"
        )
    except (ShareToBrowseRequiredError, AccessBlockedError):
        # Re-raise access control exceptions so they're handled by FastAPI exception handlers
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error("portfolio_get_error", portfolio_id=portfolio_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch portfolio",
        )


# ========== PORTFOLIO STATUS ENDPOINT ==========


@router.get("/{portfolio_id}/status")
async def get_portfolio_status(
    portfolio_id: str, current_user: dict = Depends(get_current_user)
):
    """
    Get the processing status of a portfolio with file tracking details.
    Used by the status page to poll for completion.

    Returns:
        - status: processing, completed, failed, or timeout
        - file_status: Current file processing stage (uploaded, validating, scanning, parsing, completed, failed)
        - holdings_breakdown: Breakdown by asset type (only on completed)
        - error: Error message if failed
        - error_code: Error code if failed
    """
    try:
        # Fetch portfolio
        portfolio = await supabase_client.get_portfolio(portfolio_id)

        if not portfolio:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Portfolio not found"
            )

        # Verify ownership
        if portfolio["user_id"] != current_user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this portfolio",
            )

        # Get file tracking status if available
        file_status = None
        error_code = None
        error_message = None
        error_details = None
        
        # Get file_id from portfolio to query the specific file
        portfolio_file_id = portfolio.get("file_id")
        
        if portfolio_file_id:
            # Query portfolio_files table for detailed status using specific file_id
            try:
                file_response = (
                    supabase_client.client.table("portfolio_files")
                    .select("status, error_code, error_message, error_details, snapshot_id")
                    .eq("id", portfolio_file_id)
                    .single()
                    .execute()
                )
                
                if file_response.data:
                    file_record = file_response.data
                    file_status = file_record.get("status")
                    error_code = file_record.get("error_code")
                    error_message = file_record.get("error_message")
                    error_details = file_record.get("error_details")
            except Exception as e:
                logger.warning("file_status_query_failed", portfolio_id=portfolio_id, file_id=portfolio_file_id, error=str(e))

        # Get processing status from portfolio
        processing_status = portfolio.get("pdf_processing_status", "unknown")
        
        # If file has failed status, override processing_status to reflect that
        if file_status == "failed":
            processing_status = "failed"
        elif file_status == "completed":
            processing_status = "completed"
        
        # Use error_message from file record if not already set (file record takes precedence)
        if not error_message:
            error_message = portfolio.get("processing_error")

        # Calculate holdings breakdown if completed
        holdings_breakdown = None
        if processing_status == "completed":
            try:
                # Get latest snapshot for this portfolio
                snapshot_response = (
                    supabase_client.client.table("portfolio_snapshots")
                    .select("holdings")
                    .eq("user_id", current_user["id"])
                    .order("upload_time", desc=True)
                    .limit(1)
                    .execute()
                )
                
                if snapshot_response.data and len(snapshot_response.data) > 0:
                    holdings_data = snapshot_response.data[0].get("holdings", {})
                    
                    # Calculate breakdown by asset type
                    breakdown = {
                        "stocks": 0,
                        "mutual_funds": 0,
                        "gold": 0,
                        "other": 0,
                        "total": 0
                    }
                    
                    if isinstance(holdings_data, list):
                        holdings = holdings_data
                    elif isinstance(holdings_data, dict):
                        holdings = holdings_data.get("holdings", [])
                    else:
                        holdings = []
                    
                    if holdings:
                        for holding in holdings:
                            asset_type = holding.get("asset_type", "").lower()
                            breakdown["total"] += 1
                            
                            if "equity" in asset_type or "stock" in asset_type:
                                breakdown["stocks"] += 1
                            elif "mutual" in asset_type or "fund" in asset_type:
                                breakdown["mutual_funds"] += 1
                            elif "gold" in asset_type:
                                breakdown["gold"] += 1
                            else:
                                breakdown["other"] += 1
                    
                    holdings_breakdown = breakdown
            except Exception as e:
                logger.warning("holdings_breakdown_failed", portfolio_id=portfolio_id, error=str(e))

        return {
            "status": processing_status,
            "file_status": file_status,
            "holdings_breakdown": holdings_breakdown,
            "error": error_message,
            "error_code": error_code,
            "portfolio_id": portfolio_id,
            "file_id": portfolio_file_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("portfolio_status_error", portfolio_id=portfolio_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get portfolio status",
        )


# ========== NEW SNAPSHOT ENDPOINTS ==========


@router.get("/snapshots")
async def list_snapshots(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_user: dict = Depends(get_current_user),
):
    """
    List all portfolio snapshots for the authenticated user.

    Query params:
        - start_date: Filter snapshots from this date (YYYY-MM-DD)
        - end_date: Filter snapshots until this date (YYYY-MM-DD)
        - page: Page number (default 1)
        - page_size: Items per page (default 20, max 100)

    Returns:
        - snapshots: List of snapshot summaries
        - pagination: Page info
    """
    try:
        # Validate pagination
        page_size = min(page_size, 100)
        page_size = max(page_size, 1)
        offset = (page - 1) * page_size

        # Build query
        query = (
            supabase_client.client.table("portfolio_snapshots")
            .select(
                "id, statement_date, upload_time, total_value, xirr, "
                "risk_level, holding_count, title, is_public, extraction_method"
            )
            .eq("user_id", current_user["id"])
            .order("statement_date", desc=True)
            .range(offset, offset + page_size - 1)
        )

        # Apply date filters
        if start_date:
            query = query.gte("statement_date", start_date)
        if end_date:
            query = query.lte("statement_date", end_date)

        response = query.execute()

        # Get total count
        count_query = (
            supabase_client.client.table("portfolio_snapshots")
            .select("id", count="exact")
            .eq("user_id", current_user["id"])
        )
        if start_date:
            count_query = count_query.gte("statement_date", start_date)
        if end_date:
            count_query = count_query.lte("statement_date", end_date)

        count_response = count_query.execute()
        total_count = count_response.count if count_response.count else 0

        logger.info(
            "snapshots_listed", user_id=current_user["id"], count=len(response.data)
        )

        return {
            "snapshots": response.data,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_count": total_count,
                "total_pages": (
                    (total_count + page_size - 1) // page_size if total_count > 0 else 0
                ),
            },
        }

    except Exception as e:
        logger.error("list_snapshots_error", user_id=current_user["id"], error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch snapshots",
        )


@router.get("/snapshots/{snapshot_id}")
async def get_snapshot(
    snapshot_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Get a single snapshot with full holdings data.

    Returns:
        Complete snapshot including holdings JSON and PDF download URL
    """
    try:
        response = (
            supabase_client.client.table("portfolio_snapshots")
            .select("*")
            .eq("id", snapshot_id)
            .eq("user_id", current_user["id"])
            .execute()
        )

        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found"
            )

        snapshot = response.data[0]

        # Generate signed URL for PDF download (valid for 1 hour)
        if snapshot.get("pdf_url"):
            try:
                pdf_path = snapshot["pdf_url"].split("portfolio-documents/")[-1]
                signed_url_response = supabase_client.client.storage.from_(
                    "portfolio-documents"
                ).create_signed_url(
                    pdf_path, 3600  # 1 hour
                )
                if signed_url_response:
                    snapshot["pdf_download_url"] = signed_url_response.get("signedURL")
            except Exception as e:
                logger.warning(
                    "pdf_signed_url_error", snapshot_id=snapshot_id, error=str(e)
                )

        logger.info(
            "snapshot_fetched", snapshot_id=snapshot_id, user_id=current_user["id"]
        )
        return snapshot

    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_snapshot_error", snapshot_id=snapshot_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch snapshot",
        )


@router.get("/growth")
async def get_growth_timeline(
    months: int = 12,
    current_user: dict = Depends(get_current_user),
):
    """
    Get portfolio growth timeline data.

    Query params:
        - months: Number of months to look back (default 12, max 24)

    Returns:
        - timeline: Array of data points with date, value, xirr, growth
    """
    try:
        # Validate months
        months = min(months, 24)
        months = max(months, 1)

        start_date = (datetime.now() - timedelta(days=months * 30)).date()

        response = (
            supabase_client.client.table("portfolio_snapshots")
            .select("statement_date, total_value, xirr, holding_count")
            .eq("user_id", current_user["id"])
            .gte("statement_date", start_date.isoformat())
            .order("statement_date", desc=False)
            .execute()
        )

        snapshots = response.data

        # Calculate growth percentages
        timeline = []
        for i, snapshot in enumerate(snapshots):
            growth_percent = None
            if i > 0 and snapshots[i - 1].get("total_value"):
                prev_value = float(snapshots[i - 1]["total_value"])
                curr_value = (
                    float(snapshot["total_value"]) if snapshot.get("total_value") else 0
                )
                if prev_value > 0:
                    growth_percent = ((curr_value - prev_value) / prev_value) * 100

            timeline.append(
                {
                    "date": snapshot["statement_date"],
                    "value": (
                        float(snapshot["total_value"])
                        if snapshot.get("total_value")
                        else 0
                    ),
                    "xirr": float(snapshot["xirr"]) if snapshot.get("xirr") else None,
                    "holding_count": snapshot.get("holding_count", 0),
                    "growth_percent": (
                        round(growth_percent, 2) if growth_percent is not None else None
                    ),
                }
            )

        logger.info(
            "growth_timeline_fetched",
            user_id=current_user["id"],
            data_points=len(timeline),
        )
        return {"timeline": timeline}

    except Exception as e:
        logger.error("get_growth_error", user_id=current_user["id"], error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch growth data",
        )


@router.post(
    "/{portfolio_id}/report", response_model=Report, status_code=status.HTTP_201_CREATED
)
async def report_portfolio(
    portfolio_id: str,
    report_data: ReportCreate,
    current_user: dict = Depends(get_current_user),
):
    """
    Report a portfolio for moderation review.

    Reasons: spam, abusive, misleading, other
    """
    try:
        # Verify portfolio exists
        try:
            portfolio = await supabase_client.get_portfolio(portfolio_id)
        except PortfolioNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Portfolio not found",
            )

        # Check for auto-flagging
        is_auto_flagged, auto_flag_reason = (
            moderation_service.check_auto_flag_portfolio(
                xirr=portfolio.get("xirr"),
                holding_count=portfolio.get("holding_count", 0),
            )
        )

        # Create report
        report_record = {
            "reporter_id": current_user["id"],
            "target_type": "portfolio",
            "target_id": portfolio_id,
            "reason": report_data.reason.value,
            "note": report_data.note,
            "is_auto_flagged": is_auto_flagged,
            "status": "pending",
        }

        response = (
            supabase_client.client.table("reports").insert(report_record).execute()
        )

        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create report",
            )

        report = response.data[0]

        logger.info(
            "portfolio_reported",
            portfolio_id=portfolio_id,
            reporter_id=current_user["id"],
            reason=report_data.reason.value,
            is_auto_flagged=is_auto_flagged,
        )

        return Report(**report)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("report_portfolio_error", error=str(e), portfolio_id=portfolio_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit report",
        )
