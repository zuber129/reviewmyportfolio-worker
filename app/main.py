import logging
import os
from contextlib import asynccontextmanager
from typing import Callable

try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None  # type: ignore[assignment]
import structlog
from app.core.logging_config import configure_logging

# Initialize production logging configuration
configure_logging()

_startup_logger = logging.getLogger(__name__)

# Initialize Sentry (no-op if SENTRY_DSN is empty)
from app.core.config import settings as _early_settings
if sentry_sdk and _early_settings.sentry_dsn:
    sentry_sdk.init(
        dsn=_early_settings.sentry_dsn,
        environment=_early_settings.environment,
        traces_sample_rate=0.1,
        profiles_sample_rate=0.05,
    )

# Import routers
from app.api.v1 import (
    admin,
    auth,
    worker_callbacks,
    reviews,
    comparison,
    contact,
    files,
    flows,
    instrument_opinions,
    instruments,
    leaderboard,
    portfolio_reviews,
    portfolios,
    reactions,
    users,
)
from app.api.v1.endpoints import stats
from app.core.config import settings
from app.core.exceptions import (
    AccessBlockedError,
    AuthenticationError,
    ProfileNotFoundError,
    ShareToBrowseRequiredError,
    SupabaseError,
    UserNotFoundError,
)
from app.infrastructure.redis_client import redis_client
from app.infrastructure.supabase_client import supabase_client
from app.middleware.trace_middleware import TraceMiddleware
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = structlog.get_logger()

# Create rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    # Startup
    _startup_logger.info("starting_application version=%s", settings.api_version)

    # Connect to Redis
    await redis_client.connect()

    # Initialize other connections as needed

    yield

    # Shutdown
    _startup_logger.info("shutting_down_application")
    await redis_client.disconnect()


_is_production = settings.environment == "production"

# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    lifespan=lifespan,
    docs_url=None if _is_production else f"{settings.api_v1_prefix}/docs",
    redoc_url=None if _is_production else f"{settings.api_v1_prefix}/redoc",
    openapi_url=None if _is_production else f"{settings.api_v1_prefix}/openapi.json",
)

# Add CORS middleware with strict configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,  # Must be explicit list, no wildcards
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],  # Explicit methods only
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token", "X-Trace-Id"],  # Add X-Trace-Id
    expose_headers=["Content-Type", "X-Trace-Id"],  # Expose X-Trace-Id to client
    max_age=600,  # Cache preflight for 10 minutes
)

# Add security headers middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next: Callable) -> StarletteResponse:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Download-Options"] = "noopen"
        response.headers["X-DNS-Prefetch-Control"] = "off"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        if _is_production:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


app.add_middleware(SecurityHeadersMiddleware)

# Add trace ID middleware for request tracking
app.add_middleware(TraceMiddleware)

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Include routers
app.include_router(auth.router, prefix=settings.api_v1_prefix)
app.include_router(worker_callbacks.router, prefix=settings.api_v1_prefix)
app.include_router(users.router, prefix=settings.api_v1_prefix)
app.include_router(portfolios.router, prefix=settings.api_v1_prefix)
app.include_router(files.router, prefix=settings.api_v1_prefix)
app.include_router(flows.router, prefix=settings.api_v1_prefix)
app.include_router(
    portfolio_reviews.portfolios_router, prefix=f"{settings.api_v1_prefix}/portfolios"
)
app.include_router(reactions.router, prefix=settings.api_v1_prefix)
app.include_router(comparison.router, prefix=settings.api_v1_prefix)
app.include_router(leaderboard.router, prefix=settings.api_v1_prefix)
app.include_router(admin.router, prefix=settings.api_v1_prefix)
app.include_router(stats.router, prefix=settings.api_v1_prefix)
app.include_router(contact.router, prefix=settings.api_v1_prefix, tags=["Contact"])
# New social engagement routers
app.include_router(instruments.router, prefix=f"{settings.api_v1_prefix}/instruments", tags=["Instruments"])
app.include_router(instrument_opinions.router, prefix=f"{settings.api_v1_prefix}/opinions", tags=["Instrument Opinions"])
app.include_router(reviews.router, prefix=settings.api_v1_prefix, tags=["Reviews"])


# Exception handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions"""
    logger.error(
        "http_exception",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP_ERROR",
            "message": exc.detail,
            "status_code": exc.status_code,
        },
    )


def _make_serializable(obj):
    """Recursively convert objects to JSON-serializable format"""
    if isinstance(obj, dict):
        return {key: _make_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [_make_serializable(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(_make_serializable(item) for item in obj)
    elif isinstance(obj, Exception):
        return str(obj)
    elif hasattr(obj, "__dict__"):
        return str(obj)
    else:
        return obj


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""
    errors = exc.errors()
    # Convert error objects to JSON-serializable format recursively
    serializable_errors = _make_serializable(errors)

    logger.error("validation_error", errors=serializable_errors, path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "message": "Request validation failed",
            "details": serializable_errors,
        },
    )


# Domain exception handlers - convert domain exceptions to HTTP responses
@app.exception_handler(ProfileNotFoundError)
async def profile_not_found_handler(request: Request, exc: ProfileNotFoundError):
    """Handle profile not found - return 401 to force re-authentication"""
    logger.warning("profile_not_found", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": "PROFILE_NOT_FOUND",
            "message": "Profile not found. Please sign up again.",
        },
    )


@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    """Handle authentication errors"""
    logger.warning("authentication_error", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": "AUTHENTICATION_ERROR",
            "message": str(exc),
        },
    )


@app.exception_handler(UserNotFoundError)
async def user_not_found_handler(request: Request, exc: UserNotFoundError):
    """Handle user not found errors"""
    logger.warning("user_not_found", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": "USER_NOT_FOUND",
            "message": str(exc),
        },
    )


@app.exception_handler(SupabaseError)
async def supabase_error_handler(request: Request, exc: SupabaseError):
    """Handle Supabase/database errors"""
    logger.error("supabase_error", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "DATABASE_ERROR",
            "message": "A database error occurred. Please try again.",
        },
    )


@app.exception_handler(ShareToBrowseRequiredError)
async def share_to_browse_required_handler(
    request: Request, exc: ShareToBrowseRequiredError
):
    """Handle share to browse access control violations"""
    logger.warning(
        "share_to_browse_required", path=request.url.path, error_code=exc.error_code
    )
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "details": exc.details,
        },
    )


@app.exception_handler(AccessBlockedError)
async def access_blocked_handler(request: Request, exc: AccessBlockedError):
    """Handle account blocked access control violations"""
    logger.warning(
        "access_blocked",
        path=request.url.path,
        error_code=exc.error_code,
        details=exc.details,
    )
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "details": exc.details,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(
        "unhandled_exception", error=str(exc), path=request.url.path, exc_info=exc
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred",
        },
    )


# Health check endpoint
@app.get("/health")
async def health() -> JSONResponse:
    """Health check endpoint"""
    logger.info("healthcheck", status="ok")
    return JSONResponse({"status": "ok", "version": settings.api_version})


@app.get(f"{settings.api_v1_prefix}/health")
@limiter.limit(f"{settings.rate_limit_requests}/minute")
async def health_v1(request: Request) -> JSONResponse:
    """API v1 health check with rate limiting"""
    redis_status = "connected" if redis_client.redis else "disconnected"

    logger.info("healthcheck", status="ok", redis=redis_status)
    return JSONResponse(
        {"status": "ok", "version": settings.api_version, "redis": redis_status}
    )
