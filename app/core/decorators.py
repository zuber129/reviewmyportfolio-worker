"""
API Route Decorators for Cross-Cutting Concerns

Provides decorators for enforcing access control policies on API endpoints.
Inspired by Amazon's annotation-based approach for cleaner separation of concerns.
"""

from functools import wraps
from typing import Callable

import structlog
from app.core.config import settings
from fastapi import HTTPException, Request, status

logger = structlog.get_logger()


def require_proxy_caller(func: Callable) -> Callable:
    """
    Decorator to ensure endpoint is only called via Next.js proxy.
    
    Validates X-Proxy-Secret header against PROXY_API_SECRET env var.
    Use for sensitive endpoints that should never be called directly from browsers.
    
    Usage:
        @router.get("/admin/stats")
        @require_proxy_caller
        async def get_stats(current_user: dict = Depends(get_current_user)):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Extract request from kwargs (FastAPI injects it)
        request: Request = kwargs.get('request')
        if not request:
            # Try to find it in args (fallback)
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
        
        if not request:
            logger.error("require_proxy_caller_no_request", func=func.__name__)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal error: Request object not found"
            )
        
        secret = request.headers.get("X-Proxy-Secret")
        if not secret or secret != settings.proxy_api_secret:
            logger.warning(
                "proxy_only_endpoint_direct_access",
                path=request.url.path,
                func=func.__name__
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This endpoint must be accessed via the application proxy"
            )
        
        return await func(*args, **kwargs)
    
    return wrapper


def require_internal_caller(func: Callable) -> Callable:
    """
    Decorator to ensure endpoint is only called by internal services (Celery workers).
    
    Validates X-Internal-Secret header against INTERNAL_API_SECRET env var.
    Use for endpoints that should only be called by background workers.
    
    Usage:
        @router.post("/portfolios/process")
        @require_internal_caller
        async def process_portfolio(data: ProcessRequest):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Extract request from kwargs
        request: Request = kwargs.get('request')
        if not request:
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
        
        if not request:
            logger.error("require_internal_caller_no_request", func=func.__name__)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal error: Request object not found"
            )
        
        secret = request.headers.get("X-Internal-Secret")
        if not secret or secret != settings.internal_api_secret:
            logger.warning(
                "internal_endpoint_unauthorized_access",
                path=request.url.path,
                func=func.__name__
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Internal endpoint - access denied"
            )
        
        return await func(*args, **kwargs)
    
    return wrapper
