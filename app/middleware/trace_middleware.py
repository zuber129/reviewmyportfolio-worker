"""
Trace ID Middleware for Request Tracking

Generates or extracts trace IDs from incoming requests and binds them to
structlog context for automatic inclusion in all logs.
"""

import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class TraceMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add trace ID to all requests for end-to-end tracking.
    
    - Extracts X-Trace-Id from request headers if present
    - Generates new UUID if not present
    - Binds trace_id to structlog context (appears in all logs)
    - Adds X-Trace-Id to response headers
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Extract or generate trace ID
        trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
        
        # Bind to structlog context - will appear in all logs automatically
        structlog.contextvars.bind_contextvars(trace_id=trace_id)
        
        try:
            # Process request
            response = await call_next(request)
            
            # Add trace ID to response headers for client-side tracking
            response.headers["X-Trace-Id"] = trace_id
            
            return response
        finally:
            # Clean up context after request
            structlog.contextvars.unbind_contextvars("trace_id")
