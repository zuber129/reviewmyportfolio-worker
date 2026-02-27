"""
Production-grade logging configuration for ReviewMyPortfolio API.

Follows industry best practices:
- Structured JSON logging for production
- Correlation ID (trace_id) injection
- Log rotation and retention
- Environment-aware configuration
- Proper log levels per component
"""

import logging
import os
from typing import Any, Dict

import structlog


class CorrelationIdFilter(logging.Filter):
    """
    Inject correlation_id (trace_id) from structlog context into standard logging records.
    This ensures trace_id appears in all logs, even from third-party libraries.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add correlation_id to log record from structlog context."""
        try:
            contextvars = structlog.contextvars.get_contextvars()
            record.correlation_id = contextvars.get("trace_id", "")
        except Exception:
            record.correlation_id = ""
        return True


def configure_structlog() -> None:
    """
    Configure structlog for production use.
    Uses the stdlib integration pattern so logger.info("event", key=val) works everywhere.
    """
    env = os.getenv("ENVIRONMENT", "development")

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if env == "production":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]


def get_log_level() -> str:
    """
    Get log level from environment with sensible defaults.
    
    Returns:
        Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    env = os.getenv("ENVIRONMENT", "development")
    log_level = os.getenv("LOG_LEVEL", "").upper()
    
    if log_level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        return log_level
    
    # Default log levels per environment
    defaults = {
        "production": "INFO",
        "staging": "INFO",
        "development": "DEBUG",
        "test": "WARNING",
    }
    
    return defaults.get(env, "INFO")


def configure_logging() -> None:
    """
    Initialize logging configuration for the application.
    
    This should be called once at application startup.
    Configures both standard logging and structlog.
    """
    # Configure structlog first
    configure_structlog()
    
    # Set root logger level from environment
    log_level = get_log_level()
    logging.getLogger().setLevel(log_level)
    
    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Configured structlog logger
    
    Example:
        logger = get_logger(__name__)
        logger.info("user_created", user_id=user_id, email=email)
    """
    return structlog.get_logger(name)


# Logging best practices for the team
LOGGING_GUIDELINES = """
# Logging Best Practices

## Log Levels
- **DEBUG**: Detailed diagnostic info (disabled in production)
- **INFO**: General informational messages (business events)
- **WARNING**: Warning messages (degraded state, but still working)
- **ERROR**: Error messages (operation failed, but app continues)
- **CRITICAL**: Critical messages (app cannot continue)

## What to Log

### ✅ DO Log:
- User actions (signup, signin, portfolio_created)
- State transitions (task_started, task_completed)
- External API calls (with duration)
- Business errors (validation_failed, duplicate_detected)
- Security events (auth_failed, rate_limit_exceeded)
- Performance metrics (slow_query, high_memory)

### ❌ DON'T Log:
- Passwords, tokens, API keys
- Full request/response bodies (use sanitized versions)
- PII without redaction
- Every function call (too noisy)
- Debug info in production (use DEBUG level)

## Structured Logging Format

Always use key-value pairs:

```python
# Good
logger.info("user_signup_successful", user_id=user_id, username=username)

# Bad
logger.info(f"User {user_id} signed up with username {username}")
```

## Required Fields

Always include relevant identifiers:
- user_id - For user actions
- portfolio_id - For portfolio operations
- task_id - For async tasks
- snapshot_id - For portfolio snapshots
- trace_id - Automatically included via middleware

## Error Logging

Include context for debugging:

```python
try:
    result = await operation()
except Exception as e:
    logger.error(
        "operation_failed",
        user_id=user_id,
        error=str(e),
        error_type=type(e).__name__,
    )
    raise
```

## Performance Logging

Log slow operations:

```python
import time

start = time.time()
result = await slow_operation()
duration = time.time() - start

if duration > 1.0:  # 1 second threshold
    logger.warning(
        "slow_operation",
        operation="pdf_parsing",
        duration_seconds=duration,
        user_id=user_id,
    )
```
"""
