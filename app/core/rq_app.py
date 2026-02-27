import redis
import structlog
from rq import Queue

from app.core.config import settings

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Redis connection
# ---------------------------------------------------------------------------

redis_conn = redis.from_url(settings.redis_url, decode_responses=False)

# ---------------------------------------------------------------------------
# Queues
# ---------------------------------------------------------------------------

pdf_parsing_queue = Queue("pdf_parsing", connection=redis_conn)
portfolio_processing_queue = Queue("portfolio_processing", connection=redis_conn)

_QUEUES = {
    "pdf_parsing": pdf_parsing_queue,
    "portfolio_processing": portfolio_processing_queue,
}


def get_queue(name: str) -> Queue:
    """Return a named RQ queue. Raises KeyError for unknown names."""
    try:
        return _QUEUES[name]
    except KeyError:
        raise KeyError(f"Unknown queue '{name}'. Valid queues: {list(_QUEUES)}")
