"""
RQ Scheduler configuration — periodic job registrations.

Called once at worker startup (rq_worker.sh) to register cron jobs.
Uses rq-scheduler's Scheduler which stores jobs in Redis and fires them
via the same RQ worker process.

Usage:
    python -m app.core.rq_scheduler_config
"""
import structlog
from rq_scheduler import Scheduler

from app.core.rq_app import portfolio_processing_queue, redis_conn

logger = structlog.get_logger()


def register_periodic_jobs() -> None:
    """Register all cron-style periodic jobs. Safe to call repeatedly — cancels existing before re-registering."""
    scheduler = Scheduler(queue=portfolio_processing_queue, connection=redis_conn)

    # Cancel any previously registered periodic jobs to avoid duplicates on restart
    for job in scheduler.get_jobs():
        scheduler.cancel(job)
    logger.info("rq_scheduler_cleared_existing_jobs")

    # Daily 09:00 UTC — portfolio access reminder emails
    scheduler.cron(
        "0 9 * * *",
        func="app.services.jobs.tasks.send_access_reminders_task",
        id="send_access_reminders_task",
        use_local_timezone=False,
    )

    # Daily 01:00 UTC — mark stale portfolios
    scheduler.cron(
        "0 1 * * *",
        func="app.services.jobs.tasks.check_portfolio_staleness_task",
        id="check_portfolio_staleness_task",
        use_local_timezone=False,
    )

    # Hourly — clean up expired auth sessions
    scheduler.cron(
        "0 * * * *",
        func="app.services.jobs.tasks.cleanup_expired_sessions_task",
        id="cleanup_expired_sessions_task",
        use_local_timezone=False,
    )

    # Daily 02:00 UTC — retry failed transaction reconciliations
    scheduler.cron(
        "0 2 * * *",
        func="app.services.jobs.tasks.retry_failed_reconciliations_task",
        id="retry_failed_reconciliations_task",
        use_local_timezone=False,
    )

    logger.info("rq_scheduler_registered_periodic_jobs", count=4)


if __name__ == "__main__":
    register_periodic_jobs()
