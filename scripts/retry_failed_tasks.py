#!/usr/bin/env python3
"""
Retry failed portfolio parsing tasks

Usage:
    python scripts/retry_failed_tasks.py --days 1      # Retry tasks from last 24 hours
    python scripts/retry_failed_tasks.py --all         # Retry all failed tasks
    python scripts/retry_failed_tasks.py --dry-run     # Show what would be retried
"""

import argparse
import asyncio
from datetime import datetime, timedelta

import structlog
from app.infrastructure.supabase_client import supabase_client
from app.services.tasks import parse_pdf_task

logger = structlog.get_logger()


async def get_failed_snapshots(days: int = None):
    """Get snapshots that don't have extraction_method set (failed parsing)"""
    query = supabase_client.client.table("portfolio_snapshots").select("*")

    # Filter for failed parsing (no extraction_method or error state)
    query = query.is_("extraction_method", "null")

    if days:
        cutoff = datetime.now() - timedelta(days=days)
        query = query.gte("upload_time", cutoff.isoformat())

    response = query.execute()
    return response.data


async def retry_snapshot(snapshot: dict, dry_run: bool = False):
    """Retry parsing a single snapshot"""
    snapshot_id = snapshot["id"]
    pdf_url = snapshot["pdf_url"]
    pdf_hash = snapshot["pdf_hash"]
    user_id = snapshot["user_id"]

    logger.info(
        "retrying_snapshot",
        snapshot_id=snapshot_id,
        user_id=user_id,
        upload_time=snapshot["upload_time"],
        dry_run=dry_run,
    )

    if not dry_run:
        task = parse_pdf_task.apply_async(
            args=[pdf_url, pdf_hash, user_id], countdown=2  # Stagger tasks slightly
        )
        logger.info("task_queued", task_id=task.id, snapshot_id=snapshot_id)
        return task.id

    return None


async def main():
    parser = argparse.ArgumentParser(description="Retry failed portfolio parsing tasks")
    parser.add_argument("--days", type=int, help="Only retry tasks from last N days")
    parser.add_argument("--all", action="store_true", help="Retry all failed tasks")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be retried without actually doing it",
    )
    parser.add_argument(
        "--limit", type=int, default=100, help="Max number of tasks to retry"
    )

    args = parser.parse_args()

    if not args.all and not args.days:
        args.days = 1  # Default to last 24 hours

    logger.info(
        "starting_retry_script",
        days=args.days if args.days else "all",
        dry_run=args.dry_run,
        limit=args.limit,
    )

    # Get failed snapshots
    snapshots = await get_failed_snapshots(days=args.days)

    if not snapshots:
        logger.info("no_failed_snapshots_found")
        return

    logger.info("found_failed_snapshots", count=len(snapshots))

    # Limit the number
    snapshots = snapshots[: args.limit]

    if args.dry_run:
        logger.info("dry_run_mode", would_retry=len(snapshots))
        for snapshot in snapshots:
            print(f"Would retry: {snapshot['id']} (uploaded {snapshot['upload_time']})")
        return

    # Retry each snapshot
    task_ids = []
    for snapshot in snapshots:
        task_id = await retry_snapshot(snapshot, dry_run=args.dry_run)
        if task_id:
            task_ids.append(task_id)
        await asyncio.sleep(0.5)  # Rate limit

    logger.info("retry_complete", total_retried=len(task_ids), task_ids=task_ids)
    print(f"\n✅ Queued {len(task_ids)} tasks for retry")
    print(f"Monitor progress at: http://localhost:5555")


if __name__ == "__main__":
    asyncio.run(main())
