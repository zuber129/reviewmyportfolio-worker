"""
Cron job for daily streak recalculation.
Run this once per day to ensure all user streaks are up to date.
"""

import asyncio
from datetime import datetime

import structlog
from app.workers.streak_calculator import StreakCalculator

logger = structlog.get_logger()


async def daily_streak_recalculation():
    """
    Daily cron job to recalculate all user streaks.
    
    This ensures that:
    1. Streaks are broken for users who haven't been active
    2. All streak calculations are consistent
    3. Any missed calculations are caught up
    
    Recommended schedule: Run at 00:05 UTC daily
    """
    try:
        start_time = datetime.utcnow()
        logger.info("daily_streak_recalculation_started", timestamp=start_time.isoformat())
        
        users_processed = await StreakCalculator.recalculate_all_streaks()
        
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        logger.info(
            "daily_streak_recalculation_completed",
            users_processed=users_processed,
            duration_seconds=duration,
            timestamp=end_time.isoformat(),
        )
        
        return {
            "success": True,
            "users_processed": users_processed,
            "duration_seconds": duration,
        }
        
    except Exception as e:
        logger.error(
            "daily_streak_recalculation_failed",
            error=str(e),
            timestamp=datetime.utcnow().isoformat(),
        )
        raise


if __name__ == "__main__":
    # Allow running this script directly for testing
    asyncio.run(daily_streak_recalculation())
