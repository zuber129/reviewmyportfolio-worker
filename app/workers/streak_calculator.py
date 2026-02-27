"""
Async worker for calculating user streaks.
Runs as a background task triggered by activity events.
"""

import asyncio
from datetime import datetime
from typing import Optional

import structlog
from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger()


class StreakCalculator:
    """Handles async calculation of user activity streaks."""

    @staticmethod
    async def calculate_streak_for_user(user_id: str) -> dict:
        """
        Calculate and update streak for a single user.
        
        This is called asynchronously after user activity is logged.
        The calculation is done in the database via stored procedure.
        
        Args:
            user_id: User ID to calculate streak for
            
        Returns:
            dict with current_streak and longest_streak
        """
        try:
            # Call the database function to calculate streaks
            # This function updates the profiles table and returns the results
            response = supabase_client.client.rpc(
                "calculate_user_streak",
                {"p_user_id": user_id}
            ).execute()
            
            if response.data and len(response.data) > 0:
                result = response.data[0]
                current_streak = result.get("current_streak", 0)
                longest_streak = result.get("longest_streak", 0)
                
                logger.info(
                    "streak_calculated",
                    user_id=user_id,
                    current_streak=current_streak,
                    longest_streak=longest_streak,
                )
                
                return {
                    "current_streak": current_streak,
                    "longest_streak": longest_streak,
                }
            else:
                logger.warning("streak_calculation_no_data", user_id=user_id)
                return {"current_streak": 0, "longest_streak": 0}
                
        except Exception as e:
            logger.error(
                "streak_calculation_error",
                user_id=user_id,
                error=str(e),
            )
            # Don't raise - this is a background task, failures should be logged
            return {"current_streak": 0, "longest_streak": 0}

    @staticmethod
    async def recalculate_all_streaks() -> int:
        """
        Recalculate streaks for all users.
        
        This should be run as a daily cron job to ensure all streaks are up to date.
        
        Returns:
            Number of users processed
        """
        try:
            logger.info("recalculate_all_streaks_started")
            
            # Call the batch recalculation function
            response = supabase_client.client.rpc("recalculate_all_streaks").execute()
            
            users_processed = len(response.data) if response.data else 0
            
            logger.info(
                "recalculate_all_streaks_completed",
                users_processed=users_processed,
            )
            
            return users_processed
            
        except Exception as e:
            logger.error(
                "recalculate_all_streaks_error",
                error=str(e),
            )
            raise

    @staticmethod
    def schedule_streak_calculation(user_id: str) -> None:
        """
        Schedule an async streak calculation for a user.
        
        This is called after activity is logged (e.g., portfolio upload, opinion given).
        The actual calculation happens in the background without blocking the request.
        
        Args:
            user_id: User ID to calculate streak for
        """
        try:
            # Create a background task
            asyncio.create_task(StreakCalculator.calculate_streak_for_user(user_id))
            
            logger.debug("streak_calculation_scheduled", user_id=user_id)
            
        except Exception as e:
            logger.error(
                "streak_scheduling_error",
                user_id=user_id,
                error=str(e),
            )
            # Don't raise - this is best-effort background work


# Convenience function for importing
async def calculate_user_streak(user_id: str) -> dict:
    """Calculate streak for a user (async)."""
    return await StreakCalculator.calculate_streak_for_user(user_id)


def schedule_streak_calculation(user_id: str) -> None:
    """Schedule streak calculation (fire and forget)."""
    StreakCalculator.schedule_streak_calculation(user_id)
