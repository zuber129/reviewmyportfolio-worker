"""
Leaderboard Service
Pure functions for computing performance and contribution leaderboards
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()


class LeaderboardService:
    """Service for calculating leaderboard rankings"""

    @staticmethod
    async def get_performance_leaderboard(
        supabase_client,
        limit: int = 100,
        time_range: str = "all_time",
    ) -> List[Dict[str, Any]]:
        """
        Get performance leaderboard ranked by best portfolio XIRR.

        Score = MAX(xirr) from all public portfolios
        Tie-breaker: portfolio_count (more portfolios = higher rank)

        Args:
            supabase_client: Supabase client instance
            limit: Number of entries to return
            time_range: "all_time", "monthly", or "weekly"

        Returns:
            List of leaderboard entries with rank, user_id, username, performance metrics
        """
        try:
            # Build time filter
            time_filter = None
            if time_range == "monthly":
                time_filter = (datetime.utcnow() - timedelta(days=30)).isoformat()
            elif time_range == "weekly":
                time_filter = (datetime.utcnow() - timedelta(days=7)).isoformat()

            # Query portfolios and aggregate by user
            query = (
                supabase_client.client.table("portfolios")
                .select(
                    "user_id, xirr, total_value, created_at, profiles!portfolios_user_id_fkey(username, avatar_url, reputation_tier)"
                )
                .is_("deleted_at", "null")
                .not_.is_("xirr", "null")
            )

            if time_filter:
                query = query.gte("created_at", time_filter)

            response = query.execute()

            if not response.data:
                return []

            # Aggregate by user
            user_portfolios: Dict[str, Dict[str, Any]] = {}
            for portfolio in response.data:
                user_id = portfolio["user_id"]
                xirr = portfolio.get("xirr", 0)
                total_value = portfolio.get("total_value", 0)
                profile = portfolio.get("profiles", {})

                if user_id not in user_portfolios:
                    user_portfolios[user_id] = {
                        "user_id": user_id,
                        "username": profile.get("username", "Unknown"),
                        "avatar_url": profile.get("avatar_url"),
                        "tier": profile.get("reputation_tier", "beginner"),
                        "best_xirr": xirr,
                        "portfolio_count": 0,
                        "total_value": 0,
                    }

                # Update aggregates
                user_portfolios[user_id]["portfolio_count"] += 1
                user_portfolios[user_id]["total_value"] += total_value
                user_portfolios[user_id]["best_xirr"] = max(
                    user_portfolios[user_id]["best_xirr"], xirr
                )

            # Convert to list and sort
            leaderboard = list(user_portfolios.values())
            leaderboard.sort(
                key=lambda x: (x["best_xirr"], x["portfolio_count"]), reverse=True
            )

            # Apply limit and add ranks
            leaderboard = leaderboard[:limit]
            for idx, entry in enumerate(leaderboard):
                entry["rank"] = idx + 1
                entry["performance_score"] = entry["best_xirr"]  # Alias for clarity

            logger.info(
                "performance_leaderboard_computed",
                count=len(leaderboard),
                time_range=time_range,
            )

            return leaderboard

        except Exception as e:
            logger.error("get_performance_leaderboard_error", error=str(e))
            return []

    @staticmethod
    async def get_contribution_leaderboard(
        supabase_client,
        limit: int = 100,
        time_range: str = "all_time",
    ) -> List[Dict[str, Any]]:
        """
        Get contribution leaderboard ranked by weighted contribution score.

        Formula: (opinions * 5) + (helpful_votes_received * 3) + (reactions_given * 1)

        Weights:
        - Opinions written: 5 points
        - Helpful votes received: 3 points
        - Reactions given: 1 point

        Tie-breaker: opinion_count

        Args:
            supabase_client: Supabase client instance
            limit: Number of entries to return
            time_range: "all_time", "monthly", "weekly", or "daily"

        Returns:
            List of contribution entries with rank, user_id, username, metrics
        """
        try:
            # Build time filter
            time_filter = None
            if time_range == "daily":
                time_filter = (datetime.utcnow() - timedelta(days=1)).isoformat()
            elif time_range == "weekly":
                time_filter = (datetime.utcnow() - timedelta(days=7)).isoformat()
            elif time_range == "monthly":
                time_filter = (datetime.utcnow() - timedelta(days=30)).isoformat()

            # Get opinions (helpful_count moved from comments to opinions table)
            opinions_query = (
                supabase_client.client.table("opinions")
                .select("user_id, helpful_count, created_at")
                .is_("deleted_at", "null")
            )

            if time_filter:
                opinions_query = opinions_query.gte("created_at", time_filter)

            comments_response = opinions_query.execute()

            if not comments_response.data:
                return []

            # Aggregate by user
            user_contributions: Dict[str, Dict[str, int]] = {}
            for comment in comments_response.data:
                user_id = comment["user_id"]
                if user_id not in user_contributions:
                    user_contributions[user_id] = {
                        "opinion_count": 0,
                        "helpful_votes_received": 0,
                    }
                user_contributions[user_id]["opinion_count"] += 1
                user_contributions[user_id]["helpful_votes_received"] += comment.get(
                    "helpful_count", 0
                )

            # Get reactions given (optional - requires opinion_votes or similar table)
            # For now, we'll use a simplified formula without reactions_given
            # TODO: Add reactions_given when table structure is confirmed

            user_ids = list(user_contributions.keys())
            if not user_ids:
                return []

            # Get profiles
            profiles_response = (
                supabase_client.client.table("profiles")
                .select("id, username, avatar_url, reputation_tier")
                .in_("id", user_ids)
                .execute()
            )

            # Build leaderboard entries
            leaderboard = []
            for profile in profiles_response.data:
                user_id = profile["id"]
                contrib = user_contributions.get(user_id, {})
                opinion_count = contrib.get("opinion_count", 0)
                helpful_votes = contrib.get("helpful_votes_received", 0)

                # Calculate weighted score
                # Formula: (opinions * 5) + (helpful_votes * 3)
                contribution_score = (opinion_count * 5) + (helpful_votes * 3)

                leaderboard.append(
                    {
                        "user_id": user_id,
                        "username": profile["username"],
                        "avatar_url": profile.get("avatar_url"),
                        "tier": profile.get("reputation_tier", "beginner"),
                        "opinion_count": opinion_count,
                        "helpful_votes_received": helpful_votes,
                        "contribution_score": contribution_score,
                    }
                )

            # Sort by score desc, then opinion_count desc
            leaderboard.sort(
                key=lambda x: (x["contribution_score"], x["opinion_count"]),
                reverse=True,
            )

            # Apply limit and add ranks
            leaderboard = leaderboard[:limit]
            for idx, entry in enumerate(leaderboard):
                entry["rank"] = idx + 1

            logger.info(
                "contribution_leaderboard_computed",
                count=len(leaderboard),
                time_range=time_range,
            )

            return leaderboard

        except Exception as e:
            logger.error("get_contribution_leaderboard_error", error=str(e))
            return []

    @staticmethod
    async def get_user_performance_rank(supabase_client, user_id: str) -> Optional[int]:
        """
        Calculate user's rank in performance leaderboard.

        Returns:
            Rank (1-indexed) or None if user has no public portfolios
        """
        try:
            # Get user's best XIRR
            user_portfolios = (
                supabase_client.client.table("portfolios")
                .select("xirr")
                .eq("user_id", user_id)
                .is_("deleted_at", "null")
                .not_.is_("xirr", "null")
                .execute()
            )

            if not user_portfolios.data:
                return None

            user_best_xirr = max(p["xirr"] for p in user_portfolios.data)

            # Count users with better XIRR
            better_users = (
                supabase_client.client.table("portfolios")
                .select("user_id, xirr")
                .is_("deleted_at", "null")
                .gt("xirr", user_best_xirr)
                .execute()
            )

            # Get unique user_ids with better performance
            unique_better = set(p["user_id"] for p in better_users.data)
            rank = len(unique_better) + 1

            logger.info("user_performance_rank_calculated", user_id=user_id, rank=rank)
            return rank

        except Exception as e:
            logger.error(
                "get_user_performance_rank_error", user_id=user_id, error=str(e)
            )
            return None

    @staticmethod
    async def get_user_contribution_rank(
        supabase_client, user_id: str
    ) -> Optional[int]:
        """
        Calculate user's rank in contribution leaderboard.

        Returns:
            Rank (1-indexed) or None if user has no contributions
        """
        try:
            # Get user's contribution score (opinions table replaced comments)
            user_comments = (
                supabase_client.client.table("opinions")
                .select("helpful_count")
                .eq("user_id", user_id)
                .is_("deleted_at", "null")
                .execute()
            )

            if not user_comments.data:
                return None

            user_opinion_count = len(user_comments.data)
            user_helpful_votes = sum(
                c.get("helpful_count", 0) for c in user_comments.data
            )
            user_score = (user_opinion_count * 5) + (user_helpful_votes * 3)

            # Get all users' scores
            all_comments = (
                supabase_client.client.table("opinions")
                .select("user_id, helpful_count")
                .is_("deleted_at", "null")
                .execute()
            )

            # Aggregate by user
            user_scores: Dict[str, int] = {}
            for comment in all_comments.data:
                uid = comment["user_id"]
                if uid not in user_scores:
                    user_scores[uid] = 0
                # Score formula: (opinions * 5) + (helpful_votes * 3)
                # Each comment = 5 points + (helpful_count * 3) points
                user_scores[uid] += 5 + (comment.get("helpful_count", 0) * 3)

            # Count users with higher scores
            better_count = sum(
                1 for score in user_scores.values() if score > user_score
            )
            rank = better_count + 1

            logger.info("user_contribution_rank_calculated", user_id=user_id, rank=rank)
            return rank

        except Exception as e:
            logger.error(
                "get_user_contribution_rank_error", user_id=user_id, error=str(e)
            )
            return None

    @staticmethod
    async def get_1y_performance_leaderboard(
        supabase_client,
        limit: int = 100,
        min_history_days: int = 270,
    ) -> List[Dict[str, Any]]:
        """
        Get 1-year performance leaderboard using time-bounded XIRR.

        Uses xirr_1y from profiles table (computed by performance_metrics service).

        Eligibility:
        - Has xirr_1y value (not null)
        - At least one public portfolio
        - Portfolio not flagged as suspicious

        Args:
            supabase_client: Supabase client instance
            limit: Number of entries to return
            min_history_days: Minimum history requirement (default 270 = 9 months)

        Returns:
            List of leaderboard entries ranked by xirr_1y
        """
        try:
            # Get profiles with xirr_1y values
            query = (
                supabase_client.client.table("profiles")
                .select(
                    "id, username, avatar_url, reputation_tier, xirr_1y, consistency_score"
                )
                .not_.is_("xirr_1y", "null")
                .order("xirr_1y", desc=True)
                .limit(limit * 2)  # Get extra for filtering
            )

            profiles_response = query.execute()

            if not profiles_response.data:
                return []

            # Get portfolio data for each user
            leaderboard = []

            for profile in profiles_response.data:
                user_id = profile["id"]

                # Get user's portfolios (check for suspicious flag)
                portfolios_response = (
                    supabase_client.client.table("portfolios")
                    .select("id, total_value, is_suspicious, created_at")
                    .eq("user_id", user_id)
                    .eq("visibility", "public")
                    .is_("deleted_at", "null")
                    .execute()
                )

                portfolios = portfolios_response.data
                if not portfolios:
                    continue

                # Check for suspicious portfolios
                has_suspicious = any(p.get("is_suspicious", False) for p in portfolios)
                if has_suspicious:
                    continue

                # Calculate history months (from oldest portfolio)
                oldest_date = None
                for p in portfolios:
                    created = datetime.fromisoformat(
                        p["created_at"].replace("Z", "+00:00")
                    )
                    if oldest_date is None or created < oldest_date:
                        oldest_date = created

                if oldest_date:
                    history_days = (
                        datetime.utcnow().replace(tzinfo=oldest_date.tzinfo)
                        - oldest_date
                    ).days
                    history_months = history_days // 30

                    # Check minimum history requirement
                    if history_days < min_history_days:
                        continue
                else:
                    history_months = 0

                # Get snapshot count
                snapshots_response = (
                    supabase_client.client.table("portfolio_snapshots")
                    .select("id", count="exact")
                    .eq("user_id", user_id)
                    .execute()
                )
                data_points = snapshots_response.count or 0

                # Calculate total value
                total_value = sum(p.get("total_value", 0) for p in portfolios)

                leaderboard.append(
                    {
                        "user_id": user_id,
                        "username": profile["username"],
                        "avatar_url": profile.get("avatar_url"),
                        "tier": profile.get("reputation_tier", "beginner"),
                        "xirr_1y": profile["xirr_1y"],
                        "consistency_score": profile.get("consistency_score"),
                        "total_value": total_value,
                        "portfolio_count": len(portfolios),
                        "data_points": data_points,
                        "history_months": history_months,
                    }
                )

            # Sort by xirr_1y desc, then consistency_score desc
            leaderboard.sort(
                key=lambda x: (
                    x["xirr_1y"] if x["xirr_1y"] is not None else -999,
                    x["consistency_score"] if x["consistency_score"] is not None else 0,
                ),
                reverse=True,
            )

            # Apply limit and add ranks
            leaderboard = leaderboard[:limit]
            for idx, entry in enumerate(leaderboard):
                entry["rank"] = idx + 1

            logger.info(
                "performance_1y_leaderboard_computed",
                count=len(leaderboard),
                min_history_days=min_history_days,
            )

            return leaderboard

        except Exception as e:
            logger.error("get_1y_performance_leaderboard_error", error=str(e))
            return []

    @staticmethod
    async def get_consistency_leaderboard(
        supabase_client,
        limit: int = 100,
        min_snapshots: int = 6,
    ) -> List[Dict[str, Any]]:
        """
        Get consistency leaderboard ranked by stability of returns.

        Uses consistency_score from profiles table (computed by performance_metrics service).

        Eligibility:
        - Has consistency_score value (not null)
        - At least min_snapshots portfolio snapshots
        - Not flagged as suspicious

        Args:
            supabase_client: Supabase client instance
            limit: Number of entries to return
            min_snapshots: Minimum snapshots required (default 6)

        Returns:
            List of leaderboard entries ranked by consistency_score
        """
        try:
            # Get profiles with consistency scores
            query = (
                supabase_client.client.table("profiles")
                .select(
                    "id, username, avatar_url, reputation_tier, consistency_score, xirr_1y"
                )
                .not_.is_("consistency_score", "null")
                .order("consistency_score", desc=True)
                .limit(limit * 2)  # Get extra for filtering
            )

            profiles_response = query.execute()

            if not profiles_response.data:
                return []

            # Get portfolio and snapshot data for each user
            leaderboard = []

            for profile in profiles_response.data:
                user_id = profile["id"]

                # Get snapshot count
                snapshots_response = (
                    supabase_client.client.table("portfolio_snapshots")
                    .select("id, created_at", count="exact")
                    .eq("user_id", user_id)
                    .execute()
                )

                data_points = snapshots_response.count or 0
                if data_points < min_snapshots:
                    continue

                # Calculate history months
                if snapshots_response.data:
                    dates = [
                        datetime.fromisoformat(s["created_at"].replace("Z", "+00:00"))
                        for s in snapshots_response.data
                    ]
                    oldest = min(dates)
                    history_days = (
                        datetime.utcnow().replace(tzinfo=oldest.tzinfo) - oldest
                    ).days
                    history_months = history_days // 30
                else:
                    history_months = 0

                # Get user's portfolios
                portfolios_response = (
                    supabase_client.client.table("portfolios")
                    .select("id, total_value, is_suspicious")
                    .eq("user_id", user_id)
                    .eq("visibility", "public")
                    .is_("deleted_at", "null")
                    .execute()
                )

                portfolios = portfolios_response.data
                if not portfolios:
                    continue

                # Check for suspicious portfolios
                has_suspicious = any(p.get("is_suspicious", False) for p in portfolios)
                if has_suspicious:
                    continue

                # Calculate total value
                total_value = sum(p.get("total_value", 0) for p in portfolios)

                leaderboard.append(
                    {
                        "user_id": user_id,
                        "username": profile["username"],
                        "avatar_url": profile.get("avatar_url"),
                        "tier": profile.get("reputation_tier", "beginner"),
                        "consistency_score": profile["consistency_score"],
                        "xirr_1y": profile.get("xirr_1y"),
                        "total_value": total_value,
                        "portfolio_count": len(portfolios),
                        "data_points": data_points,
                        "history_months": history_months,
                    }
                )

            # Sort by consistency_score desc, then xirr_1y desc
            leaderboard.sort(
                key=lambda x: (
                    (
                        x["consistency_score"]
                        if x["consistency_score"] is not None
                        else -999
                    ),
                    x["xirr_1y"] if x["xirr_1y"] is not None else 0,
                ),
                reverse=True,
            )

            # Apply limit and add ranks
            leaderboard = leaderboard[:limit]
            for idx, entry in enumerate(leaderboard):
                entry["rank"] = idx + 1

            logger.info(
                "consistency_leaderboard_computed",
                count=len(leaderboard),
                min_snapshots=min_snapshots,
            )

            return leaderboard

        except Exception as e:
            logger.error("get_consistency_leaderboard_error", error=str(e))
            return []
