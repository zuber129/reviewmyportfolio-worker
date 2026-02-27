"""
Performance Metrics Service
Computes time-bounded and consistency-based portfolio performance metrics
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import structlog
from app.services.finance.xirr_calculator import calculate_xirr

logger = structlog.get_logger()

# Configuration
MINIMUM_PORTFOLIO_VALUE = 10000.0  # ₹10,000
XIRR_MIN = -50.0
XIRR_MAX = 200.0

MINIMUM_HISTORY = {
    "performance_1y": timedelta(days=270),  # 9 months
    "consistency": timedelta(days=180),  # 6 months
    "all_time": timedelta(days=90),  # 3 months
}


class PerformanceMetricsService:
    """Service for computing advanced performance metrics"""

    @staticmethod
    def compute_1y_xirr(
        supabase_client, user_id: str
    ) -> Tuple[Optional[float], Dict[str, Any]]:
        """
        Compute 1-year XIRR using portfolio snapshots.

        Method:
        1. Get most recent snapshot (within last 30 days)
        2. Get snapshot from ~12 months ago (365 ± 30 days)
        3. Compute XIRR between these two points
        4. Return XIRR and metadata

        Args:
            supabase_client: Supabase client instance
            user_id: User ID

        Returns:
            (xirr_1y, metadata) where:
            - xirr_1y: 1-year XIRR percentage or None
            - metadata: dict with computation details
        """
        try:
            # Get user's snapshots from last 13 months
            cutoff_date = datetime.utcnow() - timedelta(days=395)

            response = (
                supabase_client.client.table("portfolio_snapshots")
                .select("statement_date, total_value, created_at")
                .eq("user_id", user_id)
                .gte("statement_date", cutoff_date.date().isoformat())
                .order("statement_date", desc=True)
                .execute()
            )

            snapshots = response.data
            if not snapshots or len(snapshots) < 2:
                logger.info(
                    "insufficient_snapshots_for_1y",
                    user_id=user_id,
                    count=len(snapshots) if snapshots else 0,
                )
                return None, {
                    "reason": "insufficient_snapshots",
                    "count": len(snapshots) if snapshots else 0,
                }

            # Get most recent snapshot (within last 30 days)
            today = datetime.utcnow().date()
            recent_cutoff = today - timedelta(days=30)

            recent_snapshot = None
            for snap in snapshots:
                snap_date = (
                    datetime.fromisoformat(snap["statement_date"]).date()
                    if isinstance(snap["statement_date"], str)
                    else snap["statement_date"]
                )
                if snap_date >= recent_cutoff:
                    recent_snapshot = snap
                    break

            if not recent_snapshot:
                logger.info(
                    "no_recent_snapshot",
                    user_id=user_id,
                    most_recent=snapshots[0]["statement_date"],
                )
                return None, {"reason": "no_recent_snapshot"}

            # Get snapshot from ~12 months ago (365 ± 30 days)
            target_date = today - timedelta(days=365)
            min_date = target_date - timedelta(days=30)
            max_date = target_date + timedelta(days=30)

            old_snapshot = None
            min_diff = timedelta(days=9999)

            for snap in snapshots:
                snap_date = (
                    datetime.fromisoformat(snap["statement_date"]).date()
                    if isinstance(snap["statement_date"], str)
                    else snap["statement_date"]
                )

                if min_date <= snap_date <= max_date:
                    diff = abs((snap_date - target_date).days)
                    if timedelta(days=diff) < min_diff:
                        min_diff = timedelta(days=diff)
                        old_snapshot = snap

            if not old_snapshot:
                logger.info(
                    "no_old_snapshot_for_1y",
                    user_id=user_id,
                    target_date=target_date.isoformat(),
                )
                return None, {"reason": "no_old_snapshot"}

            # Compute XIRR
            recent_date = datetime.fromisoformat(recent_snapshot["statement_date"])
            old_date = datetime.fromisoformat(old_snapshot["statement_date"])

            transactions = [
                (old_date, -abs(old_snapshot["total_value"])),
                (recent_date, abs(recent_snapshot["total_value"])),
            ]

            xirr_1y = calculate_xirr(transactions)

            if xirr_1y is None:
                return None, {"reason": "xirr_calculation_failed"}

            # Validate XIRR bounds
            if not (XIRR_MIN <= xirr_1y <= XIRR_MAX):
                logger.warning(
                    "xirr_1y_out_of_bounds",
                    user_id=user_id,
                    xirr=xirr_1y,
                    bounds=(XIRR_MIN, XIRR_MAX),
                )
                return None, {"reason": "xirr_out_of_bounds", "xirr": xirr_1y}

            metadata = {
                "xirr_1y": xirr_1y,
                "start_date": old_date.date().isoformat(),
                "end_date": recent_date.date().isoformat(),
                "days": (recent_date - old_date).days,
                "start_value": old_snapshot["total_value"],
                "end_value": recent_snapshot["total_value"],
            }

            logger.info("xirr_1y_computed", user_id=user_id, **metadata)

            return xirr_1y, metadata

        except Exception as e:
            logger.error("compute_1y_xirr_error", user_id=user_id, error=str(e))
            return None, {"reason": "error", "error": str(e)}

    @staticmethod
    def compute_consistency_score(
        supabase_client, user_id: str
    ) -> Tuple[Optional[float], Dict[str, Any]]:
        """
        Compute consistency score based on snapshot-to-snapshot stability.

        Method:
        1. Get all snapshots from last 18 months
        2. Compute returns between consecutive snapshots
        3. Calculate win rate and volatility
        4. Score = (win_rate * 60) + (stability_factor * 40)

        Args:
            supabase_client: Supabase client instance
            user_id: User ID

        Returns:
            (consistency_score, metadata) where:
            - consistency_score: 0-100 score or None
            - metadata: dict with computation details
        """
        try:
            # Get snapshots from last 18 months
            cutoff_date = datetime.utcnow() - timedelta(days=545)  # ~18 months

            response = (
                supabase_client.client.table("portfolio_snapshots")
                .select("statement_date, total_value")
                .eq("user_id", user_id)
                .gte("statement_date", cutoff_date.date().isoformat())
                .order("statement_date", desc=False)
                .execute()
            )

            snapshots = response.data
            if not snapshots or len(snapshots) < 6:
                logger.info(
                    "insufficient_snapshots_for_consistency",
                    user_id=user_id,
                    count=len(snapshots) if snapshots else 0,
                )
                return None, {
                    "reason": "insufficient_snapshots",
                    "required": 6,
                    "found": len(snapshots) if snapshots else 0,
                }

            # Compute period-to-period returns
            returns = []
            for i in range(1, len(snapshots)):
                prev = snapshots[i - 1]
                curr = snapshots[i]

                prev_date = (
                    datetime.fromisoformat(prev["statement_date"]).date()
                    if isinstance(prev["statement_date"], str)
                    else prev["statement_date"]
                )
                curr_date = (
                    datetime.fromisoformat(curr["statement_date"]).date()
                    if isinstance(curr["statement_date"], str)
                    else curr["statement_date"]
                )

                days = (curr_date - prev_date).days
                if days == 0:
                    continue

                # Annualized return
                if prev["total_value"] > 0:
                    growth = curr["total_value"] / prev["total_value"]
                    annualized_return = (growth ** (365.0 / days) - 1) * 100
                    returns.append(annualized_return)

            if len(returns) < 3:
                return None, {
                    "reason": "insufficient_return_periods",
                    "count": len(returns),
                }

            # Calculate metrics
            positive_count = sum(1 for r in returns if r > 0)
            win_rate = positive_count / len(returns)

            # Volatility (standard deviation)
            mean_return = sum(returns) / len(returns)
            variance = sum((r - mean_return) ** 2 for r in returns) / len(returns)
            volatility = variance**0.5

            # Stability factor (inverse volatility, normalized)
            # Lower volatility = higher stability
            stability_factor = 1 / (1 + (volatility / 10))

            # Consistency score formula
            consistency_score = (win_rate * 60) + (stability_factor * 40)
            consistency_score = round(min(100, max(0, consistency_score)), 2)

            metadata = {
                "consistency_score": consistency_score,
                "win_rate": round(win_rate, 3),
                "positive_periods": positive_count,
                "total_periods": len(returns),
                "volatility": round(volatility, 2),
                "stability_factor": round(stability_factor, 3),
                "mean_return": round(mean_return, 2),
                "snapshot_count": len(snapshots),
            }

            logger.info("consistency_score_computed", user_id=user_id, **metadata)

            return consistency_score, metadata

        except Exception as e:
            logger.error(
                "compute_consistency_score_error", user_id=user_id, error=str(e)
            )
            return None, {"reason": "error", "error": str(e)}

    @staticmethod
    def compute_consistency_score_fallback(
        supabase_client, user_id: str
    ) -> Tuple[Optional[float], Dict[str, Any]]:
        """
        Fallback consistency score when snapshots unavailable.
        Uses portfolio count and XIRR range as proxy.

        Score = min(portfolio_count * 10, 50) + max(0, 50 - (max_xirr - min_xirr))

        Logic: More portfolios with similar XIRRs = more consistent
        """
        try:
            response = (
                supabase_client.client.table("portfolios")
                .select("xirr")
                .eq("user_id", user_id)
                .eq("visibility", "public")
                .is_("deleted_at", "null")
                .not_.is_("xirr", "null")
                .execute()
            )

            portfolios = response.data
            if not portfolios or len(portfolios) < 2:
                return None, {"reason": "insufficient_portfolios"}

            xirrs = [p["xirr"] for p in portfolios]
            portfolio_count = len(xirrs)
            max_xirr = max(xirrs)
            min_xirr = min(xirrs)
            xirr_range = max_xirr - min_xirr

            # Score calculation
            count_score = min(portfolio_count * 10, 50)
            range_penalty = max(0, 50 - xirr_range)
            consistency_score = count_score + range_penalty
            consistency_score = round(min(100, max(0, consistency_score)), 2)

            metadata = {
                "consistency_score": consistency_score,
                "portfolio_count": portfolio_count,
                "xirr_range": round(xirr_range, 2),
                "max_xirr": round(max_xirr, 2),
                "min_xirr": round(min_xirr, 2),
                "method": "fallback",
            }

            logger.info(
                "consistency_score_fallback_computed", user_id=user_id, **metadata
            )

            return consistency_score, metadata

        except Exception as e:
            logger.error(
                "compute_consistency_score_fallback_error",
                user_id=user_id,
                error=str(e),
            )
            return None, {"reason": "error", "error": str(e)}

    @staticmethod
    def check_suspicious_portfolio(
        portfolio: Dict[str, Any]
    ) -> Tuple[bool, float, List[str]]:
        """
        Check if portfolio shows signs of manipulation or unrealistic returns.

        Flags if ANY of:
        1. XIRR > 200% with history < 90 days
        2. XIRR > 100% with history < 180 days
        3. Total value < ₹1,000 but XIRR > 100%
        4. Only 1 holding with XIRR > 100%
        5. XIRR < -50% (catastrophic loss)

        Args:
            portfolio: Portfolio dict with fields: xirr, created_at, total_value, holding_count

        Returns:
            (is_suspicious, suspicion_score, reasons)
        """
        reasons = []
        suspicion_score = 0.0

        xirr = portfolio.get("xirr", 0)
        total_value = portfolio.get("total_value", 0)
        holding_count = portfolio.get("holding_count", 0)

        # Calculate history
        created_at = portfolio.get("created_at")
        if created_at:
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            history_days = (
                datetime.utcnow().replace(tzinfo=created_at.tzinfo) - created_at
            ).days
        else:
            history_days = 0

        # Rule 1: Extreme XIRR with short history
        if xirr > 200 and history_days < 90:
            reasons.append("extreme_xirr_short_history")
            suspicion_score += 40

        # Rule 2: High XIRR with insufficient history
        if xirr > 100 and history_days < 180:
            reasons.append("high_xirr_short_history")
            suspicion_score += 30

        # Rule 3: Small portfolio with extreme gains
        if total_value < 1000 and xirr > 100:
            reasons.append("tiny_portfolio_extreme_gains")
            suspicion_score += 25

        # Rule 4: Single holding with extreme XIRR
        if holding_count == 1 and xirr > 100:
            reasons.append("single_holding_extreme_xirr")
            suspicion_score += 20

        # Rule 5: Catastrophic loss
        if xirr < -50:
            reasons.append("catastrophic_loss")
            suspicion_score += 35

        # Rule 6: Out of bounds
        if xirr > XIRR_MAX or xirr < XIRR_MIN:
            reasons.append("xirr_out_of_bounds")
            suspicion_score += 50

        is_suspicious = suspicion_score >= 30  # Threshold

        return is_suspicious, round(suspicion_score, 2), reasons

    @staticmethod
    async def update_user_metrics(supabase_client, user_id: str) -> Dict[str, Any]:
        """
        Recompute and update all advanced metrics for a user.
        Called periodically or after portfolio upload.

        Args:
            supabase_client: Supabase client instance
            user_id: User ID

        Returns:
            dict with updated metrics
        """
        try:
            # Compute 1Y XIRR
            xirr_1y, xirr_metadata = PerformanceMetricsService.compute_1y_xirr(
                supabase_client, user_id
            )

            # Compute consistency score
            consistency_score, consistency_metadata = (
                PerformanceMetricsService.compute_consistency_score(
                    supabase_client, user_id
                )
            )

            # Fallback if primary method failed
            if consistency_score is None:
                consistency_score, consistency_metadata = (
                    PerformanceMetricsService.compute_consistency_score_fallback(
                        supabase_client, user_id
                    )
                )

            # Update profiles table
            update_data = {
                "xirr_1y": xirr_1y,
                "consistency_score": consistency_score,
                "last_metrics_update": datetime.utcnow().isoformat(),
            }

            supabase_client.client.table("profiles").update(update_data).eq(
                "id", user_id
            ).execute()

            logger.info(
                "user_metrics_updated",
                user_id=user_id,
                xirr_1y=xirr_1y,
                consistency_score=consistency_score,
            )

            return {
                "user_id": user_id,
                "xirr_1y": xirr_1y,
                "xirr_metadata": xirr_metadata,
                "consistency_score": consistency_score,
                "consistency_metadata": consistency_metadata,
                "updated_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("update_user_metrics_error", user_id=user_id, error=str(e))
            return {"user_id": user_id, "error": str(e)}
