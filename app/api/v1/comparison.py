"""
Portfolio Comparison API endpoints
Allows comparing 2-3 portfolios side-by-side
"""

from typing import List

import structlog
from app.infrastructure.supabase_client import supabase_client
from fastapi import APIRouter, HTTPException, Query, status

logger = structlog.get_logger()
router = APIRouter(prefix="/comparison", tags=["Comparison"])


@router.get("")
async def compare_portfolios(
    portfolio_ids: List[str] = Query(..., min_length=2, max_length=3),
):
    """
    Compare 2-3 portfolios side-by-side.

    Returns detailed comparison including:
    - Performance metrics (XIRR, returns)
    - Portfolio size and allocation
    - Risk levels
    - Holdings distribution
    - Top performers
    """
    try:
        if len(portfolio_ids) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least 2 portfolio IDs required",
            )

        if len(portfolio_ids) > 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum 3 portfolios can be compared",
            )

        # Fetch all portfolios
        portfolios = []
        for pid in portfolio_ids:
            try:
                portfolio = await supabase_client.get_portfolio(pid)
                portfolios.append(portfolio)
            except Exception as e:
                logger.warning("portfolio_not_found", portfolio_id=pid)
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Portfolio {pid} not found",
                )

        # Calculate comparative metrics
        comparison_data = {
            "portfolios": portfolios,
            "comparison": {
                "performance": {
                    "best_xirr": max(portfolios, key=lambda p: p.get("xirr", 0) or 0),
                    "highest_returns": max(
                        portfolios, key=lambda p: p.get("total_value", 0)
                    ),
                },
                "size": {
                    "largest": max(portfolios, key=lambda p: p.get("total_value", 0)),
                    "smallest": min(portfolios, key=lambda p: p.get("total_value", 0)),
                },
                "risk": {
                    "most_conservative": [
                        p for p in portfolios if p.get("risk_level") == "conservative"
                    ],
                    "most_aggressive": [
                        p for p in portfolios if p.get("risk_level") == "aggressive"
                    ],
                },
                "diversification": {
                    "most_diversified": max(
                        portfolios, key=lambda p: len(p.get("holdings", []))
                    ),
                    "least_diversified": min(
                        portfolios, key=lambda p: len(p.get("holdings", []))
                    ),
                },
            },
        }

        logger.info(
            "portfolios_compared",
            count=len(portfolio_ids),
            portfolio_ids=portfolio_ids,
        )

        return comparison_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error("compare_portfolios_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compare portfolios",
        )


@router.get("/metrics")
async def get_comparison_metrics(
    portfolio_ids: List[str] = Query(..., min_length=2, max_length=3),
):
    """
    Get detailed comparison metrics for portfolios.

    Returns granular metrics for charts and detailed analysis.
    """
    try:
        if len(portfolio_ids) < 2 or len(portfolio_ids) > 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Requires 2-3 portfolio IDs",
            )

        # Fetch portfolio details
        portfolios = []
        for pid in portfolio_ids:
            try:
                portfolio = await supabase_client.get_portfolio(pid)
                portfolios.append(portfolio)
            except:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Portfolio {pid} not found",
                )

        # Build detailed metrics
        metrics = {
            "xirr_comparison": [
                {
                    "portfolio_id": p["id"],
                    "title": p["title"],
                    "xirr": p.get("xirr"),
                }
                for p in portfolios
            ],
            "size_comparison": [
                {
                    "portfolio_id": p["id"],
                    "title": p["title"],
                    "total_value": p.get("total_value", 0),
                    "invested_value": p.get("invested_value", 0),
                    "current_value": p.get("current_value", 0),
                }
                for p in portfolios
            ],
            "allocation_comparison": [
                {
                    "portfolio_id": p["id"],
                    "title": p["title"],
                    "holdings_count": len(p.get("holdings", [])),
                    "asset_types": _get_asset_type_breakdown(p.get("holdings", [])),
                }
                for p in portfolios
            ],
        }

        logger.info("comparison_metrics_fetched", count=len(portfolio_ids))

        return metrics

    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_comparison_metrics_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get comparison metrics",
        )


def _get_asset_type_breakdown(holdings: List[dict]) -> dict:
    """Calculate breakdown of holdings by asset type"""
    breakdown = {}
    for holding in holdings:
        asset_type = holding.get("asset_type", "unknown")
        if asset_type not in breakdown:
            breakdown[asset_type] = 0
        breakdown[asset_type] += holding.get("percentage", 0)
    return breakdown
