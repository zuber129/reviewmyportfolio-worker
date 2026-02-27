"""
Portfolio Quality Service
Calculates portfolio quality metrics for the reputation system.

Metrics:
- Diversification score (0-40): Herfindahl-Hirschman Index from holdings percentages
- Position sizing score (0-30): Top-3 holdings concentration ratio
- Thesis score (0-30): Presence of investment thesis
"""

import math
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()


class PortfolioQualityService:
    """Calculates portfolio quality metrics using CAS PDF data (no external APIs needed)."""

    @staticmethod
    def calculate_diversification_score(holdings: List[Dict[str, Any]]) -> int:
        """
        Calculate diversification score using Herfindahl-Hirschman Index (HHI).

        HHI = sum((percentage/100)^2) for all holdings
        - HHI < 0.15 (well diversified) = 40 points
        - HHI > 0.50 (concentrated)     =  0 points
        - Linear scale between 0.15 and 0.50

        Returns: int 0-40
        """
        if not holdings:
            return 0

        percentages = [h.get("percentage", 0) for h in holdings if h.get("percentage", 0) > 0]
        if not percentages:
            return 0

        total = sum(percentages)
        if total <= 0:
            return 0

        # Normalise to 100% in case of rounding drift
        normalised = [p / total for p in percentages]
        hhi = sum(w ** 2 for w in normalised)

        if hhi <= 0.15:
            return 40
        if hhi >= 0.50:
            return 0

        # Linear interpolation: 40 at 0.15, 0 at 0.50
        score = int(40 * (0.50 - hhi) / (0.50 - 0.15))
        return max(0, min(40, score))

    @staticmethod
    def calculate_position_sizing_score(holdings: List[Dict[str, Any]]) -> int:
        """
        Calculate position sizing score based on top-3 holdings concentration.

        - Top 3 < 40% = 30 points
        - Top 3 > 70% =  0 points
        - Linear scale between 40% and 70%

        Returns: int 0-30
        """
        if not holdings:
            return 0

        percentages = sorted(
            [h.get("percentage", 0) for h in holdings if h.get("percentage", 0) > 0],
            reverse=True,
        )
        if not percentages:
            return 0

        top3_sum = sum(percentages[:3])

        if top3_sum <= 40.0:
            return 30
        if top3_sum >= 70.0:
            return 0

        # Linear interpolation: 30 at 40%, 0 at 70%
        score = int(30 * (70.0 - top3_sum) / (70.0 - 40.0))
        return max(0, min(30, score))

    @staticmethod
    def calculate_thesis_score(investment_thesis: Optional[str]) -> int:
        """
        Calculate thesis score based on presence of investment thesis.

        - Has thesis (30-2000 chars) = 30 points
        - No thesis                  =  0 points

        Returns: int 0-30
        """
        if not investment_thesis:
            return 0
        stripped = investment_thesis.strip()
        if len(stripped) >= 30:
            return 30
        return 0

    @staticmethod
    def calculate_portfolio_quality_score(
        holdings: List[Dict[str, Any]],
        investment_thesis: Optional[str],
    ) -> int:
        """
        Calculate composite portfolio quality score (0-100).

        Components:
        - Diversification (40 pts): HHI-based
        - Position Sizing (30 pts): Top-3 concentration
        - Thesis          (30 pts): Has investment thesis

        Returns: int 0-100
        """
        diversification = PortfolioQualityService.calculate_diversification_score(holdings)
        position_sizing = PortfolioQualityService.calculate_position_sizing_score(holdings)
        thesis = PortfolioQualityService.calculate_thesis_score(investment_thesis)

        total = diversification + position_sizing + thesis

        logger.debug(
            "portfolio_quality_calculated",
            diversification=diversification,
            position_sizing=position_sizing,
            thesis=thesis,
            total=total,
        )

        return max(0, min(100, total))

    @staticmethod
    def calculate_best_portfolio_quality(portfolios: List[Dict[str, Any]]) -> int:
        """
        Calculate portfolio quality score across all user portfolios.
        Uses the best-scoring portfolio to represent the user.

        Each portfolio dict should contain:
        - holdings: list of holding dicts with 'percentage' field
        - investment_thesis: optional string

        Returns: int 0-100
        """
        if not portfolios:
            return 0

        scores = []
        for portfolio in portfolios:
            holdings = portfolio.get("holdings", [])
            thesis = portfolio.get("investment_thesis")
            score = PortfolioQualityService.calculate_portfolio_quality_score(
                holdings=holdings,
                investment_thesis=thesis,
            )
            scores.append(score)

        return max(scores) if scores else 0
