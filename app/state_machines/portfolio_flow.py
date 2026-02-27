"""
Portfolio Processing Flow State Machine.

Manages portfolio post-processing (metrics calculation, price fetching, insights).
Ready for future market data integration.
"""

import asyncio
from typing import Any, Dict, Optional
from statemachine import State
import structlog

from .base import FlowMachine
from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger(__name__)


class PortfolioFlowMachine(FlowMachine):
    """
    State machine for portfolio processing flow.
    
    Manages post-upload processing: metrics, prices, insights.
    State persisted in portfolios.pdf_processing_status
    """
    
    pending = State(initial=True, value="pending")
    processing_metrics = State(value="processing_metrics")
    fetching_prices = State(value="fetching_prices")
    generating_insights = State(value="generating_insights")
    ready = State(value="ready", final=True)
    failed = State(value="failed", final=True)
    
    start_processing = pending.to(processing_metrics)
    metrics_complete = processing_metrics.to(fetching_prices)
    prices_fetched = fetching_prices.to(generating_insights)
    insights_generated = generating_insights.to(ready)
    
    fail_from_pending = pending.to(failed)
    fail_from_metrics = processing_metrics.to(failed)
    fail_from_prices = fetching_prices.to(failed)
    fail_from_insights = generating_insights.to(failed)
    
    def __init__(self, model: Optional[Dict[str, Any]] = None, **kwargs):
        """
        Initialize portfolio processing flow machine.
        
        Args:
            model: portfolio record as dict
            **kwargs: Additional context (user_id, etc.)
        """
        super().__init__(model=model, **kwargs)
        
        if model and "pdf_processing_status" in model:
            current_state = model["pdf_processing_status"]
            try:
                self.current_state = getattr(self, current_state)
            except AttributeError:
                logger.warning(
                    "unknown_portfolio_state",
                    state=current_state,
                    portfolio_id=model.get("id"),
                    defaulting_to="pending"
                )
                self.current_state = self.pending
    
    def sync_to_db(self):
        """
        Persist current state to database.
        
        Updates portfolios.pdf_processing_status field.
        """
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_portfolio(
                    portfolio_id=self.model["id"],
                    updates={"pdf_processing_status": self.current_state.value}
                )
            )
    
    def on_enter_processing_metrics(self):
        """Action: Log metrics processing start."""
        self.log_transition("start_processing", "pending", "processing_metrics")
        self.sync_to_db()
        logger.info(
            "portfolio_metrics_processing_started",
            portfolio_id=self.model.get("id") if self.model else None
        )
    
    def on_enter_fetching_prices(self):
        """Action: Log price fetching start."""
        self.log_transition("metrics_complete", "processing_metrics", "fetching_prices")
        self.sync_to_db()
        logger.info(
            "portfolio_price_fetching_started",
            portfolio_id=self.model.get("id") if self.model else None
        )
    
    def on_enter_generating_insights(self):
        """Action: Log insights generation start."""
        self.log_transition("prices_fetched", "fetching_prices", "generating_insights")
        self.sync_to_db()
        logger.info(
            "portfolio_insights_generation_started",
            portfolio_id=self.model.get("id") if self.model else None
        )
    
    def on_enter_ready(self):
        """Action: Log processing completion."""
        self.log_transition("insights_generated", "generating_insights", "ready")
        self.sync_to_db()
        logger.info(
            "portfolio_processing_completed",
            portfolio_id=self.model.get("id") if self.model else None
        )
    
    def on_enter_failed(self):
        """Action: Log processing failure."""
        from_state = "unknown"
        if hasattr(self, "_previous_state"):
            from_state = self._previous_state
        
        self.log_transition("fail", from_state, "failed")
        self.sync_to_db()
        logger.error(
            "portfolio_processing_failed",
            portfolio_id=self.model.get("id") if self.model else None,
            error_code=self.error_code,
            error_message=self.error_message,
            from_state=from_state
        )
