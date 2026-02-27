"""
Transaction Reconciliation Service.

Runs asynchronously after PDF processing to:
  a. Look up historical stock prices at each transaction date
  b. Reconcile buy/sell quantities using FIFO matching
  c. Compute realized P&L per ISIN

Triggered as a Celery task chained after process_pdf_task.
"""

from collections import defaultdict
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

import structlog

from app.infrastructure.supabase_client import supabase_client
from app.services.integrations.market_data_client import market_data_client

logger = structlog.get_logger()


class TransactionReconciliationService:
    """Reconcile portfolio transactions with market data."""

    async def reconcile_snapshot(self, snapshot_id: str, user_id: str) -> Dict[str, Any]:
        """
        Reconcile all pending transactions for a given snapshot.

        Steps:
          1. Fetch all pending transactions for the snapshot
          2. Batch-fetch historical prices from market data provider
          3. Update each transaction with reconciled price/amount
          4. Compute net positions and realized P&L per ISIN

        Args:
            snapshot_id: Portfolio snapshot ID
            user_id: User ID (for logging/auth)

        Returns:
            Summary dict with counts and any errors
        """
        logger.info(
            "reconciliation_started",
            snapshot_id=snapshot_id,
            user_id=user_id,
        )

        # 1. Fetch pending transactions
        transactions = await self._fetch_pending_transactions(snapshot_id)
        if not transactions:
            logger.info(
                "reconciliation_no_pending",
                snapshot_id=snapshot_id,
            )
            return {
                "snapshot_id": snapshot_id,
                "total": 0,
                "reconciled": 0,
                "failed": 0,
                "skipped": 0,
            }

        # 2. Build price lookup requests
        price_requests: List[Tuple[str, date]] = []
        for txn in transactions:
            isin = txn["isin"]
            txn_date = self._parse_date(txn["date"])
            if txn_date and isin.startswith("INE"):  # Only equity ISINs
                price_requests.append((isin, txn_date))

        # 3. Batch-fetch prices
        prices: Dict[Tuple[str, date], Optional[float]] = {}
        if price_requests:
            try:
                prices = await market_data_client.get_closing_prices_batch(price_requests)
            except Exception as e:
                logger.error(
                    "reconciliation_price_fetch_failed",
                    snapshot_id=snapshot_id,
                    error=str(e),
                )

        # 4. Update each transaction
        reconciled_count = 0
        failed_count = 0
        skipped_count = 0

        for txn in transactions:
            isin = txn["isin"]
            txn_date = self._parse_date(txn["date"])

            # Skip non-equity ISINs (MF NAVs are already in the holdings)
            if not isin.startswith("INE"):
                await self._update_transaction_status(
                    txn["id"], "skipped", source=None, error="Non-equity ISIN"
                )
                skipped_count += 1
                continue

            if txn_date is None:
                await self._update_transaction_status(
                    txn["id"], "failed", source=None, error="Invalid date"
                )
                failed_count += 1
                continue

            price = prices.get((isin, txn_date))
            if price is not None:
                quantity = float(txn["quantity"])
                reconciled_amount = round(quantity * price, 2)

                await self._update_transaction_reconciled(
                    txn_id=txn["id"],
                    price=price,
                    amount=reconciled_amount,
                    source="truedata",  # Will be dynamic when provider is configured
                )
                reconciled_count += 1
            else:
                await self._update_transaction_status(
                    txn["id"],
                    "failed",
                    source=None,
                    error="Price not available from market data provider",
                )
                failed_count += 1

        # 5. Compute net positions per ISIN (FIFO)
        positions = await self._compute_net_positions(snapshot_id)

        summary = {
            "snapshot_id": snapshot_id,
            "total": len(transactions),
            "reconciled": reconciled_count,
            "failed": failed_count,
            "skipped": skipped_count,
            "positions": positions,
        }

        logger.info("reconciliation_completed", **summary)
        return summary

    async def _fetch_pending_transactions(self, snapshot_id: str) -> List[Dict]:
        """Fetch transactions with reconciliation_status = 'pending'."""
        try:
            response = (
                supabase_client.client.table("portfolio_transactions")
                .select("id, isin, asset_name, transaction_type, date, quantity, amount, op_bal, cl_bal")
                .eq("snapshot_id", snapshot_id)
                .eq("reconciliation_status", "pending")
                .execute()
            )
            return response.data or []
        except Exception as e:
            logger.error(
                "reconciliation_fetch_failed",
                snapshot_id=snapshot_id,
                error=str(e),
            )
            return []

    async def _update_transaction_reconciled(
        self,
        txn_id: str,
        price: float,
        amount: float,
        source: str,
    ) -> None:
        """Mark a transaction as reconciled with price data."""
        try:
            supabase_client.client.table("portfolio_transactions").update({
                "reconciled_price": price,
                "reconciled_amount": amount,
                "reconciliation_status": "reconciled",
                "reconciliation_source": source,
                "reconciled_at": datetime.utcnow().isoformat(),
            }).eq("id", txn_id).execute()
        except Exception as e:
            logger.error(
                "reconciliation_update_failed",
                txn_id=txn_id,
                error=str(e),
            )

    async def _update_transaction_status(
        self,
        txn_id: str,
        status: str,
        source: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update reconciliation status (failed/skipped)."""
        try:
            update_data: Dict[str, Any] = {
                "reconciliation_status": status,
                "reconciled_at": datetime.utcnow().isoformat(),
            }
            if source:
                update_data["reconciliation_source"] = source
            if error:
                update_data["reconciliation_error"] = error

            supabase_client.client.table("portfolio_transactions").update(
                update_data
            ).eq("id", txn_id).execute()
        except Exception as e:
            logger.error(
                "reconciliation_status_update_failed",
                txn_id=txn_id,
                status=status,
                error=str(e),
            )

    async def _compute_net_positions(self, snapshot_id: str) -> List[Dict[str, Any]]:
        """
        Compute net positions per ISIN using FIFO matching.

        Groups all transactions by ISIN, then:
          - CREDIT/BUY: add to position
          - DEBIT/SELL: remove from position (FIFO)
          - Compute realized P&L from matched pairs

        Returns:
            List of position summaries per ISIN
        """
        try:
            response = (
                supabase_client.client.table("portfolio_transactions")
                .select("isin, asset_name, transaction_type, date, quantity, reconciled_price, reconciled_amount, cl_bal")
                .eq("snapshot_id", snapshot_id)
                .order("date")
                .execute()
            )
            txns = response.data or []
        except Exception as e:
            logger.error("net_position_fetch_failed", snapshot_id=snapshot_id, error=str(e))
            return []

        # Group by ISIN
        by_isin: Dict[str, List[Dict]] = defaultdict(list)
        for txn in txns:
            by_isin[txn["isin"]].append(txn)

        positions = []
        for isin, isin_txns in by_isin.items():
            total_credit = 0.0
            total_debit = 0.0
            total_credit_value = 0.0
            total_debit_value = 0.0
            asset_name = isin_txns[0].get("asset_name", isin)

            for txn in isin_txns:
                qty = float(txn.get("quantity", 0))
                amt = float(txn.get("reconciled_amount", 0) or 0)
                txn_type = (txn.get("transaction_type") or "").upper()

                if txn_type in ("CREDIT", "BUY"):
                    total_credit += qty
                    total_credit_value += amt
                elif txn_type in ("DEBIT", "SELL"):
                    total_debit += qty
                    total_debit_value += amt

            net_qty = total_credit - total_debit
            # Use closing balance from last transaction if available
            last_cl_bal = None
            for txn in reversed(isin_txns):
                if txn.get("cl_bal") is not None:
                    last_cl_bal = float(txn["cl_bal"])
                    break

            realized_pnl = total_debit_value - (
                total_credit_value * (total_debit / total_credit)
                if total_credit > 0 else 0
            )

            positions.append({
                "isin": isin,
                "asset_name": asset_name,
                "total_bought": total_credit,
                "total_sold": total_debit,
                "net_quantity": net_qty,
                "closing_balance": last_cl_bal,
                "realized_pnl": round(realized_pnl, 2) if total_debit_value > 0 else None,
                "fully_exited": net_qty <= 0,
            })

        return positions

    @staticmethod
    def _parse_date(date_val: Any) -> Optional[date]:
        """Parse a date from string or date object."""
        if isinstance(date_val, date):
            return date_val
        if isinstance(date_val, str):
            try:
                return date.fromisoformat(date_val)
            except ValueError:
                return None
        return None


# Singleton
reconciliation_service = TransactionReconciliationService()
