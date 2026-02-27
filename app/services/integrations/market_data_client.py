"""
Market data client for fetching historical stock prices.

Uses BSE Bhav Copy (free, no API key) as the default provider.
Designed to be swapped with TrueData REST API when available.

All external calls wrapped with:
  - Circuit breaker (pybreaker): 5-fail / 60-sec reset  [G-08]
  - Exponential backoff + structured error logging       [G-07]
"""

import time
from datetime import date, timedelta
from typing import Dict, List, Optional, Tuple

import httpx
import pybreaker
import structlog

logger = structlog.get_logger()

# Circuit breaker: 5 consecutive failures → open for 60 seconds
_market_data_cb = pybreaker.CircuitBreaker(
    fail_max=5,
    reset_timeout=60,
    name="market_data",
)


class MarketDataClient:
    """Fetch historical closing prices for Indian equities by ISIN."""

    # BSE Bhav Copy CSV endpoint (free, no auth)
    # Format: https://www.bseindia.com/download/BhseCsv/Equity/EQ{DDMMYY}_CSV.ZIP
    BSE_BHAV_BASE = "https://www.bseindia.com/download/BhavCopy/Equity"

    # ISIN-to-scrip mapping cache (populated lazily)
    _isin_scrip_cache: Dict[str, str] = {}

    def __init__(self, timeout: float = 10.0, max_retries: int = 3):
        self._timeout = timeout
        self._max_retries = max_retries

    @_market_data_cb
    async def get_closing_price(
        self, isin: str, txn_date: date
    ) -> Optional[float]:
        """
        Look up the closing price for an ISIN on a given date.

        Tries the transaction date first, then falls back to the previous
        trading day (up to 5 business days back) to handle weekends/holidays.

        Args:
            isin: 12-char ISIN (e.g. INE925R01014)
            txn_date: Date to look up

        Returns:
            Closing price as float, or None if unavailable
        """
        # Try txn_date and up to 5 previous business days
        for offset in range(6):
            lookup_date = txn_date - timedelta(days=offset)
            if lookup_date.weekday() >= 5:  # Skip weekends
                continue

            price = await self._fetch_price_with_backoff(isin, lookup_date)
            if price is not None:
                return price

        logger.warning(
            "market_price_not_found",
            isin=isin,
            txn_date=txn_date.isoformat(),
        )
        return None

    async def get_closing_prices_batch(
        self, requests: List[Tuple[str, date]]
    ) -> Dict[Tuple[str, date], Optional[float]]:
        """
        Batch lookup of closing prices.

        Groups requests by date to minimize API calls (one Bhav Copy per date).

        Args:
            requests: List of (isin, date) tuples

        Returns:
            Dict mapping (isin, date) → price or None
        """
        results: Dict[Tuple[str, date], Optional[float]] = {}

        # Group by date for efficient batch fetching
        by_date: Dict[date, List[str]] = {}
        for isin, txn_date in requests:
            by_date.setdefault(txn_date, []).append(isin)

        for txn_date, isins in by_date.items():
            for isin in isins:
                price = await self.get_closing_price(isin, txn_date)
                results[(isin, txn_date)] = price

        return results

    async def _fetch_price_with_backoff(
        self, isin: str, lookup_date: date
    ) -> Optional[float]:
        """
        Fetch price with exponential backoff.  [G-07]

        Args:
            isin: ISIN to look up
            lookup_date: Specific date

        Returns:
            Price or None
        """
        for attempt in range(self._max_retries):
            try:
                return await self._fetch_price(isin, lookup_date)
            except (httpx.HTTPError, httpx.TimeoutException) as e:
                wait = min(2 ** attempt, 16)
                logger.warning(
                    "market_data_retry",
                    isin=isin,
                    date=lookup_date.isoformat(),
                    attempt=attempt + 1,
                    wait_seconds=wait,
                    error=str(e),
                )
                time.sleep(wait)
            except pybreaker.CircuitBreakerError:
                logger.error(
                    "market_data_circuit_open",
                    isin=isin,
                    date=lookup_date.isoformat(),
                )
                return None
            except Exception as e:
                logger.error(
                    "market_data_unexpected_error",
                    isin=isin,
                    date=lookup_date.isoformat(),
                    error=str(e),
                )
                return None

        return None

    async def _fetch_price(self, isin: str, lookup_date: date) -> Optional[float]:
        """
        Fetch closing price from market data provider.

        Current implementation: placeholder that returns None.
        Replace with TrueData REST API or BSE Bhav Copy when ready.

        To integrate TrueData:
            GET https://api.truedata.in/getbhavcopy
            ?segment=E&date={YYYY-MM-DD}
            Headers: Authorization: Bearer {TRUEDATA_API_KEY}

        To integrate BSE Bhav Copy (free):
            Download CSV from BSE, parse for ISIN match.
        """
        # TODO: Replace with actual market data provider
        # For now, return None — reconciliation will mark as 'failed'
        # with source='none' so it can be retried when a provider is configured.
        logger.debug(
            "market_data_fetch_placeholder",
            isin=isin,
            date=lookup_date.isoformat(),
            message="No market data provider configured yet",
        )
        return None


# Singleton
market_data_client = MarketDataClient()
