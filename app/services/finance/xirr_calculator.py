"""
XIRR Calculator - Pure Python implementation
Replaces the overengineered Supabase Edge Function for MVP
"""

from datetime import datetime
from typing import List, Optional, Tuple

import numpy as np  # type: ignore[import-not-found]
import structlog  # type: ignore[import-not-found]
from scipy import optimize  # type: ignore[import-not-found]

logger = structlog.get_logger()


def calculate_xirr(
    transactions: List[Tuple[datetime, float]], guess: float = 0.1
) -> Optional[float]:
    """
    Calculate XIRR (Extended Internal Rate of Return) for a series of transactions.

    Args:
        transactions: List of (date, amount) tuples where:
            - date: Transaction date
            - amount: Cash flow (negative for investments, positive for redemptions)
        guess: Initial guess for the rate (default 0.1 = 10%)

    Returns:
        XIRR as a percentage (e.g., 12.5 for 12.5%) or None if calculation fails

    Example:
        >>> transactions = [
        ...     (datetime(2023, 1, 1), -10000),  # Investment
        ...     (datetime(2023, 6, 1), -5000),   # Additional investment
        ...     (datetime(2024, 1, 1), 16000),   # Redemption
        ... ]
        >>> xirr = calculate_xirr(transactions)
        >>> print(f"XIRR: {xirr:.2f}%")
    """

    if not transactions or len(transactions) < 2:
        logger.warning("insufficient_transactions", count=len(transactions))
        return None

    # Sort transactions by date
    transactions = sorted(transactions, key=lambda x: x[0])

    # Extract dates and amounts
    dates = [t[0] for t in transactions]
    amounts = [t[1] for t in transactions]

    # Validate: need both positive and negative cash flows
    if all(a >= 0 for a in amounts) or all(a <= 0 for a in amounts):
        logger.warning("invalid_cash_flows", all_positive=all(a >= 0 for a in amounts))
        return None

    # Calculate days from first transaction
    first_date = dates[0]
    days = [(d - first_date).days for d in dates]

    def xirr_func(rate):
        """NPV function that should equal zero at the correct XIRR"""
        return sum(
            amount / ((1 + rate) ** (day / 365.0)) for amount, day in zip(amounts, days)
        )

    try:
        # Try different initial guesses if first one fails
        for _ in [guess, 0.0, -0.1, 0.5, -0.5]:
            try:
                # Find rate where NPV = 0
                result = optimize.root_scalar(
                    xirr_func,
                    method="brentq",
                    bracket=[-0.99, 10],  # Rate between -99% and 1000%
                    xtol=1e-6,
                )

                if result.converged:
                    xirr_rate = result.root * 100  # Convert to percentage

                    # Sanity check
                    if -99 <= xirr_rate <= 1000:
                        logger.info("xirr_calculated", xirr=xirr_rate)
                        return round(xirr_rate, 2)
                    else:
                        logger.warning("xirr_out_of_range", xirr=xirr_rate)

            except (ValueError, RuntimeError):
                continue

        # If all guesses failed, try Newton's method
        result = optimize.newton(xirr_func, guess, maxiter=100)
        xirr_rate = result * 100

        if -99 <= xirr_rate <= 1000:
            logger.info("xirr_calculated_newton", xirr=xirr_rate)
            return round(xirr_rate, 2)

    except Exception as e:
        logger.error("xirr_calculation_failed", error=str(e))

    return None


def calculate_portfolio_xirr(holdings: List[dict]) -> Optional[float]:
    """
    Calculate XIRR from portfolio holdings.

    Args:
        holdings: List of holding dictionaries with:
            - purchase_date: Date of purchase
            - purchase_value: Amount invested (positive number)
            - current_value: Current value
            - transactions: Optional list of intermediate transactions

    Returns:
        XIRR percentage or None
    """

    transactions = []

    for holding in holdings:
        # Add purchase as negative cash flow
        if "purchase_date" in holding and "purchase_value" in holding:
            purchase_date = holding["purchase_date"]
            if isinstance(purchase_date, str):
                purchase_date = datetime.fromisoformat(purchase_date)
            transactions.append((purchase_date, -abs(holding["purchase_value"])))

        # Add any intermediate transactions
        if "transactions" in holding:
            for txn in holding["transactions"]:
                txn_date = txn["date"]
                if isinstance(txn_date, str):
                    txn_date = datetime.fromisoformat(txn_date)
                # Negative for purchases, positive for sales
                amount = -txn["amount"] if txn["type"] == "buy" else txn["amount"]
                transactions.append((txn_date, amount))

    # Add current value as positive cash flow (today)
    total_current_value = sum(h.get("current_value", 0) for h in holdings)
    if total_current_value > 0:
        transactions.append((datetime.now(), total_current_value))

    return calculate_xirr(transactions)


def validate_xirr(xirr: float) -> Tuple[bool, Optional[str]]:
    """
    Validate if XIRR value makes sense.

    Returns:
        (is_valid, error_message)
    """

    if xirr is None:
        return False, "XIRR calculation failed"

    if xirr < -50:
        return False, f"Unrealistic loss: {xirr}%"

    if xirr > 200:
        return False, f"Unrealistic gain: {xirr}%"

    return True, None


# Example usage for testing
if __name__ == "__main__":
    # Test with sample transactions
    test_transactions = [
        (datetime(2023, 1, 1), -100000.0),  # Initial investment
        (datetime(2023, 4, 1), -25000.0),  # SIP
        (datetime(2023, 7, 1), -25000.0),  # SIP
        (datetime(2023, 10, 1), -25000.0),  # SIP
        (datetime(2024, 1, 1), 180000.0),  # Current value
    ]

    xirr = calculate_xirr(test_transactions)
    print(f"XIRR: {xirr}%")

    if xirr is not None:
        is_valid, error = validate_xirr(xirr)
    else:
        is_valid, error = False, "XIRR calculation failed"
    print(f"Valid: {is_valid}, Error: {error}")
