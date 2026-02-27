"""
XIRR Calculation Client for Supabase Edge Function
Calls the calculate-xirr edge function to compute annualized returns
"""

import logging
import os
from datetime import date, datetime
from typing import Dict, List, Optional

import httpx  # type: ignore[import-untyped]
from app.core.config import settings

logger = logging.getLogger(__name__)


class XIRRTransaction:
    """Represents a single transaction for XIRR calculation"""

    def __init__(self, transaction_date: date, amount: float):
        """
        Initialize a transaction

        Args:
            transaction_date: Date of the transaction
            amount: Transaction amount (negative for investments, positive for returns)
        """
        self.date = transaction_date
        self.amount = amount

    def to_dict(self) -> Dict[str, float | str]:
        """Convert to dictionary for API request"""
        return {
            "date": self.date.isoformat() if isinstance(self.date, date) else self.date,
            "amount": float(self.amount),
        }


class XIRRClient:
    """Client for calculating XIRR using Supabase Edge Function"""

    def __init__(self):
        """Initialize XIRR client with Supabase configuration"""
        # Get Supabase URL and anon key from settings or environment
        self.supabase_url = os.getenv("SUPABASE_URL", settings.supabase_url)
        self.supabase_anon_key = os.getenv("SUPABASE_ANON_KEY", settings.supabase_anon_key)
        self.function_url = f"{self.supabase_url}/functions/v1/calculate-xirr"

        # Configure HTTP client with timeout
        self.client = httpx.AsyncClient(timeout=30.0)

    async def calculate(
        self, transactions: List[XIRRTransaction], initial_guess: float = 0.1
    ) -> Optional[float]:
        """
        Calculate XIRR for a list of transactions

        Args:
            transactions: List of XIRRTransaction objects
            initial_guess: Initial guess for XIRR calculation (default 0.1 = 10%)

        Returns:
            XIRR as a percentage (e.g., 15.5 for 15.5%), or None if calculation fails
        """
        try:
            # Validate transactions
            if len(transactions) < 2:
                logger.error("At least 2 transactions required for XIRR calculation")
                return None

            # Check for both negative and positive cash flows
            amounts = [t.amount for t in transactions]
            has_investment = any(a < 0 for a in amounts)
            has_return = any(a > 0 for a in amounts)

            if not has_investment or not has_return:
                logger.error("Transactions must include both investments and returns")
                return None

            # Prepare request payload
            payload = {
                "transactions": [t.to_dict() for t in transactions],
                "guess": initial_guess,
            }

            # Call edge function
            response = await self.client.post(
                self.function_url,
                headers={
                    "Authorization": f"Bearer {self.supabase_anon_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )

            # Handle response
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    xirr = result.get("xirr")
                    logger.info(f"XIRR calculated successfully: {xirr}%")
                    return xirr
                else:
                    error = result.get("error", "Unknown error")
                    logger.error(f"XIRR calculation failed: {error}")
                    return None
            else:
                logger.error(
                    f"Edge function returned status {response.status_code}: {response.text}"
                )
                return None

        except httpx.TimeoutException:
            logger.error("XIRR calculation timed out")
            return None
        except Exception as e:
            logger.error(f"Error calculating XIRR: {str(e)}")
            return None

    async def calculate_from_holdings(
        self,
        holdings: List[Dict],
        current_value: float,
        current_date: Optional[date] = None,
    ) -> Optional[float]:
        """
        Calculate XIRR from portfolio holdings

        Args:
            holdings: List of holdings with purchase_date and purchase_value
            current_value: Current total portfolio value
            current_date: Date for current value (default: today)

        Returns:
            XIRR percentage or None if calculation fails
        """
        try:
            transactions = []

            # Add purchase transactions (negative cash flows)
            for holding in holdings:
                purchase_date = holding.get("purchase_date")
                purchase_value = holding.get("purchase_value") or holding.get(
                    "avg_price", 0
                ) * holding.get("quantity", 0)

                if purchase_date and purchase_value > 0:
                    # Parse date if it's a string
                    if isinstance(purchase_date, str):
                        purchase_date = datetime.fromisoformat(purchase_date).date()

                    transactions.append(XIRRTransaction(purchase_date, -purchase_value))

            # Add current value (positive cash flow)
            if current_date is None:
                current_date = datetime.now().date()

            transactions.append(XIRRTransaction(current_date, current_value))

            # Sort transactions by date
            transactions.sort(key=lambda t: t.date)

            # Calculate XIRR
            return await self.calculate(transactions)

        except Exception as e:
            logger.error(f"Error preparing holdings for XIRR: {str(e)}")
            return None

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


# Integration with existing PDF parser
async def update_portfolio_xirr(portfolio_id: str, parsed_data: Dict):
    """
    Update portfolio XIRR after PDF parsing

    Args:
        portfolio_id: ID of the portfolio to update
        parsed_data: Parsed data from PDF containing holdings and transactions
    """
    from app.infrastructure.supabase_client import supabase_client

    xirr_client = XIRRClient()

    try:
        # Extract holdings and current value from parsed data
        holdings = parsed_data.get("holdings", [])
        current_value = parsed_data.get("total_value", 0)

        # Calculate XIRR
        xirr = await xirr_client.calculate_from_holdings(
            holdings=holdings, current_value=current_value
        )

        if xirr is not None:
            # Update portfolio with XIRR
            await supabase_client.update_portfolio(
                portfolio_id,
                {"xirr": xirr, "updated_at": datetime.now().isoformat()},
            )

            logger.info(f"Updated portfolio {portfolio_id} with XIRR: {xirr}%")
            return xirr
        else:
            logger.warning(f"Could not calculate XIRR for portfolio {portfolio_id}")
            return None

    except Exception as e:
        logger.error(f"Error updating portfolio XIRR: {str(e)}")
        return None
    finally:
        await xirr_client.close()


# Example usage in PDF processing task
async def process_pdf_with_xirr(pdf_path: str, portfolio_id: str):
    """
    Process PDF and calculate XIRR

    Args:
        pdf_path: Path to the PDF file
        portfolio_id: Portfolio ID to update
    """
    from app.services.pdf.parser import pdf_parser

    # Parse PDF (expects base64 content string)
    parsed_data = await pdf_parser.parse_pdf(pdf_path)

    if parsed_data:
        # Calculate and update XIRR
        xirr = await update_portfolio_xirr(portfolio_id, parsed_data)

        # Add XIRR to parsed data
        parsed_data["xirr"] = xirr

    return parsed_data
