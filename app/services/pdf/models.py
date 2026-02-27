"""
Data models for enhanced NSDL CAS PDF parsing
"""

from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any, Dict, List, Optional

from app.domain.schemas import Holding


@dataclass
class PortfolioSummary:
    """Portfolio summary from NSDL CAS statement"""

    total_value: Decimal
    nsdl_value: Decimal
    nsdl_isin_count: int
    cdsl_value: Decimal
    cdsl_isin_count: int
    mutual_fund_value: Decimal
    mutual_fund_scheme_count: int
    unclaimed_amount: Decimal


@dataclass
class UserMetadata:
    """User information from NSDL CAS statement"""

    pan: str
    email: str
    mobile: str
    holder_name: Optional[str] = None  # For ownership verification (Issue #41)
    date_of_birth: Optional[date] = None
    bank_ifsc: Optional[str] = None
    nominee_registered: bool = False


@dataclass
class Transaction:
    """Transaction record from NSDL CAS statement"""

    date: date
    isin: str
    asset_name: str
    transaction_type: str  # BUY, SELL, DEBIT, CREDIT, REDEMPTION, etc.
    quantity: Decimal
    amount: Optional[Decimal] = None  # Not always available (e.g. demat-only transfers)
    price: Optional[Decimal] = None
    broker: Optional[str] = None
    reference: Optional[str] = None  # Transaction ref / order no
    op_bal: Optional[Decimal] = None  # Opening balance before transaction
    cl_bal: Optional[Decimal] = None  # Closing balance after transaction


class EnhancedHolding(Holding):
    """Extended holding information with additional fields"""

    def __init__(
        self,
        symbol: str,
        name: str,
        quantity: float,
        avg_price: float,
        current_price: float,
        current_value: float,
        percentage: float,
        asset_type: str = "equity",
        isin: Optional[str] = None,
        # Insurance fields
        policy_number: Optional[str] = None,
        sum_assured: Optional[float] = None,
        premium_amount: Optional[float] = None,
        maturity_date: Optional[str] = None,
        # Bond/Debt fields
        face_value: Optional[Decimal] = None,
        coupon_rate: Optional[float] = None,
        credit_rating: Optional[str] = None,
        # Retirement account fields
        account_number: Optional[str] = None,
        contribution_amount: Optional[float] = None,
        # Additional metadata
        folio_number: Optional[str] = None,
        purchase_date: Optional[str] = None,
        purchase_price: Optional[Decimal] = None,
        unrealized_pnl: Optional[Decimal] = None,
        xirr_value: Optional[Decimal] = None,
    ):
        super().__init__(
            symbol=symbol,
            name=name,
            quantity=quantity,
            avg_price=avg_price,
            current_price=current_price,
            current_value=current_value,
            percentage=percentage,
            asset_type=asset_type,
            isin=isin,
            policy_number=policy_number,
            sum_assured=sum_assured,
            premium_amount=premium_amount,
            maturity_date=maturity_date,
            face_value=face_value,
            coupon_rate=coupon_rate,
            credit_rating=credit_rating,
            account_number=account_number,
            contribution_amount=contribution_amount,
            folio_number=folio_number,
            purchase_date=purchase_date,
        )
        self.purchase_price = purchase_price
        self.unrealized_pnl = unrealized_pnl
        self.xirr_value = xirr_value


@dataclass
class NSDLCASData:
    """Complete data extracted from NSDL CAS"""

    summary: Optional[PortfolioSummary]
    equity_holdings: List[EnhancedHolding]
    mutual_fund_holdings: List[EnhancedHolding]
    equity_transactions: List[Transaction]
    mutual_fund_transactions: List[Transaction]
    user_metadata: Optional[UserMetadata]
    portfolio_trend: List[Dict[str, Any]]
    statement_period: str
    generated_on: date
