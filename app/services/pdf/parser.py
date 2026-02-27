import asyncio
import base64
import json
import re
from datetime import date, datetime
from decimal import Decimal
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import fitz  # PyMuPDF
import numpy as np
import pandas as pd
import structlog
from app.core.config import settings
from app.domain.schemas import Holding, PortfolioCreate, PortfolioTransaction, RiskLevel
from app.services.pdf.exceptions import (
    IncorrectPasswordError,
    InvalidXIRRError,
    MissingRequiredDataError,
    ParsingFailedError,
    PasswordProtectedError,
    PortfolioTooLargeError,
    UnreadableOrCorruptError,
    UnsupportedFormatError,
)
from app.services.pdf.models import (
    EnhancedHolding,
    NSDLCASData,
    PortfolioSummary,
    Transaction,
    UserMetadata,
)
from app.services.pdf.parser_extensions import (
    parse_insurance_holdings,
    parse_bond_holdings,
    parse_gold_holdings,
    parse_alternative_holdings,
    parse_retirement_holdings,
)
from app.utils.encryption import encrypt_pii, hash_pii, mask_pan
# DISABLED: OpenAI integration - using deterministic parsing only
# from openai import AsyncOpenAI
from pyxirr import xirr
from tenacity import retry, stop_after_attempt, wait_exponential

logger = structlog.get_logger()


class NSDLCASParser:
    """
    Enhanced Parser for NSDL CAS (Consolidated Account Statement) PDF files.

    PII STORAGE POLICY (Issue #41):
    -------------------------------
    PII (holder name, PAN) is stored in ENCRYPTED form for ownership verification:

    - encrypted_holder_name: AES-256-GCM encrypted full name
    - encrypted_pan_last4: AES-256-GCM encrypted last 4 digits of PAN
    - pii_hash: SHA-256 hash for duplicate detection without decryption

    This ensures:
    1. Portfolio ownership can be verified if disputes arise
    2. Same user uploading multiple times can be detected
    3. Raw PII is never exposed in database queries or logs

    See also: app/utils/encryption.py for encryption implementation.
    """

    # NSDL CAS detection markers
    NSDL_MARKERS = [
        "NSDL",
        "National Securities Depository Limited",
        "Consolidated Account Statement",
        "CAS",
        "CONSOLIDATED ACCOUNT STATEMENT",
    ]

    # Required sections in NSDL CAS
    REQUIRED_SECTIONS = [
        "portfolio",
        "holdings",
        "equity",
    ]

    def __init__(self):
        # DISABLED: OpenAI integration - using deterministic parsing only
        # api_key = getattr(settings, "openai_api_key", None)
        # self.openai_client = (
        #     AsyncOpenAI(api_key=api_key) if api_key and api_key.strip() else None
        # )
        self.openai_client = None  # Disabled for production
        self.patterns = {
            "isin": re.compile(r"([A-Z]{2}[A-Z0-9]{10})"),
            "symbol": re.compile(r"([A-Z][A-Z0-9]{2,})(?:\.NSE|\.BSE)?"),
            "quantity": re.compile(r"([\d,]+\.?\d*)\s*(?:shares?|units?)"),
            "value": re.compile(r"₹\s*([\d,]+\.?\d*)"),
            "price": re.compile(r"₹\s*([\d,]+\.?\d*)\s*(?:per|/)?\s*(?:share|unit)?"),
            "date": re.compile(
                r"(\d{1,2}[-/]\w{3}[-/]\d{4}|\d{1,2}[-/]\d{1,2}[-/]\d{4})"
            ),
            "pan": re.compile(r"[A-Z]{5}[0-9]{4}[A-Z]"),
            "email": re.compile(r"[\w\.-]+@[\w\.-]+\.\w+"),
            "mobile": re.compile(r"(?:\+91)?[6-9]\d{9}"),
            "percentage": re.compile(r"([-+]?\d+\.?\d*)\s*%"),
            "folio": re.compile(r"(\d{5,15})"),
            "transaction": re.compile(
                r"(Buy|Purchase|Sell|Redemption|Switch\s+In|Switch\s+Out|Dividend).*?"
                r"([\d,]+\.?\d*).*?₹\s*([\d,]+\.?\d*)",
                re.IGNORECASE,
            ),
            "equity_section": r"(?:Equity\s+Shares?|Equities).*?(?=Mutual\s+Fund|Debt|Bond|Total|$)",
            "mutual_fund_section": r"(?:Mutual\s+Funds?).*?(?=Equity|Debt|Bond|Total|$)",
            "holdings_table": r"(?:Holdings?|Portfolio).*?(?:ISIN|Symbol|Name).*?(?:Quantity|Units).*?(?:Value|Amount)",
            # Insurance patterns
            "insurance_section": r"(?:Insurance|Life\s+Insurance|Health\s+Insurance|ULIP).*?(?=Equity|Mutual\s+Fund|Debt|Bond|Total|$)",
            "policy_number": re.compile(r"(?:Policy\s+No\.?|Policy\s+Number)[\s:]*([A-Z0-9/-]+)", re.IGNORECASE),
            "sum_assured": re.compile(r"(?:Sum\s+Assured|Cover\s+Amount)[\s:]*₹?\s*([\d,]+\.?\d*)", re.IGNORECASE),
            "premium": re.compile(r"(?:Premium|Annual\s+Premium)[\s:]*₹?\s*([\d,]+\.?\d*)", re.IGNORECASE),
            # Bond/Debt patterns
            "bond_section": r"(?:Bonds?|Debentures?|NCDs?|G-Sec|Government\s+Securities|Corporate\s+Bonds?).*?(?=Equity|Mutual\s+Fund|Insurance|Total|$)",
            "coupon_rate": re.compile(r"(?:Coupon|Interest\s+Rate)[\s:]*(\d+\.?\d*)\s*%", re.IGNORECASE),
            "credit_rating": re.compile(r"(?:Rating|Credit\s+Rating)[\s:]*(AAA|AA\+?|A\+?|BBB\+?|BB\+?|B\+?|C|D)", re.IGNORECASE),
            "maturity_date": re.compile(r"(?:Maturity|Maturity\s+Date)[\s:]*(\d{1,2}[-/]\w{3}[-/]\d{4}|\d{1,2}[-/]\d{1,2}[-/]\d{4})", re.IGNORECASE),
            # Gold patterns
            "gold_section": r"(?:Gold|Sovereign\s+Gold\s+Bond|SGB|Gold\s+ETF).*?(?=Equity|Mutual\s+Fund|Insurance|Total|$)",
            # Alternative investments
            "reit_section": r"(?:REIT|Real\s+Estate\s+Investment\s+Trust).*?(?=Equity|Mutual\s+Fund|Insurance|Total|$)",
            "invit_section": r"(?:InvIT|Infrastructure\s+Investment\s+Trust).*?(?=Equity|Mutual\s+Fund|Insurance|Total|$)",
            # Retirement accounts
            "nps_section": r"(?:NPS|National\s+Pension\s+System|Pension).*?(?=Equity|Mutual\s+Fund|Insurance|Total|$)",
            "ppf_section": r"(?:PPF|Public\s+Provident\s+Fund).*?(?=Equity|Mutual\s+Fund|Insurance|Total|$)",
            "account_number": re.compile(r"(?:Account\s+No\.?|A/C\s+No\.?|PRAN)[\s:]*([A-Z0-9/-]+)", re.IGNORECASE),
        }

    def detect_statement_type(self, pdf_text: str) -> str:
        """
        Detect if PDF is a valid NSDL CAS statement.

        Args:
            pdf_text: Extracted text from PDF

        Returns:
            "NSDL_CAS" if valid, raises UnsupportedFormatError otherwise

        Raises:
            UnsupportedFormatError: If not an NSDL CAS statement
        """
        if not pdf_text or len(pdf_text.strip()) < 100:
            raise UnreadableOrCorruptError(
                "PDF appears to be empty or contains too little text"
            )

        # Convert to lowercase for case-insensitive matching
        text_lower = pdf_text.lower()

        # Check for NSDL markers (must have at least 2)
        marker_count = sum(
            1 for marker in self.NSDL_MARKERS if marker.lower() in text_lower
        )

        if marker_count < 2:
            logger.warning(
                "nsdl_markers_not_found",
                marker_count=marker_count,
                text_preview=pdf_text[:200],
            )
            raise UnsupportedFormatError(
                "This does not appear to be an NSDL Consolidated Account Statement. "
                "Please upload an NSDL CAS PDF obtained from your broker or NSDL website."
            )

        # Check for at least one required section
        section_found = any(section in text_lower for section in self.REQUIRED_SECTIONS)

        if not section_found:
            logger.warning(
                "nsdl_required_sections_not_found",
                text_preview=pdf_text[:200],
            )
            raise UnsupportedFormatError(
                "This PDF appears to be an incomplete or modified NSDL statement. "
                "Required sections (portfolio, holdings) are missing."
            )

        # Check for ISIN patterns (NSDL CAS should have ISINs)
        isin_matches = self.patterns["isin"].findall(pdf_text)
        if len(isin_matches) < 1:
            logger.warning(
                "no_isin_codes_found",
                text_preview=pdf_text[:200],
            )
            raise UnsupportedFormatError(
                "No ISIN codes found in the statement. "
                "This may not be a valid NSDL CAS or may be missing holdings data."
            )

        logger.info(
            "nsdl_cas_detected",
            marker_count=marker_count,
            isin_count=len(isin_matches),
        )
        return "NSDL_CAS"

    async def _extract_portfolio_summary(
        self, doc: fitz.Document
    ) -> Optional[PortfolioSummary]:
        """Extract portfolio summary from the document"""
        try:
            for page_num in range(min(5, len(doc))):  # Usually in first few pages
                page = doc[page_num]
                text = page.get_text()

                # Look for consolidated portfolio value
                if "YOUR CONSOLIDATED PORTFOLIO VALUE" not in text.upper():
                    continue

                # Extract total value — handles both ₹ and backtick (PyMuPDF font variant)
                # Also handles inline format: "YOUR CONSOLIDATED PORTFOLIO VALUE\n` 3,34,230.92 Summary"
                total_match = re.search(
                    r"YOUR CONSOLIDATED PORTFOLIO VALUE[:\s]*[`₹]\s*([\d,]+\.?\d*)",
                    text,
                    re.IGNORECASE,
                )
                total_value = (
                    self._parse_indian_currency(total_match.group(1))
                    if total_match
                    else Decimal("0")
                )

                # Initialize summary
                summary = PortfolioSummary(
                    total_value=total_value,
                    nsdl_value=Decimal("0"),
                    nsdl_isin_count=0,
                    cdsl_value=Decimal("0"),
                    cdsl_isin_count=0,
                    mutual_fund_value=Decimal("0"),
                    mutual_fund_scheme_count=0,
                    unclaimed_amount=Decimal("0"),
                )

                # Extract NSDL data — value column uses backtick or rupee
                nsdl_match = re.search(
                    r"NSDL[^:]*[:\s]*(\d+)\s*ISINs?[^`₹]*([₹`])\s*([\d,]+\.?\d*)",
                    text,
                    re.IGNORECASE,
                )
                if nsdl_match:
                    summary.nsdl_isin_count = int(nsdl_match.group(1))
                    summary.nsdl_value = self._parse_indian_currency(nsdl_match.group(3))

                # Extract CDSL data
                cdsl_match = re.search(
                    r"CDSL[^:]*[:\s]*(\d+)\s*ISINs?[^`₹]*([₹`])\s*([\d,]+\.?\d*)",
                    text,
                    re.IGNORECASE,
                )
                if cdsl_match:
                    summary.cdsl_isin_count = int(cdsl_match.group(1))
                    summary.cdsl_value = self._parse_indian_currency(cdsl_match.group(3))

                # Extract Mutual Fund data
                mf_match = re.search(
                    r"Mutual Fund[^:]*[:\s]*(\d+)\s*(?:Schemes?|Folios?)[^`₹]*([₹`])\s*([\d,]+\.?\d*)",
                    text,
                    re.IGNORECASE,
                )
                if mf_match:
                    summary.mutual_fund_scheme_count = int(mf_match.group(1))
                    summary.mutual_fund_value = self._parse_indian_currency(mf_match.group(3))

                # Extract unclaimed amount
                unclaimed_match = re.search(
                    r"Unclaimed[^`₹]*([₹`])\s*([\d,]+\.?\d*)", text, re.IGNORECASE
                )
                if unclaimed_match:
                    summary.unclaimed_amount = self._parse_indian_currency(
                        unclaimed_match.group(2)
                    )

                logger.info("portfolio_summary_extracted", total_value=str(total_value))
                return summary

            logger.warning("portfolio_summary_not_found")
            return None

        except Exception as e:
            logger.error("summary_extraction_failed", error=str(e))
            return None

    async def _extract_user_metadata(
        self, doc: fitz.Document
    ) -> Optional[UserMetadata]:
        """Extract user metadata from the document"""
        try:
            for page_num in range(len(doc)):
                page = doc[page_num]
                text = page.get_text()

                # Look for PAN (unmasked or masked)
                if "pan" not in text.lower():
                    continue

                metadata = UserMetadata(
                    pan="",
                    email="",
                    mobile="",
                )

                # Extract PAN — handles both full PAN (ABCDE1234F) and masked (ABXXXXXX2J)
                # Use word boundary to avoid matching substrings of longer tokens
                pan_patterns = [
                    r"\b([A-Z]{5}[0-9]{4}[A-Z])\b",           # Full unmasked PAN
                    r"\b([A-Z]{2}X{4,6}[0-9]{1,2}[A-Z])\b",  # Masked: GUXXXXXX2J
                    r"PAN[:\s]*([A-Z0-9X]{10})\b",             # After "PAN:" label
                ]
                for pan_pat in pan_patterns:
                    pan_match = re.search(pan_pat, text)
                    if pan_match:
                        metadata.pan = pan_match.group(1)
                        break

                # Extract holder name
                # Priority 1: "NAME (PAN:XXXXXXXXXX)" pattern — most reliable in NSDL CAS
                name_patterns = [
                    # "SHAIK MOHAMMED ZUBER (PAN:GUEPS8812J)" or masked variant
                    r"([A-Z][A-Z\s]{5,60}?)\s*\(PAN:[A-Z0-9X]{10}\)",
                    # "In the Single Name of\nNAME (PAN:...)" — summary table
                    r"In the Single Name of[\s\n]+([A-Z][A-Z\s]{5,60}?)\s*\(",
                    # "ACCOUNT HOLDER\nNAME (PAN:...)" — holdings section header
                    r"ACCOUNT HOLDER[\s\n]+([A-Z][A-Z\s]{5,60}?)\s*\(",
                    # Standard "Name:" label patterns
                    r"(?:Name|Account Holder|Investor Name)[:\s]+([A-Z][A-Z\s]+?)(?:\n|PAN|Email|Mobile|Address)",
                    # Name before unmasked PAN
                    r"([A-Z][A-Z\s]{10,50}?)\s+PAN[:\s]*[A-Z]{5}\d{4}[A-Z]",
                ]

                for pattern in name_patterns:
                    name_match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                    if name_match:
                        holder_name = name_match.group(1).strip()
                        # Validate: length > 5, at least 2 words, no digits, uppercase
                        if (
                            len(holder_name) > 5
                            and len(holder_name.split()) >= 2
                            and not any(char.isdigit() for char in holder_name)
                            and holder_name.isupper()
                        ):
                            metadata.holder_name = holder_name
                            logger.debug("holder_name_extracted", name=holder_name)
                            break

                # Extract email
                email_match = self.patterns["email"].search(text)
                if email_match:
                    metadata.email = email_match.group(0)

                # Extract mobile
                mobile_match = self.patterns["mobile"].search(text)
                if mobile_match:
                    metadata.mobile = mobile_match.group(0)

                # Extract date of birth
                dob_match = re.search(
                    r"Date of Birth[:\s]*(\d{1,2}[-/]\d{1,2}[-/]\d{4})",
                    text,
                    re.IGNORECASE,
                )
                if dob_match:
                    metadata.date_of_birth = self._parse_indian_date(
                        dob_match.group(1)
                    )

                # Extract bank IFSC
                ifsc_match = re.search(
                    r"IFSC[:\s]*([A-Z]{4}0[A-Z0-9]{6})", text, re.IGNORECASE
                )
                if ifsc_match:
                    metadata.bank_ifsc = ifsc_match.group(1)

                # Check nominee status
                metadata.nominee_registered = (
                    "nominee" in text.lower()
                    and "not registered" not in text.lower()
                )

                if metadata.pan:  # Only return if we found at least PAN
                    logger.info(
                        "user_metadata_extracted",
                        pan_found=True,
                        has_holder_name=bool(getattr(metadata, "holder_name", None)),
                    )
                    return metadata

            logger.warning("user_metadata_not_found")
            return None

        except Exception as e:
            logger.error("metadata_extraction_failed", error=str(e))
            return None

    async def _extract_portfolio_trend(
        self, doc: fitz.Document
    ) -> List[Dict[str, Any]]:
        """
        Extract portfolio value trend over months.

        Uses structured table data (find_tables) as primary source since the trend
        table is always a proper table in both NSDL 2021 and CDSL 2025 formats.
        Falls back to regex on raw text if table extraction fails.
        """
        trend = []
        MONTH_ABBREVS = {
            "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
            "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
        }

        try:
            for page_num in range(min(6, len(doc))):
                page = doc[page_num]
                text = page.get_text()

                if "month" not in text.lower() or "portfolio value" not in text.lower():
                    continue

                # Primary: parse from structured table
                tables = page.find_tables()
                for table in tables:
                    rows = table.extract()
                    if not rows:
                        continue
                    # Check if this is the trend table (header: Month | Portfolio Value | Change | %)
                    header_text = " ".join(
                        str(c).lower() for c in rows[0] if c
                    )
                    if "month" not in header_text or "portfolio" not in header_text:
                        continue

                    for row in rows[1:]:
                        if not row or row[0] is None:
                            continue
                        month_str = str(row[0]).strip().upper()
                        # Validate: must be "MMM YYYY" format
                        parts = month_str.split()
                        if len(parts) != 2 or parts[0] not in MONTH_ABBREVS:
                            continue
                        try:
                            value_str = str(row[1]).strip() if len(row) > 1 and row[1] else "0"
                            value = float(self._parse_indian_currency(value_str))
                            entry: Dict[str, Any] = {"month": month_str, "value": value}

                            if len(row) > 2 and row[2] and str(row[2]).strip() not in ("NA", "", "None"):
                                try:
                                    entry["change"] = float(
                                        self._parse_indian_currency(str(row[2]))
                                    )
                                except:
                                    pass

                            if len(row) > 3 and row[3] and str(row[3]).strip() not in ("NA", "", "None"):
                                try:
                                    entry["change_percent"] = float(
                                        str(row[3]).replace("%", "").replace("+", "").strip()
                                    )
                                except:
                                    pass

                            trend.append(entry)
                        except Exception:
                            continue

                    if trend:
                        logger.info("portfolio_trend_extracted_from_table", months=len(trend))
                        return trend

                # Fallback: regex on raw text lines (handles backtick and rupee)
                lines = text.split("\n")
                for line in lines:
                    trend_match = re.search(
                        r"([A-Z]{3}\s+\d{4})\s+[`₹]?\s*([\d,]+\.?\d*)\s*([-+][\d,]+\.?\d*)?",
                        line,
                    )
                    if trend_match:
                        month_str = trend_match.group(1).strip().upper()
                        parts = month_str.split()
                        if len(parts) != 2 or parts[0] not in MONTH_ABBREVS:
                            continue
                        try:
                            value = float(self._parse_indian_currency(trend_match.group(2)))
                            entry = {"month": month_str, "value": value}
                            trend.append(entry)
                        except:
                            continue

                if trend:
                    logger.info("portfolio_trend_extracted_from_text", months=len(trend))
                    break

        except Exception as e:
            logger.error("trend_extraction_failed", error=str(e))

        return trend

    async def parse_pdf(
        self, pdf_base64: str, use_openai_fallback: bool = False, password: Optional[str] = None
    ) -> Optional[PortfolioCreate]:
        """
        Parse NSDL CAS PDF and extract portfolio information.

        Args:
            pdf_base64: Base64-encoded PDF bytes
            use_openai_fallback: DISABLED - Always False (deterministic parsing only)
            password: Optional password for encrypted PDFs

        Returns:
            PortfolioCreate object or None

        Raises:
            UnsupportedFormatError: If PDF is not NSDL CAS
            UnreadableOrCorruptError: If PDF is corrupted
            ParsingFailedError: If NSDL CAS detected but extraction failed
            PasswordProtectedError: If PDF is encrypted and no/wrong password provided
            IncorrectPasswordError: If provided password is incorrect
        """
        try:
            # Decode base64 PDF
            pdf_bytes = base64.b64decode(pdf_base64)

            # Validate PDF magic number
            if not pdf_bytes.startswith(b"%PDF"):
                raise UnreadableOrCorruptError(
                    "Invalid PDF file format - file does not start with PDF header"
                )

            # Open PDF document
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")

            # Check if PDF is password-protected or encrypted
            if doc.is_encrypted:
                if password:
                    # Try to authenticate with provided password
                    auth_result = doc.authenticate(password)
                    if not auth_result:
                        doc.close()
                        raise IncorrectPasswordError("Incorrect password for encrypted PDF")
                else:
                    doc.close()
                    raise PasswordProtectedError(
                        "This PDF is password-protected. Please provide the password to unlock it.",
                        needs_password=True
                    )
                
                logger.info("pdf_unlocked_with_password", has_user_password=auth_result == 1, has_owner_password=auth_result == 2)

            # Extract text using PyMuPDF for better extraction
            full_text, structured_data = await self._extract_text_pymupdf(pdf_bytes, password=password)

            # STEP 1: Detect and validate NSDL CAS (raises exception if not valid)
            statement_type = self.detect_statement_type(full_text)
            logger.info("statement_validated", type=statement_type)

            # STEP 2: Try structured extraction first (deterministic)
            holdings = await self._extract_holdings_structured(structured_data)

            # If no holdings found, try regex-based extraction (deterministic)
            if not holdings:
                holdings = await self._extract_holdings(full_text)

            # DISABLED: OpenAI fallback - using deterministic parsing only
            # if not holdings and use_openai_fallback and self.openai_client:
            #     logger.info(
            #         "using_openai_fallback_parser",
            #         reason="deterministic_extraction_failed",
            #         statement_type=statement_type,
            #     )
            #     holdings = await self._extract_holdings_with_openai(full_text)

            # If still no holdings after all attempts, this is a parsing failure
            if not holdings:
                logger.error(
                    "no_holdings_extracted_after_all_attempts",
                    statement_type=statement_type,
                )
                raise ParsingFailedError(
                    "Unable to extract holdings from the NSDL CAS statement. "
                    "The statement format may be unusual or contain no holdings."
                )

            # Validate holdings count (max 500)
            if len(holdings) > 500:
                logger.error(
                    "portfolio_too_large",
                    holdings_count=len(holdings),
                )
                raise PortfolioTooLargeError(
                    f"Portfolio has {len(holdings)} holdings, which exceeds the maximum limit of 500. "
                    "Please contact support if you need to upload larger portfolios."
                )

            # Extract additional data
            portfolio_summary = await self._extract_portfolio_summary(doc)
            user_metadata = await self._extract_user_metadata(doc)
            portfolio_trend = await self._extract_portfolio_trend(doc)

            # Close document when done
            doc.close()

            # Extract transactions from structured tables (demat movements)
            structured_transactions = await self._extract_transactions_structured(structured_data)

            # Extract transaction history for XIRR (regex fallback on raw text)
            transactions = await self._extract_transactions(full_text)

            # Calculate portfolio metrics
            total_value = sum(h.current_value for h in holdings)
            xirr_value = await self._calculate_xirr(holdings, transactions)
            risk_level = await self._assess_risk_level(holdings)

            # Validate XIRR range (-100% to +500%)
            if xirr_value < -100 or xirr_value > 500:
                logger.warning(
                    "xirr_outside_reasonable_range",
                    xirr=xirr_value,
                )
                raise InvalidXIRRError(
                    f"Calculated XIRR ({xirr_value}%) is outside the reasonable range (-100% to +500%). "
                    "This may indicate data quality issues in the statement."
                )

            # Validate portfolio size (₹1,000 to ₹10 crore)
            if total_value < 1000:
                logger.warning(
                    "portfolio_value_too_small",
                    total_value=total_value,
                )
                raise MissingRequiredDataError(
                    f"Portfolio value (₹{total_value:,.2f}) is too small. Minimum value is ₹1,000."
                )
            if total_value > 50000000000:  # ₹500 crore
                logger.warning(
                    "portfolio_value_too_large",
                    total_value=total_value,
                )
                raise MissingRequiredDataError(
                    f"Portfolio value (₹{total_value:,.2f}) exceeds ₹500 crore. "
                    "Please contact support for large portfolio uploads."
                )

            # Encrypt PII for ownership verification (Issue #41)
            encrypted_holder_name = None
            encrypted_pan_last4 = None
            pii_hash_value = None

            if user_metadata:
                # Extract holder name from the PDF (look for name patterns)
                holder_name = getattr(user_metadata, "holder_name", None) or ""
                pan = getattr(user_metadata, "pan", None) or ""

                if holder_name:
                    encrypted_holder_name = encrypt_pii(holder_name)
                if pan:
                    encrypted_pan_last4 = encrypt_pii(mask_pan(pan))
                    # Create hash from PAN only if holder_name is missing
                    if holder_name:
                        pii_hash_value = hash_pii(holder_name, pan)
                    else:
                        # Use PAN-only hash when holder name not available
                        pii_hash_value = hash_pii("", pan)

                logger.info(
                    "pii_encrypted_for_verification",
                    has_holder_name=bool(holder_name),
                    has_pan=bool(pan),
                    has_hash=bool(pii_hash_value),
                )

            # Create portfolio object
            portfolio = PortfolioCreate(
                title="NSDL CAS Portfolio",
                description=f"Portfolio imported from NSDL CAS statement on {datetime.now().strftime('%Y-%m-%d')}",
                total_value=total_value,
                risk_level=risk_level,
                holdings=holdings,
                transactions=structured_transactions,
                xirr=xirr_value,
                encrypted_holder_name=encrypted_holder_name,
                encrypted_pan_last4=encrypted_pan_last4,
                pii_hash=pii_hash_value,
            )

            # Validate extracted data
            self._validate_extracted_data(holdings, total_value)

            logger.info(
                "pdf_parsed_successfully",
                holdings_count=len(holdings),
                total_value=total_value,
                xirr=xirr_value,
            )
            return portfolio

        except (
            UnsupportedFormatError,
            UnreadableOrCorruptError,
            ParsingFailedError,
            PasswordProtectedError,
            IncorrectPasswordError,
            PortfolioTooLargeError,
            InvalidXIRRError,
        ):
            # Re-raise validation errors without retry
            raise
        except Exception as e:
            logger.error("pdf_parsing_failed", error=str(e), exc_info=True)
            # DISABLED: OpenAI recovery - using deterministic parsing only
            # if use_openai_fallback and self.openai_client:
            #     try:
            #         logger.info("attempting_openai_recovery", error=str(e))
            #         return await self._parse_with_openai_recovery(pdf_base64)
            #     except Exception as recovery_error:
            #         logger.error("openai_recovery_failed", error=str(recovery_error))
            # Convert generic exceptions to ParsingFailedError
            raise ParsingFailedError(f"Failed to parse NSDL CAS statement: {str(e)}")

    async def _extract_text_pymupdf(self, pdf_bytes: bytes, password: Optional[str] = None) -> Tuple[str, List[Dict]]:
        """Extract text and structured data using PyMuPDF"""
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        
        # Authenticate if password provided and PDF is encrypted
        if doc.is_encrypted and password:
            doc.authenticate(password)
        
        full_text = ""
        structured_data = []

        for page_num, page in enumerate(doc):
            # Get text with better formatting
            text = page.get_text("text")
            full_text += text + "\n"

            # Try to extract tables
            tables = page.find_tables()
            for table in tables:
                structured_data.append(
                    {"page": page_num, "data": table.extract(), "bbox": table.bbox}
                )

        doc.close()
        return full_text, structured_data

    # Sentinel ISIN values that indicate special/non-standard holdings
    _SENTINEL_ISINS = frozenset({
        "NOT AVAILABLE", "NOTAVAILABLE", "UNCLAIMDISIN", "ISIN SUSPENDED",
        "NA", "N/A",
    })

    # ISIN prefix to asset_type mapping
    _ISIN_ASSET_TYPE = {
        "INE": "equity",
        "INF": "mutual_fund",
        "IN0": "sgb",          # Sovereign Gold Bonds
        "INB": "bond",
        "IND": "bond",
    }

    @staticmethod
    def _normalize_cell(cell: Any) -> str:
        """
        Normalize a table cell for header matching.

        Bilingual PDFs rendered by PyMuPDF interleave Devanagari chars with ASCII,
        producing garbled headers like 'IISSIINN' (every char doubled) or
        'SJeKcurKity' (Hindi chars interspersed).

        Strategy:
          1. Strip non-ASCII (Devanagari, control chars) - fixes partial garbling.
          2. For each whitespace-delimited token, if it is fully doubled
             (every consecutive pair is the same char, even length), halve it.
             Fixes 'IISSIINN' -> 'ISIN' without breaking 'Current' (rr is not
             a fully-doubled token).
        """
        if cell is None:
            return ""
        text = str(cell)
        ascii_only = re.sub(r"[^\x20-\x7E]", "", text)

        def _dedup_token(tok: str) -> str:
            # Try repetition factors 2, 3, 4 — bilingual PDFs can double or triple chars
            for n in (2, 3, 4):
                if len(tok) < n * 2 or len(tok) % n != 0:
                    continue
                if all(len(set(tok[i : i + n])) == 1 for i in range(0, len(tok), n)):
                    return tok[::n]
            return tok

        return " ".join(_dedup_token(t) for t in ascii_only.split()).strip()

    def _classify_asset_type(self, isin: str) -> str:
        """Classify asset type from ISIN prefix."""
        if not isin:
            return "mutual_fund"
        prefix = isin[:3].upper()
        return self._ISIN_ASSET_TYPE.get(prefix, "equity" if isin.startswith("INE") else "mutual_fund")

    def _is_holdings_table(self, table_data: List[List]) -> Optional[str]:
        """
        Detect if a table is a holdings table and return its schema type.

        Returns:
            'nsdl_equity'       - NSDL 2021: ISIN+Symbol | Company | Shares | Price | Value
            'cdsl_equity'       - CDSL merged-cell: ISIN | Security | Current Bal (merged) | Price | Value
            'cdsl_holding_stmt' - CDSL bilingual: ISIN | Security | Cur Bal | Frozen | Pledge | Free Bal | Price | Value
            'mutual_fund'       - MF folio: ISIN+UCC | Description | Folio | Units | NAV | Value
            None                - Not a holdings table
        """
        for row in table_data[:3]:
            norm_cells = [self._normalize_cell(cell).lower() for cell in row if cell]
            row_text = " ".join(norm_cells)
            if "isin" not in row_text:
                continue
            # Transaction table (Op.Bal / Credit / Debit / Cl.Bal) — skip
            if "credit" in row_text and "debit" in row_text:
                continue
            if "shares" in row_text or "stock symbol" in row_text:
                return "nsdl_equity"
            # CDSL holding statement: ISIN | Security | Cur Bal | Frozen | Pledge | Free Bal | Price | Value
            # Detect by: ISIN in first cell + "bal" keyword present + 7+ columns
            # (garbling makes 'security'/'current bal' unreliable, but structure is stable)
            has_bal = any("bal" in c or "balance" in c for c in norm_cells)
            col_count = len([c for c in row if c is not None])
            if has_bal and col_count >= 7:
                return "cdsl_holding_stmt"
            # CDSL equity (merged cell variant): ISIN | Security | Current Bal (merged) | Price | Value
            if "security" in row_text and ("current bal" in row_text or "free bal" in row_text):
                return "cdsl_equity"
            if "units" in row_text or "nav" in row_text or "folio" in row_text:
                return "mutual_fund"
        return None

    async def _extract_holdings_structured(
        self, structured_data: List[Dict]
    ) -> List[Holding]:
        """Extract holdings from structured table data"""
        holdings: List[Holding] = []

        logger.info("structured_tables_found", count=len(structured_data))

        for idx, table_info in enumerate(structured_data):
            table_data = table_info.get("data", [])
            if not table_data:
                continue

            schema = self._is_holdings_table(table_data)
            if schema is None:
                continue

            logger.info(
                "holdings_table_found", table_index=idx, rows=len(table_data), schema=schema
            )
            parsed = await self._parse_table_holdings(table_data, schema=schema)
            logger.info("holdings_parsed_from_table", count=len(parsed), schema=schema)
            holdings.extend(parsed)

        return holdings

    async def _parse_table_holdings(
        self, table_data: List[List], schema: str = "nsdl_equity"
    ) -> List[Holding]:
        """
        Parse holdings from table data.

        Supports four schemas:
        - 'nsdl_equity':       NSDL 2021 (ISIN+Symbol | Company | Face Value | Shares | Price | Value)
        - 'cdsl_equity':       CDSL 2025 holdings (ISIN | Security | Current Bal merged | ... | Price | Value)
        - 'cdsl_holding_stmt': CDSL bilingual (ISIN | Security | Cur Bal | Frozen | Pledge | Free Bal | Market Price | Value)
        - 'mutual_fund':       MF folio (ISIN+UCC | Description | Folio | Units | Cost | NAV | Value)
        """
        holdings: List[Holding] = []
        if len(table_data) < 2:
            return holdings

        # Find header row (may not be first row)
        # Use _normalize_cell to handle bilingual/garbled headers
        header_row_idx = 0
        for i, row in enumerate(table_data[:4]):
            row_text = " ".join([self._normalize_cell(cell).lower() for cell in row if cell])
            if "isin" in row_text and (
                "shares" in row_text or "units" in row_text
                or "security" in row_text or "current bal" in row_text
                or "nav" in row_text
            ):
                header_row_idx = i
                break

        # Build normalized headers: strip Hindi chars, deduplicate doubled ASCII, flatten newlines
        headers = [
            self._normalize_cell(h).lower().replace("\n", " ") if h is not None else ""
            for h in table_data[header_row_idx]
        ]
        logger.debug("table_headers", headers=headers, schema=schema)

        # Build column index map based on schema
        if schema == "cdsl_holding_stmt":
            # CDSL bilingual holding statement — fixed 9-col structure (headers garbled by Hindi):
            # [0]ISIN [1]Security [2]CurBal [3]Frozen [4]Pledge [5]PledgeSetup [6]FreeBal [7]MarketPrice [8]Value
            # Use positional fallbacks since header text is unreliable after normalization.
            n = len(headers)
            isin_col = next((i for i, h in enumerate(headers) if "isin" in h), 0)
            name_col = next((i for i, h in enumerate(headers) if "security" in h), 1 if n > 1 else None)
            # Free Bal (col 6) = actual holdable qty; fall back to Current Bal (col 2)
            qty_col = next(
                (i for i, h in enumerate(headers) if "ee bal" in h),
                next((i for i, h in enumerate(headers) if "current" in h), 6 if n > 6 else 2),
            )
            price_col = n - 2 if n >= 2 else None  # second-to-last
            value_col = n - 1 if n >= 1 else None  # last
            indices = {
                "isin": isin_col,
                "symbol": None,
                "name": name_col,
                "quantity": qty_col,
                "price": price_col,
                "value": value_col,
            }
        elif schema == "cdsl_equity":
            # CDSL 2025 merged-cell: ISIN | Security | Current Bal (merged) | Price | Value
            indices = {
                "isin": next(
                    (i for i, h in enumerate(headers) if h.strip() == "isin"),
                    next((i for i, h in enumerate(headers) if h.startswith("isin")), None),
                ),
                "symbol": None,
                "name": next((i for i, h in enumerate(headers) if "security" in h), None),
                "quantity": next(
                    (i for i, h in enumerate(headers) if "free bal" in h),
                    next((i for i, h in enumerate(headers) if "current bal" in h), None),
                ),
                "price": next(
                    (i for i, h in enumerate(headers) if "market" in h and ("price" in h or "value" in h)),
                    next((i for i, h in enumerate(headers) if "face value" in h or "face" in h), None),
                ),
                "value": next(
                    (i for i, h in enumerate(headers) if "value" in h and "face" not in h and "market" not in h),
                    len(headers) - 1 if headers else None,
                ),
            }
        elif schema == "mutual_fund":
            # MF: ISIN+UCC | Description | Folio | Units | Avg Cost | Total Cost | Current NAV | Current Value | Unrealised P/L | Annualised Return
            indices = {
                "isin": next((i for i, h in enumerate(headers) if "isin" in h), None),
                "symbol": None,
                "name": next((i for i, h in enumerate(headers) if "description" in h or "isin description" in h), None),
                "quantity": next((i for i, h in enumerate(headers) if "units" in h and "no" in h), None),
                "price": next((i for i, h in enumerate(headers) if "nav" in h and "current" in h), None),
                "value": next(
                    (i for i, h in enumerate(headers) if "current value" in h),
                    next((i for i, h in enumerate(headers) if "value" in h and "face" not in h), None),
                ),
                "cost": next((i for i, h in enumerate(headers) if "total cost" in h), None),
            }
        else:
            # NSDL 2021 equity: ISIN+Symbol | Company Name | Face Value | No. of Shares | Market Price | Value
            indices = {
                "isin": next((i for i, h in enumerate(headers) if "isin" in h), None),
                "symbol": next(
                    (i for i, h in enumerate(headers) if "symbol" in h or "stock" in h),
                    None,
                ),
                "name": next(
                    (i for i, h in enumerate(headers) if "company" in h or "name" in h),
                    None,
                ),
                "quantity": next(
                    (i for i, h in enumerate(headers) if "shares" in h or "no. of" in h),
                    None,
                ),
                "price": next(
                    (i for i, h in enumerate(headers) if "market" in h and "price" in h),
                    None,
                ),
                "value": next(
                    (i for i, h in enumerate(headers) if "value" in h and "face" not in h),
                    len(headers) - 1 if headers else None,
                ),
            }

        logger.info("column_indices", indices=indices, schema=schema)

        # Parse rows starting after header
        rows_processed = 0
        rows_rejected = 0
        for row in table_data[header_row_idx + 1:]:
            try:
                rows_processed += 1

                # Skip rows that are clearly subtotal/total rows
                first_cell = str(row[0]).strip().lower() if row and row[0] is not None else ""
                if first_cell in ("sub total", "total", "grand total", ""):
                    continue

                # Skip rows where all cells are None (spacer rows)
                if all(cell is None for cell in row):
                    continue

                if (
                    indices.get("isin") is None
                    or indices.get("value") is None
                ):
                    logger.debug("row_skipped_missing_indices", row_num=rows_processed)
                    rows_rejected += 1
                    continue

                # --- Extract ISIN ---
                isin_col = indices["isin"]  # guaranteed non-None by guard above
                assert isin_col is not None
                isin_cell = str(row[isin_col]).strip() if isin_col < len(row) and row[isin_col] is not None else ""

                # NSDL format: ISIN and symbol are newline-separated in one cell
                # CDSL format: ISIN is a standalone cell
                cell_lines = isin_cell.split("\n")
                isin = cell_lines[0].strip()
                # For NSDL equity, second line is the stock symbol
                inline_symbol = cell_lines[1].strip() if len(cell_lines) > 1 else ""

                # Handle sentinel ISIN values (unclaimed amounts, suspended ISINs)
                isin_upper = isin.upper().replace(" ", "")
                is_sentinel = (
                    isin_upper in {s.replace(" ", "") for s in self._SENTINEL_ISINS}
                    or "SUSPENDED" in isin_upper
                    or "NOTAVAILABLE" in isin_upper
                    or "UNCLAIM" in isin_upper
                )

                if is_sentinel:
                    # Still try to extract value for unclaimed amounts
                    val_col = indices["value"]  # guaranteed non-None by guard above
                    assert val_col is not None
                    sentinel_value = (
                        self._parse_number(row[val_col])
                        if val_col < len(row) and row[val_col] is not None
                        else 0.0
                    )
                    if sentinel_value > 0:
                        name_col = indices.get("name")
                        sentinel_name = (
                            str(row[name_col]).replace("\n", " ").strip()
                            if name_col is not None and name_col < len(row) and row[name_col] is not None
                            else "Unclaimed Amount"
                        )
                        holding = Holding(
                            symbol="UNCLAIMED",
                            name=sentinel_name or "Unclaimed Amount",
                            quantity=1.0,
                            avg_price=sentinel_value,
                            current_price=sentinel_value,
                            current_value=sentinel_value,
                            percentage=0,
                            isin="",
                            asset_type="unclaimed",
                        )
                        holdings.append(holding)
                        logger.info("sentinel_isin_holding_captured", name=sentinel_name, value=sentinel_value)
                    else:
                        logger.debug("sentinel_isin_skipped_zero_value", isin=isin)
                    continue

                # Validate ISIN format
                if not self.patterns["isin"].match(isin):
                    if not inline_symbol or len(inline_symbol) < 2:
                        logger.debug(
                            "row_skipped_invalid_isin_and_no_symbol",
                            row_num=rows_processed,
                            isin=isin[:20] if isin else "empty",
                        )
                        rows_rejected += 1
                        continue
                    else:
                        logger.warning("holding_missing_isin_using_symbol", row_num=rows_processed, symbol=inline_symbol)
                        isin = ""

                # --- Extract name ---
                name_col = indices.get("name")
                if name_col is not None and name_col < len(row) and row[name_col] is not None:
                    name = str(row[name_col]).replace("\n", " ").strip()
                    # Remove trailing notes like "# NEW EQUITY SHARES..."
                    name = re.sub(r"\s*#.*$", "", name).strip()
                else:
                    name = inline_symbol or isin

                # --- Extract quantity ---
                quantity = 0.0
                qty_col = indices.get("quantity")
                if qty_col is not None and qty_col < len(row) and row[qty_col] is not None:
                    qty_raw = str(row[qty_col])
                    if schema == "cdsl_equity":
                        # CDSL merged cell: "35.000\n35.000\n0.000" — first value is Current Balance
                        qty_raw = qty_raw.split("\n")[0].strip()
                    # cdsl_holding_stmt: "--" means zero (sold/transferred); parse normally
                    quantity = self._parse_number(qty_raw)

                # --- Extract value ---
                val_col = indices["value"]  # guaranteed non-None by guard above
                assert val_col is not None
                value = (
                    self._parse_number(row[val_col])
                    if val_col < len(row) and row[val_col] is not None
                    else 0.0
                )

                # Skip zero-quantity or zero-value holdings (e.g., sold positions)
                if quantity <= 0 or value <= 0:
                    logger.debug(
                        "row_skipped_zero_qty_or_value",
                        isin=isin, quantity=quantity, value=value
                    )
                    continue

                # --- Extract price ---
                price_col = indices.get("price")
                if price_col is not None and price_col < len(row) and row[price_col] is not None:
                    price_raw = str(row[price_col]).strip()
                    # Skip non-numeric price cells (e.g., "See Note", "--")
                    # Use _parse_number which already returns 0.0 for non-numeric strings
                    price = self._parse_number(price_raw)
                else:
                    price = 0.0
                if price <= 0 and quantity > 0:
                    price = value / quantity

                # --- Extract cost (MF only) ---
                avg_price = price
                if schema == "mutual_fund":
                    cost_col = indices.get("cost")
                    if cost_col is not None and cost_col < len(row) and row[cost_col] is not None:
                        total_cost = self._parse_number(row[cost_col])
                        if total_cost > 0 and quantity > 0:
                            avg_price = total_cost / quantity

                # --- Determine symbol ---
                symbol = inline_symbol
                if not symbol and indices.get("symbol") is not None:
                    sym_col = indices["symbol"]
                    if sym_col < len(row) and row[sym_col] is not None:
                        symbol = str(row[sym_col]).strip()
                if not symbol:
                    symbol = isin[:6] if isin else "UNKNOWN"

                # --- Classify asset type ---
                asset_type = self._classify_asset_type(isin)
                if schema == "mutual_fund":
                    asset_type = "mutual_fund"

                holding = Holding(
                    symbol=symbol,
                    name=name or symbol or isin,
                    quantity=quantity,
                    avg_price=avg_price,
                    current_price=price,
                    current_value=value,
                    percentage=0,
                    isin=isin,
                    asset_type=asset_type,
                )
                holdings.append(holding)
            except Exception as e:
                logger.debug(
                    "row_parsing_error",
                    error=str(e),
                    row=str(row[:3]) if len(row) > 3 else str(row),
                )
                rows_rejected += 1
                continue

        logger.info(
            "table_parsing_complete",
            schema=schema,
            total_rows=rows_processed,
            rejected=rows_rejected,
            parsed=len(holdings),
        )
        return holdings

    async def _extract_holdings(self, text: str) -> List[Holding]:
        """Extract holdings from PDF text using regex"""
        holdings: List[Holding] = []

        # Find equity section
        equity_match = re.search(
            self.patterns["equity_section"], text, re.DOTALL | re.IGNORECASE
        )
        if equity_match:
            equity_text = equity_match.group(0)
            holdings.extend(await self._parse_equity_holdings(equity_text))

        # Find mutual fund section
        mf_match = re.search(
            self.patterns["mutual_fund_section"], text, re.DOTALL | re.IGNORECASE
        )
        if mf_match:
            mf_text = mf_match.group(0)
            holdings.extend(await self._parse_mutual_fund_holdings(mf_text))

        # Find insurance section
        insurance_match = re.search(
            self.patterns["insurance_section"], text, re.DOTALL | re.IGNORECASE
        )
        if insurance_match:
            insurance_text = insurance_match.group(0)
            holdings.extend(await parse_insurance_holdings(insurance_text, self.patterns))

        # Find bond/debt section
        bond_match = re.search(
            self.patterns["bond_section"], text, re.DOTALL | re.IGNORECASE
        )
        if bond_match:
            bond_text = bond_match.group(0)
            holdings.extend(await parse_bond_holdings(bond_text, self.patterns))

        # Find gold section
        gold_match = re.search(
            self.patterns["gold_section"], text, re.DOTALL | re.IGNORECASE
        )
        if gold_match:
            gold_text = gold_match.group(0)
            holdings.extend(await parse_gold_holdings(gold_text, self.patterns))

        # Find REIT section
        reit_match = re.search(
            self.patterns["reit_section"], text, re.DOTALL | re.IGNORECASE
        )
        if reit_match:
            reit_text = reit_match.group(0)
            holdings.extend(await parse_alternative_holdings(reit_text, self.patterns, "reit"))

        # Find InvIT section
        invit_match = re.search(
            self.patterns["invit_section"], text, re.DOTALL | re.IGNORECASE
        )
        if invit_match:
            invit_text = invit_match.group(0)
            holdings.extend(await parse_alternative_holdings(invit_text, self.patterns, "invit"))

        # Find NPS section
        nps_match = re.search(
            self.patterns["nps_section"], text, re.DOTALL | re.IGNORECASE
        )
        if nps_match:
            nps_text = nps_match.group(0)
            holdings.extend(await parse_retirement_holdings(nps_text, self.patterns, "nps"))

        # Find PPF section
        ppf_match = re.search(
            self.patterns["ppf_section"], text, re.DOTALL | re.IGNORECASE
        )
        if ppf_match:
            ppf_text = ppf_match.group(0)
            holdings.extend(await parse_retirement_holdings(ppf_text, self.patterns, "ppf"))

        return holdings

    def _parse_number(self, value: Any) -> float:
        """Parse number from various formats. Handles ₹ and backtick (PyMuPDF renders ₹ as ` in some fonts)."""
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            # Remove currency symbols (₹ and backtick variant), commas, whitespace
            cleaned = re.sub(r"[₹`$,\s]", "", value)
            try:
                return float(cleaned)
            except:
                return 0.0
        return 0.0

    def _parse_indian_currency(self, value: str) -> Decimal:
        """Parse Indian currency format: ₹1,23,456.78 or `1,23,456.78 (backtick = PyMuPDF rupee variant)."""
        cleaned = re.sub(r"[₹`,\s]", "", value).strip()
        try:
            return Decimal(cleaned)
        except:
            return Decimal("0")

    def _parse_indian_date(self, date_str: str) -> Optional[date]:
        """Parse formats: DD-MMM-YYYY, DD/MM/YYYY"""
        if not date_str:
            return None

        # Clean the date string
        date_str = date_str.strip()

        # Try different date formats
        formats = [
            "%d-%b-%Y",  # 02-Mar-2021
            "%d-%b-%y",  # 02-Mar-21
            "%d/%m/%Y",  # 02/03/2021
            "%d-%m-%Y",  # 02-03-2021
            "%d/%m/%y",  # 02/03/21
            "%d-%m-%y",  # 02-03-21
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str.upper(), fmt).date()
            except ValueError:
                continue

        logger.debug("date_parse_failed", date_str=date_str)
        return None

    def _extract_broker_name(self, description: str) -> Optional[str]:
        """Extract broker from transaction description"""
        # "By CM ICICI SECURITIES LIMITED" -> "ICICI SECURITIES LIMITED"
        patterns = [
            r"By CM (.+?)(?:\s+ELECTRONIC)?$",
            r"From (.+?)(?:\s+ELECTRONIC)?$",
            r"Through (.+?)(?:\s+ELECTRONIC)?$",
        ]
        for pattern in patterns:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _validate_extracted_data(
        self, holdings: List[Holding], total_value: float
    ) -> None:
        """
        Validate extracted holdings data for consistency.

        Args:
            holdings: List of extracted holdings
            total_value: Total portfolio value

        Raises:
            MissingRequiredDataError: If data is invalid
        """
        if not holdings:
            raise MissingRequiredDataError(
                "No holdings were extracted from the statement"
            )

        # Validate each holding has required fields
        for i, holding in enumerate(holdings):
            if not holding.symbol and not holding.isin:
                raise MissingRequiredDataError(
                    f"Holding #{i+1} is missing both symbol and ISIN"
                )

            if holding.quantity <= 0:
                raise MissingRequiredDataError(
                    f"Holding {holding.symbol or holding.isin} has invalid quantity: {holding.quantity}"
                )

            if holding.current_value <= 0:
                raise MissingRequiredDataError(
                    f"Holding {holding.symbol or holding.isin} has invalid value: {holding.current_value}"
                )

            # Validate ISIN format if present
            if holding.isin and not self.patterns["isin"].match(holding.isin):
                raise MissingRequiredDataError(
                    f"Holding {holding.symbol or holding.isin} has invalid ISIN format"
                )

        # Validate total value matches sum of holdings (with 10% tolerance)
        holdings_sum = sum(h.current_value for h in holdings)
        if holdings_sum > 0 and total_value > 0:
            difference_pct = abs(holdings_sum - total_value) / total_value
            if difference_pct > 0.10:  # More than 10% difference
                logger.warning(
                    "holdings_sum_mismatch",
                    holdings_sum=holdings_sum,
                    total_value=total_value,
                    difference_pct=difference_pct * 100,
                )

        logger.info(
            "data_validation_passed",
            holdings_count=len(holdings),
            total_value=total_value,
        )

    # DISABLED: OpenAI extraction - using deterministic parsing only
    # The _extract_holdings_with_openai method has been removed to eliminate AI dependencies.
    # All PDF parsing now uses deterministic methods: structured table extraction and regex patterns.

    async def _extract_transactions_structured(
        self, structured_data: List[Dict]
    ) -> List[PortfolioTransaction]:
        """
        Extract transactions from structured demat transaction tables.

        CDSL bilingual transaction table layout (9 cols, headers garbled):
          [0] ISIN  [1] Security  [2] Txn Particulars  [3] Date
          [4] Op.Bal  [5] Credit  [6] Debit  [7] Cl.Bal  [8] Stamp Duty
        """
        transactions: List[PortfolioTransaction] = []

        for table_info in structured_data:
            rows = table_info.get("data", [])
            if len(rows) < 2:
                continue

            # Detect transaction table structurally:
            #   - ISIN present in first cell (after normalization handles 2x/3x garbling)
            #   - Exactly 9 columns (ISIN|Security|Particulars|Date|OpBal|Credit|Debit|ClBal|StampDuty)
            #   - NOT already classified as a holdings table (which has "bal" + 7+ cols)
            norm_hdr = [self._normalize_cell(c).lower() for c in rows[0] if c]
            norm_hdr_text = " ".join(norm_hdr)
            n = len(rows[0])

            if "isin" not in norm_hdr_text:
                continue

            # Holdings tables have 8-9 cols too — distinguish by "date" column presence
            # Transaction tables always have a date column; holding tables do not
            has_date = any("date" in h for h in norm_hdr)
            if not has_date:
                continue

            # Must have at least 7 columns and ISIN in first position
            if n < 7:
                continue

            # Determine column positions — positional fallback for garbled headers
            n = len(rows[0])
            isin_col = next((i for i, h in enumerate(norm_hdr) if "isin" in h), 0)
            name_col = 1 if n > 1 else None
            particulars_col = 2 if n > 2 else None
            date_col = next((i for i, h in enumerate(norm_hdr) if "date" in h), 3 if n > 3 else None)
            op_bal_col = 4 if n > 4 else None
            credit_col = next((i for i, h in enumerate(norm_hdr) if "credit" in h or "cred" in h), 5 if n > 5 else None)
            debit_col = next((i for i, h in enumerate(norm_hdr) if "debit" in h or "deb" in h), 6 if n > 6 else None)
            cl_bal_col = 7 if n > 7 else None

            logger.debug(
                "transaction_table_detected",
                rows=len(rows),
                cols=n,
                norm_hdr=norm_hdr,
            )

            for row_num, row in enumerate(rows[1:], start=1):
                try:
                    if not row or isin_col >= len(row) or not row[isin_col]:
                        continue

                    isin = str(row[isin_col]).strip()
                    if not re.match(r"^[A-Z]{2}[A-Z0-9]{10}$", isin):
                        continue

                    # Asset name — strip newlines
                    asset_name = ""
                    if name_col is not None and name_col < len(row) and row[name_col]:
                        asset_name = str(row[name_col]).replace("\n", " ").strip()

                    # Date
                    txn_date: Optional[date] = None
                    if date_col is not None and date_col < len(row) and row[date_col]:
                        date_str = str(row[date_col]).strip()
                        for fmt in ["%d-%m-%Y", "%d/%m/%Y", "%d-%b-%Y", "%d-%b-%y"]:
                            try:
                                txn_date = datetime.strptime(date_str.upper(), fmt).date()
                                break
                            except ValueError:
                                continue
                    if txn_date is None:
                        continue

                    # Credit / Debit quantities
                    credit_qty = 0.0
                    debit_qty = 0.0
                    if credit_col is not None and credit_col < len(row) and row[credit_col]:
                        credit_qty = self._parse_number(str(row[credit_col]))
                    if debit_col is not None and debit_col < len(row) and row[debit_col]:
                        debit_qty = self._parse_number(str(row[debit_col]))

                    if credit_qty == 0.0 and debit_qty == 0.0:
                        continue

                    # Determine transaction type and net quantity
                    if credit_qty > 0 and debit_qty == 0:
                        txn_type = "CREDIT"
                        quantity = credit_qty
                    elif debit_qty > 0 and credit_qty == 0:
                        txn_type = "DEBIT"
                        quantity = debit_qty
                    else:
                        txn_type = "CREDIT" if credit_qty >= debit_qty else "DEBIT"
                        quantity = max(credit_qty, debit_qty)

                    # Refine type from transaction particulars (e.g. "EP-DR" = early payout debit)
                    if particulars_col is not None and particulars_col < len(row) and row[particulars_col]:
                        particulars = str(row[particulars_col]).upper()
                        if "EP-DR" in particulars or "DEBIT" in particulars:
                            txn_type = "DEBIT"
                        elif "EP-CR" in particulars or "CREDIT" in particulars:
                            txn_type = "CREDIT"
                        elif "BUY" in particulars or "PURCHASE" in particulars:
                            txn_type = "BUY"
                        elif "SELL" in particulars or "REDEMPTION" in particulars:
                            txn_type = "SELL"

                    # Opening / closing balances
                    op_bal = None
                    cl_bal = None
                    if op_bal_col is not None and op_bal_col < len(row) and row[op_bal_col]:
                        v = self._parse_number(str(row[op_bal_col]))
                        if v != 0.0:
                            op_bal = v
                    if cl_bal_col is not None and cl_bal_col < len(row) and row[cl_bal_col]:
                        v = self._parse_number(str(row[cl_bal_col]))
                        if v != 0.0:
                            cl_bal = v

                    # Reference from particulars
                    reference = None
                    if particulars_col is not None and particulars_col < len(row) and row[particulars_col]:
                        ref_match = re.search(r"Txn:(\d+)", str(row[particulars_col]))
                        if ref_match:
                            reference = ref_match.group(1)

                    transactions.append(
                        PortfolioTransaction(
                            isin=isin,
                            asset_name=asset_name,
                            transaction_type=txn_type,
                            date=txn_date.isoformat(),
                            quantity=quantity,
                            reference=reference,
                            op_bal=op_bal,
                            cl_bal=cl_bal,
                        )
                    )
                except Exception as e:
                    logger.debug("structured_transaction_parse_error", row_num=row_num, error=str(e))

        logger.info("structured_transactions_extracted", count=len(transactions))
        return transactions

    async def _extract_transactions(self, text: str) -> List[Dict[str, Any]]:
        """Extract transaction history for XIRR calculation"""
        transactions = []

        # Look for transaction patterns
        lines = text.split("\n")
        for line in lines:
            # Match buy/sell transactions (pattern already compiled with IGNORECASE)
            trans_match = self.patterns["transaction"].search(line)
            if trans_match:
                trans_type = trans_match.group(1)
                quantity = self._parse_number(trans_match.group(2))
                amount = self._parse_number(trans_match.group(3))

                # Try to find date near this line
                date_match = self.patterns["date"].search(line)
                if date_match:
                    date_str = date_match.group(1)
                    try:
                        # Parse date — initialize to None to avoid NameError if all formats fail
                        trans_date = None
                        for fmt in ["%d-%m-%Y", "%d/%m/%Y", "%d-%b-%Y", "%d-%b-%y"]:
                            try:
                                trans_date = datetime.strptime(date_str.upper(), fmt)
                                break
                            except:
                                continue

                        if trans_date is None:
                            continue

                        # Determine cash flow sign
                        if trans_type.lower() in ["buy", "purchase"]:
                            cash_flow = -amount  # Outflow
                        else:
                            cash_flow = amount  # Inflow

                        transactions.append(
                            {
                                "date": trans_date,
                                "amount": cash_flow,
                                "type": trans_type,
                            }
                        )
                    except Exception as e:
                        logger.debug("transaction_parse_error", error=str(e))

        return transactions

    async def _parse_equity_holdings(self, text: str) -> List[Holding]:
        """Parse equity holdings from text"""
        holdings: List[Holding] = []

        # Split by common delimiters
        lines = text.split("\n")

        # Basic pattern matching for equity holdings
        # This is simplified - real implementation would need more sophisticated parsing
        for i in range(len(lines)):
            line = lines[i]

            # Look for ISIN patterns
            isin_match = self.patterns["isin"].search(line)
            if isin_match:
                isin = isin_match.group(1)

                # Try to extract other details from nearby lines
                symbol = self._extract_symbol(lines, i)
                quantity = self._extract_quantity(lines, i)
                value = self._extract_value(lines, i)

                if symbol and quantity and value:
                    holding = Holding(
                        symbol=symbol,
                        name=symbol,  # Would need company name lookup
                        quantity=quantity,
                        avg_price=value / quantity if quantity > 0 else 0,
                        current_price=value / quantity if quantity > 0 else 0,
                        current_value=value,
                        percentage=0,  # Will be calculated later
                        isin=isin,
                        asset_type="equity",
                    )
                    holdings.append(holding)

        return holdings

    async def _parse_mutual_fund_holdings(self, text: str) -> List[Holding]:
        """Parse mutual fund holdings from text"""
        holdings: List[Holding] = []

        # Split into lines for processing
        lines = text.split("\n")

        i = 0
        while i < len(lines):
            line = lines[i]

            # Look for ISIN pattern in mutual fund context
            isin_match = self.patterns["isin"].search(line)
            if isin_match and "INF" in isin_match.group(
                1
            ):  # MF ISINs typically start with INF
                isin = isin_match.group(1)

                # Extract scheme name (may be on same or next line)
                scheme_name = ""
                for j in range(i, min(i + 3, len(lines))):
                    if "fund" in lines[j].lower() or "scheme" in lines[j].lower():
                        scheme_name = lines[j].strip()
                        # Remove ISIN from scheme name if present
                        scheme_name = self.patterns["isin"].sub("", scheme_name).strip()
                        break

                # Extract units
                units = 0.0
                units_match = re.search(
                    r"([\d,]+\.?\d*)\s*units?",
                    " ".join(lines[i : i + 3]),
                    re.IGNORECASE,
                )
                if units_match:
                    units = self._parse_number(units_match.group(1))

                # Extract NAV
                nav = 0.0
                nav_match = re.search(
                    r"nav[\s:]*₹?\s*([\d,]+\.?\d*)",
                    " ".join(lines[i : i + 3]),
                    re.IGNORECASE,
                )
                if nav_match:
                    nav = self._parse_number(nav_match.group(1))

                # Extract value
                value = 0.0
                value_match = self.patterns["value"].search(" ".join(lines[i : i + 3]))
                if value_match:
                    value = self._parse_number(value_match.group(1))

                if units > 0 and value > 0:
                    holding = Holding(
                        symbol=isin[:8],  # Use first 8 chars as symbol
                        name=scheme_name or isin,
                        quantity=units,
                        avg_price=nav if nav > 0 else value / units,
                        current_price=nav if nav > 0 else value / units,
                        current_value=value,
                        percentage=0,
                        isin=isin,
                        asset_type="mutual_fund",
                    )
                    holdings.append(holding)

            i += 1

        return holdings

    def _extract_symbol(self, lines: List[str], current_index: int) -> Optional[str]:
        """Extract symbol from nearby lines"""
        for offset in range(-2, 3):
            if 0 <= current_index + offset < len(lines):
                match = re.search(r"([A-Z]{3,})", lines[current_index + offset])
                if match:
                    return match.group(1)
        return None

    def _extract_quantity(self, lines: List[str], current_index: int) -> float:
        """Extract quantity from nearby lines"""
        for offset in range(-2, 3):
            if 0 <= current_index + offset < len(lines):
                match = re.search(
                    r"([\d,]+\.?\d*)\s*(?:shares?|units?)",
                    lines[current_index + offset],
                    re.IGNORECASE,
                )
                if match:
                    return float(match.group(1).replace(",", ""))
        return 0.0

    def _extract_value(self, lines: List[str], current_index: int) -> float:
        """Extract value from nearby lines"""
        for offset in range(-2, 3):
            if 0 <= current_index + offset < len(lines):
                match = re.search(r"₹\s*([\d,]+\.?\d*)", lines[current_index + offset])
                if match:
                    return float(match.group(1).replace(",", ""))
        return 0.0

    async def _calculate_xirr(
        self, holdings: List[Holding], transactions: List[Dict[str, Any]]
    ) -> float:
        """Calculate XIRR for the portfolio using pyxirr"""
        if not transactions and not holdings:
            return 0.0

        try:
            # If we have transaction history, use it for XIRR
            if transactions:
                dates = [t["date"] for t in transactions]
                amounts = [t["amount"] for t in transactions]

                # Add current value as final cash flow
                current_value = sum(h.current_value for h in holdings)
                dates.append(datetime.now())
                amounts.append(current_value)

                # Calculate XIRR
                xirr_value = xirr(dates, amounts)
                return round(xirr_value * 100, 2)  # Convert to percentage

            # Fallback: estimate based on holdings
            total_current = sum(h.current_value for h in holdings)
            total_invested = sum(h.avg_price * h.quantity for h in holdings)

            if total_invested > 0:
                # Simple annualized return (assuming 1 year holding)
                simple_return = (
                    (total_current - total_invested) / total_invested
                ) * 100
                return round(simple_return, 2)

        except Exception as e:
            logger.error("xirr_calculation_failed", error=str(e))

        return 0.0

    async def _assess_risk_level(self, holdings: List[Holding]) -> RiskLevel:
        """Assess portfolio risk level based on holdings"""
        if not holdings:
            return RiskLevel.MODERATE

        # Calculate equity percentage
        equity_value = sum(
            h.current_value for h in holdings if h.asset_type == "equity"
        )
        total_value = sum(h.current_value for h in holdings)

        if total_value == 0:
            return RiskLevel.MODERATE

        equity_percentage = (equity_value / total_value) * 100

        # Determine risk level based on equity allocation
        if equity_percentage >= 70:
            return RiskLevel.AGGRESSIVE
        elif equity_percentage >= 40:
            return RiskLevel.MODERATE
        else:
            return RiskLevel.CONSERVATIVE

    # DISABLED: OpenAI recovery - using deterministic parsing only
    # The _parse_with_openai_recovery method has been removed to eliminate AI dependencies.


pdf_parser = NSDLCASParser()


def parse_cas_pdf(pdf_bytes: bytes) -> Dict[str, Any]:
    """
    Synchronous wrapper for parsing CAS PDF from bytes.
    Used for unit tests and simple parsing scenarios.

    Args:
        pdf_bytes: Raw PDF file bytes

    Returns:
        Dict with keys:
        - status: "success" or "error"
        - error_code: Structured error code if error
        - message: Error message if status is "error"
        - holdings: List of holdings dicts
        - total_value: Total portfolio value
        - xirr: Annualized return percentage
    """
    try:
        if not pdf_bytes:
            return {
                "status": "error",
                "error_code": "UNREADABLE_OR_CORRUPT",
                "message": "Empty PDF data provided",
            }

        # Convert bytes to base64
        pdf_base64 = base64.b64encode(pdf_bytes).decode()

        # Parse using async method (run in sync context)
        portfolio = asyncio.run(
            pdf_parser.parse_pdf(pdf_base64, use_openai_fallback=False)
        )

        if not portfolio:
            return {
                "status": "error",
                "error_code": "PARSING_FAILED",
                "message": "Failed to extract holdings from PDF",
                "holdings": [],
            }

        # Convert PortfolioCreate to dict
        return {
            "status": "success",
            "holdings": [h.model_dump() for h in portfolio.holdings],
            "total_value": portfolio.total_value,
            "xirr": portfolio.xirr,
            "risk_level": portfolio.risk_level.value,
        }

    except (
        UnsupportedFormatError,
        UnreadableOrCorruptError,
        ParsingFailedError,
        MissingRequiredDataError,
    ) as e:
        # Structured validation errors
        logger.warning(
            "parse_cas_pdf_validation_error", error_code=e.error_code, message=e.message
        )
        return {
            "status": "error",
            "error_code": e.error_code,
            "message": e.message,
            "holdings": [],
        }
    except Exception as e:
        logger.error("parse_cas_pdf_error", error=str(e), exc_info=True)
        return {
            "status": "error",
            "error_code": "INTERNAL_ERROR",
            "message": str(e),
            "holdings": [],
        }
