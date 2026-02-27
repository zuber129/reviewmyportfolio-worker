"""Custom exceptions for domain-specific errors"""

from typing import Any, Dict, Optional


class DomainException(Exception):
    """Base exception for all domain errors"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


# Authentication & Authorization Errors
class AuthenticationError(DomainException):
    """Raised when authentication fails"""

    pass


class AuthorizationError(DomainException):
    """Raised when user lacks permission"""

    pass


class TokenExpiredError(AuthenticationError):
    """Raised when auth token has expired"""

    pass


class InvalidTokenError(AuthenticationError):
    """Raised when auth token is invalid"""

    pass


# User & Profile Errors
class UserNotFoundError(DomainException):
    """Raised when user does not exist"""

    pass


class ProfileNotFoundError(DomainException):
    """Raised when profile does not exist"""

    pass


class UsernameAlreadyExistsError(DomainException):
    """Raised when username is taken"""

    pass


# Portfolio Errors
class PortfolioNotFoundError(DomainException):
    """Raised when portfolio does not exist"""

    pass


class PortfolioAccessDeniedError(AuthorizationError):
    """Raised when user cannot access portfolio"""

    pass


# Access Control Errors
class AccessControlError(AuthorizationError):
    """Base exception for access control violations"""

    def __init__(
        self, message: str, error_code: str, details: Optional[Dict[str, Any]] = None
    ):
        self.error_code = error_code
        super().__init__(message, details)


class ShareToBrowseRequiredError(AccessControlError):
    """Raised when user must upload portfolio to browse community content"""

    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="You must upload your first portfolio to browse community content. Share to browse!",
            error_code="SHARE_TO_BROWSE_REQUIRED",
            details=details,
        )


class AccessBlockedError(AccessControlError):
    """Raised when user's account is blocked due to no uploads for 75+ days"""

    def __init__(
        self,
        days_since_upload: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        msg = (
            f"Your account has been blocked after {days_since_upload} days without a portfolio upload. "
            "Upload a portfolio to restore access."
            if days_since_upload
            else "Your account has been blocked. Upload a portfolio to restore access."
        )
        super().__init__(
            message=msg,
            error_code="ACCESS_BLOCKED_REQUIRES_UPLOAD",
            details=details or {"days_since_upload": days_since_upload},
        )


class InvalidPortfolioDataError(DomainException):
    """Raised when portfolio data is invalid"""

    pass


# XIRR Calculation Errors
class XIRRCalculationError(DomainException):
    """Raised when XIRR calculation fails"""

    pass


class InsufficientTransactionsError(XIRRCalculationError):
    """Raised when not enough transactions for XIRR"""

    pass


class InvalidCashFlowsError(XIRRCalculationError):
    """Raised when cash flows are invalid (all same sign)"""

    pass


# PDF Parsing Errors
class PDFParsingError(DomainException):
    """Raised when PDF parsing fails"""

    pass


class UnsupportedPDFFormatError(PDFParsingError):
    """Raised when PDF format is not supported"""

    pass


# External Service Errors
class ExternalServiceError(DomainException):
    """Raised when external service call fails"""

    pass


class SupabaseError(ExternalServiceError):
    """Raised when Supabase operation fails"""

    pass


class RedisError(ExternalServiceError):
    """Raised when Redis operation fails"""

    pass


class RateLimitExceededError(ExternalServiceError):
    """Raised when rate limit is exceeded"""

    pass


# Validation Errors
class ValidationError(DomainException):
    """Raised when input validation fails"""

    pass


# PII Validation Errors
class PIIValidationError(DomainException):
    """Base exception for PII validation failures"""

    pass


class DuplicatePANError(PIIValidationError):
    """Raised when PAN already exists for different user"""

    def __init__(self, pan_hash: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="This portfolio belongs to another user. Each user can only upload their own portfolio.",
            details=details or {"pii_hash": pan_hash}
        )


class MultiplePANError(PIIValidationError):
    """Raised when user tries to upload portfolio with different PAN"""

    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="You can only upload portfolios associated with one PAN number.",
            details=details
        )


class MissingPANError(PIIValidationError):
    """Raised when PAN extraction fails"""

    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Could not extract PAN from the uploaded document. Please ensure your CAS statement contains valid PAN information.",
            details=details
        )
