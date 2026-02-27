"""
PDF parsing specific exceptions for structured error handling
"""


class PDFValidationError(Exception):
    """Base exception for PDF validation errors"""

    def __init__(self, message: str, error_code: str):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


class UnsupportedFormatError(PDFValidationError):
    """PDF is not a supported format (e.g., not NSDL CAS)"""

    def __init__(self, message: str = "This PDF is not a supported statement format"):
        super().__init__(message, error_code="UNSUPPORTED_FORMAT")


class UnreadableOrCorruptError(PDFValidationError):
    """PDF is damaged, corrupted, or impossible to parse"""

    def __init__(self, message: str = "PDF file is corrupted or unreadable"):
        super().__init__(message, error_code="UNREADABLE_OR_CORRUPT")


class ParsingFailedError(PDFValidationError):
    """PDF is valid NSDL CAS but extraction failed"""

    def __init__(
        self, message: str = "Unable to extract consistent holdings from the PDF"
    ):
        super().__init__(message, error_code="PARSING_FAILED")


class MissingRequiredDataError(PDFValidationError):
    """Required data fields are missing or invalid"""

    def __init__(self, message: str = "Required data is missing or invalid"):
        super().__init__(message, error_code="MISSING_REQUIRED_DATA")


class InternalError(PDFValidationError):
    """Unexpected server-side failure"""

    def __init__(self, message: str = "An unexpected error occurred"):
        super().__init__(message, error_code="INTERNAL_ERROR")


class PasswordProtectedError(PDFValidationError):
    """PDF is password-protected or encrypted"""

    def __init__(self, message: str = "PDF is password-protected", needs_password: bool = True):
        super().__init__(message, error_code="PASSWORD_PROTECTED")
        self.needs_password = needs_password


class IncorrectPasswordError(PDFValidationError):
    """Incorrect password provided for encrypted PDF"""

    def __init__(self, message: str = "Incorrect password for encrypted PDF", attempts: int = 1):
        super().__init__(message, error_code="INCORRECT_PASSWORD")
        self.attempts = attempts


class PortfolioTooLargeError(PDFValidationError):
    """Portfolio has too many holdings"""

    def __init__(self, message: str = "Portfolio has too many holdings"):
        super().__init__(message, error_code="PORTFOLIO_TOO_LARGE")


class InvalidXIRRError(PDFValidationError):
    """XIRR value is outside reasonable range"""

    def __init__(self, message: str = "XIRR value is outside reasonable range"):
        super().__init__(message, error_code="INVALID_XIRR")


class MalwareDetectedError(PDFValidationError):
    """Malware or malicious content detected in PDF"""

    def __init__(self, message: str = "Malware detected in PDF"):
        super().__init__(message, error_code="MALWARE_DETECTED")


class InvalidFileTypeError(PDFValidationError):
    """File is not a valid PDF (magic bytes mismatch)"""

    def __init__(self, message: str = "File is not a valid PDF"):
        super().__init__(message, error_code="INVALID_FILE_TYPE")


class FileTooComplexError(PDFValidationError):
    """PDF is too large or complex (>100 pages or >500 holdings)"""

    def __init__(self, message: str = "PDF is too large or complex"):
        super().__init__(message, error_code="FILE_TOO_COMPLEX")


class FileTooSmallError(PDFValidationError):
    """File is suspiciously small"""

    def __init__(self, message: str = "File is too small to be a valid statement"):
        super().__init__(message, error_code="FILE_TOO_SMALL")


# Error code to user-friendly message mapping
ERROR_MESSAGES = {
    "UNSUPPORTED_FORMAT": {
        "title": "Unsupported Statement Format",
        "message": "Please upload an NSDL Consolidated Account Statement (CAS) PDF.",
        "help": "You can download your NSDL CAS from https://www.camsonline.com/InvestorServices/COL_ISAccountStatementRequest.aspx",
    },
    "UNREADABLE_OR_CORRUPT": {
        "title": "Unreadable or Corrupted PDF",
        "message": "The PDF file appears to be damaged or corrupted.",
        "help": "Please try downloading a fresh copy of your statement and uploading again.",
    },
    "PARSING_FAILED": {
        "title": "Extraction Failed",
        "message": "We couldn't extract consistent holdings from your statement.",
        "help": "This might be due to an unusual statement format. Please contact support.",
    },
    "MISSING_REQUIRED_DATA": {
        "title": "Missing Required Information",
        "message": "Some required information is missing from the statement.",
        "help": "Ensure your statement includes complete holding information with ISIN codes and values.",
    },
    "INTERNAL_ERROR": {
        "title": "Server Error",
        "message": "An unexpected error occurred while processing your statement.",
        "help": "Please try again. If the problem persists, contact support.",
    },
    "PASSWORD_PROTECTED": {
        "title": "Password-Protected PDF",
        "message": "This PDF is password-protected or encrypted.",
        "help": "Please remove the password protection and upload an unprotected PDF.",
    },
    "PORTFOLIO_TOO_LARGE": {
        "title": "Portfolio Too Large",
        "message": "This portfolio has too many holdings (maximum 500 allowed).",
        "help": "Please upload a statement with fewer holdings or contact support for assistance.",
    },
    "INVALID_XIRR": {
        "title": "Invalid Returns Calculation",
        "message": "The calculated returns (XIRR) are outside the reasonable range.",
        "help": "This may indicate data quality issues. Please verify your statement or contact support.",
    },
    "MALWARE_DETECTED": {
        "title": "Security Threat Detected",
        "message": "This file contains potentially malicious content.",
        "help": "For security reasons, we cannot process this file. Please upload a clean PDF from your broker.",
    },
    "INVALID_FILE_TYPE": {
        "title": "Invalid File Type",
        "message": "The uploaded file is not a valid PDF document.",
        "help": "Please ensure you're uploading a PDF file, not a renamed document or image.",
    },
    "FILE_TOO_COMPLEX": {
        "title": "File Too Complex",
        "message": "This PDF is too large or complex to process (>100 pages or >500 holdings).",
        "help": "Please upload a smaller statement or contact support for assistance with large portfolios.",
    },
    "FILE_TOO_SMALL": {
        "title": "File Too Small",
        "message": "This file is too small to be a valid portfolio statement.",
        "help": "Please ensure you're uploading a complete PDF statement, not a partial or corrupted file.",
    },
}
