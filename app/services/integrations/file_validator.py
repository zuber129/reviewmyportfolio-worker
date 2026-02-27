"""
File validation service for uploaded PDFs.
Provides comprehensive validation including magic bytes, structure checks, and size limits.
"""

import magic
import structlog
from typing import Dict, Any
import fitz

from app.services.pdf.exceptions import (
    UnreadableOrCorruptError,
    PasswordProtectedError,
    PDFValidationError,
)

logger = structlog.get_logger()


class FileValidator:
    """
    Validates uploaded PDF files for security and integrity.
    """

    MAX_FILE_SIZE = 10 * 1024 * 1024
    MAX_PAGE_COUNT = 100
    MAX_HOLDINGS_COUNT = 500

    def __init__(self):
        self.magic = magic.Magic(mime=True)

    def validate_magic_bytes(self, pdf_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Validate PDF magic bytes and MIME type"""
        try:
            mime_type = self.magic.from_buffer(pdf_bytes)
            
            if mime_type != "application/pdf":
                logger.warning(
                    "invalid_mime_type",
                    detected_mime=mime_type,
                    filename=filename,
                )
                raise PDFValidationError(
                    "File is not a valid PDF (magic bytes mismatch)",
                    error_code="INVALID_FILE_TYPE"
                )
            
            if not pdf_bytes.startswith(b"%PDF-1."):
                raise PDFValidationError(
                    "Invalid PDF header",
                    error_code="INVALID_FILE_TYPE"
                )
            
            logger.info("magic_bytes_valid", filename=filename, mime_type=mime_type)
            return {"valid": True, "mime_type": mime_type}
            
        except PDFValidationError:
            raise
        except Exception as e:
            logger.error("magic_bytes_validation_failed", error=str(e), filename=filename)
            raise UnreadableOrCorruptError("Failed to validate file type")

    def validate_pdf_structure(self, pdf_bytes: bytes, password: str = None) -> Dict[str, Any]:
        """Validate PDF structure for security issues
        
        Args:
            pdf_bytes: PDF file bytes
            password: Optional password to decrypt encrypted PDFs
        """
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            
            if doc.is_encrypted:
                logger.info("pdf_is_encrypted", has_password=password is not None)
                if password:
                    # Try to decrypt with provided password
                    logger.info("attempting_decrypt", password_provided=True, password_length=len(password))
                    auth_result = doc.authenticate(password)
                    logger.info("decrypt_attempt_result", auth_result=auth_result, result_type=type(auth_result).__name__)
                    if not auth_result:
                        doc.close()
                        from app.services.pdf.exceptions import IncorrectPasswordError
                        logger.error("decrypt_failed", password_length=len(password))
                        raise IncorrectPasswordError("Incorrect password for encrypted PDF")
                    logger.info("pdf_decrypted_successfully", password_length=len(password), auth_result=auth_result)
                else:
                    doc.close()
                    raise PasswordProtectedError("PDF is password-protected or encrypted")
            
            warnings = []
            
            # Check for JavaScript using catalog inspection (PyMuPDF 1.23.0+)
            try:
                # Check if PDF has JavaScript actions in the catalog
                catalog = doc.pdf_catalog()
                if catalog and "Names" in catalog:
                    names_dict = catalog["Names"]
                    if isinstance(names_dict, dict) and "JavaScript" in names_dict:
                        warnings.append("PDF contains JavaScript")
                        logger.warning("pdf_contains_javascript", page_count=doc.page_count)
            except Exception as e:
                # JavaScript detection is optional, don't fail validation
                logger.debug("javascript_check_skipped", reason=str(e))
            
            if doc.embfile_count() > 0:
                warnings.append(f"PDF has {doc.embfile_count()} embedded files")
                logger.warning("pdf_has_embedded_files", count=doc.embfile_count())
            
            page_count = doc.page_count
            doc.close()
            
            if page_count > self.MAX_PAGE_COUNT:
                raise PDFValidationError(
                    f"PDF has too many pages ({page_count} > {self.MAX_PAGE_COUNT})",
                    error_code="FILE_TOO_COMPLEX"
                )
            
            logger.info(
                "pdf_structure_valid",
                page_count=page_count,
                warnings=warnings
            )
            
            return {
                "valid": True,
                "page_count": page_count,
                "warnings": warnings
            }
            
        except PasswordProtectedError:
            raise
        except PDFValidationError:
            raise
        except Exception as e:
            logger.error("pdf_structure_validation_failed", error=str(e))
            raise UnreadableOrCorruptError("Failed to validate PDF structure")

    def validate_file_size(self, pdf_bytes: bytes) -> Dict[str, Any]:
        """Validate file size is within acceptable limits"""
        file_size = len(pdf_bytes)
        
        if file_size > self.MAX_FILE_SIZE:
            raise PDFValidationError(
                f"File too large ({file_size / 1024 / 1024:.1f}MB > 10MB)",
                error_code="FILE_TOO_LARGE"
            )
        
        logger.info("file_size_valid", size_mb=file_size / 1024 / 1024)
        return {"valid": True, "size_bytes": file_size}

    def validate_all(self, pdf_bytes: bytes, filename: str, password: str = None) -> Dict[str, Any]:
        """Run all validation checks
        
        Args:
            pdf_bytes: PDF file bytes
            filename: Original filename
            password: Optional password to decrypt encrypted PDFs
        """
        results = {}
        
        # 1. Validate size
        results["size"] = self.validate_file_size(pdf_bytes)
        
        # 2. Validate magic bytes
        results["magic_bytes"] = self.validate_magic_bytes(pdf_bytes, filename)
        
        # 3. Validate PDF structure (with optional password)
        results["structure"] = self.validate_pdf_structure(pdf_bytes, password=password)
        
        logger.info(
            "file_validation_complete",
            filename=filename,
            all_checks_passed=True
        )
        
        return results


file_validator = FileValidator()
