"""
Parsing Flow State Machine.

Replaces the 400-line _parse_and_save() function with a clean SM pipeline.
Each step is a focused action with centralized error handling.
"""

import base64
from datetime import date
from typing import Any, Dict, Optional
from statemachine import State
import structlog

from .base import FlowMachine

logger = structlog.get_logger(__name__)


class ParsingFlowMachine(FlowMachine):
    """
    State machine for PDF parsing flow (in-memory, not DB-persisted).
    
    Manages the complete parsing pipeline from download to snapshot creation.
    Each state represents a discrete step with focused actions.
    """
    
    downloading = State(initial=True, value="downloading")
    validating_file = State(value="validating_file")
    scanning_malware = State(value="scanning_malware")
    extracting_holdings = State(value="extracting_holdings")
    validating_pii = State(value="validating_pii")
    checking_duplicates = State(value="checking_duplicates")
    saving_snapshot = State(value="saving_snapshot")
    done = State(value="done", final=True)
    error = State(value="error", final=True)
    
    download = downloading.to(validating_file)
    validate = validating_file.to(scanning_malware)
    scan = scanning_malware.to(extracting_holdings)
    extract = extracting_holdings.to(validating_pii)
    validate_pii = validating_pii.to(checking_duplicates)
    check_duplicates = checking_duplicates.to(saving_snapshot)
    save = saving_snapshot.to(done)
    
    fail_from_downloading = downloading.to(error)
    fail_from_validating = validating_file.to(error)
    fail_from_scanning = scanning_malware.to(error)
    fail_from_extracting = extracting_holdings.to(error)
    fail_from_validating_pii = validating_pii.to(error)
    fail_from_checking = checking_duplicates.to(error)
    fail_from_saving = saving_snapshot.to(error)
    
    def __init__(
        self,
        context: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize parsing flow machine.
        
        Args:
            context: Parsing context (pdf_url, user_id, file_id, etc.)
            **kwargs: Additional context
        """
        super().__init__(model=context or {}, **kwargs)
        self.context = context or {}
        self.result: Optional[Dict[str, Any]] = None
    
    def fail(self, error_code: str, error_message: str, exception: Optional[Exception] = None):
        """
        Trigger failure from any state.
        
        Args:
            error_code: Error code for categorization
            error_message: Human-readable error message
            exception: Original exception if available
        """
        self.error_code = error_code
        self.error_message = error_message
        
        if exception:
            self.context["exception"] = exception
            self.context["exception_type"] = type(exception).__name__
        
        current = self.current_state.value
        if current == "downloading":
            self.fail_from_downloading()
        elif current == "validating_file":
            self.fail_from_validating()
        elif current == "scanning_malware":
            self.fail_from_scanning()
        elif current == "extracting_holdings":
            self.fail_from_extracting()
        elif current == "validating_pii":
            self.fail_from_validating_pii()
        elif current == "checking_duplicates":
            self.fail_from_checking()
        elif current == "saving_snapshot":
            self.fail_from_saving()
        else:
            logger.warning(
                "fail_from_unexpected_state",
                state=current,
                error_code=error_code
            )
    
    def on_enter_downloading(self):
        """Action: Log download start."""
        self.log_transition("start", "init", "downloading")
        logger.info(
            "parsing_flow_started",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id")
        )
    
    def on_enter_validating_file(self):
        """Action: Log validation start."""
        self.log_transition("download", "downloading", "validating_file")
        logger.info(
            "validating_pdf",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id")
        )
    
    def on_enter_scanning_malware(self):
        """Action: Log scanning start."""
        self.log_transition("validate", "validating_file", "scanning_malware")
        logger.info(
            "scanning_malware",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id")
        )
    
    def on_enter_extracting_holdings(self):
        """Action: Log extraction start."""
        self.log_transition("scan", "scanning_malware", "extracting_holdings")
        logger.info(
            "extracting_holdings",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id")
        )
    
    def on_enter_validating_pii(self):
        """Action: Log PII validation start."""
        self.log_transition("extract", "extracting_holdings", "validating_pii")
        logger.info(
            "validating_pii",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id")
        )
    
    def on_enter_checking_duplicates(self):
        """Action: Log duplicate check start."""
        self.log_transition("validate_pii", "validating_pii", "checking_duplicates")
        logger.info(
            "checking_duplicates",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id")
        )
    
    def on_enter_saving_snapshot(self):
        """Action: Log snapshot save start."""
        self.log_transition("check_duplicates", "checking_duplicates", "saving_snapshot")
        logger.info(
            "saving_snapshot",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id")
        )
    
    def on_enter_done(self):
        """Action: Log completion."""
        self.log_transition("save", "saving_snapshot", "done")
        logger.info(
            "parsing_flow_completed",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id"),
            snapshot_id=self.result.get("snapshot_id") if self.result else None
        )
    
    def on_enter_error(self):
        """Action: Log error."""
        from_state = self.current_state.value if hasattr(self.current_state, 'value') else 'unknown'
        self.log_transition("fail", from_state, "error")
        logger.error(
            "parsing_flow_failed",
            user_id=self.context.get("user_id"),
            file_id=self.context.get("file_id"),
            error_code=self.error_code,
            error_message=self.error_message,
            from_state=from_state
        )
