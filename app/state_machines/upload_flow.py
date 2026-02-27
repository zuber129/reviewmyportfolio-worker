"""
Upload Flow State Machine.

Manages the complete lifecycle of PDF upload, validation, scanning, and parsing.
Handles password-protected PDFs with retry limits.
"""

import asyncio
from typing import Any, Dict, Optional
from statemachine import State
import structlog

from .base import FlowMachine
from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger(__name__)


class UploadFlowMachine(FlowMachine):
    """
    State machine for PDF upload flow.
    
    States map to portfolio_files.status column.
    Handles transitions, guards, and DB persistence.
    """
    
    uploaded = State(initial=True, value="uploaded")
    validating = State(value="validating")
    scanning = State(value="scanning")
    parsing = State(value="parsing")
    completed = State(value="completed", final=True)
    failed = State(value="failed", final=True)
    password_required = State(value="password_required")
    
    file_uploaded = uploaded.to(uploaded)
    start_validation = uploaded.to(validating)
    validation_passed = validating.to(scanning)
    need_password = validating.to(password_required)
    scan_passed = scanning.to(parsing)
    parsing_complete = parsing.to(completed)
    
    password_provided = password_required.to(uploaded, cond="can_unlock")
    password_incorrect = password_required.to(password_required, cond="can_unlock")
    max_unlock_attempts = password_required.to(failed)
    
    fail_from_uploaded = uploaded.to(failed)
    fail_from_validating = validating.to(failed)
    fail_from_scanning = scanning.to(failed)
    fail_from_parsing = parsing.to(failed)
    
    def __init__(self, model: Optional[Dict[str, Any]] = None, **kwargs):
        """
        Initialize upload flow machine.
        
        Args:
            model: portfolio_files record as dict
            **kwargs: Additional context (user_id, etc.)
        """
        super().__init__(model=model, **kwargs)
        
        if model and "status" in model:
            current_status = model["status"]
            try:
                self.current_state = getattr(self, current_status)
            except AttributeError:
                logger.warning(
                    "unknown_status_in_model",
                    status=current_status,
                    file_id=model.get("id"),
                    defaulting_to="uploaded"
                )
                self.current_state = self.uploaded
    
    def sync_to_db(self):
        """Persist current state to database."""
        if not self.model or "id" not in self.model:
            logger.warning("sync_to_db_no_model_id")
            return
        
        asyncio.run(
            supabase_client.update_file_status(
                file_id=self.model["id"],
                status=self.current_state.value,
                error_code=self.error_code,
                error_message=self.error_message,
            )
        )
    
    def on_enter_validating(self):
        """Action: Update DB when entering validating state."""
        self.log_transition("start_validation", "uploaded", "validating")
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="validating",
                )
            )
    
    def on_enter_scanning(self):
        """Action: Update DB when entering scanning state."""
        self.log_transition("validation_passed", "validating", "scanning")
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="scanning",
                )
            )
    
    def on_enter_parsing(self):
        """Action: Update DB when entering parsing state."""
        self.log_transition("scan_passed", "scanning", "parsing")
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="parsing",
                )
            )
    
    def on_enter_completed(self):
        """Action: Update DB when entering completed state."""
        self.log_transition("parsing_complete", "parsing", "completed")
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="completed",
                    error_code=None,
                    error_message=None,
                )
            )
    
    def on_enter_password_required(self):
        """Action: Update DB when password is required."""
        self.log_transition("need_password", "validating", "password_required")
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="password_required",
                    error_code="PASSWORD_PROTECTED",
                    error_message="PDF is password protected. Please provide the password to continue.",
                )
            )
    
    def on_password_incorrect(self):
        """Action: Increment unlock attempts, stay in password_required."""
        unlock_attempts = self.model.get("unlock_attempts", 0) + 1
        self.model["unlock_attempts"] = unlock_attempts
        
        remaining = 3 - unlock_attempts
        self.error_message = f"Incorrect password. {remaining} attempt{'s' if remaining != 1 else ''} remaining."
        
        logger.info(
            "password_incorrect",
            file_id=self.model.get("id"),
            unlock_attempts=unlock_attempts,
            remaining=remaining
        )
        
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="password_required",
                    unlock_attempts=unlock_attempts,
                    error_message=self.error_message,
                )
            )
    
    def on_password_provided(self):
        """Action: Clear error, transition to uploaded for reprocessing."""
        self.log_transition("password_provided", "password_required", "uploaded")
        self.error_code = None
        self.error_message = None
        
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="uploaded",
                    error_code=None,
                    error_message=None,
                )
            )
    
    def on_max_unlock_attempts(self):
        """Action: Permanent failure after 3 incorrect passwords."""
        self.log_transition("max_unlock_attempts", "password_required", "failed")
        self.error_code = "MAX_PASSWORD_ATTEMPTS"
        self.error_message = "Maximum password unlock attempts (3) reached. Please upload a new PDF."
        
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="failed",
                    error_code=self.error_code,
                    error_message=self.error_message,
                )
            )
    
    def on_enter_failed(self):
        """Action: Update DB when entering failed state."""
        from_state = self.current_state.value if hasattr(self.current_state, 'value') else 'unknown'
        self.log_transition("fail", from_state, "failed")
        
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="failed",
                    error_code=self.error_code or "UNKNOWN_ERROR",
                    error_message=self.error_message or "An unknown error occurred",
                )
            )
    
    def fail(self, error_code: str, error_message: str):
        """
        Trigger failure from any state.
        
        Args:
            error_code: Error code for categorization
            error_message: Human-readable error message
        """
        self.error_code = error_code
        self.error_message = error_message
        
        current = self.current_state.value
        if current == "uploaded":
            self.fail_from_uploaded()
        elif current == "validating":
            self.fail_from_validating()
        elif current == "scanning":
            self.fail_from_scanning()
        elif current == "parsing":
            self.fail_from_parsing()
        else:
            logger.warning(
                "fail_from_unexpected_state",
                state=current,
                file_id=self.model.get("id")
            )
    
    def on_retry_from_failed(self):
        """Action: Increment retry count and reset to uploaded."""
        retry_count = self.model.get("retry_count", 0) + 1
        self.model["retry_count"] = retry_count
        
        self.log_transition("retry_from_failed", "failed", "uploaded")
        self.error_code = None
        self.error_message = None
        
        if self.model and "id" in self.model:
            asyncio.run(
                supabase_client.update_file_status(
                    file_id=self.model["id"],
                    status="uploaded",
                    retry_count=retry_count,
                    error_code=None,
                    error_message=None,
                )
            )
