"""
Base state machine class for all flow state machines.

Provides common functionality for state persistence, logging, and flow info retrieval.
"""

import asyncio
from typing import Any, Dict, List, Optional
from statemachine import StateMachine, State
import structlog


class FlowMachine(StateMachine):
    """
    Base class for all flow state machines.
    
    Features:
    - Auto-sync state to model's state field on transition
    - Structured logging on every transition
    - get_flow_info() for API responses
    - Guard helpers for common checks
    """
    
    def __init__(
        self,
        model: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize flow machine.
        
        Args:
            model: DB record as dict (e.g., portfolio_files row)
            user_id: User ID for logging and ownership checks
            **kwargs: Additional context passed to StateMachine
        """
        self.model = model or {}
        self.user_id = user_id
        self.logger = structlog.get_logger(__name__)
        self.error_code: Optional[str] = None
        self.error_message: Optional[str] = None
        super().__init__(**kwargs)
    
    def get_flow_info(self) -> Dict[str, Any]:
        """
        Returns current state + allowed events for API responses.
        
        Returns:
            Dict with state, allowed_events, metadata, and error info
        """
        # Handle both dict and StateMachine Model object
        if hasattr(self.model, 'get'):
            metadata = self.model.get("metadata", {})
            error_code = self.model.get("error_code")
            error_message = self.model.get("error_message")
        else:
            metadata = getattr(self.model, 'metadata', {})
            error_code = getattr(self.model, 'error_code', None)
            error_message = getattr(self.model, 'error_message', None)
        
        return {
            "state": self.current_state.id,
            "allowed_events": [t.name for t in self.allowed_transitions()],
            "metadata": metadata,
            "error_code": self.error_code or error_code,
            "error_message": self.error_message or error_message,
        }
    
    def sync_to_db(self):
        """
        Override in subclasses to persist state to DB.
        
        This is called after transitions to sync in-memory state to database.
        Use asyncio.run() for async DB operations.
        """
        pass
    
    def log_transition(self, event: str, from_state: str, to_state: str):
        """
        Log state transition with structured logging.
        
        Args:
            event: Event name that triggered transition
            from_state: Previous state
            to_state: New state
        """
        # Handle both dict and StateMachine Model object
        if hasattr(self.model, 'get'):
            model_id = self.model.get("id")
        else:
            model_id = getattr(self.model, 'id', None)
        
        self.logger.info(
            "state_transition",
            transition_event=event,
            from_state=from_state,
            to_state=to_state,
            user_id=self.user_id,
            model_id=model_id,
        )
    
    def can_retry(self) -> bool:
        """
        Guard: Check if retry is allowed (retry_count < 3).
        
        Returns:
            True if retry is allowed
        """
        # Handle both dict and StateMachine Model object
        if hasattr(self.model, 'get'):
            retry_count = self.model.get("retry_count", 0)
        else:
            retry_count = getattr(self.model, 'retry_count', 0)
        return retry_count < 3
    
    def can_unlock(self) -> bool:
        """
        Guard: Check if unlock attempt is allowed (unlock_attempts < 3).
        
        Returns:
            True if unlock is allowed
        """
        # Handle both dict and StateMachine Model object
        if hasattr(self.model, 'get'):
            unlock_attempts = self.model.get("unlock_attempts", 0)
        else:
            unlock_attempts = getattr(self.model, 'unlock_attempts', 0)
        return unlock_attempts < 3
    
    def is_owner(self, user_id: str) -> bool:
        """
        Guard: Check if user owns this resource.
        
        Args:
            user_id: User ID to check
            
        Returns:
            True if user owns the resource
        """
        # Handle both dict and StateMachine Model object
        if hasattr(self.model, 'get'):
            model_user_id = self.model.get("user_id")
        elif hasattr(self.model, 'user_id'):
            model_user_id = self.model.user_id
        else:
            model_user_id = None
        
        return model_user_id == user_id or self.user_id == user_id
