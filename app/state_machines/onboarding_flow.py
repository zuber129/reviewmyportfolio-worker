"""
Onboarding Flow State Machine.

Manages user onboarding after signup (username selection, consent).
State is derived from profiles table fields, not stored separately.
"""

import asyncio
from typing import Any, Dict, Optional
from statemachine import State
import structlog

from .base import FlowMachine
from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger(__name__)


class OnboardingFlowMachine(FlowMachine):
    """
    State machine for user onboarding flow.
    
    State derived from profiles table fields:
    - username IS NULL → needs_username
    - privacy_consent_given = false → needs_consent
    - else → onboarded
    """
    
    needs_username = State(initial=True, value="needs_username")
    needs_consent = State(value="needs_consent")
    onboarded = State(value="onboarded", final=True)
    
    username_set = needs_username.to(needs_consent)
    skip_username = needs_username.to(needs_consent)
    consent_given = needs_consent.to(onboarded)
    
    def __init__(self, model: Optional[Dict[str, Any]] = None, **kwargs):
        """
        Initialize onboarding flow machine.
        
        Args:
            model: profiles record as dict
            **kwargs: Additional context (user_id, etc.)
        """
        super().__init__(model=model, **kwargs)
        
        if model:
            current_state = self._derive_state_from_profile(model)
            try:
                self.current_state = getattr(self, current_state)
            except AttributeError:
                logger.warning(
                    "unknown_onboarding_state",
                    state=current_state,
                    user_id=model.get("id"),
                    defaulting_to="needs_username"
                )
                self.current_state = self.needs_username
    
    def _derive_state_from_profile(self, profile: Dict[str, Any]) -> str:
        """
        Derive onboarding state from profile fields.
        
        Args:
            profile: Profile record
            
        Returns:
            State name (needs_username, needs_consent, onboarded)
        """
        if not profile.get("username"):
            return "needs_username"
        
        if not profile.get("privacy_consent_given"):
            return "needs_consent"
        
        return "onboarded"
    
    def sync_to_db(self):
        """
        Persist current state to database.
        
        Note: Onboarding state is derived from profile fields,
        so we don't need to persist a separate state column.
        """
        pass
    
    def on_username_set(self):
        """Action: Log username set transition."""
        self.log_transition("username_set", "needs_username", "needs_consent")
        logger.info(
            "username_set",
            user_id=self.model.get("id"),
            username=self.model.get("username")
        )
    
    def on_skip_username(self):
        """Action: Log username skip (already set)."""
        self.log_transition("skip_username", "needs_username", "needs_consent")
        logger.info(
            "username_skipped",
            user_id=self.model.get("id")
        )
    
    def on_consent_given(self):
        """Action: Log consent given."""
        self.log_transition("consent_given", "needs_consent", "onboarded")
        logger.info(
            "consent_given",
            user_id=self.model.get("id")
        )
    
    def on_enter_onboarded(self):
        """Action: Log onboarding completion."""
        logger.info(
            "onboarding_completed",
            user_id=self.model.get("id")
        )
