"""
Session-scoped authentication state machine.

Each browser/device has independent state. Multi-device safe:
- Password reset on laptop doesn't affect desktop session
- Signout on phone doesn't affect tablet session
- Portfolio refresh requirement affects all user sessions (user-level)
- Account locking affects all user sessions (user-level)
"""

from datetime import datetime, timezone
from typing import Optional
from statemachine import State
from .base import FlowMachine


class AuthSessionFlowMachine(FlowMachine):
    """
    Session-scoped auth state machine.
    Each browser/device has independent state.
    Integrates portfolio refresh requirement (186-day rule).
    """
    
    # States
    unverified_email = State(initial=True)
    username_selection = State()
    needs_consent = State()
    active = State()
    portfolio_refresh_required = State()
    signed_out = State()
    locked = State()
    
    # Note: password_reset_pending and password_reset_active states removed
    # Password reset is handled via email tokens (Supabase), not session state
    # User can request reset while in any state without blocking their session
    
    # Signup → Onboarding transitions
    verify_email = (
        unverified_email.to(username_selection, cond="needs_username_confirmation") |
        unverified_email.to(needs_consent, cond="username_confirmed_no_consent") |
        unverified_email.to(active, cond="fully_onboarded_and_fresh_portfolio")
    )
    
    confirm_username = username_selection.to(needs_consent)
    give_consent = needs_consent.to(active)
    
    # Signin transitions (derive state from user flags + portfolio freshness)
    signin = (
        signed_out.to(username_selection, cond="needs_username_confirmation") |
        signed_out.to(needs_consent, cond="username_confirmed_no_consent") |
        signed_out.to(portfolio_refresh_required, cond="portfolio_stale") |
        signed_out.to(active, cond="fully_onboarded_and_fresh_portfolio")
    )
    
    # Portfolio refresh (user-level, affects all sessions)
    # No grace period - required immediately at 186 days
    # Soft-lock: user can access all features except viewing others' portfolios
    require_portfolio_refresh = active.to(portfolio_refresh_required)
    upload_portfolio = portfolio_refresh_required.to(active)
    
    # Signout
    signout = (
        active.to(signed_out) | 
        portfolio_refresh_required.to(signed_out) | 
        username_selection.to(signed_out) | 
        needs_consent.to(signed_out)
    )
    
    # Account locking (user-level)
    lock_account = (
        active.to(locked) | 
        username_selection.to(locked) | 
        needs_consent.to(locked) | 
        portfolio_refresh_required.to(locked) | 
        signed_out.to(locked)
    )
    unlock_account = locked.to(signed_out)
    
    # Guards
    def needs_username_confirmation(self) -> bool:
        """User has not yet confirmed/customized their username."""
        return not self.model.get("privacy_consent_given") and not self.model.get("username_confirmed")
    
    def username_confirmed_no_consent(self) -> bool:
        """Username confirmed but privacy consent not yet given."""
        return self.model.get("username_confirmed") and not self.model.get("privacy_consent_given")
    
    def fully_onboarded_and_fresh_portfolio(self) -> bool:
        """User has completed onboarding AND portfolio is fresh (<186 days)."""
        if not (bool(self.model.get("username")) and self.model.get("privacy_consent_given")):
            return False
        return not self.portfolio_stale()
    
    def portfolio_stale(self) -> bool:
        """Check if portfolio needs refresh using portfolio_refresh_due_at or 186-day fallback."""
        # Use explicit due date if available (admin may have extended it)
        refresh_due_at = self.model.get("refresh_due_at")
        if refresh_due_at is not None:
            if isinstance(refresh_due_at, str):
                refresh_due_at = datetime.fromisoformat(refresh_due_at.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) >= refresh_due_at
        
        # Fallback: compute from last_holdings_update
        last_holdings_update = self.model.get("last_holdings_update")
        if not last_holdings_update:
            # New users (no portfolios yet) — not stale
            return False
        
        if isinstance(last_holdings_update, str):
            last_holdings_update = datetime.fromisoformat(last_holdings_update.replace("Z", "+00:00"))
        
        days_since_update = (datetime.now(timezone.utc) - last_holdings_update).days
        return days_since_update >= 186
    
    def on_transition(self, event: str, source: State, target: State):
        """Hook called after every transition."""
        self.log_transition(event, source.id, target.id)
        
        # Update model state
        if hasattr(self.model, '__setitem__'):
            self.model["state"] = target.id
        else:
            self.model.state = target.id
