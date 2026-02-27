"""
Permission guards for feature access control.

These are separate from the auth state machine - they check specific
eligibility criteria for features rather than tracking user journey state.

Tier system (4-axis reputation, composite score 0-100):
  - newcomer    (0-20):  View and comment
  - contributor (21-40): Can vote (requires Community >= 30, Trust >= 20)
  - trusted     (41-60): Can publish opinions (requires Performance >= 40, Trust >= 40)
  - expert      (61-80): Featured portfolio eligible (requires Performance >= 60, Community >= 50)
  - legend      (81-100): Moderation eligible (requires all axes >= 70)
"""

from fastapi import HTTPException, status
from typing import Dict, Any

# Tier ordering for comparison
_TIER_ORDER = {
    "newcomer": 0,
    "contributor": 1,
    "trusted": 2,
    "expert": 3,
    "legend": 4,
    # legacy tier aliases
    "beginner": 0,
    "intermediate": 1,
    "elite": 4,
}


def _tier_rank(tier: str) -> int:
    return _TIER_ORDER.get(tier.lower() if tier else "newcomer", 0)


def require_fresh_portfolio(current_user: Dict[str, Any]):
    """
    Guard: User must have fresh portfolio (< 186 days) to view others' content.
    
    Blocks access to:
    - Viewing others' portfolios
    - Portfolio feed
    - Leaderboard
    
    Always allows:
    - Viewing own portfolio
    - Uploading new portfolio
    - Account settings
    """
    session_state = current_user.get("session_state")
    
    if session_state == "portfolio_refresh_required":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Portfolio update required. Please upload a new portfolio to access this feature."
        )


def require_minimum_reputation(
    current_user: Dict[str, Any],
    min_reputation: int = 50
):
    """
    Guard: User must have minimum reputation score (0-100) to access feature.
    
    Used for:
    - Writing opinions (requires score >= 41, i.e. trusted tier)
    - Voting on content (requires score >= 21, i.e. contributor tier)
    
    Note: Commenting does NOT require reputation - anyone can comment.
    
    Args:
        current_user: User dict from get_current_user dependency
        min_reputation: Minimum composite reputation score required (0-100)
    """
    user_reputation = current_user.get("reputation_score", 0)
    
    if user_reputation < min_reputation:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Insufficient reputation. You need {min_reputation} reputation points "
                f"to access this feature. Current: {user_reputation}"
            )
        )


def require_minimum_tier(
    current_user: Dict[str, Any],
    min_tier: str,
):
    """
    Guard: User must have at least the specified reputation tier.

    Tier order: newcomer < contributor < trusted < expert < legend

    Args:
        current_user: User dict from get_current_user dependency
        min_tier: Minimum tier name required (e.g. 'contributor', 'trusted')
    """
    user_tier = current_user.get("reputation_tier", "newcomer")
    if _tier_rank(user_tier) < _tier_rank(min_tier):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Insufficient tier. You need '{min_tier}' tier or higher to access this feature. "
                f"Current tier: '{user_tier}'. Build your reputation to unlock this."
            )
        )


def require_can_vote(current_user: Dict[str, Any]):
    """
    Guard: User must be at least 'contributor' tier to vote on opinions.
    Requires Community >= 30, Trust >= 20 (enforced by tier assignment).
    """
    require_minimum_tier(current_user, min_tier="contributor")


def require_can_publish_opinion(current_user: Dict[str, Any]):
    """
    Guard: User must be at least 'trusted' tier to publish opinions.
    Requires Performance >= 40, Trust >= 40 (enforced by tier assignment).
    """
    require_minimum_tier(current_user, min_tier="trusted")


def require_can_moderate(current_user: Dict[str, Any]):
    """
    Guard: User must be at least 'legend' tier to perform moderation actions.
    Requires all axes >= 70 (enforced by tier assignment).
    """
    require_minimum_tier(current_user, min_tier="legend")


def require_verified_email(current_user: Dict[str, Any]):
    """
    Guard: User must have verified email.
    
    Note: This is redundant with state machine (unverified_email state),
    but kept as explicit guard for clarity in endpoints.
    """
    session_state = current_user.get("session_state")
    
    if session_state == "unverified_email":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required. Please check your email and verify your account."
        )


def require_completed_onboarding(current_user: Dict[str, Any]):
    """
    Guard: User must have completed onboarding (username confirmed + privacy consent).
    
    Blocks if in states:
    - username_selection
    - needs_consent
    """
    session_state = current_user.get("session_state")
    
    if session_state in ["username_selection", "needs_consent"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please complete your profile setup to access this feature."
        )


def check_account_not_locked(current_user: Dict[str, Any]):
    """
    Guard: Account must not be locked.
    
    Locked accounts cannot access any features except account appeal.
    """
    session_state = current_user.get("session_state")
    
    if session_state == "locked":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been locked. Please contact support."
        )


# Convenience function for common permission combinations
def require_active_user(current_user: Dict[str, Any]):
    """
    Guard: User must be fully active (completed onboarding, not locked).
    
    This is the most common permission check - use for most protected endpoints.
    """
    check_account_not_locked(current_user)
    require_completed_onboarding(current_user)
