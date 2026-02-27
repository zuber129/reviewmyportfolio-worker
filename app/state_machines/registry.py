"""
State machine registry for dynamic instantiation.

Provides factory function to create state machine instances by flow type.
"""

from typing import Any, Dict, Optional, Type
from .base import FlowMachine


FLOW_REGISTRY: Dict[str, str] = {
    "upload": "UploadFlowMachine",
    "parsing": "ParsingFlowMachine",
    "onboarding": "OnboardingFlowMachine",
    "portfolio": "PortfolioFlowMachine",
}


def get_flow_machine(
    flow_type: str,
    model: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None,
    **kwargs
) -> FlowMachine:
    """
    Factory to instantiate state machine by flow type.
    
    Args:
        flow_type: Type of flow (upload, parsing, onboarding, portfolio)
        model: DB record as dict
        user_id: User ID for logging and ownership
        **kwargs: Additional context
        
    Returns:
        Instantiated state machine
        
    Raises:
        ValueError: If flow_type is not registered
    """
    if flow_type not in FLOW_REGISTRY:
        raise ValueError(
            f"Unknown flow type: {flow_type}. "
            f"Available: {list(FLOW_REGISTRY.keys())}"
        )
    
    class_name = FLOW_REGISTRY[flow_type]
    
    if flow_type == "upload":
        from .upload_flow import UploadFlowMachine
        return UploadFlowMachine(model=model, user_id=user_id, **kwargs)
    elif flow_type == "parsing":
        from .parsing_flow import ParsingFlowMachine
        return ParsingFlowMachine(model=model, user_id=user_id, **kwargs)
    elif flow_type == "onboarding":
        from .onboarding_flow import OnboardingFlowMachine
        return OnboardingFlowMachine(model=model, user_id=user_id, **kwargs)
    elif flow_type == "portfolio":
        from .portfolio_flow import PortfolioFlowMachine
        return PortfolioFlowMachine(model=model, user_id=user_id, **kwargs)
    else:
        raise ValueError(f"Flow type {flow_type} not implemented yet")
