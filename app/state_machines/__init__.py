"""
State machine infrastructure for multi-step flows.

This package provides state machines for managing complex workflows like
PDF upload, parsing, onboarding, and portfolio processing.
"""

from .base import FlowMachine
from .registry import get_flow_machine, FLOW_REGISTRY

__all__ = ["FlowMachine", "get_flow_machine", "FLOW_REGISTRY"]
