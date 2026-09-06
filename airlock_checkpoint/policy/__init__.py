from __future__ import annotations

"""Airlock policy layer — the pluggable Policy Decision Point (PDP).

The PEP (``airlock_checkpoint``) asks a :class:`PolicyEngine` whether a
verified agent (the *principal*) may perform a tool call (*action + resource*),
given PIP-supplied context (identity, trust score, delegation).  The engine is
swappable: a zero-dependency built-in matcher ships for fast local use, and an
AWS Cedar adapter is the recommended reference engine.  OPA and other engines
can implement the same ``PolicyEngine`` protocol.
"""

from airlock_checkpoint.policy.builtin_engine import BuiltinPolicyEngine, Condition, Rule
from airlock_checkpoint.policy.engine import (
    Decision,
    Effect,
    PolicyEngine,
    PrincipalContext,
    ToolCall,
)

__all__ = [
    "BuiltinPolicyEngine",
    "Condition",
    "Decision",
    "Effect",
    "PolicyEngine",
    "PrincipalContext",
    "Rule",
    "ToolCall",
]
