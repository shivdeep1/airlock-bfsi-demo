from __future__ import annotations

"""Airlock Checkpoint — the Policy Enforcement Point (PEP) for agent tool calls.

The Checkpoint sits between an agent and the tools it calls (e.g. an MCP
server). For each call it (1) builds the principal from verified identity +
live reputation (the PIP), (2) asks a :class:`~airlock_checkpoint.policy.engine.PolicyEngine`
(the PDP) for an ALLOW/DENY decision, and (3) emits a signed, hash-chained
:class:`~airlock_checkpoint.records.DecisionRecord` (the proof).
"""

from airlock_checkpoint.pep import Checkpoint, EnforcementResult
from airlock_checkpoint.records import DecisionRecord, arguments_digest

__all__ = ["Checkpoint", "DecisionRecord", "EnforcementResult", "arguments_digest"]
