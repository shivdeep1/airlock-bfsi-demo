from __future__ import annotations

"""Engine-agnostic Policy Decision Point (PDP) interface.

This module defines the contract every policy engine implements.  Keeping the
contract small and stable is the platform asset: enforcement
(``airlock_checkpoint``) and information (identity + reputation) stay constant
while the decision engine behind :class:`PolicyEngine` can be swapped.
"""

from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class Effect(StrEnum):
    """The two terminal authorization effects."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class PrincipalContext(BaseModel):
    """Facts about the calling agent, supplied by the PIP (identity + reputation).

    This is what a policy evaluates against. ``trust_score`` and ``tier`` come
    from the Airlock reputation store; ``roles`` and ``delegated_by`` come from
    the verified identity / delegation chain.
    """

    agent_did: str
    agent_name: str = ""
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    tier: int = 0
    roles: list[str] = Field(default_factory=list)
    delegated_by: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """The action + resource being attempted: an MCP tool invocation."""

    tool: str
    server: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    """The PDP's verdict for a single tool call."""

    effect: Effect
    reason: str = ""
    policy_id: str = ""
    matched_rule: str = ""
    obligations: list[str] = Field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect == Effect.ALLOW


@runtime_checkable
class PolicyEngine(Protocol):
    """A swappable Policy Decision Point.

    Implementations are pure decision functions: given a verified principal and
    an attempted tool call, return an ALLOW/DENY :class:`Decision`. Evaluation
    is expected to be in-process and fast (no I/O) for the bundled engines;
    network-backed engines (e.g. OPA) should wrap their own transport.
    """

    name: str

    def decide(self, principal: PrincipalContext, call: ToolCall) -> Decision: ...
