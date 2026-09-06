from __future__ import annotations

"""Signed, auditable record of a single Checkpoint enforcement decision."""

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from airlock.crypto.signing import canonicalize
from pydantic import BaseModel, Field

from airlock_checkpoint.policy.engine import Decision, Effect, PrincipalContext, ToolCall


def arguments_digest(arguments: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON of tool arguments.

    We persist the digest, not the raw arguments, so audit records never carry
    sensitive payloads (amounts, account numbers, PII) while still proving which
    exact call was evaluated.
    """
    return hashlib.sha256(canonicalize(arguments)).hexdigest()


class DecisionRecord(BaseModel):
    """One enforcement decision, signed by the gateway and chained into the audit trail."""

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    agent_did: str
    agent_name: str = ""
    server: str = ""
    tool: str
    effect: Effect
    reason: str = ""
    policy_id: str = ""
    matched_rule: str = ""
    trust_score: float = 0.5
    tier: int = 0
    delegated_by: str | None = None
    arguments_digest: str = ""
    airlock_signature: str | None = None

    @classmethod
    def from_decision(
        cls, principal: PrincipalContext, call: ToolCall, decision: Decision
    ) -> DecisionRecord:
        return cls(
            agent_did=principal.agent_did,
            agent_name=principal.agent_name,
            server=call.server,
            tool=call.tool,
            effect=decision.effect,
            reason=decision.reason,
            policy_id=decision.policy_id,
            matched_rule=decision.matched_rule,
            trust_score=principal.trust_score,
            tier=principal.tier,
            delegated_by=principal.delegated_by,
            arguments_digest=arguments_digest(call.arguments),
        )

    @property
    def allowed(self) -> bool:
        return self.effect == Effect.ALLOW
