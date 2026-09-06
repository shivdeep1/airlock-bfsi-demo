from __future__ import annotations

"""The Checkpoint — Policy Enforcement Point (PEP) for agent tool calls.

Flow per call:
  1. Build the principal (PIP): verified identity + live trust from reputation.
  2. Ask the PDP (:class:`PolicyEngine`) for an ALLOW/DENY decision.
  3. Record it: sign (Ed25519) and append to the hash-chained audit trail (proof).

Identity is established upstream (the proxy validates the agent's Airlock token
or Ed25519 signature). This module trusts the :class:`PrincipalContext` it is
given but enriches it from the reputation store so policies can reason over live
trust.
"""

import logging
from typing import TYPE_CHECKING

from airlock.crypto.signing import sign_message
from pydantic import BaseModel

from airlock_checkpoint.policy.engine import (
    Decision,
    Effect,
    PolicyEngine,
    PrincipalContext,
    ToolCall,
)
from airlock_checkpoint.records import DecisionRecord

if TYPE_CHECKING:
    from airlock.audit.trail import AuditTrail
    from airlock.reputation.store import ReputationStore
    from nacl.signing import SigningKey

logger = logging.getLogger(__name__)


class EnforcementResult(BaseModel):
    """Outcome of a single enforcement: the decision plus its signed record."""

    decision: Decision
    record: DecisionRecord

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


class Checkpoint:
    """Enforce policy on tool calls and emit signed, auditable decision records."""

    def __init__(
        self,
        engine: PolicyEngine,
        *,
        reputation_store: ReputationStore | None = None,
        audit_trail: AuditTrail | None = None,
        signing_key: SigningKey | None = None,
        airlock_did: str = "",
    ) -> None:
        self._engine = engine
        self._reputation = reputation_store
        self._audit = audit_trail
        self._signing_key = signing_key
        self._airlock_did = airlock_did

    def build_principal(
        self,
        agent_did: str,
        *,
        agent_name: str = "",
        roles: list[str] | None = None,
        delegated_by: str | None = None,
    ) -> PrincipalContext:
        """PIP: assemble the principal, sourcing live trust from the reputation store."""
        trust_score = 0.5
        tier = 0
        if self._reputation is not None:
            score = self._reputation.get_or_default(agent_did)
            trust_score = score.score
            tier = int(score.tier)
        return PrincipalContext(
            agent_did=agent_did,
            agent_name=agent_name,
            trust_score=trust_score,
            tier=tier,
            roles=roles or [],
            delegated_by=delegated_by,
        )

    async def enforce(self, principal: PrincipalContext, call: ToolCall) -> EnforcementResult:
        """Decide, sign, and audit a single tool call.

        Fails **closed**: if the policy engine raises, the decision is DENY.
        Signing and audit failures are logged but never turn a DENY into an
        ALLOW or drop the returned decision.
        """
        try:
            decision: Decision = self._engine.decide(principal, call)
        except Exception as exc:
            logger.exception("Policy engine raised; failing closed to DENY")
            decision = Decision(
                effect=Effect.DENY,
                reason=f"policy engine error: {exc}",
                policy_id=getattr(self._engine, "name", ""),
                matched_rule="engine-error",
            )

        record = DecisionRecord.from_decision(principal, call, decision)

        if self._signing_key is not None:
            try:
                record.airlock_signature = sign_message(
                    record.model_dump(mode="json"), self._signing_key
                )
            except Exception:
                logger.exception("Failed to sign decision record %s", record.record_id)

        if self._audit is not None:
            try:
                await self._audit.append(
                    event_type="tool_call_decision",
                    actor_did=principal.agent_did,
                    detail={
                        "record_id": record.record_id,
                        "tool": call.tool,
                        "server": call.server,
                        "effect": record.effect.value,
                        "reason": record.reason,
                        "policy_id": record.policy_id,
                        "matched_rule": record.matched_rule,
                        "trust_score": record.trust_score,
                        "arguments_digest": record.arguments_digest,
                        "airlock_signature": record.airlock_signature,
                    },
                )
            except Exception:
                logger.exception("Failed to append decision %s to audit trail", record.record_id)

        logger.info(
            "Checkpoint %s: %s -> %s (%s)",
            record.effect.value,
            principal.agent_did,
            call.tool,
            record.reason,
        )
        return EnforcementResult(decision=decision, record=record)
