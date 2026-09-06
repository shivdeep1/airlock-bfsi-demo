from __future__ import annotations

"""AWS Cedar reference adapter for the PDP.

Cedar is the recommended reference engine: policy-as-code that reads clearly
and evaluates deterministically. This adapter maps Airlock's
:class:`PrincipalContext` / :class:`ToolCall` onto a Cedar authorization
request and returns a :class:`Decision`.

Cedar's numeric type is a 64-bit integer (no float literals), so trust is
passed to policies as ``trust_score`` on a 0-100 scale (e.g. a policy reads
``principal.trust_score >= 75``).

Requires the optional ``cedarpy`` dependency::

    pip install cedarpy

If it is not installed, constructing the engine raises a clear error so the
caller can fall back to :class:`~airlock_checkpoint.policy.builtin_engine.BuiltinPolicyEngine`.
"""

import logging
from pathlib import Path
from typing import Any

from airlock_checkpoint.policy.engine import Decision, Effect, PrincipalContext, ToolCall

logger = logging.getLogger(__name__)

_ACTION = 'Action::"callTool"'


def _trust_pct(trust_score: float) -> int:
    """Map a 0.0-1.0 trust score to Cedar's integer 0-100 scale."""
    return int(round(trust_score * 100))


class CedarPolicyEngine:
    """PolicyEngine backed by AWS Cedar via the ``cedarpy`` bindings."""

    name = "cedar"

    def __init__(self, policy_text: str, policy_id: str = "cedar") -> None:
        try:
            import cedarpy  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "CedarPolicyEngine requires the 'cedarpy' package "
                "(pip install cedarpy). Use BuiltinPolicyEngine for a "
                "dependency-free fallback."
            ) from exc
        self._cedarpy = cedarpy
        self._policy_text = policy_text
        self._policy_id = policy_id

    @classmethod
    def from_file(cls, path: str | Path, policy_id: str = "cedar") -> CedarPolicyEngine:
        text = Path(path).read_text(encoding="utf-8")
        return cls(text, policy_id=policy_id or Path(path).stem)

    def decide(self, principal: PrincipalContext, call: ToolCall) -> Decision:
        role = principal.roles[0] if principal.roles else ""
        trust_pct = _trust_pct(principal.trust_score)
        entities: list[dict[str, Any]] = [
            {
                "uid": {"type": "Agent", "id": principal.agent_did},
                "attrs": {"role": role, "trust_score": trust_pct, "tier": principal.tier},
                "parents": [],
            },
            {"uid": {"type": "Tool", "id": call.tool}, "attrs": {}, "parents": []},
        ]
        # Tool arguments are exposed to policies under ``context.args`` so a
        # policy can gate on them (e.g. ``context.args.amount <= 50000`` or
        # ``context.args.account in Tool::"wire_funds".allowlist``). Cedar's
        # numeric type is a 64-bit integer with no float literals, so callers
        # should pass money as integer minor units (paise/cents); a float
        # argument makes ``is_authorized`` raise, which we fail closed to DENY.
        request: dict[str, Any] = {
            "principal": f'Agent::"{principal.agent_did}"',
            "action": _ACTION,
            "resource": f'Tool::"{call.tool}"',
            "context": {
                "trust_score": trust_pct,
                "tier": principal.tier,
                "args": call.arguments,
            },
        }
        try:
            result = self._cedarpy.is_authorized(request, self._policy_text, entities)
        except Exception as exc:  # pragma: no cover - binding-specific errors
            logger.warning("Cedar evaluation error: %s", exc)
            return Decision(
                effect=Effect.DENY,
                reason=f"cedar evaluation error: {exc}",
                policy_id=self._policy_id,
                matched_rule="cedar-error",
            )

        decision_obj = getattr(result, "decision", None)
        decision_value = str(getattr(decision_obj, "value", decision_obj))
        allowed = decision_value == "Allow"
        return Decision(
            effect=Effect.ALLOW if allowed else Effect.DENY,
            reason=f"cedar: {decision_value.lower()}",
            policy_id=self._policy_id,
            matched_rule=_ACTION,
        )
