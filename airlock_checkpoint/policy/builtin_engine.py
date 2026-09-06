from __future__ import annotations

"""Zero-dependency reference PDP: a default-deny allow/forbid matcher.

Semantics intentionally mirror Cedar's permit/forbid with explicit-deny
precedence, so swapping to the Cedar engine yields the same decisions for the
bundled scenarios:

* Default is DENY.
* A ``forbid`` rule that matches always wins (explicit deny overrides allow).
* A ``permit`` rule grants access when principal + tool match, the principal's
  ``trust_score`` meets ``min_trust`` (when set), and every argument
  :class:`Condition` holds (when set).

Argument conditions make enforcement *fine-grained*. Role + trust answer "may
this agent use this tool at all"; conditions answer "with these arguments" —
which is what mandate-style controls require: spend ceilings, payee allowlists,
scope caps. Without them the engine stops the wrong *agent* but not the right
agent making a wrong *call* (wire the wrong amount to the wrong account).

Fail-closed rule: a condition over a **missing** argument evaluates ``False``
for ordered comparisons (``lt``/``le``/``gt``/``ge``) and ``not_in``. A permit
that requires ``amount <= 50000`` therefore does **not** grant when ``amount``
is absent — the call falls through to default-deny.
"""

import logging
from typing import Any

from pydantic import BaseModel, Field

from airlock_checkpoint.policy.engine import Decision, Effect, PrincipalContext, ToolCall

logger = logging.getLogger(__name__)

WILDCARD = "*"

# Comparison operators supported by :class:`Condition`. Kept as an explicit,
# closed set of pure comparisons — no expression evaluation, no callables.
_ORDERED_OPS = frozenset({"lt", "le", "gt", "ge"})
_OPS = _ORDERED_OPS | frozenset({"eq", "ne", "in", "not_in"})


def _dig(arguments: dict[str, Any], path: str) -> Any:
    """Resolve a dotted argument path (e.g. ``"transfer.amount"``), or None."""
    cur: Any = arguments
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


class Condition(BaseModel):
    """A single deterministic predicate over a tool call's arguments.

    ``arg`` is a (possibly dotted) argument key; ``op`` is one of
    eq / ne / lt / le / gt / ge / in / not_in; ``value`` is the literal to
    compare against (a list/tuple/set for ``in`` / ``not_in``).
    """

    arg: str
    op: str = "eq"
    value: Any = None

    def evaluate(self, arguments: dict[str, Any]) -> bool:
        actual = _dig(arguments, self.arg)
        op = self.op
        try:
            if op == "eq":
                return bool(actual == self.value)
            if op == "ne":
                return bool(actual != self.value)
            if op == "in":
                return actual in self.value if _is_container(self.value) else False
            if op == "not_in":
                # Fail closed on a missing arg: absence does not satisfy "not in".
                if actual is None or not _is_container(self.value):
                    return False
                return actual not in self.value
            # Ordered comparisons: a missing/incomparable arg fails closed.
            if actual is None:
                return False
            if op == "lt":
                return bool(actual < self.value)
            if op == "le":
                return bool(actual <= self.value)
            if op == "gt":
                return bool(actual > self.value)
            if op == "ge":
                return bool(actual >= self.value)
        except TypeError:
            # e.g. comparing str to int — treat as not satisfied, never crash.
            return False
        logger.warning("Unknown condition operator %r — failing closed", op)
        return False

    def describe(self, arguments: dict[str, Any]) -> str:
        return (
            f"{self.arg}={_dig(arguments, self.arg)!r} violates {self.arg} {self.op} {self.value!r}"
        )


def _is_container(value: Any) -> bool:
    return isinstance(value, (list, tuple, set))


class Rule(BaseModel):
    """A single permit/forbid rule for the built-in engine."""

    effect: Effect
    principals: list[str] = Field(default_factory=lambda: [WILDCARD])
    tools: list[str] = Field(default_factory=lambda: [WILDCARD])
    min_trust: float | None = None
    conditions: list[Condition] = Field(default_factory=list)
    description: str = ""

    def matches_principal(self, principal: PrincipalContext) -> bool:
        for spec in self.principals:
            if spec == WILDCARD or spec == principal.agent_did:
                return True
            if spec.startswith("role:") and spec[len("role:") :] in principal.roles:
                return True
        return False

    def matches_tool(self, call: ToolCall) -> bool:
        return any(spec == WILDCARD or spec == call.tool for spec in self.tools)

    def matches_conditions(self, call: ToolCall) -> bool:
        """True when every argument condition holds (vacuously true if none)."""
        return all(cond.evaluate(call.arguments) for cond in self.conditions)

    def first_failing_condition(self, call: ToolCall) -> Condition | None:
        for cond in self.conditions:
            if not cond.evaluate(call.arguments):
                return cond
        return None


class BuiltinPolicyEngine:
    """In-process allow/forbid engine implementing the ``PolicyEngine`` protocol."""

    name = "builtin"

    def __init__(self, rules: list[Rule], policy_id: str = "builtin") -> None:
        self._rules = rules
        self._policy_id = policy_id

    def decide(self, principal: PrincipalContext, call: ToolCall) -> Decision:
        # 1. Explicit forbid wins over everything (only when its conditions hold).
        for rule in self._rules:
            if (
                rule.effect == Effect.DENY
                and rule.matches_principal(principal)
                and rule.matches_tool(call)
                and rule.matches_conditions(call)
            ):
                return Decision(
                    effect=Effect.DENY,
                    reason=rule.description or f"forbidden: {call.tool}",
                    policy_id=self._policy_id,
                    matched_rule=rule.description or "forbid",
                )

        # 2. A satisfied permit grants access. Remember the most specific block
        #    (trust shortfall / condition failure) to report if nothing grants.
        trust_block: Decision | None = None
        cond_block: Decision | None = None
        for rule in self._rules:
            if rule.effect != Effect.ALLOW:
                continue
            if not (rule.matches_principal(principal) and rule.matches_tool(call)):
                continue
            if rule.min_trust is not None and principal.trust_score < rule.min_trust:
                trust_block = Decision(
                    effect=Effect.DENY,
                    reason=(
                        f"trust_score {principal.trust_score:.2f} below required "
                        f"{rule.min_trust:.2f} for {call.tool}"
                    ),
                    policy_id=self._policy_id,
                    matched_rule=rule.description or "permit(min_trust)",
                )
                continue
            if rule.conditions and not rule.matches_conditions(call):
                failing = rule.first_failing_condition(call)
                cond_block = Decision(
                    effect=Effect.DENY,
                    reason=(
                        failing.describe(call.arguments)
                        if failing is not None
                        else f"argument conditions not met for {call.tool}"
                    ),
                    policy_id=self._policy_id,
                    matched_rule=rule.description or "permit(condition)",
                )
                continue
            return Decision(
                effect=Effect.ALLOW,
                reason=rule.description or f"permitted: {call.tool}",
                policy_id=self._policy_id,
                matched_rule=rule.description or "permit",
            )

        # A specific block (why the closest-matching permit didn't grant) beats
        # the generic default-deny message.
        if cond_block is not None:
            return cond_block
        if trust_block is not None:
            return trust_block

        # 3. Default deny.
        return Decision(
            effect=Effect.DENY,
            reason=f"no matching permit for {principal.agent_did} -> {call.tool}",
            policy_id=self._policy_id,
            matched_rule="default-deny",
        )
