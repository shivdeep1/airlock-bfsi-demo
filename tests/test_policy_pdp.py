from __future__ import annotations

import pytest

from airlock_checkpoint.policy import Effect, PrincipalContext, ToolCall
from airlock_checkpoint.policy.builtin_engine import BuiltinPolicyEngine, Condition, Rule


def _fintech_engine() -> BuiltinPolicyEngine:
    """Treasury agents may move money (with trust); any agent may read."""
    rules = [
        Rule(
            effect=Effect.ALLOW,
            principals=["role:treasury"],
            tools=["wire_funds"],
            min_trust=0.75,
            description="treasury may wire funds when trust >= 0.75",
        ),
        Rule(
            effect=Effect.ALLOW,
            principals=["role:treasury"],
            tools=["charge_fee"],
            description="treasury may charge fees",
        ),
        Rule(
            effect=Effect.ALLOW,
            principals=["*"],
            tools=["read_application", "get_credit_score"],
            description="any verified agent may read",
        ),
    ]
    return BuiltinPolicyEngine(rules, policy_id="fintech")


def _agent(
    did: str = "did:key:zIntake", roles: list[str] | None = None, trust: float = 0.6
) -> PrincipalContext:
    return PrincipalContext(agent_did=did, roles=roles or ["intake"], trust_score=trust)


def test_intake_agent_denied_wire_funds() -> None:
    d = _fintech_engine().decide(_agent(roles=["intake"], trust=0.9), ToolCall(tool="wire_funds"))
    assert d.effect == Effect.DENY
    assert not d.allowed


def test_treasury_agent_allowed_wire_funds() -> None:
    d = _fintech_engine().decide(
        _agent(did="did:key:zTreasury", roles=["treasury"], trust=0.9),
        ToolCall(tool="wire_funds"),
    )
    assert d.effect == Effect.ALLOW
    assert d.allowed


def test_treasury_low_trust_denied_wire_funds() -> None:
    d = _fintech_engine().decide(
        _agent(did="did:key:zTreasury", roles=["treasury"], trust=0.6),
        ToolCall(tool="wire_funds"),
    )
    assert d.effect == Effect.DENY
    assert "trust_score" in d.reason


def test_read_tool_allowed_for_any_agent() -> None:
    d = _fintech_engine().decide(
        _agent(roles=["intake"], trust=0.5), ToolCall(tool="read_application")
    )
    assert d.effect == Effect.ALLOW


def test_unknown_tool_default_deny() -> None:
    d = _fintech_engine().decide(
        _agent(roles=["treasury"], trust=0.9), ToolCall(tool="launch_missiles")
    )
    assert d.effect == Effect.DENY
    assert d.matched_rule == "default-deny"


# --- Argument-level conditions (mandate controls: limits, payees, scopes) ---


def _mandate_engine() -> BuiltinPolicyEngine:
    """Treasury may wire <= 50000 minor units, only to allowlisted accounts."""
    rules = [
        Rule(
            effect=Effect.DENY,
            principals=["*"],
            tools=["wire_funds"],
            conditions=[Condition(arg="amount", op="gt", value=100000)],
            description="hard cap: no wire above 100000 regardless of role",
        ),
        Rule(
            effect=Effect.ALLOW,
            principals=["role:treasury"],
            tools=["wire_funds"],
            min_trust=0.75,
            conditions=[
                Condition(arg="amount", op="le", value=50000),
                Condition(arg="account", op="in", value=["GB-ALLOW-1", "GB-ALLOW-2"]),
            ],
            description="treasury may wire <= 50000 to allowlisted accounts",
        ),
    ]
    return BuiltinPolicyEngine(rules, policy_id="fintech_mandate")


def _treasury(trust: float = 0.9) -> PrincipalContext:
    return PrincipalContext(agent_did="did:key:zTreasury", roles=["treasury"], trust_score=trust)


def test_within_mandate_allowed() -> None:
    d = _mandate_engine().decide(
        _treasury(),
        ToolCall(tool="wire_funds", arguments={"amount": 40000, "account": "GB-ALLOW-1"}),
    )
    assert d.effect == Effect.ALLOW


def test_over_limit_denied_even_for_treasury() -> None:
    d = _mandate_engine().decide(
        _treasury(),
        ToolCall(tool="wire_funds", arguments={"amount": 50001, "account": "GB-ALLOW-1"}),
    )
    assert d.effect == Effect.DENY
    assert "amount" in d.reason


def test_unlisted_payee_denied() -> None:
    d = _mandate_engine().decide(
        _treasury(),
        ToolCall(tool="wire_funds", arguments={"amount": 100, "account": "GB-ATTACKER"}),
    )
    assert d.effect == Effect.DENY
    assert "account" in d.reason


def test_missing_amount_fails_closed() -> None:
    d = _mandate_engine().decide(
        _treasury(),
        ToolCall(tool="wire_funds", arguments={"account": "GB-ALLOW-1"}),
    )
    assert d.effect == Effect.DENY


def test_hard_cap_forbid_beats_permit() -> None:
    # 200000 is within no permit and above the hard cap -> explicit forbid.
    d = _mandate_engine().decide(
        _treasury(),
        ToolCall(tool="wire_funds", arguments={"amount": 200000, "account": "GB-ALLOW-1"}),
    )
    assert d.effect == Effect.DENY
    assert "cap" in d.reason.lower()


def test_conditions_are_backward_compatible() -> None:
    # A rule with no conditions behaves exactly as before.
    engine = BuiltinPolicyEngine(
        [Rule(effect=Effect.ALLOW, principals=["*"], tools=["read_application"])]
    )
    d = engine.decide(_agent(), ToolCall(tool="read_application", arguments={"anything": 1}))
    assert d.effect == Effect.ALLOW


def test_cedar_engine_if_available() -> None:
    pytest.importorskip("cedarpy")
    from pathlib import Path

    from airlock_checkpoint.policy.cedar_engine import CedarPolicyEngine

    policy_path = (
        Path(__file__).resolve().parents[1]
        / "airlock_checkpoint"
        / "policy"
        / "policies"
        / "fintech.cedar"
    )
    engine = CedarPolicyEngine.from_file(policy_path, policy_id="fintech")
    intake = PrincipalContext(agent_did="did:key:zIntake", roles=["intake"], trust_score=0.9)
    treasury = PrincipalContext(agent_did="did:key:zTreasury", roles=["treasury"], trust_score=0.9)
    assert engine.decide(intake, ToolCall(tool="wire_funds")).effect == Effect.DENY
    assert engine.decide(treasury, ToolCall(tool="wire_funds")).effect == Effect.ALLOW
