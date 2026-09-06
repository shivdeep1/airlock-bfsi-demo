from __future__ import annotations

from airlock.audit.trail import AuditTrail
from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import verify_signature

from airlock_checkpoint.pep import Checkpoint
from airlock_checkpoint.policy.builtin_engine import BuiltinPolicyEngine, Rule
from airlock_checkpoint.policy.engine import Effect, PrincipalContext, ToolCall


def _engine() -> BuiltinPolicyEngine:
    return BuiltinPolicyEngine(
        [
            Rule(
                effect=Effect.ALLOW,
                principals=["role:treasury"],
                tools=["wire_funds"],
                min_trust=0.75,
                description="treasury may wire funds",
            ),
            Rule(
                effect=Effect.ALLOW,
                principals=["*"],
                tools=["read_application"],
                description="any agent may read",
            ),
        ],
        policy_id="fintech",
    )


async def test_denies_unauthorized_tool_and_audits() -> None:
    audit = AuditTrail()
    cp = Checkpoint(_engine(), audit_trail=audit)
    principal = PrincipalContext(agent_did="did:key:zIntake", roles=["intake"], trust_score=0.9)
    result = await cp.enforce(principal, ToolCall(tool="wire_funds", server="fintech-mcp"))
    assert not result.allowed
    assert result.record.effect == Effect.DENY
    entries = await audit.get_entries()
    assert len(entries) == 1
    assert entries[0].detail["effect"] == "DENY"
    ok, reason = await audit.verify_chain()
    assert ok, reason


async def test_allows_authorized_tool() -> None:
    cp = Checkpoint(_engine())
    principal = PrincipalContext(agent_did="did:key:zTreasury", roles=["treasury"], trust_score=0.9)
    result = await cp.enforce(principal, ToolCall(tool="wire_funds"))
    assert result.allowed


async def test_signed_record_verifies() -> None:
    kp = KeyPair.generate()
    cp = Checkpoint(_engine(), signing_key=kp.signing_key, airlock_did=kp.did)
    principal = PrincipalContext(agent_did="did:key:zTreasury", roles=["treasury"], trust_score=0.9)
    result = await cp.enforce(principal, ToolCall(tool="wire_funds", arguments={"amount": 50000}))
    rec = result.record
    assert rec.airlock_signature is not None
    data = rec.model_dump(mode="json")
    data.pop("airlock_signature", None)
    assert verify_signature(data, rec.airlock_signature, kp.verify_key)


async def test_tampered_record_fails_verification() -> None:
    kp = KeyPair.generate()
    cp = Checkpoint(_engine(), signing_key=kp.signing_key)
    principal = PrincipalContext(agent_did="did:key:zTreasury", roles=["treasury"], trust_score=0.9)
    result = await cp.enforce(principal, ToolCall(tool="wire_funds"))
    rec = result.record
    data = rec.model_dump(mode="json")
    data.pop("airlock_signature", None)
    data["effect"] = "DENY"  # tamper: flip the decision after signing
    assert not verify_signature(data, rec.airlock_signature, kp.verify_key)
