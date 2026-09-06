from __future__ import annotations

import copy
import json
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from airlock_checkpoint.submission.app import create_app
from airlock_checkpoint.submission.core import EvidenceStore, Runtime, verify_bundle


@pytest.fixture
def rt(tmp_path):
    runtime = Runtime(tmp_path)
    yield runtime
    runtime.close()


@pytest.fixture
def client(rt):
    with TestClient(create_app(rt)) as browser:
        yield browser


def auth(value):
    return {"Authorization": "Bearer " + value}


def test_brand_logo_is_served_without_opening_other_files(client):
    response = client.get("/assets/logo.jpeg")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.content.startswith(b"\xff\xd8\xff")
    assert client.get("/assets/core.py").status_code == 404
    assert 'alt="" width="48" height="48">Airlock' in client.get("/").text


def assigned(rt):
    return rt.assign(rt.operator_token).id


def read(rt, task):
    return rt.execute(rt.agent_token, task, "read_documents", {"borrower": "A"})


def test_allowed_read_reaches_http_backend_and_has_correlated_receipt(rt):
    result = read(rt, assigned(rt))
    assert result["decision"] == "ALLOW"
    assert result["execution"] == "completed"
    assert result["document"]["borrower"] == "A"
    assert rt.bank.ledger()[0]["correlation_id"] == result["correlation_id"]
    assert rt.bank.ledger()[0]["backend_request_id"] == result["backend_request_id"]
    events = rt.evidence()["payload"]["events"]
    assert [e["kind"] for e in events] == ["assignment", "decision", "dispatch_intent", "outcome"]


@pytest.mark.parametrize(
    ("tool", "arguments", "reason"),
    [
        ("read_documents", {"borrower": "B"}, "outside_task_scope"),
        (
            "external_upload",
            {"destination": "https://unapproved.invalid/upload"},
            "tool_not_permitted",
        ),
        ("http_get", {"url": "http://localhost/"}, "tool_not_permitted"),
        ("read_documents", {"borrower": "../B"}, "invalid_arguments"),
        ("read_documents", {"borrower": "A", "tenant": "other-bank"}, "invalid_arguments"),
        ("read_documents", {"borrower": ["A"]}, "invalid_arguments"),
        ("read_documents", {"borrower": {"id": "A"}}, "invalid_arguments"),
        ("read_documents", {}, "invalid_arguments"),
    ],
)
def test_disallowed_requests_never_dispatch(rt, tool, arguments, reason):
    result = rt.execute(rt.agent_token, assigned(rt), tool, arguments)
    assert result["decision"] == "DENY"
    assert result["reason"] == reason
    assert result["execution"] == "not_dispatched"
    assert rt.bank.ledger() == []
    assert "B_ONLY_CANARY" not in json.dumps(result)


@pytest.mark.parametrize("credential", ["other_agent_token", "other_tenant_token"])
def test_task_reference_bound_to_agent_user_tenant(rt, credential):
    result = rt.execute(getattr(rt, credential), assigned(rt), "read_documents", {"borrower": "A"})
    assert result["reason"] == "identity_or_tenant_mismatch"
    assert rt.bank.ledger() == []


def test_invalid_agent_credential_cannot_execute(rt):
    with pytest.raises(PermissionError):
        rt.execute("forged", assigned(rt), "read_documents", {"borrower": "A"})
    assert rt.bank.ledger() == []


def test_operator_is_not_an_agent_credential(rt):
    with pytest.raises(PermissionError):
        rt.execute(rt.operator_token, assigned(rt), "read_documents", {"borrower": "A"})


def test_agent_cannot_issue_or_revoke_tasks(rt):
    task = assigned(rt)
    with pytest.raises(PermissionError):
        rt.assign(rt.agent_token)
    with pytest.raises(PermissionError):
        rt.revoke(rt.agent_token, task)


def test_revocation_stops_next_read_and_does_not_erase_evidence(rt):
    task = assigned(rt)
    read(rt, task)
    rt.revoke(rt.operator_token, task)
    result = read(rt, task)
    assert result["reason"] == "task_revoked"
    assert result["task_version"] == 2
    assert len(rt.bank.ledger()) == 1
    assert any(e["kind"] == "revocation" for e in rt.store.events())


def test_expiry_and_removed_entitlement(rt):
    task = assigned(rt)
    rt.tasks[task].expires_at = time.time() - 1
    assert read(rt, task)["reason"] == "task_expired"
    task = assigned(rt)
    rt.entitlements[("demo-bank", "analyst-01")].remove("A")
    assert read(rt, task)["reason"] == "user_entitlement_removed"
    assert rt.bank.ledger() == []


def test_unknown_task_denied(rt):
    assert read(rt, "invented-task")["reason"] == "unknown_task"
    assert rt.bank.ledger() == []


def test_direct_backend_bypass_rejected_even_with_agent_token(rt):
    with httpx.Client(trust_env=False) as client:
        for headers in [{}, auth(rt.agent_token), auth(rt.operator_token)]:
            response = client.get(rt.bank.url + "/documents/demo-bank/B", headers=headers)
            assert response.status_code == 401
            assert "B_ONLY_CANARY" not in response.text
    assert rt.bank.ledger() == []


def test_policy_exception_fails_closed(rt, monkeypatch):
    def unavailable(*_):
        raise RuntimeError("policy offline")

    monkeypatch.setattr(rt.engine, "decide", unavailable)
    assert read(rt, assigned(rt))["reason"] == "policy_unavailable"
    assert rt.bank.ledger() == []


def test_evidence_failure_before_dispatch_stops_execution(rt):
    task = assigned(rt)
    rt.store.fail_writes = True
    with pytest.raises(OSError):
        read(rt, task)
    assert rt.bank.ledger() == []


def test_failed_assignment_not_issued_and_failed_revocation_not_acknowledged(rt):
    task = assigned(rt)
    rt.store.fail_writes = True
    with pytest.raises(OSError):
        rt.assign(rt.operator_token)
    with pytest.raises(OSError):
        rt.revoke(rt.operator_token, task)
    assert len(rt.tasks) == 1
    assert rt.tasks[task].status == "active"
    with pytest.raises(OSError):
        read(rt, task)
    assert rt.bank.ledger() == []


def test_backend_timeout_is_not_reported_successful(rt, monkeypatch):
    def timeout(*_):
        raise httpx.ReadTimeout("timeout")

    monkeypatch.setattr(rt.bank, "read", timeout)
    result = read(rt, assigned(rt))
    assert result["execution"] == "indeterminate"
    assert "document" not in result


def test_result_evidence_failure_leaves_unresolved_intent(rt, monkeypatch):
    original = rt.bank.read

    def completed_then_storage_fails(*args):
        result = original(*args)
        rt.store.fail_writes = True
        return result

    monkeypatch.setattr(rt.bank, "read", completed_then_storage_fails)
    with pytest.raises(OSError):
        read(rt, assigned(rt))
    assert len(rt.bank.ledger()) == 1
    assert rt.store.events()[-1]["kind"] == "dispatch_intent"


def test_export_signature_and_tamper_and_pinned_key(rt):
    read(rt, assigned(rt))
    bundle = rt.evidence()
    assert verify_bundle(bundle)
    assert verify_bundle(bundle, bundle["public_key"])
    assert not verify_bundle(bundle, "00" * 32)
    changed = copy.deepcopy(bundle)
    changed["payload"]["events"][1]["decision"] = "DENY"
    assert not verify_bundle(changed)
    assert not verify_bundle({})
    assert "Latest audited" not in json.dumps(bundle)
    assert rt.agent_token not in json.dumps(bundle)
    assert rt.bank.credential not in json.dumps(bundle)


def test_durable_events_survive_reopening(tmp_path):
    path = tmp_path / "events.sqlite3"
    store = EvidenceStore(path)
    store.append({"kind": "example"})
    store.close()
    reopened = EvidenceStore(path)
    assert reopened.events() == [{"kind": "example"}]
    reopened.close()


def test_revoke_and_dispatch_have_serial_order(rt, monkeypatch):
    task = assigned(rt)
    started = threading.Event()
    release = threading.Event()
    revoked = threading.Event()
    original = rt.bank.read

    def slow_read(*args):
        started.set()
        assert release.wait(timeout=3)
        return original(*args)

    monkeypatch.setattr(rt.bank, "read", slow_read)
    worker = threading.Thread(target=read, args=(rt, task))

    def revoke():
        rt.revoke(rt.operator_token, task)
        revoked.set()

    worker.start()
    assert started.wait(timeout=3)
    closer = threading.Thread(target=revoke)
    closer.start()
    assert not revoked.wait(timeout=0.05)
    release.set()
    worker.join(timeout=3)
    closer.join(timeout=3)
    assert revoked.is_set()
    assert read(rt, task)["reason"] == "task_revoked"
    assert len(rt.bank.ledger()) == 1


def test_http_auth_and_operator_separation(rt, client):
    assert client.get("/api/state").status_code == 401
    assert client.get("/api/evidence", headers=auth(rt.agent_token)).status_code == 403
    assert client.post("/api/tasks", headers=auth(rt.agent_token)).status_code == 403
    assert client.post("/api/demo/read", headers=auth(rt.agent_token)).status_code == 403
    assert client.get("/api/state", headers=auth(rt.operator_token)).status_code == 200


def test_http_rejects_forged_principal_fields(rt, client):
    response = client.post(
        "/api/execute",
        headers=auth(rt.agent_token),
        json={
            "task_ref": assigned(rt),
            "tool": "read_documents",
            "arguments": {"borrower": "A"},
            "principal": {"role": "admin"},
        },
    )
    assert response.status_code == 422
    assert rt.bank.ledger() == []


def test_http_denied_returns_403(rt, client):
    response = client.post(
        "/api/execute",
        headers=auth(rt.agent_token),
        json={
            "task_ref": assigned(rt),
            "tool": "read_documents",
            "arguments": {"borrower": "B"},
        },
    )
    assert response.status_code == 403
    assert response.json()["execution"] == "not_dispatched"


def test_http_cross_origin_and_host_rejected(rt, client):
    assert (
        client.post(
            "/api/tasks", headers={**auth(rt.operator_token), "Origin": "https://evil.invalid"}
        ).status_code
        == 403
    )
    assert client.get("/", headers={"Host": "evil.invalid"}).status_code == 400


def test_complete_submission_flow(rt, client):
    headers = auth(rt.operator_token)
    task = client.post("/api/tasks", headers=headers).json()
    result = client.post("/api/demo/read", headers=headers).json()
    assert result["execution"] == "completed"
    assert "not a live LLM" in result["draft"]["label"]
    assert client.post("/api/demo/cross-case", headers=headers).json()["decision"] == "DENY"
    assert client.post("/api/demo/upload", headers=headers).json()["decision"] == "DENY"
    assert client.post(f"/api/tasks/{task['id']}/revoke", headers=headers).status_code == 200
    assert client.post("/api/demo/read", headers=headers).json()["reason"] == "task_revoked"
    state = client.get("/api/state", headers=headers).json()
    assert len(state["backend_reads"]) == 1
    assert state["signature_valid"]
    bundle = client.get("/api/evidence", headers=headers).json()
    assert verify_bundle(bundle)


def test_page_assets_no_credentials_or_external_dependencies(rt, client):
    for path in ["/", "/assets/app.js", "/assets/style.css"]:
        response = client.get(path)
        assert response.status_code == 200
        assert rt.agent_token not in response.text
        assert rt.operator_token not in response.text
        assert rt.bank.credential not in response.text
        assert response.headers["Cache-Control"] == "no-store"
    assert client.get("/assets/core.py").status_code == 404
