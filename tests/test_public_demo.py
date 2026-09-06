"""Public-demo protections: visitor isolation, expiry, limits, restart behaviour.

These cover the gap between the single-operator demo and something safe to put
on the open internet. The single-operator path is covered by test_submission.py
and must keep working unchanged.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from airlock_checkpoint.submission.app import COOKIE, create_app
from airlock_checkpoint.submission.core import EvidenceStore, MockBank
from airlock_checkpoint.submission.sessions import RateLimiter, SessionManager

HOSTS = ["testserver", "demo.airlock.ing"]


def tc(app):
    """A client that speaks https, so the Secure session cookie is sent back."""
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def manager(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    bank = MockBank()
    mgr = SessionManager(store, bank, idle_ttl=60, absolute_ttl=120, max_sessions=5)
    yield mgr
    mgr.close()


@pytest.fixture
def app(manager):
    return create_app(sessions=manager, allowed_hosts=HOSTS, secure_cookie=True)


def visitor(app):
    client = tc(app)
    response = client.post("/api/session")
    assert response.status_code == 200, response.text
    return client, response


def walk(client):
    """Assignment then one permitted read."""
    assert client.post("/api/tasks").status_code == 200
    return client.post("/api/demo/read").json()


# -- isolation -------------------------------------------------------------


def test_two_visitors_get_separate_workspaces(app):
    a, ra = visitor(app)
    b, rb = visitor(app)
    assert ra.json()["run_id"] != rb.json()["run_id"]
    assert ra.cookies[COOKIE] != rb.cookies[COOKIE]

    walk(a)
    # B has done nothing, so B must see no task and none of A's events.
    state_b = b.get("/api/state").json()
    assert state_b["task"] is None
    assert state_b["events"] == []
    assert state_b["backend_reads"] == []

    state_a = a.get("/api/state").json()
    assert state_a["task"] is not None
    assert len(state_a["backend_reads"]) == 1
    assert {e["run_id"] for e in state_a["events"]} == {ra.json()["run_id"]}


def test_evidence_export_contains_only_the_callers_run(app):
    a, ra = visitor(app)
    b, rb = visitor(app)
    walk(a)
    walk(b)
    bundle_a = a.get("/api/evidence").json()
    runs = {e["run_id"] for e in bundle_a["payload"]["events"]}
    assert runs == {ra.json()["run_id"]}
    assert rb.json()["run_id"] not in runs
    assert bundle_a["payload"]["backend_reads"]
    assert all(r["scope"] == ra.json()["run_id"] for r in bundle_a["payload"]["backend_reads"])


def test_each_visitor_signs_with_their_own_key(app):
    a, _ = visitor(app)
    b, _ = visitor(app)
    walk(a)
    walk(b)
    key_a = a.get("/api/evidence").json()["public_key"]
    key_b = b.get("/api/evidence").json()["public_key"]
    assert key_a != key_b


def test_agent_token_from_another_session_is_rejected(app):
    a, ra = visitor(app)
    b, _ = visitor(app)
    task = a.post("/api/tasks").json()["id"]
    # B presents A's agent credential against B's own session.
    response = b.post(
        "/api/execute",
        headers={"Authorization": "Bearer " + ra.json()["agent_token"]},
        json={"task_ref": task, "tool": "read_documents", "arguments": {"borrower": "A"}},
    )
    assert response.status_code == 403


def test_revoking_in_one_session_does_not_touch_another(app):
    a, _ = visitor(app)
    b, _ = visitor(app)
    walk(a)
    task_b = b.post("/api/tasks").json()["id"]
    a_task = a.get("/api/state").json()["task"]["id"]
    assert a.post("/api/tasks/" + a_task + "/revoke").status_code == 200
    # A's revocation must not reach B, and A cannot name B's task either.
    assert b.post("/api/demo/read").json()["decision"] == "ALLOW"
    assert a.post("/api/tasks/" + task_b + "/revoke").status_code == 404


# -- no shared credential --------------------------------------------------


def test_api_requires_a_session(app):
    client = tc(app)
    for path in ["/api/state", "/api/evidence"]:
        assert client.get(path).status_code == 401
    for path in ["/api/tasks", "/api/demo/read"]:
        assert client.post(path).status_code == 401


def test_no_bearer_token_substitutes_for_a_session(app):
    client = tc(app)
    for candidate in ["operator", "x" * 43, ""]:
        response = client.get("/api/state", headers={"Authorization": "Bearer " + candidate})
        assert response.status_code == 401


def test_forged_cookie_is_rejected(app):
    client = tc(app)
    client.cookies.set(COOKIE, "not-a-real-session-id")
    assert client.get("/api/state").status_code == 401


def test_session_cookie_is_httponly_strict_and_secure(app):
    client = tc(app)
    header = client.post("/api/session").headers["set-cookie"].lower()
    assert "httponly" in header
    assert "samesite=strict" in header
    assert "secure" in header


def test_insecure_cookie_only_when_explicitly_requested(manager):
    client = tc(create_app(sessions=manager, allowed_hosts=HOSTS, secure_cookie=False))
    assert "secure" not in client.post("/api/session").headers["set-cookie"].lower()


# -- expiry and cleanup ----------------------------------------------------


def test_idle_expiry_invalidates_the_session_and_reclaims_storage(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    bank = MockBank()
    mgr = SessionManager(store, bank, idle_ttl=0.3, absolute_ttl=120, max_sessions=5)
    try:
        client = tc(create_app(sessions=mgr, allowed_hosts=HOSTS))
        client.post("/api/session")
        walk(client)
        assert store.count() > 0
        time.sleep(0.4)
        assert client.get("/api/state").status_code == 401
        assert mgr.live == 0
        assert store.count() == 0  # the expired run's evidence is deleted
        assert bank.ledger() == []  # and its ledger rows pruned
    finally:
        mgr.close()


def test_absolute_expiry_applies_even_while_active(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    bank = MockBank()
    mgr = SessionManager(store, bank, idle_ttl=60, absolute_ttl=1.0, max_sessions=5)
    try:
        client = tc(create_app(sessions=mgr, allowed_hosts=HOSTS))
        client.post("/api/session")
        assert client.get("/api/state").status_code == 200
        time.sleep(1.2)
        assert client.get("/api/state").status_code == 401
    finally:
        mgr.close()


def test_sweep_leaves_live_sessions_alone(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    bank = MockBank()
    mgr = SessionManager(store, bank, idle_ttl=60, absolute_ttl=120, max_sessions=5)
    try:
        app = create_app(sessions=mgr, allowed_hosts=HOSTS)
        a, _ = visitor(app)
        walk(a)
        before = store.count()
        assert mgr.sweep() == 0
        assert store.count() == before
        assert a.get("/api/state").status_code == 200
    finally:
        mgr.close()


def test_restart_drops_sessions_and_the_client_is_told(app, tmp_path):
    client, _ = visitor(app)
    assert client.get("/api/state").status_code == 200
    fresh = SessionManager(EvidenceStore(tmp_path / "other.sqlite3"), MockBank(), max_sessions=5)
    try:
        moved = tc(create_app(sessions=fresh, allowed_hosts=HOSTS))
        moved.cookies.set(COOKIE, client.cookies[COOKIE])
        assert moved.get("/api/state").status_code == 401
    finally:
        fresh.close()


# -- capacity and rate limits ----------------------------------------------


def test_session_cap_returns_503_not_a_crash(app):
    made = [visitor(app) for _ in range(5)]
    assert len(made) == 5
    response = tc(app).post("/api/session")
    assert response.status_code == 503
    assert "capacity" in response.json()["detail"].lower()


def test_session_creation_is_rate_limited_per_caller(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    bank = MockBank()
    mgr = SessionManager(store, bank, max_sessions=1000)
    try:
        client = tc(create_app(sessions=mgr, allowed_hosts=HOSTS))
        codes = [client.post("/api/session").status_code for _ in range(12)]
        assert codes.count(200) == 10
        assert codes[-1] == 429
    finally:
        mgr.close()


def test_rate_limiter_window_rolls_over():
    limiter = RateLimiter(limit=2, window=0.3)
    assert limiter.allow("k")
    assert limiter.allow("k")
    assert not limiter.allow("k")
    time.sleep(0.35)
    assert limiter.allow("k")


def test_event_ceiling_refuses_new_sessions(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    bank = MockBank()
    mgr = SessionManager(store, bank, max_sessions=50, max_events=1)
    try:
        app = create_app(sessions=mgr, allowed_hosts=HOSTS)
        first = tc(app)
        first.post("/api/session")
        walk(first)
        assert tc(app).post("/api/session").status_code == 503
    finally:
        mgr.close()


# -- public-facing surface -------------------------------------------------


def test_unexpected_host_is_rejected(app):
    client = TestClient(app, base_url="https://evil.invalid")
    assert client.post("/api/session").status_code == 400


def test_configured_public_host_is_accepted(app):
    client = TestClient(app, base_url="https://demo.airlock.ing")
    assert client.post("/api/session").status_code == 200


def test_cross_origin_still_refused_with_a_valid_session(app):
    client, _ = visitor(app)
    response = client.post("/api/tasks", headers={"Origin": "https://evil.invalid"})
    assert response.status_code == 403


def test_healthz_reports_capacity_without_a_session(app):
    body = tc(app).get("/healthz").json()
    assert body["mode"] == "public"
    assert body["capacity"] == 5
    assert "sessions" in body
    assert "events" in body


def test_pages_and_assets_carry_no_session_credential(app):
    client, response = visitor(app)
    secret = client.cookies[COOKIE]
    agent = response.json()["agent_token"]
    for path in ["/", "/assets/app.js", "/assets/style.css"]:
        text = client.get(path).text
        assert secret not in text
        assert agent not in text


def test_denied_requests_never_reach_the_document_backend(app, manager):
    client, response = visitor(app)
    run = response.json()["run_id"]
    client.post("/api/tasks")
    for action, reason in [("cross-case", "outside_task_scope"), ("upload", "tool_not_permitted")]:
        body = client.post("/api/demo/" + action).json()
        assert body["decision"] == "DENY"
        assert body["reason"] == reason
        assert body["execution"] == "not_dispatched"
    assert manager.bank.ledger(run) == []


def test_full_five_step_flow_in_public_mode(app):
    client, _ = visitor(app)
    client.post("/api/tasks")
    assert client.post("/api/demo/read").json()["decision"] == "ALLOW"
    assert client.post("/api/demo/cross-case").json()["reason"] == "outside_task_scope"
    assert client.post("/api/demo/upload").json()["reason"] == "tool_not_permitted"
    task = client.get("/api/state").json()["task"]["id"]
    assert client.post("/api/tasks/" + task + "/revoke").status_code == 200
    assert client.post("/api/demo/read").json()["reason"] == "task_revoked"
    bundle = client.get("/api/evidence").json()
    assert bundle["payload"]["synthetic"] is True
    assert client.get("/api/state").json()["signature_valid"] is True


# -- transport -------------------------------------------------------------


def test_plain_http_is_redirected_so_the_secure_cookie_survives(app):
    """A Secure cookie is dropped over http, which 401s every later call."""
    client = tc(app)
    r = client.post("/api/session", headers={"X-Forwarded-Proto": "http"}, follow_redirects=False)
    assert r.status_code == 308
    assert r.headers["location"].startswith("https://")


def test_https_requests_are_not_redirected(app):
    client = tc(app)
    r = client.post("/api/session", headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
    assert r.status_code == 200


def test_local_insecure_cookie_mode_is_never_redirected(manager):
    """--insecure-cookie exists for local http testing; it must stay usable."""
    client = tc(create_app(sessions=manager, allowed_hosts=HOSTS, secure_cookie=False))
    r = client.post("/api/session", headers={"X-Forwarded-Proto": "http"}, follow_redirects=False)
    assert r.status_code == 200
