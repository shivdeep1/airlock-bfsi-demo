from __future__ import annotations

import os
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .core import POLICY, Runtime, verify_bundle
from .sessions import RateLimiter, SessionExhaustedError, SessionManager

#: Name of the per-visitor cookie in public mode.
COOKIE = "airlock_demo_session"
LOCAL_HOSTS = ["127.0.0.1", "localhost", "testserver"]


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    task_ref: str = Field(min_length=1, max_length=100)
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any]


def create_app(
    runtime: Runtime | None = None,
    *,
    sessions: SessionManager | None = None,
    allowed_hosts: list[str] | None = None,
    secure_cookie: bool = True,
) -> FastAPI:
    """Build the demo app.

    Two modes. Pass ``runtime`` for the original single-operator demo: one
    process, one operator bearer token, loopback only. Pass ``sessions`` for the
    public demo: every visitor gets an isolated Runtime behind a cookie, and the
    shared operator token does not exist.
    """
    public = sessions is not None
    owned = runtime is None and not public
    rt = runtime or (
        None if public else Runtime(Path(os.environ.get("AIRLOCK_DEMO_DATA", "data/submission")))
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if owned and rt is not None:
            rt.close()

    app = FastAPI(
        title="Airlock task access | synthetic submission demo",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.runtime = rt
    app.state.sessions = sessions
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or LOCAL_HOSTS)

    # Session creation is the expensive call; ordinary API traffic is cheap.
    new_session_limit = RateLimiter(limit=10, window=600)
    api_limit = RateLimiter(limit=180, window=60)

    def caller(request: Request) -> str:
        # Behind the Cloudflare Tunnel the edge sets CF-Connecting-IP and the
        # origin is not otherwise reachable, so it is the only useful key. On a
        # directly exposed origin this header would be attacker-controlled.
        if public and (edge := request.headers.get("cf-connecting-ip")):
            return edge
        return request.client.host if request.client else "unknown"

    @app.middleware("http")
    async def guard(request: Request, call_next: RequestResponseEndpoint) -> Response:
        # The session cookie is Secure, so a browser silently drops it over plain
        # http and every later call 401s. Cloudflare should redirect at the edge,
        # but the demo must not depend on a dashboard toggle being right.
        if public and secure_cookie and request.headers.get("x-forwarded-proto") == "http":
            return RedirectResponse(str(request.url.replace(scheme="https")), status_code=308)
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.headers.get('host')}":
            return JSONResponse({"detail": "Cross-origin requests are disabled"}, status_code=403)
        if public and request.url.path.startswith("/api/") and not api_limit.allow(caller(request)):
            return JSONResponse({"detail": "Rate limit exceeded. Slow down."}, status_code=429)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        return response

    def token(header: str) -> str:
        if not header.startswith("Bearer "):
            raise HTTPException(401, "Bearer credential required")
        return header[7:]

    def workspace(request: Request, header: str) -> Runtime:
        """The caller's Runtime, having proved they own it.

        Public mode: ownership is the session cookie. Single-operator mode: the
        operator bearer token, exactly as before.
        """
        if public:
            assert sessions is not None
            session = sessions.get(request.cookies.get(COOKIE))
            if session is None:
                raise HTTPException(401, "No active demo session. Reload to start one.")
            return session.runtime
        assert rt is not None
        if not rt.is_operator(token(header)):
            raise HTTPException(403, "Demo operator credential required")
        return rt

    @app.exception_handler(SessionExhaustedError)
    async def exhausted(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse(
            {"detail": "The demo is at capacity right now. Try again shortly."}, status_code=503
        )

    @app.exception_handler(PermissionError)
    async def permission_error(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse({"detail": "Credential not authorized"}, status_code=403)

    @app.exception_handler(sqlite3.Error)
    @app.exception_handler(OSError)
    async def evidence_error(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse(
            {
                "detail": "Evidence write unavailable. Do not assume execution succeeded or retry blindly."
            },
            status_code=503,
        )

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return Path(__file__).with_name("index.html").read_text(encoding="utf-8")

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        if public:
            assert sessions is not None
            return {"status": "ok", "mode": "public", **sessions.stats()}
        return {"status": "ok", "mode": "single-operator"}

    @app.get("/assets/{name}")
    def asset(name: str) -> Response:
        if name == "logo.jpeg":
            return Response(Path(__file__).with_name(name).read_bytes(), media_type="image/jpeg")
        if name not in {"app.js", "style.css"}:
            raise HTTPException(404)
        mime = "text/javascript" if name.endswith(".js") else "text/css"
        return Response(Path(__file__).with_name(name).read_text(encoding="utf-8"), media_type=mime)

    @app.post("/api/session")
    def open_session(request: Request) -> JSONResponse:
        """Start an isolated visitor workspace. Public mode only."""
        if not public:
            raise HTTPException(404)
        assert sessions is not None
        if not new_session_limit.allow(caller(request)):
            raise HTTPException(429, "Too many demo sessions from this address.")
        session = sessions.create()
        body = JSONResponse(
            {
                "run_id": session.runtime.run_id,
                "agent_token": session.runtime.agent_token,
                "expires_in": int(sessions.idle_ttl),
                "isolated": True,
            }
        )
        body.set_cookie(
            COOKIE,
            session.id,
            httponly=True,
            samesite="strict",
            secure=secure_cookie,
            max_age=max(1, int(sessions.absolute_ttl)),  # never round a short TTL down to 0
            path="/",
        )
        return body

    @app.get("/api/state")
    def state(request: Request, authorization: str = Header(default="")) -> dict[str, Any]:
        ws = workspace(request, authorization)
        bundle = ws.evidence()
        return {
            "run_id": ws.run_id,
            "task": asdict(ws.tasks[ws.latest_task]) if ws.latest_task else None,
            "analyst_entitlements": sorted(ws.entitlements[("demo-bank", "analyst-01")]),
            "policy": POLICY,
            "events": bundle["payload"]["events"],
            "backend_reads": bundle["payload"]["backend_reads"],
            "signature_valid": verify_bundle(bundle),
            "public_key": bundle["public_key"],
        }

    @app.post("/api/tasks")
    def assign(request: Request, authorization: str = Header(default="")) -> dict[str, Any]:
        ws = workspace(request, authorization)
        return asdict(ws.assign(ws.operator_token))

    @app.post("/api/tasks/{task_ref}/revoke")
    def revoke(
        task_ref: str, request: Request, authorization: str = Header(default="")
    ) -> dict[str, Any]:
        ws = workspace(request, authorization)
        if task_ref not in ws.tasks:
            raise HTTPException(404, "Unknown task")
        return asdict(ws.revoke(ws.operator_token, task_ref))

    @app.post("/api/execute")
    def execute(
        body: ExecuteRequest, request: Request, authorization: str = Header(default="")
    ) -> JSONResponse:
        """Agent-credential path. The credential must belong to the caller's own workspace."""
        if public:
            assert sessions is not None
            session = sessions.get(request.cookies.get(COOKIE))
            if session is None:
                raise HTTPException(401, "No active demo session. Reload to start one.")
            ws = session.runtime
        else:
            assert rt is not None
            ws = rt
        result = ws.execute(token(authorization), body.task_ref, body.tool, body.arguments)
        return JSONResponse(result, status_code=200 if result["decision"] == "ALLOW" else 403)

    @app.post("/api/demo/{action}")
    def demo(
        action: str, request: Request, authorization: str = Header(default="")
    ) -> dict[str, Any]:
        # Privileged operator harness, not an agent-accessible identity switch.
        ws = workspace(request, authorization)
        if ws.latest_task is None:
            raise HTTPException(409, "Create an assignment first")
        actions = {
            "read": ("read_documents", {"borrower": "A"}),
            "cross-case": ("read_documents", {"borrower": "B"}),
            "upload": ("external_upload", {"destination": "https://unapproved.invalid/upload"}),
        }
        if action not in actions:
            raise HTTPException(404)
        tool, arguments = actions[action]
        result = ws.execute(ws.agent_token, ws.latest_task, tool, arguments)
        if result["execution"] == "completed":
            document = result["document"]
            result["draft"] = {
                "label": "Deterministic document extraction, not a live LLM summary",
                "name": document["name"],
                "observations": [
                    {"source": d["id"], "text": d["text"]}
                    for d in document["documents"]
                    if d["title"] != "Untrusted attachment"
                ],
                "notice": "Draft for human review. No credit recommendation or loan decision.",
            }
        result["agent_mode"] = "scripted test request"
        return result

    @app.get("/api/evidence")
    def evidence(request: Request, authorization: str = Header(default="")) -> JSONResponse:
        ws = workspace(request, authorization)
        return JSONResponse(
            ws.evidence(),
            headers={"Content-Disposition": 'attachment; filename="airlock-evidence.json"'},
        )

    return app
