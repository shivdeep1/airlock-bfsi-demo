from __future__ import annotations

import os
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .core import POLICY, Runtime, verify_bundle


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    task_ref: str = Field(min_length=1, max_length=100)
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any]


def create_app(runtime: Runtime | None = None) -> FastAPI:
    owned = runtime is None
    rt = runtime or Runtime(Path(os.environ.get("AIRLOCK_DEMO_DATA", "data/submission")))

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if owned:
            rt.close()

    app = FastAPI(
        title="Airlock task access | synthetic submission demo",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.runtime = rt
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"]
    )

    @app.middleware("http")
    async def local_only(request: Request, call_next: RequestResponseEndpoint) -> Response:
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.headers.get('host')}":
            return JSONResponse({"detail": "Cross-origin requests are disabled"}, status_code=403)
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

    def operator(header: str) -> str:
        value = token(header)
        if not rt.is_operator(value):
            raise HTTPException(403, "Demo operator credential required")
        return value

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

    @app.get("/assets/{name}")
    def asset(name: str) -> Response:
        if name == "logo.jpeg":
            return Response(Path(__file__).with_name(name).read_bytes(), media_type="image/jpeg")
        if name not in {"app.js", "style.css"}:
            raise HTTPException(404)
        mime = "text/javascript" if name.endswith(".js") else "text/css"
        return Response(Path(__file__).with_name(name).read_text(encoding="utf-8"), media_type=mime)

    @app.get("/api/state")
    def state(authorization: str = Header(default="")) -> dict[str, Any]:
        operator(authorization)
        bundle = rt.evidence()
        return {
            "run_id": rt.run_id,
            "task": asdict(rt.tasks[rt.latest_task]) if rt.latest_task else None,
            "analyst_entitlements": sorted(rt.entitlements[("demo-bank", "analyst-01")]),
            "policy": POLICY,
            "events": bundle["payload"]["events"],
            "backend_reads": bundle["payload"]["backend_reads"],
            "signature_valid": verify_bundle(bundle),
            "public_key": bundle["public_key"],
        }

    @app.post("/api/tasks")
    def assign(authorization: str = Header(default="")) -> dict[str, Any]:
        return asdict(rt.assign(operator(authorization)))

    @app.post("/api/tasks/{task_ref}/revoke")
    def revoke(task_ref: str, authorization: str = Header(default="")) -> dict[str, Any]:
        credential = operator(authorization)
        if task_ref not in rt.tasks:
            raise HTTPException(404, "Unknown task")
        return asdict(rt.revoke(credential, task_ref))

    @app.post("/api/execute")
    def execute(body: ExecuteRequest, authorization: str = Header(default="")) -> JSONResponse:
        result = rt.execute(token(authorization), body.task_ref, body.tool, body.arguments)
        return JSONResponse(result, status_code=200 if result["decision"] == "ALLOW" else 403)

    @app.post("/api/demo/{action}")
    def demo(action: str, authorization: str = Header(default="")) -> dict[str, Any]:
        # Privileged operator harness, not an agent-accessible identity switch.
        operator(authorization)
        if rt.latest_task is None:
            raise HTTPException(409, "Create an assignment first")
        actions = {
            "read": ("read_documents", {"borrower": "A"}),
            "cross-case": ("read_documents", {"borrower": "B"}),
            "upload": ("external_upload", {"destination": "https://unapproved.invalid/upload"}),
        }
        if action not in actions:
            raise HTTPException(404)
        tool, arguments = actions[action]
        result = rt.execute(rt.agent_token, rt.latest_task, tool, arguments)
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
    def evidence(authorization: str = Header(default="")) -> JSONResponse:
        operator(authorization)
        return JSONResponse(
            rt.evidence(),
            headers={"Content-Disposition": 'attachment; filename="airlock-evidence.json"'},
        )

    return app
