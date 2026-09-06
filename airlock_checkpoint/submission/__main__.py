"""Run with python -m airlock_checkpoint.submission.

Two modes:

* default, single operator, loopback only. One process handed to one trusted
  person, launched with a private token in the URL fragment.
* ``--public``, for the hosted demo. Every visitor gets an isolated workspace
  behind a session cookie, there is no shared operator token, sessions expire
  and storage is bounded.
"""

from __future__ import annotations

import argparse
import json
import os
import webbrowser
from pathlib import Path

import uvicorn

from .app import create_app
from .core import EvidenceStore, MockBank, Runtime, verify_bundle
from .sessions import ABSOLUTE_TTL, IDLE_TTL, MAX_SESSIONS, SessionManager


def main() -> None:
    parser = argparse.ArgumentParser(description="Airlock synthetic submission demo")
    parser.add_argument("--port", type=int, default=8801)
    parser.add_argument("--data-dir", type=Path, default=Path("data/submission"))
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument(
        "--verify", type=Path, help="Verify an exported evidence JSON file instead of starting"
    )
    parser.add_argument("--public-key", help="Optional independently recorded expected public key")
    parser.add_argument(
        "--public",
        action="store_true",
        help="Serve the multi-visitor public demo instead of the single-operator one",
    )
    parser.add_argument("--host", default=None, help="Bind address (default 127.0.0.1)")
    parser.add_argument(
        "--allowed-hosts",
        default=os.environ.get("AIRLOCK_DEMO_ALLOWED_HOSTS", ""),
        help="Comma-separated Host values to accept in public mode",
    )
    parser.add_argument(
        "--insecure-cookie",
        action="store_true",
        help="Send the session cookie without Secure, for local http testing only",
    )
    parser.add_argument("--idle-ttl", type=int, default=IDLE_TTL)
    parser.add_argument("--absolute-ttl", type=int, default=ABSOLUTE_TTL)
    parser.add_argument("--max-sessions", type=int, default=MAX_SESSIONS)
    args = parser.parse_args()

    if args.verify:
        valid = verify_bundle(json.loads(args.verify.read_text(encoding="utf-8")), args.public_key)
        print("Signature valid" if valid else "INVALID signature or key")
        print("Integrity only. The embedded key is not an independent trust anchor.")
        raise SystemExit(0 if valid else 1)

    if args.public:
        hosts = [h.strip() for h in args.allowed_hosts.split(",") if h.strip()]
        if not hosts:
            parser.error(
                "--public needs --allowed-hosts (or AIRLOCK_DEMO_ALLOWED_HOSTS), "
                "for example demo.airlock.ing"
            )
        args.data_dir.mkdir(parents=True, exist_ok=True)
        store = EvidenceStore(args.data_dir / "evidence.sqlite3")
        bank = MockBank()
        manager = SessionManager(
            store,
            bank,
            idle_ttl=args.idle_ttl,
            absolute_ttl=args.absolute_ttl,
            max_sessions=args.max_sessions,
        )
        # A restart drops in-memory sessions, so rows from earlier runs can never
        # be reached again. Clear them rather than letting the file grow forever.
        stale = {e["run_id"] for e in store.events() if "run_id" in e}
        if stale:
            store.drop_runs(stale)
        app = create_app(
            sessions=manager,
            allowed_hosts=hosts,
            secure_cookie=not args.insecure_cookie,
        )
        print("\nAirlock | synthetic public demo", flush=True)
        print(f"Isolated visitor sessions, idle TTL {args.idle_ttl}s, cap {args.max_sessions}.")
        print(f"Accepting Host: {', '.join(hosts)}", flush=True)
        print("Scripted agent; no live model, bank connection or customer data.\n", flush=True)
        try:
            uvicorn.run(app, host=args.host or "127.0.0.1", port=args.port, access_log=False)
        finally:
            manager.close()
        return

    rt = Runtime(args.data_dir)
    url = f"http://127.0.0.1:{args.port}/#token={rt.operator_token}"
    print("\nAirlock | synthetic, local submission demo", flush=True)
    print("Private operator launch URL (do not share this token):", flush=True)
    print(url, flush=True)
    print("Scripted agent; no live model, bank connection or customer data.\n", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        uvicorn.run(create_app(rt), host=args.host or "127.0.0.1", port=args.port, access_log=False)
    finally:
        rt.close()


if __name__ == "__main__":
    main()
