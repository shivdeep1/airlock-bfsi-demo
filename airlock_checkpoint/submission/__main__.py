"""Run with python -m airlock_checkpoint.submission; listen on loopback only."""

from __future__ import annotations

import argparse
import json
import webbrowser
from pathlib import Path

import uvicorn

from .app import create_app
from .core import Runtime, verify_bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="Airlock synthetic submission demo")
    parser.add_argument("--port", type=int, default=8801)
    parser.add_argument("--data-dir", type=Path, default=Path("data/submission"))
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument(
        "--verify", type=Path, help="Verify an exported evidence JSON file instead of starting"
    )
    parser.add_argument("--public-key", help="Optional independently recorded expected public key")
    args = parser.parse_args()
    if args.verify:
        valid = verify_bundle(json.loads(args.verify.read_text(encoding="utf-8")), args.public_key)
        print("Signature valid" if valid else "INVALID signature or key")
        print("Integrity only. The embedded key is not an independent trust anchor.")
        raise SystemExit(0 if valid else 1)
    rt = Runtime(args.data_dir)
    url = f"http://127.0.0.1:{args.port}/#token={rt.operator_token}"
    print("\nAirlock | synthetic, local submission demo", flush=True)
    print("Private operator launch URL (do not share this token):", flush=True)
    print(url, flush=True)
    print("Scripted agent; no live model, bank connection or customer data.\n", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        uvicorn.run(create_app(rt), host="127.0.0.1", port=args.port, access_log=False)
    finally:
        rt.close()


if __name__ == "__main__":
    main()
