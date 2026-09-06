# Airlock: task access for banking AI

A synthetic, local prototype prepared for the BITSoM Builders Pitch Fest 2026 BFSI track.

An analyst may access two borrowers. An agent assigned borrower A should not inherit access to borrower B. Airlock checks the trusted assignment at execution and records the decision and actual backend result.

[Watch the 3:15 captioned walkthrough](demo/Airlock-demo.mp4) · [Testing guide](docs/TESTING.md) · [Website](https://airlock.ing/) · [Public protocol foundation](https://github.com/airlock-protocol/airlock)

![Task-access demonstration](demo/03-verified.png)

## Run locally

On another computer, install Git, Python 3.12 and `uv`, then run:

```powershell
git clone https://github.com/shivdeep1/airlock-bfsi-demo.git
cd airlock-bfsi-demo
uv sync --frozen --extra dev
uv run --frozen --no-sync python -m airlock_checkpoint.submission
```

If you already cloned this repository, run `git pull --ff-only` inside it before the two `uv` commands. GitHub hosts the source code, not a running application. Each computer starts its own local demo and gets its own private launch URL.

First setup downloads dependencies. No API key or real customer data is required. Open the private launch URL printed by the server. It binds to `127.0.0.1:8801` only. If that port is in use, append `--port 8802` to the Python command. Keep the temporary launch credential private. Stop with Ctrl+C.

## What to try

Follow the main button through the five-step walkthrough:

1. **Let AI read borrower A.** Creates permission and reads the permitted documents.
2. **Try borrower B.** The other borrower's documents are blocked.
3. **Try an external upload.** The upload is blocked.
4. **Stop AI access.** Removes permission.
5. **Try borrower A again.** The previously allowed read is now blocked.

Open **Technical details & request history** for document output, backend receipts, extra test controls and the signed evidence download. The existing video shows the earlier interface; the execution controls are unchanged.

A clean run produces one completed backend read and three denials. New assignments do not clear the current run's evidence. Restart for fresh counters.

## Verified behavior

48 automated tests cover the existing policy foundation and new demonstration. Tests include task and tenant binding, forged identity fields, direct backend bypass, expiry, revocation ordering, policy failure, evidence-write failure and signed-export tampering. Desktop and mobile browser testing covered the click flow and evidence download.

```powershell
uv run --frozen --no-sync python -m pytest -q
uv run --frozen --no-sync ruff check airlock_checkpoint/submission tests/test_submission.py
uv run --frozen --no-sync python -m airlock_checkpoint.submission --verify demo/sample-evidence.json
```

## Banking use case and deployment

The site's **For bank teams** section explains the proposed deployment boundary, a first pilot and what these controls do not cover. The walkthrough includes illustrative impersonation and document-injection messages. Those messages are explanatory text, not inputs to a model. The buttons submit the unauthorized tool requests that such an attack could cause. This tests enforcement, not live-model attack resistance.

The intended starting point is one document workflow behind an existing bank assistant, not a new customer-facing portal. Bank identity, case permissions, isolated execution, model and network destinations, secure key custody and independent review remain integration work. Local execution is not evidence of enterprise on-premise readiness.

See [OWASP's prompt-injection guidance](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) for the threat background. Least-privilege checks are one part of a broader security design, not a promise that every AI action is safe.

## Scope and limitations

The agent requests are scripted and document extraction is deterministic. No live LLM, bank connection, customer data, loan decision, customer pilot or regulatory certification is claimed.

Separate local credentials demonstrate the execution path. They do not replace production SSO, workload identity, host isolation or key custody. Local administrators can inspect process memory and modify storage. SQLite retains events, while assignments, signing keys and the mock backend ledger are per-run. Restart invalidates prior assignments.

An Ed25519 signature establishes integrity of the exported snapshot under its key. It does not establish completeness or policy correctness. Use `--public-key` with an independently recorded key when verifying the signer.

This is a public evaluation copy. The broader private Airlock repository and its business materials are not included. The existing public protocol project has its own license and scope.

## Contact

Shivdeep Singh, founder of Airlock. Contact: [shivdeepsachdeva@gmail.com](mailto:shivdeepsachdeva@gmail.com).
