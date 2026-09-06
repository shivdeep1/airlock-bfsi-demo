# Testing Airlock's task-access prototype

The application runs on your own computer. A localhost link from someone else's computer will not work for you. Use the README to start your own instance.

## Expected results

| Action | Policy result | Backend result |
|---|---|---|
| Let AI read borrower A | ALLOW | Permission created, then one actual synthetic HTTP document read |
| Attempt B | DENY | Not dispatched |
| Attempt external upload | DENY | Not dispatched |
| Stop AI access, then try borrower A again | DENY | Not dispatched |

The document output is deterministic extraction, not a live LLM summary. The attack buttons submit reproducible prohibited tool requests. They do not claim that a live model independently chose those actions.

## Evidence

Open Technical details & request history, then Backend receipts & trust limits. It should show only the permitted A read for a clean run. Download the evidence and use the verification command in the README. Edited snapshot contents should fail signature verification. Public keys embedded in a file are not independent trust anchors.

## How it works

The trusted operator creates a narrow assignment. The server verifies the agent credential, resolves its tenant and delegating user, checks current entitlement and task state, then evaluates the exact tool request. Only an allowed request reaches the executor's separately credentialed HTTP backend. The application writes mandatory pre-dispatch evidence and records the confirmed result. A backend timeout yields an indeterminate outcome rather than a fabricated success.

The test suite exercises negative cases that the screen does not expose as controls. There is no public HTTP endpoint for altering credentials or disabling evidence storage.

## Limits

This demonstration uses a single process and synthetic data. Revocation serializes with execution. A read already completed before revocation remains completed, and returned data cannot be recalled. Production deployment needs customer-approved identity integration, isolation, retention, operations and model/data destinations.
