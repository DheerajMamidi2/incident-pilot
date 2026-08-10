# IncidentPilot interview and demo guide

## The 90-second demo

1. Start with `make run` and open `http://127.0.0.1:8080`.
2. Frame the product in one line: “IncidentPilot is incident decision support with bounded remediation, not an autonomous production SRE.”
3. Choose **Checkout latency regression**.
4. Point to `AWAITING_APPROVAL`. Explain that telemetry, triage, proposal, and policy ran synchronously, but execution did not.
5. Open the evidence ledger. Highlight the hostile-looking application log marked **Untrusted** and the three observation IDs cited by the hypothesis.
6. Show the typed action (`ROLLBACK_DEMO_CONFIG`), exact target/transition, deterministic policy result, SHA-256 proposal digest, and expiry.
7. Approve. The incident advances through typed execution and fresh verification to `RESOLVED`.
8. Compare the red before-SLO values to the green after-SLO values. Point out that the verifier never receives the executor result.
9. Finish on the hash-linked timeline and `$0.0000` cost ledger.

If time permits, run a second scenario and reject it. The result is `ESCALATED`, and the execution field remains absent.

## The core story

The project separates five questions that unsafe automation often blends together:

1. **What happened?** Typed observations from known sources.
2. **Why might it have happened?** A hypothesis linked to evidence IDs.
3. **What could help?** One typed demo action with no command-shaped escape hatch.
4. **May it happen?** Deterministic policy plus an exact human approval digest.
5. **Did it work?** Fresh telemetry evaluated by an independent verifier.

That separation is the architecture. The polished UI simply makes the trust boundaries visible.

## Code tour

| Area | What to show |
|---|---|
| `internal/core/service.go` | The bounded state transitions and approval stop |
| `internal/core/components.go` | Independent policy/executor allowlists, typed failure retry rules, fresh verifier |
| `internal/core/types.go` | Typed observation/error envelopes, proposal, budget, event hash chain |
| `internal/core/repository.go` | Defensive copies preventing caller mutation of history |
| `internal/httpapi/server.go` | Strict JSON, 4 KiB cap, generic errors, same-origin guard, local rate limiter |
| `internal/webui/static/app.js` | Dependency-free rendering via `textContent`, including hostile log strings |
| `internal/core/service_test.go` | Safety invariants under approval, failure, expiry, tampering, and verification outcomes |

## Likely interview questions

### Why no LLM?

The safety loop should work without one. Deterministic triage makes the control boundaries testable, reproducible, cheap, and easy to review. A future model could implement a `TriageProvider` that returns a schema-validated hypothesis and evidence IDs; it still would not receive an executor capability or bypass policy, approval, or verification.

### Why Go?

The standard library provides the HTTP server, strict decoder, embedding, crypto digests, concurrency primitives, and graceful shutdown needed for the whole MVP. One static binary keeps deployment and review simple, while typed interfaces make trust boundaries explicit.

### Why not OPA/Rego?

There are only three fixed actions and targets. Deterministic Go policy is smaller and more reviewable for this scope. The `Policy` interface and `PolicyDecision` envelope are the deliberate migration seam; OPA becomes valuable when independent policy authorship and bundles exist.

### How is approval protected from a time-of-check/time-of-use change?

The submitted decision must match the proposal ID and recomputed proposal digest. That digest binds the action, policy digest/version, evidence IDs, and TTL. Immediately before execution, policy is evaluated again and its digest must still match. The executor then applies its own independent exact allowlist.

### Why can only some failures retry?

Retrying an unknown outcome can duplicate an effect. The loop retries only a typed `TRANSIENT` error, only for a known-idempotent action, only while both retry and time budgets remain. Permanent, unknown-outcome, and untyped errors escalate after one call.

### Is the verification actually independent?

Yes at the component boundary: the executor returns only an execution record. The verifier receives the scenario’s synthetic probe adapter and recomputes SLO checks from a fresh snapshot; it never receives or trusts executor success. A production adapter would replace the synthetic probe with read-only telemetry queries behind the same contract.

### What happens when verification fails?

The incident becomes `ESCALATED`. `FAIL` and `INCONCLUSIVE` never auto-replan in the MVP. A different remediation would require a new human-owned workflow so approval cannot silently expand.

### What is durable today?

Nothing across process restart; this is explicitly local. Within a process, repository reads/writes are defensive copies, updates are mutex-serialized, and events form a SHA-256 chain. Production would add transactional storage, optimistic concurrency, authenticated actors, and externally signed audit checkpoints.

### What would you build next?

Durable event storage and authenticated approval first, then real read-only telemetry adapters, shared rate limiting, signed audit anchors, explicit human closure, and finally an OPA or model-backed adapter if product requirements justify them. A real actuator remains last.

## Test strategy

The test suite checks behavior rather than snapshots alone:

- The loop reaches `AWAITING_APPROVAL` without execution.
- Evidence citations resolve to real typed observations and logs remain untrusted.
- Approval must match both proposal ID and digest.
- Rejection escalates and never creates an execution record.
- Transient idempotent failures honor retry limits; permanent failures do not retry.
- Expired TTL/run budgets prevent execution and cannot reset.
- Executor and policy reject unknown action types independently.
- Fresh verification `PASS` resolves; `FAIL` and `INCONCLUSIVE` escalate without replanning.
- Repository copies resist caller mutation and the event chain detects tampering.
- HTTP requests enforce size, media type, strict fields, origin, rate, method, identifier, and generic-error rules.
- Embedded UI assets and security headers are served from the same binary.

Run `make check` before the interview; it includes the race detector and enforces at least 80% aggregate statement coverage.

## Honest boundaries to volunteer

- Synthetic scenarios are evidence of architecture, not proof of a real monitoring integration.
- In-memory state and rate limiting make this a single-process demo.
- There is no authentication, so the default address is loopback only.
- The audit chain detects changes but is not externally signed or durable.
- There is no automatic escalation closure endpoint yet.

Naming these boundaries strengthens the story: the system is intentionally safe about what it can and cannot claim.
