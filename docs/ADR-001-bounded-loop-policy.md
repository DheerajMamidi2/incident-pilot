# ADR-001: Bounded incident loop with deterministic policy

- Status: Accepted
- Date: 2026-08-09
- Owners: IncidentPilot MVP

## Context

The demo must show useful incident automation without pretending an unconstrained agent is safe. It needs a legible path from telemetry through remediation, a mandatory human stop, bounded work, and a resolution decision based on independent evidence. It also needs to run locally with no external services and a deterministic `$0` baseline.

The primary design risk is collapsing distinct trust boundaries into one “agent” call: allowing logs to influence instructions, letting a proposal imply permission, treating actuator success as recovery, or automatically replanning after a failed check.

## Decision

Use an explicit state machine with one remediation iteration, one optional typed transient retry, a fixed run deadline, and terminal `RESOLVED` or `ESCALATED` outcomes.

The stages are:

1. Collect synthetic telemetry in typed observation envelopes.
2. Treat log text as untrusted data and select evidence only by typed scenario rules.
3. Produce a deterministic hypothesis with observation-ID citations.
4. Produce one typed `DemoAction`; the schema has no command or arbitrary payload.
5. Evaluate an exact deterministic policy allowlist.
6. Stop in `AWAITING_APPROVAL`.
7. Bind approval or rejection to the proposal ID and SHA-256 digest before its TTL and the run deadline.
8. Re-evaluate policy and compare the policy digest immediately before execution.
9. Execute only if a separate executor allowlist independently accepts the action, target, and transition.
10. Collect fresh SLO telemetry through an independent verifier that never receives executor success as input.
11. Resolve only on a fresh `PASS`; `FAIL` and `INCONCLUSIVE` escalate without automatic replanning.

The proposal digest binds:

```text
proposal ID
SHA-256(action kind + target + from + to)
policy digest and version
creation time
expiry time
ordered evidence IDs
```

Audit events are returned and stored as defensive copies, have monotonically increasing sequence numbers, and are chained through `previous_hash` and `hash`. This detects in-memory/history tampering in the MVP. The original budget timestamps live on the incident and are never recalculated during approval, retries, or verification.

## Why deterministic policy instead of OPA/Rego now

A Rego policy engine is valuable when policy authorship, bundles, environment overlays, and policy-query tooling justify the operational surface. In this MVP there are exactly three actions, three isolated targets, and fixed transitions. A Go `switch` makes the entire allowlist reviewable in seconds, removes a runtime dependency, keeps the binary reproducible, and preserves deterministic tests.

Adding OPA now would demonstrate integration breadth but not improve the safety decision. It could also obscure the more important control: even a policy ALLOW never bypasses the executor’s independent typed allowlist.

This is not a rejection of OPA. The `Policy` interface is the migration seam. A future `RegoPolicy` can return the same `PolicyDecision` envelope containing `allowed`, rule, version, reason, digest, and evaluation time. Contract tests must run the deterministic and Rego implementations against the same allow/deny corpus before substitution.

## Retry classification

An executor failure must be a typed `ExecutionError`:

- `TRANSIENT`: retryable only when the known action metadata marks the action idempotent and retry budget remains.
- `PERMANENT`: terminal after one call.
- `UNKNOWN_OUTCOME`: terminal after one call because repeating may duplicate an effect.
- Untyped errors: treated like unknown outcome and terminal after one call.

The maximum retry count is stored in the original incident budget. A retry cannot create a new budget or extend the deadline.

## Consequences

Positive:

- The approval stop and every trust boundary are visible in code and UI.
- Tests are deterministic and require no network, model, policy daemon, or database.
- Logs cannot directly create executable content.
- A successful action cannot produce a false `RESOLVED` state.
- The policy engine remains replaceable behind a small typed contract.

Negative:

- The policy is compiled with the service rather than independently deployed.
- In-memory state does not survive restart and the hash chain is not externally anchored.
- One remediation iteration cannot demonstrate multi-step recovery planning.
- Synthetic fresh telemetry proves separation of concerns, not integration with a real monitoring backend.

## Follow-up path

Before any real actuator is connected:

1. Move incidents and audit events to transactional durable storage with optimistic concurrency.
2. Add authenticated operator identity and action-level authorization.
3. Anchor signed audit checkpoints outside the primary database.
4. Replace the local limiter with a gateway/shared-store limiter.
5. Add read-only OpenTelemetry and deployment-metadata adapters.
6. Add OPA bundles only after policy ownership and deployment boundaries are defined.
7. Add an explicit human closure endpoint for terminal escalations.
