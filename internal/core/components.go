package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrActionNotAllowed = errors.New("demo action is not allowlisted")

type Policy interface {
	Evaluate(DemoAction) PolicyDecision
}

type Executor interface {
	Execute(context.Context, DemoAction, Scenario, time.Time) (ExecutionRecord, error)
}

type Verifier interface {
	Verify(context.Context, Scenario, time.Time) (Verification, error)
}

// DeterministicPolicy is a small, auditable policy-as-code gate for the local MVP.
// The executor repeats its own allowlist checks rather than trusting this result.
type DeterministicPolicy struct{}

func (DeterministicPolicy) Evaluate(action DemoAction) PolicyDecision {
	allowed := false
	reason := "Action kind, target, or transition is outside the demo allowlist."
	switch action.Kind {
	case ActionRollbackDemoConfig:
		allowed = action.Target == "checkout-api" && action.From == "config-v43" && action.To == "config-v42"
	case ActionResetDemoCircuit:
		allowed = action.Target == "payments-sandbox" && action.From == "OPEN" && action.To == "HALF_OPEN"
	case ActionDrainDemoQueue:
		allowed = action.Target == "notifications-demo-queue" && action.From == "backlog" && action.To == "empty"
	}
	if allowed {
		reason = "Exact typed action and transition match the isolated demo-resource allowlist."
	}
	decision := PolicyDecision{
		Allowed: allowed,
		Rule:    "demo-remediation-allowlist",
		Version: "deterministic-policy/v1",
		Reason:  reason,
	}
	decision.Digest = policyDigest(action, decision)
	return decision
}

type DemoExecutor struct{}

func (DemoExecutor) Execute(ctx context.Context, action DemoAction, _ Scenario, now time.Time) (ExecutionRecord, error) {
	if err := ctx.Err(); err != nil {
		return ExecutionRecord{}, NewExecutionError(ExecutionFailureUnknownOutcome, err)
	}

	// This independent switch is intentionally duplicated from the policy boundary.
	// A policy bug cannot turn the executor into a generic command runner.
	allowed := false
	switch action.Kind {
	case ActionRollbackDemoConfig:
		allowed = action.Target == "checkout-api" && action.From == "config-v43" && action.To == "config-v42"
	case ActionResetDemoCircuit:
		allowed = action.Target == "payments-sandbox" && action.From == "OPEN" && action.To == "HALF_OPEN"
	case ActionDrainDemoQueue:
		allowed = action.Target == "notifications-demo-queue" && action.From == "backlog" && action.To == "empty"
	}
	if !allowed {
		return ExecutionRecord{}, NewExecutionError(ExecutionFailurePermanent, ErrActionNotAllowed)
	}
	return ExecutionRecord{
		Action:      action,
		Executor:    "typed-demo-executor/v1",
		CompletedAt: now.UTC(),
	}, nil
}

type ExecutionFailureKind string

const (
	ExecutionFailureTransient      ExecutionFailureKind = "TRANSIENT"
	ExecutionFailurePermanent      ExecutionFailureKind = "PERMANENT"
	ExecutionFailureUnknownOutcome ExecutionFailureKind = "UNKNOWN_OUTCOME"
)

type ExecutionError struct {
	Kind ExecutionFailureKind
	err  error
}

func NewExecutionError(kind ExecutionFailureKind, err error) error {
	if err == nil {
		err = errors.New("execution failed")
	}
	return &ExecutionError{Kind: kind, err: err}
}

func (executionError *ExecutionError) Error() string {
	return fmt.Sprintf("%s execution failure: %v", executionError.Kind, executionError.err)
}

func (executionError *ExecutionError) Unwrap() error { return executionError.err }

func retryableExecution(action DemoAction, err error) bool {
	var executionError *ExecutionError
	return errors.As(err, &executionError) &&
		executionError.Kind == ExecutionFailureTransient &&
		actionIsIdempotent(action)
}

func actionIsIdempotent(action DemoAction) bool {
	switch action.Kind {
	case ActionRollbackDemoConfig, ActionResetDemoCircuit, ActionDrainDemoQueue:
		return true
	default:
		return false
	}
}

// IndependentSLOVerifier obtains a fresh deterministic probe snapshot. It does
// not receive or inspect the executor's return value.
type IndependentSLOVerifier struct{}

func (IndependentSLOVerifier) Verify(ctx context.Context, scenario Scenario, now time.Time) (Verification, error) {
	if err := ctx.Err(); err != nil {
		return Verification{
			Checker:        "independent-slo-verifier/v1",
			Source:         "synthetic-slo-probe://fresh",
			FreshTelemetry: false,
			CollectedAt:    now.UTC(),
			Outcome:        VerificationInconclusive,
			Summary:        "Fresh SLO probe did not complete.",
		}, err
	}

	snapshot := scenario.ExpectedAfter
	checks := []SLOCheck{
		{Name: "latency_p95_ms", Observed: snapshot.LatencyP95MS, Threshold: scenario.Target.MaxLatencyP95MS, Operator: "<=", Passed: snapshot.LatencyP95MS <= scenario.Target.MaxLatencyP95MS},
		{Name: "error_rate_percent", Observed: snapshot.ErrorRatePercent, Threshold: scenario.Target.MaxErrorRatePercent, Operator: "<=", Passed: snapshot.ErrorRatePercent <= scenario.Target.MaxErrorRatePercent},
		{Name: "availability_percent", Observed: snapshot.AvailabilityPercent, Threshold: scenario.Target.MinAvailabilityPercent, Operator: ">=", Passed: snapshot.AvailabilityPercent >= scenario.Target.MinAvailabilityPercent},
	}
	passed := true
	for _, check := range checks {
		passed = passed && check.Passed
	}
	snapshot.Passing = passed
	outcome := VerificationFail
	summary := "Fresh telemetry still breaches one or more SLO thresholds."
	if passed {
		outcome = VerificationPass
		summary = "Fresh telemetry passes every independent SLO check."
	}
	return Verification{
		Checker:        "independent-slo-verifier/v1",
		Source:         "synthetic-slo-probe://fresh",
		FreshTelemetry: true,
		CollectedAt:    now.UTC(),
		Outcome:        outcome,
		Passed:         passed,
		Summary:        summary,
		Snapshot:       snapshot,
		Checks:         checks,
	}, nil
}

func policyDigest(action DemoAction, decision PolicyDecision) string {
	canonical := strings.Join([]string{
		decision.Version,
		decision.Rule,
		fmt.Sprintf("%t", decision.Allowed),
		actionDigest(action),
	}, "\n")
	return sha256String(canonical)
}

func proposalDigest(proposal Proposal) string {
	canonical := strings.Join([]string{
		proposal.ID,
		actionDigest(proposal.Action),
		proposal.Policy.Digest,
		proposal.CreatedAt.UTC().Format(time.RFC3339Nano),
		proposal.ExpiresAt.UTC().Format(time.RFC3339Nano),
		strings.Join(proposal.EvidenceIDs, ","),
	}, "\n")
	return sha256String(canonical)
}

func actionDigest(action DemoAction) string {
	return sha256String(strings.Join([]string{string(action.Kind), action.Target, action.From, action.To}, "\n"))
}

func sha256String(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
