package core

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestCreateIncidentStopsAtApprovalWithLinkedEvidence(t *testing.T) {
	service := newTestService(t)

	incident, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	if incident.State != StateAwaitingApproval {
		t.Fatalf("state = %q, want %q", incident.State, StateAwaitingApproval)
	}
	if incident.Proposal == nil || !incident.Proposal.Policy.Allowed {
		t.Fatal("expected an allowlisted, policy-approved proposal")
	}
	if incident.Proposal.Action.Kind != ActionRollbackDemoConfig {
		t.Fatalf("action = %q, want %q", incident.Proposal.Action.Kind, ActionRollbackDemoConfig)
	}
	if incident.Execution != nil || incident.After != nil {
		t.Fatal("the loop executed before explicit approval")
	}
	if incident.Iteration != 1 || incident.Budget.MaxIterations != 1 {
		t.Fatalf("iteration budget = %d/%d, want 1/1", incident.Iteration, incident.Budget.MaxIterations)
	}
	if incident.TotalCostUSD() != 0 {
		t.Fatalf("cost = %v, want deterministic $0 baseline", incident.TotalCostUSD())
	}

	observationIDs := make(map[string]bool, len(incident.Observations))
	for _, observation := range incident.Observations {
		observationIDs[observation.ID] = true
		if observation.Type == ObservationLog && observation.Trust != TrustUntrusted {
			t.Fatalf("log observation trust = %q, want %q", observation.Trust, TrustUntrusted)
		}
	}
	for _, evidenceID := range incident.Triage.EvidenceIDs {
		if !observationIDs[evidenceID] {
			t.Fatalf("triage references missing observation %q", evidenceID)
		}
	}
	for _, evidenceID := range incident.Proposal.EvidenceIDs {
		if !observationIDs[evidenceID] {
			t.Fatalf("proposal references missing observation %q", evidenceID)
		}
	}

	wantEvents := []EventType{
		EventIncidentCreated,
		EventTelemetryCollected,
		EventTriageCompleted,
		EventProposalCreated,
		EventPolicyEvaluated,
		EventAwaitingApproval,
	}
	if got := eventTypes(incident.Events); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("events = %v, want %v", got, wantEvents)
	}
	assertSequentialEvents(t, incident.Events)
}

func TestApproveExecutesTypedActionAndIndependentlyVerifiesSLO(t *testing.T) {
	service := newTestService(t)
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := service.Approve(context.Background(), created.ID, ApprovalInput{
		ProposalID:     created.Proposal.ID,
		ProposalDigest: created.Proposal.Digest,
		Actor:          "on-call@example.test",
	})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if resolved.State != StateResolved {
		t.Fatalf("state = %q, want %q", resolved.State, StateResolved)
	}
	if resolved.Execution == nil || resolved.Execution.Action.Kind != ActionRollbackDemoConfig {
		t.Fatal("expected the exact typed proposal action to execute")
	}
	if resolved.Verification == nil || !resolved.Verification.Passed || resolved.Verification.Checker != "independent-slo-verifier/v1" {
		t.Fatalf("verification = %#v, want independent passing verification", resolved.Verification)
	}
	if resolved.After == nil || !resolved.After.Passing {
		t.Fatalf("after SLO = %#v, want passing", resolved.After)
	}
	if got := eventTypes(resolved.Events); !reflect.DeepEqual(got[len(got)-5:], []EventType{
		EventApprovalGranted,
		EventActionExecuted,
		EventVerificationStarted,
		EventSLOVerified,
		EventIncidentResolved,
	}) {
		t.Fatalf("terminal events = %v", got)
	}
}

func TestRejectEscalatesWithoutExecuting(t *testing.T) {
	service := newTestService(t)
	created, err := service.CreateIncident(context.Background(), "dependency-saturation")
	if err != nil {
		t.Fatal(err)
	}

	rejected, err := service.Reject(context.Background(), created.ID, RejectionInput{
		ProposalID:     created.Proposal.ID,
		ProposalDigest: created.Proposal.Digest,
		Actor:          "incident-commander@example.test",
		Reason:         "Needs a coordinated maintenance window.",
	})
	if err != nil {
		t.Fatalf("Reject() error = %v", err)
	}
	if rejected.State != StateEscalated {
		t.Fatalf("state = %q, want %q", rejected.State, StateEscalated)
	}
	if rejected.Execution != nil {
		t.Fatal("rejected proposal must never execute")
	}
	if got := eventTypes(rejected.Events); !reflect.DeepEqual(got[len(got)-2:], []EventType{EventApprovalRejected, EventIncidentEscalated}) {
		t.Fatalf("terminal events = %v", got)
	}
}

func TestApprovalGuardsProposalAndState(t *testing.T) {
	service := newTestService(t)
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Approve(context.Background(), created.ID, ApprovalInput{ProposalID: "proposal-wrong", ProposalDigest: created.Proposal.Digest, Actor: "operator"})
	if !errors.Is(err, ErrProposalMismatch) {
		t.Fatalf("mismatched proposal error = %v, want %v", err, ErrProposalMismatch)
	}
	_, err = service.Approve(context.Background(), created.ID, ApprovalInput{ProposalID: created.Proposal.ID, ProposalDigest: "sha256:tampered", Actor: "operator"})
	if !errors.Is(err, ErrProposalMismatch) {
		t.Fatalf("mismatched digest error = %v, want %v", err, ErrProposalMismatch)
	}
	resolved, err := service.Approve(context.Background(), created.ID, ApprovalInput{ProposalID: created.Proposal.ID, ProposalDigest: created.Proposal.Digest, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Approve(context.Background(), resolved.ID, ApprovalInput{ProposalID: created.Proposal.ID, ProposalDigest: created.Proposal.Digest, Actor: "operator"})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("re-approval error = %v, want %v", err, ErrInvalidTransition)
	}
}

func TestExecutionFailureHonorsRetryBudgetAndEscalates(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	executor := &failingExecutor{err: NewExecutionError(ExecutionFailureTransient, errors.New("synthetic actuator failure"))}
	service := NewService(NewMemoryRepository(), Dependencies{
		Clock:    clock.Now,
		IDs:      sequentialIDs(),
		Executor: executor,
	})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}

	escalated, err := service.Approve(context.Background(), created.ID, ApprovalInput{ProposalID: created.Proposal.ID, ProposalDigest: created.Proposal.Digest, Actor: "operator"})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if escalated.State != StateEscalated {
		t.Fatalf("state = %q, want %q", escalated.State, StateEscalated)
	}
	if executor.calls != escalated.Budget.MaxRetries+1 {
		t.Fatalf("executor calls = %d, want %d", executor.calls, escalated.Budget.MaxRetries+1)
	}
	if escalated.RetryCount != escalated.Budget.MaxRetries {
		t.Fatalf("retry count = %d, want %d", escalated.RetryCount, escalated.Budget.MaxRetries)
	}
	if escalated.LastError == nil || escalated.LastError.Code != "execution_failed" {
		t.Fatalf("typed error = %#v", escalated.LastError)
	}
}

func TestPermanentExecutionFailureDoesNotRetry(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	executor := &failingExecutor{err: NewExecutionError(ExecutionFailurePermanent, errors.New("typed actuator rejection"))}
	service := NewService(NewMemoryRepository(), Dependencies{Clock: clock.Now, IDs: sequentialIDs(), Executor: executor})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}

	escalated, err := service.Approve(context.Background(), created.ID, ApprovalInput{ProposalID: created.Proposal.ID, ProposalDigest: created.Proposal.Digest, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if escalated.State != StateEscalated || executor.calls != 1 || escalated.RetryCount != 0 {
		t.Fatalf("state = %q calls = %d retries = %d; want escalation after one call", escalated.State, executor.calls, escalated.RetryCount)
	}
}

func TestUnknownAndUntypedExecutionFailuresDoNotRetry(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "unknown outcome",
			err:  NewExecutionError(ExecutionFailureUnknownOutcome, errors.New("actuator response was lost")),
		},
		{
			name: "untyped error",
			err:  errors.New("unexpected actuator failure"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
			executor := &failingExecutor{err: test.err}
			service := NewService(NewMemoryRepository(), Dependencies{Clock: clock.Now, IDs: sequentialIDs(), Executor: executor})
			created, err := service.CreateIncident(context.Background(), "checkout-latency")
			if err != nil {
				t.Fatal(err)
			}

			escalated, err := service.Approve(context.Background(), created.ID, ApprovalInput{
				ProposalID:     created.Proposal.ID,
				ProposalDigest: created.Proposal.Digest,
				Actor:          "operator",
			})
			if err != nil {
				t.Fatal(err)
			}
			if escalated.State != StateEscalated || executor.calls != 1 || escalated.RetryCount != 0 {
				t.Fatalf("state = %q calls = %d retries = %d; want escalation after one call", escalated.State, executor.calls, escalated.RetryCount)
			}
		})
	}
}

func TestFailedIndependentVerificationEscalates(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	service := NewService(NewMemoryRepository(), Dependencies{
		Clock:    clock.Now,
		IDs:      sequentialIDs(),
		Verifier: alwaysFailVerifier{},
	})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}

	escalated, err := service.Approve(context.Background(), created.ID, ApprovalInput{ProposalID: created.Proposal.ID, ProposalDigest: created.Proposal.Digest, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if escalated.State != StateEscalated || escalated.Verification == nil || escalated.Verification.Passed {
		t.Fatalf("incident = %#v, want failed verification escalation", escalated)
	}
	if !escalated.Verification.FreshTelemetry || escalated.Verification.Outcome != VerificationFail {
		t.Fatalf("verification = %#v, want fresh FAIL outcome", escalated.Verification)
	}
}

func TestInconclusiveVerificationEscalatesWithoutAutoReplan(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	service := NewService(NewMemoryRepository(), Dependencies{Clock: clock.Now, IDs: sequentialIDs(), Verifier: inconclusiveVerifier{}})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}

	escalated, err := service.Approve(context.Background(), created.ID, ApprovalInput{ProposalID: created.Proposal.ID, ProposalDigest: created.Proposal.Digest, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if escalated.State != StateEscalated || escalated.Verification == nil || escalated.Verification.Outcome != VerificationInconclusive {
		t.Fatalf("incident = %#v, want INCONCLUSIVE escalation", escalated)
	}
	if escalated.Iteration != 1 {
		t.Fatalf("iteration = %d, want no automatic replan", escalated.Iteration)
	}
}

func TestExpiredBudgetEscalatesWithoutExecution(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	executor := &recordingExecutor{}
	service := NewService(NewMemoryRepository(), Dependencies{
		Clock:    clock.Now,
		IDs:      sequentialIDs(),
		Executor: executor,
		Limits:   Limits{MaxIterations: 1, MaxRetries: 0, TimeBudget: time.Second, ApprovalTTL: time.Minute},
	})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}
	clock.now = created.Proposal.ExpiresAt

	escalated, err := service.Approve(context.Background(), created.ID, ApprovalInput{ProposalID: created.Proposal.ID, ProposalDigest: created.Proposal.Digest, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if escalated.State != StateEscalated || executor.calls != 0 {
		t.Fatalf("state = %q, executor calls = %d; want escalated and 0", escalated.State, executor.calls)
	}
	if escalated.LastError == nil || escalated.LastError.Code != "budget_exhausted" {
		t.Fatalf("typed error = %#v", escalated.LastError)
	}
	if !escalated.Budget.StartedAt.Equal(created.Budget.StartedAt) || !escalated.Budget.Deadline.Equal(created.Budget.Deadline) {
		t.Fatal("run budget reset during approval")
	}
}

func TestApprovalTTLExpiresBeforeLongerRunBudget(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	executor := &recordingExecutor{}
	service := NewService(NewMemoryRepository(), Dependencies{
		Clock:    clock.Now,
		IDs:      sequentialIDs(),
		Executor: executor,
		Limits:   Limits{MaxIterations: 1, MaxRetries: 0, TimeBudget: time.Minute, ApprovalTTL: time.Second},
	})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}
	if !created.Proposal.ExpiresAt.Before(created.Budget.Deadline) {
		t.Fatalf("proposal expiry = %v, budget deadline = %v; want shorter approval TTL", created.Proposal.ExpiresAt, created.Budget.Deadline)
	}
	clock.now = created.Proposal.ExpiresAt

	escalated, err := service.Approve(context.Background(), created.ID, ApprovalInput{
		ProposalID:     created.Proposal.ID,
		ProposalDigest: created.Proposal.Digest,
		Actor:          "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if escalated.State != StateEscalated || executor.calls != 0 {
		t.Fatalf("state = %q, executor calls = %d; want approval-expiry escalation without execution", escalated.State, executor.calls)
	}
	if escalated.LastError == nil || escalated.LastError.Code != "budget_exhausted" {
		t.Fatalf("typed error = %#v", escalated.LastError)
	}
}

func TestExpiredRejectionEscalatesAsExpiryWithoutRecordingDecision(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	service := NewService(NewMemoryRepository(), Dependencies{
		Clock:  clock.Now,
		IDs:    sequentialIDs(),
		Limits: Limits{MaxIterations: 1, MaxRetries: 0, TimeBudget: time.Second, ApprovalTTL: time.Second},
	})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(2 * time.Second)

	escalated, err := service.Reject(context.Background(), created.ID, RejectionInput{
		ProposalID:     created.Proposal.ID,
		ProposalDigest: created.Proposal.Digest,
		Actor:          "operator",
		Reason:         "Late decision",
	})
	if err != nil {
		t.Fatal(err)
	}
	if escalated.State != StateEscalated || escalated.Approval != nil {
		t.Fatalf("state/approval = %q/%#v, want expiry escalation without decision", escalated.State, escalated.Approval)
	}
	if escalated.LastError == nil || escalated.LastError.Code != "budget_exhausted" {
		t.Fatalf("typed error = %#v", escalated.LastError)
	}
}

func TestSlowExecutorDoesNotBlockIncidentReadsOrUnrelatedCreates(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	executor := &blockingExecutor{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-executor.release:
		default:
			close(executor.release)
		}
	})
	service := NewService(NewMemoryRepository(), Dependencies{Clock: clock.Now, IDs: sequentialIDs(), Executor: executor})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}

	type approvalResult struct {
		incident Incident
		err      error
	}
	approvalDone := make(chan approvalResult, 1)
	go func() {
		incident, approveErr := service.Approve(context.Background(), created.ID, ApprovalInput{
			ProposalID:     created.Proposal.ID,
			ProposalDigest: created.Proposal.Digest,
			Actor:          "operator",
		})
		approvalDone <- approvalResult{incident: incident, err: approveErr}
	}()

	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("executor did not start")
	}

	readDone := make(chan error, 1)
	go func() {
		inFlight, getErr := service.GetIncident(context.Background(), created.ID)
		if getErr == nil && inFlight.State != StateExecuting {
			getErr = errors.New("incident was not persisted as EXECUTING before the side effect")
		}
		readDone <- getErr
	}()
	select {
	case readErr := <-readDone:
		if readErr != nil {
			t.Fatal(readErr)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow executor blocked a repository read")
	}

	createDone := make(chan error, 1)
	go func() {
		_, createErr := service.CreateIncident(context.Background(), "worker-backlog")
		createDone <- createErr
	}()
	select {
	case createErr := <-createDone:
		if createErr != nil {
			t.Fatal(createErr)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow executor blocked an unrelated incident create")
	}

	close(executor.release)
	result := <-approvalDone
	if result.err != nil || result.incident.State != StateResolved {
		t.Fatalf("approval result = %#v, error = %v", result.incident, result.err)
	}
}

func TestApprovedRunSurvivesClientCancellationUnderServerBudget(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	executor := &blockingExecutor{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-executor.release:
		default:
			close(executor.release)
		}
	})
	service := NewService(NewMemoryRepository(), Dependencies{Clock: clock.Now, IDs: sequentialIDs(), Executor: executor})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}

	type approvalResult struct {
		incident Incident
		err      error
	}
	requestContext, cancelRequest := context.WithCancel(context.Background())
	approvalDone := make(chan approvalResult, 1)
	go func() {
		incident, approveErr := service.Approve(requestContext, created.ID, ApprovalInput{
			ProposalID:     created.Proposal.ID,
			ProposalDigest: created.Proposal.Digest,
			Actor:          "operator",
		})
		approvalDone <- approvalResult{incident: incident, err: approveErr}
	}()

	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("executor did not start after EXECUTING was persisted")
	}
	cancelRequest()
	close(executor.release)

	select {
	case result := <-approvalDone:
		if result.err != nil {
			t.Fatalf("Approve() error after client cancellation = %v", result.err)
		}
		if result.incident.State != StateResolved {
			t.Fatalf("state = %q, want server-owned run to resolve", result.incident.State)
		}
		if result.incident.Verification == nil || !result.incident.Verification.Passed {
			t.Fatalf("verification = %#v, want fresh independent pass", result.incident.Verification)
		}
	case <-time.After(time.Second):
		t.Fatal("approved run did not finish after client cancellation")
	}
}

func TestPolicyAndExecutorRejectNonAllowlistedActions(t *testing.T) {
	action := DemoAction{Kind: ActionKind("RUN_SHELL"), Target: "demo-api", From: "ignored", To: "ignored"}
	decision := (DeterministicPolicy{}).Evaluate(action)
	if decision.Allowed {
		t.Fatal("policy allowed unknown action")
	}
	_, err := (DemoExecutor{}).Execute(context.Background(), action, Scenario{}, time.Now())
	if !errors.Is(err, ErrActionNotAllowed) {
		t.Fatalf("executor error = %v, want %v", err, ErrActionNotAllowed)
	}
}

func TestMemoryRepositoryReturnsDefensiveCopies(t *testing.T) {
	repository := NewMemoryRepository()
	service := NewService(repository, Dependencies{Clock: (&fakeClock{now: time.Now()}).Now, IDs: sequentialIDs()})
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}
	created.Events[0].Summary = "tampered"
	created.Observations[0].Text = "tampered"
	created.Proposal.EvidenceIDs[0] = "tampered"

	stored, err := service.GetIncident(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Events[0].Summary == "tampered" || stored.Observations[0].Text == "tampered" || stored.Proposal.EvidenceIDs[0] == "tampered" {
		t.Fatal("caller mutated repository state")
	}
}

func TestAuditEventHashChainDetectsTampering(t *testing.T) {
	service := newTestService(t)
	created, err := service.CreateIncident(context.Background(), "checkout-latency")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateEventChain(created.Events) {
		t.Fatal("valid event chain was rejected")
	}
	tampered := append([]Event(nil), created.Events...)
	tampered[1].Summary = "rewritten history"
	if ValidateEventChain(tampered) {
		t.Fatal("tampered event chain was accepted")
	}
}

func TestScenarioListIsDefensiveAndUnknownScenarioFails(t *testing.T) {
	service := newTestService(t)
	scenarios := service.ListScenarios()
	if len(scenarios) < 3 {
		t.Fatalf("scenario count = %d, want at least 3", len(scenarios))
	}
	scenarios[0].Title = "tampered"
	if service.ListScenarios()[0].Title == "tampered" {
		t.Fatal("scenario list was mutable")
	}
	_, err := service.CreateIncident(context.Background(), "not-a-scenario")
	if !errors.Is(err, ErrScenarioNotFound) {
		t.Fatalf("error = %v, want %v", err, ErrScenarioNotFound)
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	return NewService(NewMemoryRepository(), Dependencies{Clock: clock.Now, IDs: sequentialIDs()})
}

func sequentialIDs() IDGenerator {
	next := 0
	return func(prefix string) string {
		next++
		return prefix + "-test-" + string(rune('a'+next-1))
	}
}

type fakeClock struct{ now time.Time }

func (clock *fakeClock) Now() time.Time { return clock.now }

type failingExecutor struct {
	calls int
	err   error
}

func (executor *failingExecutor) Execute(context.Context, DemoAction, Scenario, time.Time) (ExecutionRecord, error) {
	executor.calls++
	return ExecutionRecord{}, executor.err
}

type recordingExecutor struct{ calls int }

func (executor *recordingExecutor) Execute(_ context.Context, action DemoAction, _ Scenario, now time.Time) (ExecutionRecord, error) {
	executor.calls++
	return ExecutionRecord{Action: action, Executor: "recording-executor", CompletedAt: now}, nil
}

type blockingExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (executor *blockingExecutor) Execute(_ context.Context, action DemoAction, _ Scenario, now time.Time) (ExecutionRecord, error) {
	close(executor.started)
	<-executor.release
	return ExecutionRecord{Action: action, Executor: "blocking-executor", CompletedAt: now}, nil
}

type alwaysFailVerifier struct{}

func (alwaysFailVerifier) Verify(_ context.Context, _ Scenario, now time.Time) (Verification, error) {
	return Verification{Checker: "independent-slo-verifier/v1", FreshTelemetry: true, CollectedAt: now, Outcome: VerificationFail, Passed: false, Summary: "SLO remains breached"}, nil
}

type inconclusiveVerifier struct{}

func (inconclusiveVerifier) Verify(_ context.Context, _ Scenario, now time.Time) (Verification, error) {
	return Verification{Checker: "independent-slo-verifier/v1", FreshTelemetry: true, CollectedAt: now, Outcome: VerificationInconclusive, Summary: "Probe unavailable"}, errors.New("probe unavailable")
}

func eventTypes(events []Event) []EventType {
	types := make([]EventType, len(events))
	for index, event := range events {
		types[index] = event.Type
	}
	return types
}

func assertSequentialEvents(t *testing.T, events []Event) {
	t.Helper()
	for index, event := range events {
		if event.Sequence != index+1 {
			t.Fatalf("event %d sequence = %d, want %d", index, event.Sequence, index+1)
		}
	}
}
