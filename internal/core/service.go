package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var (
	ErrScenarioNotFound  = errors.New("scenario not found")
	ErrInvalidTransition = errors.New("invalid incident transition")
	ErrProposalMismatch  = errors.New("approval does not match proposal")
	ErrInvalidInput      = errors.New("invalid input")
)

type IDGenerator func(prefix string) string

type Limits struct {
	MaxIterations int
	MaxRetries    int
	TimeBudget    time.Duration
	ApprovalTTL   time.Duration
}

type Dependencies struct {
	Clock    func() time.Time
	IDs      IDGenerator
	Policy   Policy
	Executor Executor
	Verifier Verifier
	Limits   Limits
}

type ApprovalInput struct {
	ProposalID     string
	ProposalDigest string
	Actor          string
}

type RejectionInput struct {
	ProposalID     string
	ProposalDigest string
	Actor          string
	Reason         string
}

type Service struct {
	repository IncidentRepository
	clock      func() time.Time
	ids        IDGenerator
	policy     Policy
	executor   Executor
	verifier   Verifier
	limits     Limits
}

func NewService(repository IncidentRepository, dependencies Dependencies) *Service {
	if repository == nil {
		repository = NewMemoryRepository()
	}
	clock := dependencies.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	ids := dependencies.IDs
	if ids == nil {
		ids = randomID
	}
	policy := dependencies.Policy
	if policy == nil {
		policy = DeterministicPolicy{}
	}
	executor := dependencies.Executor
	if executor == nil {
		executor = DemoExecutor{}
	}
	verifier := dependencies.Verifier
	if verifier == nil {
		verifier = IndependentSLOVerifier{}
	}
	limits := normalizeLimits(dependencies.Limits)
	return &Service{
		repository: repository,
		clock:      clock,
		ids:        ids,
		policy:     policy,
		executor:   executor,
		verifier:   verifier,
		limits:     limits,
	}
}

func (service *Service) ListScenarios() []Scenario {
	return listScenarioCopies()
}

func (service *Service) GetIncident(ctx context.Context, id string) (Incident, error) {
	if strings.TrimSpace(id) == "" {
		return Incident{}, ErrInvalidInput
	}
	return service.repository.Get(ctx, id)
}

func (service *Service) CreateIncident(ctx context.Context, scenarioID string) (Incident, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, err
	}
	scenario, exists := findScenario(strings.TrimSpace(scenarioID))
	if !exists {
		return Incident{}, ErrScenarioNotFound
	}
	now := service.clock().UTC()
	budget := Budget{
		MaxIterations: service.limits.MaxIterations,
		MaxRetries:    service.limits.MaxRetries,
		TimeBudget:    service.limits.TimeBudget,
		StartedAt:     now,
		Deadline:      now.Add(service.limits.TimeBudget),
	}
	incident := Incident{
		ID:         service.ids("inc"),
		ScenarioID: scenario.ID,
		Title:      scenario.Title,
		Severity:   scenario.Severity,
		State:      StateDetected,
		Iteration:  1,
		Budget:     budget,
		Target:     scenario.Target,
		Before:     scenario.Before,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	incident = appendAuditEvent(incident, EventIncidentCreated, StateDetected, "Synthetic SLO breach opened a bounded incident run.", nil, now)

	observations := service.collectObservations(scenario, now)
	incident = cloneIncident(incident)
	incident.Observations = observations
	incident = appendCost(incident, CostEntry{Stage: "telemetry", Provider: "deterministic-simulator", Units: len(observations), USD: 0, At: now})
	incident = appendAuditEvent(incident, EventTelemetryCollected, StateTriaging, "Typed telemetry envelopes collected; log excerpts remain untrusted data.", observationIDs(observations), now)

	evidenceIDs := selectEvidenceIDs(observations, scenario.EvidenceIndexes)
	incident = cloneIncident(incident)
	incident.Triage = Triage{
		Hypothesis:  scenario.Hypothesis,
		Confidence:  scenario.Confidence,
		EvidenceIDs: append([]string(nil), evidenceIDs...),
		Method:      "deterministic-evidence-rules/v1",
	}
	incident = appendCost(incident, CostEntry{Stage: "triage", Provider: "deterministic-rules", Units: 1, USD: 0, At: now})
	incident = appendAuditEvent(incident, EventTriageCompleted, StateTriaging, "Evidence-linked triage produced one bounded hypothesis.", evidenceIDs, now)

	expiresAt := now.Add(service.limits.ApprovalTTL)
	if budget.Deadline.Before(expiresAt) {
		expiresAt = budget.Deadline
	}
	proposal := Proposal{
		ID:          service.ids("prop"),
		Action:      scenario.ExpectedAction,
		Reason:      "Restore the demo SLO using the smallest allowlisted typed action supported by the evidence.",
		EvidenceIDs: append([]string(nil), evidenceIDs...),
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}
	incident = cloneIncident(incident)
	incident.Proposal = &proposal
	incident = appendAuditEvent(incident, EventProposalCreated, StateProposed, "A typed demo-only remediation was proposed; no command text is accepted.", evidenceIDs, now)

	decision := service.policy.Evaluate(proposal.Action)
	decision.EvaluatedAt = now
	proposal.Policy = decision
	proposal.Digest = proposalDigest(proposal)
	incident = cloneIncident(incident)
	incident.Proposal = &proposal
	incident = appendCost(incident, CostEntry{Stage: "policy", Provider: "deterministic-policy", Units: 1, USD: 0, At: now})
	incident = appendAuditEvent(incident, EventPolicyEvaluated, StateProposed, policySummary(decision), evidenceIDs, now)

	if !decision.Allowed {
		incident = withFailure(incident, Failure{Kind: FailurePolicy, Code: "policy_denied", Message: "The proposal did not pass policy.", At: now})
		incident = appendAuditEvent(incident, EventIncidentEscalated, StateEscalated, "Policy denied the proposal; human investigation is required.", evidenceIDs, now)
		return service.repository.Create(ctx, incident)
	}
	incident = appendAuditEvent(incident, EventAwaitingApproval, StateAwaitingApproval, "Execution is stopped pending an exact, digest-bound human decision.", evidenceIDs, now)
	return service.repository.Create(ctx, incident)
}

func (service *Service) Approve(ctx context.Context, id string, input ApprovalInput) (Incident, error) {
	if !validActor(input.Actor) || strings.TrimSpace(input.ProposalID) == "" || strings.TrimSpace(input.ProposalDigest) == "" {
		return Incident{}, ErrInvalidInput
	}
	current, err := service.repository.Get(ctx, id)
	if err != nil {
		return Incident{}, err
	}
	if current.State != StateAwaitingApproval || current.Proposal == nil {
		return Incident{}, ErrInvalidTransition
	}
	if !proposalMatches(*current.Proposal, input.ProposalID, input.ProposalDigest) {
		return Incident{}, ErrProposalMismatch
	}
	now := service.clock().UTC()
	if budgetExpired(current, now) || !now.Before(current.Proposal.ExpiresAt) {
		escalated := service.escalate(current, Failure{Kind: FailureBudget, Code: "budget_exhausted", Message: "The approval or run budget expired.", At: now}, "The bounded run expired before execution.")
		return service.repository.CompareAndSwap(ctx, id, current.Version, escalated)
	}

	freshDecision := service.policy.Evaluate(current.Proposal.Action)
	if !freshDecision.Allowed || freshDecision.Digest != current.Proposal.Policy.Digest {
		escalated := service.escalate(current, Failure{Kind: FailurePolicy, Code: "policy_changed", Message: "The current policy no longer matches the approved proposal.", At: now}, "Policy changed after proposal creation; execution was stopped.")
		return service.repository.CompareAndSwap(ctx, id, current.Version, escalated)
	}

	approved := cloneIncident(current)
	approved.Approval = &Approval{
		Decision:       DecisionApproved,
		Actor:          strings.TrimSpace(input.Actor),
		ProposalID:     current.Proposal.ID,
		ProposalDigest: current.Proposal.Digest,
		DecidedAt:      now,
	}
	approved = appendAuditEvent(approved, EventApprovalGranted, StateExecuting, "A human approved the exact proposal, action, and policy digest.", current.Proposal.EvidenceIDs, now)
	approved, err = service.repository.CompareAndSwap(ctx, id, current.Version, approved)
	if err != nil {
		return Incident{}, err
	}

	// External side effects run after the EXECUTING transition is durably visible.
	// The repository mutex is never held across executor or verifier callbacks.
	// Once approved, the bounded run is owned by the server rather than by the
	// lifetime of the HTTP request that delivered the human decision.
	runContext, cancelRun := service.serverRunContext(ctx, approved)
	defer cancelRun()
	completed := service.executeApproved(runContext, approved, *approved.Proposal, now)
	return service.repository.CompareAndSwap(context.WithoutCancel(ctx), id, approved.Version, completed)
}

func (service *Service) serverRunContext(requestContext context.Context, incident Incident) (context.Context, context.CancelFunc) {
	baseContext := context.WithoutCancel(requestContext)
	remaining := incident.Budget.Deadline.Sub(service.clock().UTC())
	if remaining <= 0 {
		expiredContext, cancel := context.WithCancel(baseContext)
		cancel()
		return expiredContext, cancel
	}
	return context.WithTimeout(baseContext, remaining)
}

func (service *Service) Reject(ctx context.Context, id string, input RejectionInput) (Incident, error) {
	if !validActor(input.Actor) || !validReason(input.Reason) || strings.TrimSpace(input.ProposalID) == "" || strings.TrimSpace(input.ProposalDigest) == "" {
		return Incident{}, ErrInvalidInput
	}
	current, err := service.repository.Get(ctx, id)
	if err != nil {
		return Incident{}, err
	}
	if current.State != StateAwaitingApproval || current.Proposal == nil {
		return Incident{}, ErrInvalidTransition
	}
	if !proposalMatches(*current.Proposal, input.ProposalID, input.ProposalDigest) {
		return Incident{}, ErrProposalMismatch
	}
	now := service.clock().UTC()
	if budgetExpired(current, now) || !now.Before(current.Proposal.ExpiresAt) {
		escalated := service.escalate(current, Failure{Kind: FailureBudget, Code: "budget_exhausted", Message: "The rejection or run budget expired.", At: now}, "The bounded run expired before the decision was recorded.")
		return service.repository.CompareAndSwap(ctx, id, current.Version, escalated)
	}
	next := cloneIncident(current)
	next.Approval = &Approval{
		Decision:       DecisionRejected,
		Actor:          strings.TrimSpace(input.Actor),
		Reason:         strings.TrimSpace(input.Reason),
		ProposalID:     current.Proposal.ID,
		ProposalDigest: current.Proposal.Digest,
		DecidedAt:      now,
	}
	next = appendAuditEvent(next, EventApprovalRejected, StateAwaitingApproval, "A human rejected the exact remediation proposal.", current.Proposal.EvidenceIDs, now)
	next = appendAuditEvent(next, EventIncidentEscalated, StateEscalated, "Rejected remediation was not executed; the incident requires human follow-up.", current.Proposal.EvidenceIDs, now)
	return service.repository.CompareAndSwap(ctx, id, current.Version, next)
}

func (service *Service) executeApproved(ctx context.Context, incident Incident, proposal Proposal, now time.Time) Incident {
	scenario, exists := findScenario(incident.ScenarioID)
	if !exists {
		return service.escalate(incident, Failure{Kind: FailureExecution, Code: "execution_failed", Message: "The typed demo action could not be executed.", At: now}, "Scenario fixture is unavailable; execution stopped.")
	}
	next := cloneIncident(incident)
	for attempt := 1; attempt <= incident.Budget.MaxRetries+1; attempt++ {
		if budgetExpired(next, service.clock().UTC()) {
			return service.escalate(next, Failure{Kind: FailureBudget, Code: "budget_exhausted", Message: "The run time budget expired.", At: service.clock().UTC()}, "The bounded run expired during execution.")
		}
		execution, err := service.executor.Execute(ctx, proposal.Action, scenario, service.clock().UTC())
		if err == nil {
			execution.Attempt = attempt
			next = cloneIncident(next)
			next.Execution = &execution
			next = appendCost(next, CostEntry{Stage: "execution", Provider: execution.Executor, Units: 1, USD: 0, At: execution.CompletedAt})
			next = appendAuditEvent(next, EventActionExecuted, StateExecuting, "The independently allowlisted typed demo action completed.", proposal.EvidenceIDs, execution.CompletedAt)
			return service.verify(ctx, next, scenario)
		}

		canRetry := retryableExecution(proposal.Action, err) && next.RetryCount < next.Budget.MaxRetries
		if canRetry {
			retryAt := service.clock().UTC()
			next = cloneIncident(next)
			next.RetryCount++
			next = appendAuditEvent(next, EventActionRetry, StateExecuting, "A typed transient failure triggered one bounded idempotent retry.", proposal.EvidenceIDs, retryAt)
			continue
		}

		failedAt := service.clock().UTC()
		next = withFailure(next, Failure{Kind: FailureExecution, Code: "execution_failed", Message: "The typed demo action could not be completed safely.", Retryable: canRetry, At: failedAt})
		next = appendAuditEvent(next, EventActionFailed, StateExecuting, "Execution stopped on a permanent, unknown-outcome, or exhausted transient failure.", proposal.EvidenceIDs, failedAt)
		return appendAuditEvent(next, EventIncidentEscalated, StateEscalated, "Execution did not complete within the bounded retry policy.", proposal.EvidenceIDs, failedAt)
	}
	return service.escalate(next, Failure{Kind: FailureExecution, Code: "execution_failed", Message: "The typed demo action could not be completed safely.", At: now}, "Execution exhausted its bounded retry policy.")
}

func (service *Service) verify(ctx context.Context, incident Incident, scenario Scenario) Incident {
	now := service.clock().UTC()
	if budgetExpired(incident, now) {
		return service.escalate(incident, Failure{Kind: FailureBudget, Code: "budget_exhausted", Message: "The run time budget expired before verification.", At: now}, "The bounded run expired before verification.")
	}
	next := appendAuditEvent(incident, EventVerificationStarted, StateVerifying, "An independent probe is collecting fresh telemetry; executor success is not trusted.", nil, now)
	verification, err := service.verifier.Verify(ctx, scenario, service.clock().UTC())
	if err != nil {
		verification.Outcome = VerificationInconclusive
		verification.Passed = false
		if verification.Checker == "" {
			verification.Checker = "independent-slo-verifier/v1"
		}
		if verification.Summary == "" {
			verification.Summary = "Fresh SLO telemetry was inconclusive."
		}
	}
	next = cloneIncident(next)
	next.Verification = &verification
	next.After = &verification.Snapshot
	next = appendCost(next, CostEntry{Stage: "verification", Provider: verification.Checker, Units: 1, USD: 0, At: verification.CollectedAt})
	next = appendAuditEvent(next, EventSLOVerified, StateVerifying, verificationEventSummary(verification), nil, service.clock().UTC())
	if verification.Outcome == VerificationPass && verification.Passed && verification.FreshTelemetry {
		return appendAuditEvent(next, EventIncidentResolved, StateResolved, "All fresh SLO checks passed; the incident is resolved.", nil, service.clock().UTC())
	}
	code := "verification_failed"
	message := "Fresh telemetry still breaches the SLO."
	if verification.Outcome == VerificationInconclusive {
		code = "verification_inconclusive"
		message = "Fresh telemetry was inconclusive."
	}
	next = withFailure(next, Failure{Kind: FailureVerification, Code: code, Message: message, At: service.clock().UTC()})
	return appendAuditEvent(next, EventIncidentEscalated, StateEscalated, "Verification did not pass; automatic replanning is disabled.", nil, service.clock().UTC())
}

func (service *Service) collectObservations(scenario Scenario, now time.Time) []Observation {
	observations := make([]Observation, len(scenario.Telemetry))
	for index, template := range scenario.Telemetry {
		observations[index] = Observation{
			ID:          service.ids("obs"),
			Type:        template.Type,
			Source:      template.Source,
			SourceURI:   template.SourceURI,
			CollectedAt: now,
			Trust:       template.Trust,
			Name:        template.Name,
			Value:       template.Value,
			Unit:        template.Unit,
			Text:        template.Text,
			Breached:    template.Breached,
		}
	}
	return observations
}

func (service *Service) escalate(incident Incident, failure Failure, summary string) Incident {
	next := withFailure(incident, failure)
	return appendAuditEvent(next, EventIncidentEscalated, StateEscalated, summary, nil, failure.At)
}

func normalizeLimits(limits Limits) Limits {
	if limits == (Limits{}) {
		return Limits{MaxIterations: 1, MaxRetries: 1, TimeBudget: 10 * time.Minute, ApprovalTTL: 5 * time.Minute}
	}
	if limits.MaxIterations <= 0 {
		limits.MaxIterations = 1
	}
	if limits.MaxRetries < 0 {
		limits.MaxRetries = 0
	}
	if limits.TimeBudget <= 0 {
		limits.TimeBudget = 10 * time.Minute
	}
	if limits.ApprovalTTL <= 0 {
		limits.ApprovalTTL = 5 * time.Minute
	}
	return limits
}

func proposalMatches(proposal Proposal, id, digest string) bool {
	return proposal.ID == strings.TrimSpace(id) &&
		proposal.Digest == strings.TrimSpace(digest) &&
		proposal.Digest == proposalDigest(proposal)
}

func budgetExpired(incident Incident, now time.Time) bool {
	return incident.Iteration > incident.Budget.MaxIterations || !now.Before(incident.Budget.Deadline)
}

func withFailure(incident Incident, failure Failure) Incident {
	next := cloneIncident(incident)
	next.LastError = &failure
	next.UpdatedAt = failure.At
	return next
}

func appendCost(incident Incident, entry CostEntry) Incident {
	next := cloneIncident(incident)
	next.Costs = append(next.Costs, entry)
	return next
}

func observationIDs(observations []Observation) []string {
	ids := make([]string, len(observations))
	for index, observation := range observations {
		ids[index] = observation.ID
	}
	return ids
}

func selectEvidenceIDs(observations []Observation, indexes []int) []string {
	ids := make([]string, 0, len(indexes))
	for _, index := range indexes {
		if index >= 0 && index < len(observations) {
			ids = append(ids, observations[index].ID)
		}
	}
	return ids
}

func validActor(actor string) bool {
	trimmed := strings.TrimSpace(actor)
	return trimmed != "" && len(trimmed) <= 100 && !strings.ContainsAny(trimmed, "\r\n\x00")
}

func validReason(reason string) bool {
	trimmed := strings.TrimSpace(reason)
	return trimmed != "" && len(trimmed) <= 300 && !strings.ContainsAny(trimmed, "\r\x00")
}

func policySummary(decision PolicyDecision) string {
	if decision.Allowed {
		return "Deterministic policy allowed the exact typed action on an isolated demo target."
	}
	return "Deterministic policy denied the proposal."
}

func verificationEventSummary(verification Verification) string {
	switch verification.Outcome {
	case VerificationPass:
		return "Fresh telemetry passed every independent SLO check."
	case VerificationFail:
		return "Fresh telemetry failed one or more independent SLO checks."
	default:
		return "Fresh telemetry was inconclusive; the loop will not auto-replan."
	}
}

func randomID(prefix string) string {
	buffer := make([]byte, 10)
	if _, err := rand.Read(buffer); err != nil {
		return prefix + "-fallback-" + hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return prefix + "-" + hex.EncodeToString(buffer)
}
