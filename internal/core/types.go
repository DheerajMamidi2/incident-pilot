package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// State is the durable state of the bounded incident loop.
type State string

const (
	StateDetected         State = "DETECTED"
	StateTriaging         State = "TRIAGING"
	StateProposed         State = "PROPOSED"
	StateAwaitingApproval State = "AWAITING_APPROVAL"
	StateExecuting        State = "EXECUTING"
	StateVerifying        State = "VERIFYING"
	StateResolved         State = "RESOLVED"
	StateEscalated        State = "ESCALATED"
)

// EventType names every append-only audit event emitted by the loop.
type EventType string

const (
	EventIncidentCreated     EventType = "INCIDENT_CREATED"
	EventTelemetryCollected  EventType = "TELEMETRY_COLLECTED"
	EventTriageCompleted     EventType = "TRIAGE_COMPLETED"
	EventProposalCreated     EventType = "PROPOSAL_CREATED"
	EventPolicyEvaluated     EventType = "POLICY_EVALUATED"
	EventAwaitingApproval    EventType = "AWAITING_APPROVAL"
	EventApprovalGranted     EventType = "APPROVAL_GRANTED"
	EventApprovalRejected    EventType = "APPROVAL_REJECTED"
	EventActionRetry         EventType = "ACTION_RETRY"
	EventActionExecuted      EventType = "ACTION_EXECUTED"
	EventActionFailed        EventType = "ACTION_FAILED"
	EventVerificationStarted EventType = "VERIFICATION_STARTED"
	EventSLOVerified         EventType = "SLO_VERIFIED"
	EventIncidentResolved    EventType = "INCIDENT_RESOLVED"
	EventIncidentEscalated   EventType = "INCIDENT_ESCALATED"
)

type ObservationType string

const (
	ObservationMetric     ObservationType = "METRIC"
	ObservationDependency ObservationType = "DEPENDENCY_HEALTH"
	ObservationConfig     ObservationType = "CONFIG_STATE"
	ObservationLog        ObservationType = "LOG_EXCERPT"
)

type TrustLevel string

const (
	TrustSystem    TrustLevel = "SYSTEM_OBSERVED"
	TrustUntrusted TrustLevel = "UNTRUSTED_DATA"
)

// Observation is a typed telemetry envelope. Text is always data, never an instruction.
type Observation struct {
	ID          string          `json:"id"`
	Type        ObservationType `json:"type"`
	Source      string          `json:"source"`
	SourceURI   string          `json:"source_uri"`
	CollectedAt time.Time       `json:"collected_at"`
	Trust       TrustLevel      `json:"trust"`
	Name        string          `json:"name"`
	Value       float64         `json:"value,omitempty"`
	Unit        string          `json:"unit,omitempty"`
	Text        string          `json:"text,omitempty"`
	Breached    bool            `json:"breached"`
}

type SLOTarget struct {
	MaxLatencyP95MS        float64 `json:"max_latency_p95_ms"`
	MaxErrorRatePercent    float64 `json:"max_error_rate_percent"`
	MinAvailabilityPercent float64 `json:"min_availability_percent"`
}

type SLOSnapshot struct {
	LatencyP95MS        float64 `json:"latency_p95_ms"`
	ErrorRatePercent    float64 `json:"error_rate_percent"`
	AvailabilityPercent float64 `json:"availability_percent"`
	Passing             bool    `json:"passing"`
}

type Triage struct {
	Hypothesis  string   `json:"hypothesis"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
	Method      string   `json:"method"`
}

type ActionKind string

const (
	ActionRollbackDemoConfig ActionKind = "ROLLBACK_DEMO_CONFIG"
	ActionResetDemoCircuit   ActionKind = "RESET_DEMO_CIRCUIT"
	ActionDrainDemoQueue     ActionKind = "DRAIN_DEMO_QUEUE"
)

// DemoAction is deliberately narrow: there is no command, script, URL, or free-form payload.
type DemoAction struct {
	Kind   ActionKind `json:"kind"`
	Target string     `json:"target"`
	From   string     `json:"from"`
	To     string     `json:"to"`
}

type PolicyDecision struct {
	Allowed     bool      `json:"allowed"`
	Rule        string    `json:"rule"`
	Version     string    `json:"version"`
	Reason      string    `json:"reason"`
	Digest      string    `json:"digest"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

type Proposal struct {
	ID          string         `json:"id"`
	Digest      string         `json:"digest"`
	Action      DemoAction     `json:"action"`
	Reason      string         `json:"reason"`
	EvidenceIDs []string       `json:"evidence_ids"`
	Policy      PolicyDecision `json:"policy"`
	CreatedAt   time.Time      `json:"created_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

type ApprovalDecision string

const (
	DecisionApproved ApprovalDecision = "APPROVED"
	DecisionRejected ApprovalDecision = "REJECTED"
)

type Approval struct {
	Decision       ApprovalDecision `json:"decision"`
	Actor          string           `json:"actor"`
	Reason         string           `json:"reason,omitempty"`
	ProposalID     string           `json:"proposal_id"`
	ProposalDigest string           `json:"proposal_digest"`
	DecidedAt      time.Time        `json:"decided_at"`
}

type ExecutionRecord struct {
	Action      DemoAction `json:"action"`
	Executor    string     `json:"executor"`
	Attempt     int        `json:"attempt"`
	CompletedAt time.Time  `json:"completed_at"`
}

type VerificationOutcome string

const (
	VerificationPass         VerificationOutcome = "PASS"
	VerificationFail         VerificationOutcome = "FAIL"
	VerificationInconclusive VerificationOutcome = "INCONCLUSIVE"
)

type SLOCheck struct {
	Name      string  `json:"name"`
	Observed  float64 `json:"observed"`
	Threshold float64 `json:"threshold"`
	Operator  string  `json:"operator"`
	Passed    bool    `json:"passed"`
}

type Verification struct {
	Checker        string              `json:"checker"`
	Source         string              `json:"source"`
	FreshTelemetry bool                `json:"fresh_telemetry"`
	CollectedAt    time.Time           `json:"collected_at"`
	Outcome        VerificationOutcome `json:"outcome"`
	Passed         bool                `json:"passed"`
	Summary        string              `json:"summary"`
	Snapshot       SLOSnapshot         `json:"snapshot"`
	Checks         []SLOCheck          `json:"checks"`
}

type Budget struct {
	MaxIterations int           `json:"max_iterations"`
	MaxRetries    int           `json:"max_retries"`
	TimeBudget    time.Duration `json:"time_budget_ns"`
	StartedAt     time.Time     `json:"started_at"`
	Deadline      time.Time     `json:"deadline"`
}

type FailureKind string

const (
	FailurePolicy       FailureKind = "POLICY"
	FailureBudget       FailureKind = "BUDGET"
	FailureExecution    FailureKind = "EXECUTION"
	FailureVerification FailureKind = "VERIFICATION"
)

// Failure is the typed domain-error envelope persisted with an incident.
type Failure struct {
	Kind      FailureKind `json:"kind"`
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	Retryable bool        `json:"retryable"`
	At        time.Time   `json:"at"`
}

type CostEntry struct {
	Stage    string    `json:"stage"`
	Provider string    `json:"provider"`
	Units    int       `json:"units"`
	USD      float64   `json:"usd"`
	At       time.Time `json:"at"`
}

// Event is hash-linked. PreviousHash and Hash make accidental/history tampering detectable.
type Event struct {
	Sequence     int       `json:"sequence"`
	Type         EventType `json:"type"`
	OccurredAt   time.Time `json:"occurred_at"`
	State        State     `json:"state"`
	Summary      string    `json:"summary"`
	EvidenceIDs  []string  `json:"evidence_ids,omitempty"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash"`
}

type Incident struct {
	ID           string           `json:"id"`
	Version      int              `json:"version"`
	ScenarioID   string           `json:"scenario_id"`
	Title        string           `json:"title"`
	Severity     string           `json:"severity"`
	State        State            `json:"state"`
	Iteration    int              `json:"iteration"`
	RetryCount   int              `json:"retry_count"`
	Budget       Budget           `json:"budget"`
	Target       SLOTarget        `json:"slo_target"`
	Before       SLOSnapshot      `json:"before"`
	After        *SLOSnapshot     `json:"after,omitempty"`
	Observations []Observation    `json:"observations"`
	Triage       Triage           `json:"triage"`
	Proposal     *Proposal        `json:"proposal,omitempty"`
	Approval     *Approval        `json:"approval,omitempty"`
	Execution    *ExecutionRecord `json:"execution,omitempty"`
	Verification *Verification    `json:"verification,omitempty"`
	LastError    *Failure         `json:"last_error,omitempty"`
	Costs        []CostEntry      `json:"cost_ledger"`
	Events       []Event          `json:"events"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

func (incident Incident) TotalCostUSD() float64 {
	total := 0.0
	for _, entry := range incident.Costs {
		total += entry.USD
	}
	return total
}

func appendAuditEvent(incident Incident, eventType EventType, state State, summary string, evidenceIDs []string, now time.Time) Incident {
	next := cloneIncident(incident)
	previousHash := "GENESIS"
	if len(next.Events) > 0 {
		previousHash = next.Events[len(next.Events)-1].Hash
	}
	event := Event{
		Sequence:     len(next.Events) + 1,
		Type:         eventType,
		OccurredAt:   now.UTC(),
		State:        state,
		Summary:      summary,
		EvidenceIDs:  append([]string(nil), evidenceIDs...),
		PreviousHash: previousHash,
	}
	event.Hash = hashEvent(event)
	next.Events = append(next.Events, event)
	next.State = state
	next.UpdatedAt = now.UTC()
	return next
}

func hashEvent(event Event) string {
	canonical := fmt.Sprintf("%d\n%s\n%s\n%s\n%s\n%s\n%s",
		event.Sequence,
		event.Type,
		event.OccurredAt.UTC().Format(time.RFC3339Nano),
		event.State,
		event.Summary,
		strings.Join(event.EvidenceIDs, ","),
		event.PreviousHash,
	)
	digest := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func ValidateEventChain(events []Event) bool {
	previousHash := "GENESIS"
	for index, event := range events {
		if event.Sequence != index+1 || event.PreviousHash != previousHash || event.Hash != hashEvent(event) {
			return false
		}
		previousHash = event.Hash
	}
	return true
}
