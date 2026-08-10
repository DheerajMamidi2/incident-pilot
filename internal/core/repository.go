package core

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrIncidentNotFound = errors.New("incident not found")
	ErrIncidentExists   = errors.New("incident already exists")
	ErrConcurrentUpdate = errors.New("concurrent incident update")
)

type IncidentRepository interface {
	Create(context.Context, Incident) (Incident, error)
	Get(context.Context, string) (Incident, error)
	CompareAndSwap(context.Context, string, int, Incident) (Incident, error)
}

type MemoryRepository struct {
	mu        sync.RWMutex
	incidents map[string]Incident
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{incidents: make(map[string]Incident)}
}

func (repository *MemoryRepository) Create(ctx context.Context, incident Incident) (Incident, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.incidents[incident.ID]; exists {
		return Incident{}, ErrIncidentExists
	}
	stored := cloneIncident(incident)
	stored.Version = 1
	repository.incidents[stored.ID] = cloneIncident(stored)
	return cloneIncident(stored), nil
}

func (repository *MemoryRepository) Get(ctx context.Context, id string) (Incident, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	incident, exists := repository.incidents[id]
	if !exists {
		return Incident{}, ErrIncidentNotFound
	}
	return cloneIncident(incident), nil
}

func (repository *MemoryRepository) CompareAndSwap(ctx context.Context, id string, expectedVersion int, replacement Incident) (Incident, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, exists := repository.incidents[id]
	if !exists {
		return Incident{}, ErrIncidentNotFound
	}
	if current.Version != expectedVersion {
		return Incident{}, ErrConcurrentUpdate
	}
	if replacement.ID != current.ID || replacement.ScenarioID != current.ScenarioID {
		return Incident{}, ErrConcurrentUpdate
	}
	stored := cloneIncident(replacement)
	stored.Version = current.Version + 1
	repository.incidents[id] = cloneIncident(stored)
	return cloneIncident(stored), nil
}

func cloneIncident(incident Incident) Incident {
	copyOfIncident := incident
	copyOfIncident.Observations = append([]Observation(nil), incident.Observations...)
	copyOfIncident.Triage.EvidenceIDs = append([]string(nil), incident.Triage.EvidenceIDs...)
	copyOfIncident.Costs = append([]CostEntry(nil), incident.Costs...)
	copyOfIncident.Events = make([]Event, len(incident.Events))
	for index, event := range incident.Events {
		copyOfIncident.Events[index] = event
		copyOfIncident.Events[index].EvidenceIDs = append([]string(nil), event.EvidenceIDs...)
	}
	if incident.Proposal != nil {
		proposal := *incident.Proposal
		proposal.EvidenceIDs = append([]string(nil), incident.Proposal.EvidenceIDs...)
		copyOfIncident.Proposal = &proposal
	}
	if incident.Approval != nil {
		approval := *incident.Approval
		copyOfIncident.Approval = &approval
	}
	if incident.Execution != nil {
		execution := *incident.Execution
		copyOfIncident.Execution = &execution
	}
	if incident.Verification != nil {
		verification := *incident.Verification
		verification.Checks = append([]SLOCheck(nil), incident.Verification.Checks...)
		copyOfIncident.Verification = &verification
	}
	if incident.After != nil {
		after := *incident.After
		copyOfIncident.After = &after
	}
	if incident.LastError != nil {
		lastError := *incident.LastError
		copyOfIncident.LastError = &lastError
	}
	return copyOfIncident
}
