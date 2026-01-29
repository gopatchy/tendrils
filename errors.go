package tendrils

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	ErrorTypeNew             = "new"
	ErrorTypeUnreachable     = "unreachable"
	ErrorTypeHighUtilization = "high_utilization"
)

type Error struct {
	ID          string    `json:"id"`
	NodeID      string    `json:"node_id"`
	NodeName    string    `json:"node_name"`
	Type        string    `json:"type"`
	Port        string    `json:"port,omitempty"`
	InErrors    uint64    `json:"in_errors,omitempty"`
	OutErrors   uint64    `json:"out_errors,omitempty"`
	InDelta     uint64    `json:"in_delta,omitempty"`
	OutDelta    uint64    `json:"out_delta,omitempty"`
	Utilization float64   `json:"utilization,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastUpdated time.Time `json:"last_updated,omitempty"`
}

type ErrorTracker struct {
	mu     sync.RWMutex
	errors map[string]*Error
	nextID int
	t      *Tendrils
}

func NewErrorTracker(t *Tendrils) *ErrorTracker {
	return &ErrorTracker{
		errors: map[string]*Error{},
		t:      t,
	}
}

func (e *ErrorTracker) AddUnreachable(node *Node) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := "unreachable:" + node.ID
	if _, exists := e.errors[key]; exists {
		return
	}

	now := time.Now()
	e.nextID++
	e.errors[key] = &Error{
		ID:          fmt.Sprintf("err-%d", e.nextID),
		NodeID:      node.ID,
		NodeName:    node.DisplayName(),
		Type:        ErrorTypeUnreachable,
		FirstSeen:   now,
		LastUpdated: now,
	}
	e.t.NotifyUpdate()
}

func (e *ErrorTracker) RemoveUnreachable(node *Node) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := "unreachable:" + node.ID
	if _, exists := e.errors[key]; exists {
		delete(e.errors, key)
		e.t.NotifyUpdate()
	}
}

func (e *ErrorTracker) AddPortError(node *Node, portName string, stats *InterfaceStats, inDelta, outDelta uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := node.ID + ":" + portName
	now := time.Now()

	if existing, ok := e.errors[key]; ok {
		existing.InErrors = stats.InErrors
		existing.OutErrors = stats.OutErrors
		existing.InDelta += inDelta
		existing.OutDelta += outDelta
		existing.LastUpdated = now
	} else {
		e.nextID++
		e.errors[key] = &Error{
			ID:          fmt.Sprintf("err-%d", e.nextID),
			NodeID:      node.ID,
			NodeName:    node.DisplayName(),
			Port:        portName,
			Type:        ErrorTypeNew,
			InErrors:    stats.InErrors,
			OutErrors:   stats.OutErrors,
			InDelta:     inDelta,
			OutDelta:    outDelta,
			FirstSeen:   now,
			LastUpdated: now,
		}
	}
	e.t.NotifyUpdate()
}

func (e *ErrorTracker) AddUtilizationError(node *Node, portName string, utilization float64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := "util:" + node.ID + ":" + portName
	now := time.Now()

	if existing, ok := e.errors[key]; ok {
		if utilization > existing.Utilization {
			existing.Utilization = utilization
			existing.LastUpdated = now
			e.t.NotifyUpdate()
		}
		return
	}

	e.nextID++
	e.errors[key] = &Error{
		ID:          fmt.Sprintf("err-%d", e.nextID),
		NodeID:      node.ID,
		NodeName:    node.DisplayName(),
		Port:        portName,
		Type:        ErrorTypeHighUtilization,
		Utilization: utilization,
		FirstSeen:   now,
		LastUpdated: now,
	}
	e.t.NotifyUpdate()
}

func (e *ErrorTracker) ClearError(errorID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for key, err := range e.errors {
		if err.ID == errorID {
			delete(e.errors, key)
			e.t.NotifyUpdate()
			return
		}
	}
}

func (e *ErrorTracker) ClearAllErrors() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.errors) > 0 {
		e.errors = map[string]*Error{}
		e.t.NotifyUpdate()
	}
}

func (e *ErrorTracker) GetErrors() []*Error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	errors := make([]*Error, 0, len(e.errors))
	for _, err := range e.errors {
		errors = append(errors, err)
	}
	sort.Slice(errors, func(i, j int) bool {
		if errors[i].NodeName != errors[j].NodeName {
			return errors[i].NodeName < errors[j].NodeName
		}
		return errors[i].Port < errors[j].Port
	})
	return errors
}
