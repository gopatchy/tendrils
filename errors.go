package tendrils

import (
	"fmt"
	"sync"
	"time"
)

type PortErrorType string

const (
	ErrorTypeStartup PortErrorType = "startup"
	ErrorTypeNew     PortErrorType = "new"
)

type PortError struct {
	ID          string        `json:"id"`
	NodeTypeID  string        `json:"node_typeid"`
	NodeName    string        `json:"node_name"`
	PortName    string        `json:"port_name"`
	ErrorType   PortErrorType `json:"error_type"`
	InErrors    uint64        `json:"in_errors"`
	OutErrors   uint64        `json:"out_errors"`
	InDelta     uint64        `json:"in_delta,omitempty"`
	OutDelta    uint64        `json:"out_delta,omitempty"`
	FirstSeen   time.Time     `json:"first_seen"`
	LastUpdated time.Time     `json:"last_updated"`
}

type portErrorBaseline struct {
	InErrors  uint64
	OutErrors uint64
	HasData   bool
}

type ErrorTracker struct {
	mu        sync.RWMutex
	errors    map[string]*PortError
	baselines map[string]*portErrorBaseline
	nextID    int
}

func NewErrorTracker() *ErrorTracker {
	return &ErrorTracker{
		errors:    map[string]*PortError{},
		baselines: map[string]*portErrorBaseline{},
	}
}

func (e *ErrorTracker) CheckPort(node *Node, portName string, stats *InterfaceStats) {
	if stats == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	key := node.TypeID + ":" + portName
	baseline := e.baselines[key]

	now := time.Now()

	if baseline == nil || !baseline.HasData {
		e.baselines[key] = &portErrorBaseline{
			InErrors:  stats.InErrors,
			OutErrors: stats.OutErrors,
			HasData:   true,
		}
		if stats.InErrors > 0 || stats.OutErrors > 0 {
			e.nextID++
			e.errors[key] = &PortError{
				ID:          fmt.Sprintf("err-%d", e.nextID),
				NodeTypeID:  node.TypeID,
				NodeName:    node.DisplayName(),
				PortName:    portName,
				ErrorType:   ErrorTypeStartup,
				InErrors:    stats.InErrors,
				OutErrors:   stats.OutErrors,
				FirstSeen:   now,
				LastUpdated: now,
			}
		}
		return
	}

	inDelta := uint64(0)
	outDelta := uint64(0)
	if stats.InErrors > baseline.InErrors {
		inDelta = stats.InErrors - baseline.InErrors
	}
	if stats.OutErrors > baseline.OutErrors {
		outDelta = stats.OutErrors - baseline.OutErrors
	}

	if inDelta > 0 || outDelta > 0 {
		if existing, ok := e.errors[key]; ok {
			existing.InErrors = stats.InErrors
			existing.OutErrors = stats.OutErrors
			existing.InDelta += inDelta
			existing.OutDelta += outDelta
			existing.LastUpdated = now
		} else {
			e.nextID++
			e.errors[key] = &PortError{
				ID:          fmt.Sprintf("err-%d", e.nextID),
				NodeTypeID:  node.TypeID,
				NodeName:    node.DisplayName(),
				PortName:    portName,
				ErrorType:   ErrorTypeNew,
				InErrors:    stats.InErrors,
				OutErrors:   stats.OutErrors,
				InDelta:     inDelta,
				OutDelta:    outDelta,
				FirstSeen:   now,
				LastUpdated: now,
			}
		}
	}

	e.baselines[key].InErrors = stats.InErrors
	e.baselines[key].OutErrors = stats.OutErrors
}

func (e *ErrorTracker) ClearError(errorID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for key, err := range e.errors {
		if err.ID == errorID {
			delete(e.errors, key)
			return
		}
	}
}

func (e *ErrorTracker) ClearAllErrors() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.errors = map[string]*PortError{}
}

func (e *ErrorTracker) GetErrors() []*PortError {
	e.mu.RLock()
	defer e.mu.RUnlock()

	errors := make([]*PortError, 0, len(e.errors))
	for _, err := range e.errors {
		errors = append(errors, err)
	}
	return errors
}
