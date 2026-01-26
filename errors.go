package tendrils

import (
	"fmt"
	"sync"
	"time"
)

type PortErrorType string

const (
	ErrorTypeStartup     PortErrorType = "startup"
	ErrorTypeNew         PortErrorType = "new"
	ErrorTypeUnreachable PortErrorType = "unreachable"
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
	mu                   sync.RWMutex
	errors               map[string]*PortError
	baselines            map[string]*portErrorBaseline
	suppressedUnreachable map[string]bool
	nextID               int
	t                    *Tendrils
}

func NewErrorTracker(t *Tendrils) *ErrorTracker {
	return &ErrorTracker{
		errors:               map[string]*PortError{},
		baselines:            map[string]*portErrorBaseline{},
		suppressedUnreachable: map[string]bool{},
		t:                    t,
	}
}

func (e *ErrorTracker) CheckPort(node *Node, portName string, stats *InterfaceStats) {
	if stats == nil {
		return
	}

	changed := e.checkPortLocked(node, portName, stats)
	if changed {
		e.t.NotifyUpdate()
	}
}

func (e *ErrorTracker) checkPortLocked(node *Node, portName string, stats *InterfaceStats) bool {
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
			return true
		}
		return false
	}

	inDelta := uint64(0)
	outDelta := uint64(0)
	if stats.InErrors > baseline.InErrors {
		inDelta = stats.InErrors - baseline.InErrors
	}
	if stats.OutErrors > baseline.OutErrors {
		outDelta = stats.OutErrors - baseline.OutErrors
	}

	changed := false
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
		changed = true
	}

	e.baselines[key].InErrors = stats.InErrors
	e.baselines[key].OutErrors = stats.OutErrors

	return changed
}

func (e *ErrorTracker) ClearError(errorID string) {
	found := e.clearErrorLocked(errorID)
	if found {
		e.t.NotifyUpdate()
	}
}

func (e *ErrorTracker) clearErrorLocked(errorID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for key, err := range e.errors {
		if err.ID == errorID {
			if err.ErrorType == ErrorTypeUnreachable {
				e.suppressedUnreachable[key] = true
			}
			delete(e.errors, key)
			return true
		}
	}
	return false
}

func (e *ErrorTracker) ClearAllErrors() {
	had := e.clearAllErrorsLocked()
	if had {
		e.t.NotifyUpdate()
	}
}

func (e *ErrorTracker) clearAllErrorsLocked() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	had := len(e.errors) > 0
	for key, err := range e.errors {
		if err.ErrorType == ErrorTypeUnreachable {
			e.suppressedUnreachable[key] = true
		}
	}
	e.errors = map[string]*PortError{}
	return had
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

func (e *ErrorTracker) SetUnreachable(node *Node, ip string) {
	changed := e.setUnreachableLocked(node, ip)
	if changed {
		e.t.NotifyUpdate()
	}
}

func (e *ErrorTracker) setUnreachableLocked(node *Node, ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := "unreachable:" + node.TypeID + ":" + ip

	if e.suppressedUnreachable[key] {
		return false
	}

	if _, exists := e.errors[key]; exists {
		return false
	}

	now := time.Now()
	e.nextID++
	e.errors[key] = &PortError{
		ID:          fmt.Sprintf("err-%d", e.nextID),
		NodeTypeID:  node.TypeID,
		NodeName:    node.DisplayName(),
		PortName:    ip,
		ErrorType:   ErrorTypeUnreachable,
		FirstSeen:   now,
		LastUpdated: now,
	}
	return true
}

func (e *ErrorTracker) ClearUnreachable(node *Node, ip string) {
	changed := e.clearUnreachableLocked(node, ip)
	if changed {
		e.t.NotifyUpdate()
	}
}

func (e *ErrorTracker) clearUnreachableLocked(node *Node, ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := "unreachable:" + node.TypeID + ":" + ip

	delete(e.suppressedUnreachable, key)

	if _, exists := e.errors[key]; exists {
		delete(e.errors, key)
		return true
	}
	return false
}
