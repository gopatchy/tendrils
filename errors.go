package tendrils

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	ErrorTypeStartup         = "startup"
	ErrorTypeNew             = "new"
	ErrorTypeUnreachable     = "unreachable"
	ErrorTypeHighUtilization = "high_utilization"
)

type Error struct {
	ID          string    `json:"id"`
	NodeID  string    `json:"node_id"`
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

type errorBaseline struct {
	InErrors  uint64
	OutErrors uint64
	HasData   bool
}

type ErrorTracker struct {
	mu                    sync.RWMutex
	errors                map[string]*Error
	baselines             map[string]*errorBaseline
	suppressedUnreachable map[string]bool
	unreachableNodes      map[string]bool
	nextID                int
	t                     *Tendrils
}

func NewErrorTracker(t *Tendrils) *ErrorTracker {
	return &ErrorTracker{
		errors:                map[string]*Error{},
		baselines:             map[string]*errorBaseline{},
		suppressedUnreachable: map[string]bool{},
		unreachableNodes:      map[string]bool{},
		t:                     t,
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

func (e *ErrorTracker) CheckUtilization(node *Node, portName string, stats *InterfaceStats) {
	if stats == nil || stats.Speed == 0 {
		return
	}

	changed := e.checkUtilizationLocked(node, portName, stats)
	if changed {
		e.t.NotifyUpdate()
	}
}

func (e *ErrorTracker) checkUtilizationLocked(node *Node, portName string, stats *InterfaceStats) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	maxBytesRate := stats.InBytesRate
	if stats.OutBytesRate > maxBytesRate {
		maxBytesRate = stats.OutBytesRate
	}

	speedBytes := float64(stats.Speed) / 8.0
	utilization := (maxBytesRate / speedBytes) * 100.0

	key := "util:" + node.ID + ":" + portName
	now := time.Now()

	if utilization < 70.0 {
		return false
	}

	if existing, ok := e.errors[key]; ok {
		if utilization > existing.Utilization {
			existing.Utilization = utilization
			existing.LastUpdated = now
			return true
		}
		return false
	}

	e.nextID++
	e.errors[key] = &Error{
		ID:          fmt.Sprintf("err-%d", e.nextID),
		NodeID:  node.ID,
		NodeName:    node.DisplayName(),
		Port:        portName,
		Type:        ErrorTypeHighUtilization,
		Utilization: utilization,
		FirstSeen:   now,
		LastUpdated: now,
	}
	return true
}

func (e *ErrorTracker) checkPortLocked(node *Node, portName string, stats *InterfaceStats) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := node.ID + ":" + portName
	baseline := e.baselines[key]

	now := time.Now()

	if baseline == nil || !baseline.HasData {
		e.baselines[key] = &errorBaseline{
			InErrors:  stats.InErrors,
			OutErrors: stats.OutErrors,
			HasData:   true,
		}
		if stats.InErrors > 0 || stats.OutErrors > 0 {
			e.nextID++
			e.errors[key] = &Error{
				ID:         fmt.Sprintf("err-%d", e.nextID),
				NodeID: node.ID,
				NodeName:   node.DisplayName(),
				Port:       portName,
				Type:       ErrorTypeStartup,
				InErrors:   stats.InErrors,
				OutErrors:  stats.OutErrors,
				FirstSeen:  now,
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
			e.errors[key] = &Error{
				ID:          fmt.Sprintf("err-%d", e.nextID),
				NodeID:  node.ID,
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
			if err.Type == ErrorTypeUnreachable {
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
		if err.Type == ErrorTypeUnreachable {
			e.suppressedUnreachable[key] = true
		}
	}
	e.errors = map[string]*Error{}
	return had
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

func (e *ErrorTracker) GetUnreachableNodeSet() map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := map[string]bool{}
	for nodeID := range e.unreachableNodes {
		result[nodeID] = true
	}
	return result
}

func (e *ErrorTracker) SetUnreachable(node *Node) bool {
	changed, becameUnreachable := e.setUnreachableLocked(node)
	if changed {
		e.t.NotifyUpdate()
	}
	return becameUnreachable
}

func (e *ErrorTracker) setUnreachableLocked(node *Node) (changed bool, becameUnreachable bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := "unreachable:" + node.ID

	wasUnreachable := e.unreachableNodes[node.ID]
	e.unreachableNodes[node.ID] = true
	becameUnreachable = !wasUnreachable

	if e.suppressedUnreachable[key] {
		return becameUnreachable, becameUnreachable
	}

	if _, exists := e.errors[key]; exists {
		return becameUnreachable, becameUnreachable
	}

	now := time.Now()
	e.nextID++
	e.errors[key] = &Error{
		ID:          fmt.Sprintf("err-%d", e.nextID),
		NodeID:  node.ID,
		NodeName:    node.DisplayName(),
		Type:        ErrorTypeUnreachable,
		FirstSeen:   now,
		LastUpdated: now,
	}
	return true, becameUnreachable
}

func (e *ErrorTracker) ClearUnreachable(node *Node) bool {
	changed, becameReachable := e.clearUnreachableLocked(node)
	if changed {
		e.t.NotifyUpdate()
	}
	return becameReachable
}

func (e *ErrorTracker) clearUnreachableLocked(node *Node) (changed bool, becameReachable bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := "unreachable:" + node.ID

	delete(e.suppressedUnreachable, key)

	wasUnreachable := e.unreachableNodes[node.ID]
	delete(e.unreachableNodes, node.ID)
	becameReachable = wasUnreachable

	if _, exists := e.errors[key]; exists {
		delete(e.errors, key)
		return true, becameReachable
	}
	return becameReachable, becameReachable
}
