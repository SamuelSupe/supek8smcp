package server

import (
	"sync"
)

type requestAdmission struct {
	mu          sync.Mutex
	identities  map[string]int
	perIdentity int
	streams     chan struct{}
}

func newRequestAdmission(concurrent int) *requestAdmission {
	return &requestAdmission{
		identities: make(map[string]int), perIdentity: max(1, (concurrent+1)/2),
		streams: make(chan struct{}, max(0, concurrent-1)),
	}
}

func (a *requestAdmission) acquireIdentity(identity string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identities[identity] >= a.perIdentity {
		return false
	}
	a.identities[identity]++
	return true
}

func (a *requestAdmission) releaseIdentity(identity string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.identities[identity]--
	if a.identities[identity] == 0 {
		delete(a.identities, identity)
	}
}

func (a *App) acquireStream() (func(), error) {
	if a.admission == nil {
		return func() {}, nil
	}
	if cap(a.admission.streams) == 0 {
		return nil, policyError("stream_disabled", "streaming requires maxConcurrent of at least two to reserve capacity for short requests")
	}
	select {
	case a.admission.streams <- struct{}{}:
		return func() { <-a.admission.streams }, nil
	default:
		return nil, policyError("stream_capacity", "stream concurrency limit reached; capacity is reserved for short requests")
	}
}
