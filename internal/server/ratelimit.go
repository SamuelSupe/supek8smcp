package server

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	identityLimiterCapacity = 10_000
	identityLimiterIdleTTL  = 15 * time.Minute
)

type identityLimitEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type identityRateLimiter struct {
	mu                sync.Mutex
	entries           map[string]*identityLimitEntry
	requestsPerMinute int32
	burst             int
	lastSweep         time.Time
}

func newIdentityRateLimiter(requestsPerMinute, burst int32) *identityRateLimiter {
	return &identityRateLimiter{
		entries:           make(map[string]*identityLimitEntry),
		requestsPerMinute: requestsPerMinute,
		burst:             int(burst),
	}
}

func (l *identityRateLimiter) Allow(subject string, now time.Time) (bool, string) {
	if subject == "" {
		return false, "invalid_identity"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= time.Minute {
		l.prune(now)
		l.lastSweep = now
	}
	entry, ok := l.entries[subject]
	if !ok {
		if len(l.entries) >= identityLimiterCapacity {
			return false, "identity_capacity"
		}
		entry = &identityLimitEntry{
			limiter: rate.NewLimiter(rate.Limit(float64(l.requestsPerMinute)/60), l.burst),
		}
		l.entries[subject] = entry
	}
	if !entry.limiter.AllowN(now, 1) {
		return false, "identity_rate"
	}
	entry.lastSeen = now
	return true, ""
}

func (l *identityRateLimiter) RetryAfterSeconds() int {
	requestsPerMinute := max(int32(1), l.requestsPerMinute)
	return max(1, int(math.Ceil(60/float64(requestsPerMinute))))
}

func (l *identityRateLimiter) prune(now time.Time) {
	for subject, entry := range l.entries {
		if now.Sub(entry.lastSeen) >= identityLimiterIdleTTL {
			delete(l.entries, subject)
		}
	}
}
