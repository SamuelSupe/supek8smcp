package server

import (
	"fmt"
	"testing"
	"time"
)

func TestIdentityRateLimiterEnforcesBurstPerIdentity(t *testing.T) {
	t.Parallel()

	limiter := newIdentityRateLimiter(60, 2)
	now := time.Unix(1_000, 0)
	for attempt := 0; attempt < 2; attempt++ {
		if allowed, reason := limiter.Allow("alice", now); !allowed || reason != "" {
			t.Fatalf("Allow(alice) attempt %d = %t, %q; want allowed", attempt+1, allowed, reason)
		}
	}
	if allowed, reason := limiter.Allow("alice", now); allowed || reason != "identity_rate" {
		t.Fatalf("Allow(alice) after burst = %t, %q; want false, identity_rate", allowed, reason)
	}

	if allowed, reason := limiter.Allow("bob", now); !allowed || reason != "" {
		t.Fatalf("Allow(bob) after alice exhausted = %t, %q; want allowed", allowed, reason)
	}
}

func TestIdentityRateLimiterRefillsOverTime(t *testing.T) {
	t.Parallel()

	limiter := newIdentityRateLimiter(60, 1)
	now := time.Unix(2_000, 0)
	if allowed, reason := limiter.Allow("alice", now); !allowed || reason != "" {
		t.Fatalf("initial Allow(alice) = %t, %q; want allowed", allowed, reason)
	}
	if allowed, reason := limiter.Allow("alice", now); allowed || reason != "identity_rate" {
		t.Fatalf("immediate Allow(alice) = %t, %q; want false, identity_rate", allowed, reason)
	}
	if allowed, reason := limiter.Allow("alice", now.Add(1500*time.Millisecond)); !allowed || reason != "" {
		t.Fatalf("refilled Allow(alice) = %t, %q; want allowed", allowed, reason)
	}
}

func TestIdentityRateLimiterPrunesIdleIdentitiesAfterDeniedRequests(t *testing.T) {
	t.Parallel()

	// A denied request must not extend an identity's cache lifetime. Filling the
	// bounded cache makes that observable without inspecting its implementation.
	limiter := newIdentityRateLimiter(1, 1)
	now := time.Unix(3_000, 0)
	for i := 0; i < identityLimiterCapacity; i++ {
		if allowed, reason := limiter.Allow(fmt.Sprintf("seed-%d", i), now); !allowed || reason != "" {
			t.Fatalf("seed identity %d Allow() = %t, %q; want allowed", i, allowed, reason)
		}
	}
	if allowed, reason := limiter.Allow("seed-0", now.Add(time.Second)); allowed || reason != "identity_rate" {
		t.Fatalf("denied seed request = %t, %q; want false, identity_rate", allowed, reason)
	}

	pruneAt := now.Add(identityLimiterIdleTTL)
	for i := 0; i < identityLimiterCapacity; i++ {
		if allowed, reason := limiter.Allow(fmt.Sprintf("fresh-%d", i), pruneAt); !allowed || reason != "" {
			t.Fatalf("fresh identity %d after idle prune = %t, %q; want allowed", i, allowed, reason)
		}
	}
}

func TestIdentityRateLimiterRetryAfterSeconds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rpm  int32
		want int
	}{
		{name: "one request per second", rpm: 60, want: 1},
		{name: "half request per second", rpm: 30, want: 2},
		{name: "one request per minute", rpm: 1, want: 60},
		{name: "high rate has one second minimum", rpm: 6000, want: 1},
		{name: "invalid zero rate has one minute retry", rpm: 0, want: 60},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := newIdentityRateLimiter(tt.rpm, 1)
			if got := limiter.RetryAfterSeconds(); got != tt.want {
				t.Fatalf("RetryAfterSeconds() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRequestAdmissionIdentityLimitRecoversAfterRelease(t *testing.T) {
	for _, tt := range []struct {
		concurrent int
		attempts   int
	}{
		{concurrent: 4, attempts: 2},
		{concurrent: 5, attempts: 3},
	} {
		t.Run(fmt.Sprintf("concurrent-%d", tt.concurrent), func(t *testing.T) {
			admission := newRequestAdmission(tt.concurrent)
			for attempt := 0; attempt < tt.attempts; attempt++ {
				if !admission.acquireIdentity("alice") {
					t.Fatalf("acquireIdentity(alice) attempt %d failed before the limit", attempt+1)
				}
			}
			if admission.acquireIdentity("alice") {
				t.Fatal("acquireIdentity(alice) exceeded the per-identity limit")
			}
			admission.releaseIdentity("alice")
			if !admission.acquireIdentity("alice") {
				t.Fatal("acquireIdentity(alice) did not recover after release")
			}
			for attempt := 0; attempt < tt.attempts; attempt++ {
				admission.releaseIdentity("alice")
			}
		})
	}
}

func TestRequestAdmissionStreamCapacityReservesShortRequestSlot(t *testing.T) {
	t.Parallel()

	admission := newRequestAdmission(4)
	app := &App{admission: admission}
	const streamCapacity = 3
	releases := make([]func(), 0, streamCapacity)
	for attempt := 0; attempt < streamCapacity; attempt++ {
		release, err := app.acquireStream()
		if err != nil {
			t.Fatalf("acquireStream() attempt %d error = %v", attempt+1, err)
		}
		releases = append(releases, release)
	}
	if release, err := app.acquireStream(); err == nil || policyReason(err) != "stream_capacity" || release != nil {
		t.Fatalf("acquireStream() at reserved short-request slot = releasePresent=%t error=%v, want stream_capacity", release != nil, err)
	}
	releases[0]()
	if release, err := app.acquireStream(); err != nil || release == nil {
		t.Fatalf("acquireStream() after stream release = releasePresent=%t error=%v, want recovery", release != nil, err)
	} else {
		releases = append(releases, release)
	}
	for _, release := range releases[1:] {
		release()
	}
}

func TestRequestAdmissionDisablesStreamsWhenOnlyOneRequestIsAllowed(t *testing.T) {
	t.Parallel()

	app := &App{admission: newRequestAdmission(1)}
	if release, err := app.acquireStream(); err == nil || policyReason(err) != "stream_disabled" || release != nil {
		t.Fatalf("acquireStream() with one request slot = releasePresent=%t error=%v, want stream_disabled", release != nil, err)
	}
}
