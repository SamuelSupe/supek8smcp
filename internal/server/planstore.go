package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	planTTL                   = 2 * time.Minute
	planStoreMaxBytes         = int64(64 << 20)
	planStoreSubjectMaxBytes  = int64(16 << 20)
	planStoreSizeSafetyFactor = int64(4)
)

type Operation struct {
	Action          Action         `json:"action"`
	Namespace       string         `json:"namespace,omitempty"`
	Name            string         `json:"name,omitempty"`
	Object          map[string]any `json:"object,omitempty"`
	Patch           any            `json:"patch,omitempty"`
	PatchType       string         `json:"patchType,omitempty"`
	Replicas        *int64         `json:"replicas,omitempty"`
	Command         []string       `json:"command,omitempty"`
	Container       string         `json:"container,omitempty"`
	Stdin           string         `json:"stdin,omitempty"`
	TimeoutSeconds  int64          `json:"timeoutSeconds,omitempty"`
	GracePeriod     *int64         `json:"gracePeriodSeconds,omitempty"`
	Force           bool           `json:"force,omitempty"`
	TargetUID       string         `json:"targetUID,omitempty"`
	ResourceVersion string         `json:"resourceVersion,omitempty"`
	ExpectedAbsent  bool           `json:"expectedAbsent,omitempty"`
	Generation      int64          `json:"generation"`
}

type storedPlan struct {
	Operation  Operation
	SubjectKey string
	ExpiresAt  time.Time
	Size       int64
}

type PlanStore struct {
	mu              sync.Mutex
	plans           map[string]storedPlan
	capacity        int
	usedBytes       int64
	subjectBytes    map[string]int64
	maxBytes        int64
	maxSubjectBytes int64
}

func NewPlanStore(capacity int) *PlanStore {
	return &PlanStore{
		plans: make(map[string]storedPlan), capacity: capacity, subjectBytes: make(map[string]int64),
		maxBytes: planStoreMaxBytes, maxSubjectBytes: planStoreSubjectMaxBytes,
	}
}

func (s *PlanStore) Create(subject string, operation Operation) (string, time.Time, error) {
	data, err := json.Marshal(operation)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("measure plan: %w", err)
	}
	size := int64(len(data)) * planStoreSizeSafetyFactor
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	if len(s.plans) >= s.capacity {
		return "", time.Time{}, policyError("plan_capacity", "too many pending plans")
	}
	if size > s.maxBytes || s.usedBytes > s.maxBytes-size {
		return "", time.Time{}, policyError("plan_capacity", "pending plans exceed the server memory budget")
	}
	subjectLimit := max(s.maxSubjectBytes, size)
	if used := s.subjectBytes[subject]; used > subjectLimit-size {
		return "", time.Time{}, policyError("plan_capacity", "this Kubernetes identity has too many pending plan bytes")
	}
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", time.Time{}, fmt.Errorf("generate plan ID: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(random)
	expires := time.Now().Add(planTTL)
	s.plans[id] = storedPlan{Operation: operation, SubjectKey: subject, ExpiresAt: expires, Size: size}
	s.usedBytes += size
	s.subjectBytes[subject] += size
	return id, expires, nil
}

func (s *PlanStore) Consume(id, subject string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	plan, ok := s.plans[id]
	if !ok {
		return Operation{}, policyError("invalid_plan", "plan does not exist or has already been used")
	}
	if time.Now().After(plan.ExpiresAt) {
		s.delete(id, plan)
		return Operation{}, policyError("expired_plan", "plan has expired")
	}
	if plan.SubjectKey != subject {
		return Operation{}, policyError("identity_mismatch", "plan belongs to a different Kubernetes identity")
	}
	s.delete(id, plan)
	return plan.Operation, nil
}

func (s *PlanStore) prune(now time.Time) {
	for id, plan := range s.plans {
		if now.After(plan.ExpiresAt) {
			s.delete(id, plan)
		}
	}
}

func (s *PlanStore) delete(id string, plan storedPlan) {
	delete(s.plans, id)
	s.usedBytes -= plan.Size
	remaining := s.subjectBytes[plan.SubjectKey] - plan.Size
	if remaining <= 0 {
		delete(s.subjectBytes, plan.SubjectKey)
	} else {
		s.subjectBytes[plan.SubjectKey] = remaining
	}
}
