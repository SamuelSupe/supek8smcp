package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"
)

const (
	planTTL                   = 2 * time.Minute
	planStoreMaxBytes         = int64(64 << 20)
	planStoreSubjectMaxBytes  = int64(16 << 20)
	planStoreSizeSafetyFactor = int64(4)
	confirmationMaxAttempts   = 5
	confirmationCodePattern   = `^[0-9]{6}$`
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
	Operation            Operation
	SubjectKey           string
	ExpiresAt            time.Time
	Size                 int64
	ConfirmationHash     [sha256.Size]byte
	ConfirmationFailures int
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

func (s *PlanStore) Create(subject string, operation Operation) (string, string, time.Time, error) {
	data, err := json.Marshal(operation)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("measure plan: %w", err)
	}
	size := int64(len(data)) * planStoreSizeSafetyFactor
	id, err := randomPlanID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	confirmationCode, err := randomConfirmationCode()
	if err != nil {
		return "", "", time.Time{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	if len(s.plans) >= s.capacity {
		return "", "", time.Time{}, policyError("plan_capacity", "too many pending plans")
	}
	if size > s.maxBytes || s.usedBytes > s.maxBytes-size {
		return "", "", time.Time{}, policyError("plan_capacity", "pending plans exceed the server memory budget")
	}
	subjectLimit := max(s.maxSubjectBytes, size)
	if used := s.subjectBytes[subject]; used > subjectLimit-size {
		return "", "", time.Time{}, policyError("plan_capacity", "this Kubernetes identity has too many pending plan bytes")
	}
	expires := time.Now().Add(planTTL)
	s.plans[id] = storedPlan{
		Operation: operation, SubjectKey: subject, ExpiresAt: expires, Size: size,
		ConfirmationHash: confirmationHash(id, confirmationCode),
	}
	s.usedBytes += size
	s.subjectBytes[subject] += size
	return id, confirmationCode, expires, nil
}

func (s *PlanStore) Consume(id, subject, confirmationCode string) (Operation, error) {
	if confirmationCode == "" {
		return Operation{}, policyError("confirmation_required", "a human confirmation code is required")
	}
	if !validConfirmationCode(confirmationCode) {
		return Operation{}, policyError("invalid_confirmation", "confirmation code must be exactly six digits")
	}

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
	expected := confirmationHash(id, confirmationCode)
	if subtle.ConstantTimeCompare(plan.ConfirmationHash[:], expected[:]) != 1 {
		plan.ConfirmationFailures++
		if plan.ConfirmationFailures >= confirmationMaxAttempts {
			s.delete(id, plan)
			return Operation{}, policyError("confirmation_locked", "too many incorrect confirmation attempts; create a new plan")
		}
		s.plans[id] = plan
		return Operation{}, policyError("invalid_confirmation", "confirmation code is incorrect")
	}
	s.delete(id, plan)
	return plan.Operation, nil
}

func randomPlanID() (string, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate plan ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func randomConfirmationCode() (string, error) {
	random, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", fmt.Errorf("generate confirmation code: %w", err)
	}
	return strconv.FormatInt(random.Int64()+100000, 10), nil
}

func validConfirmationCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func confirmationHash(planID, code string) [sha256.Size]byte {
	return sha256.Sum256([]byte(planID + "\x00" + code))
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

func (s *PlanStore) isRemote(id, subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	plan, ok := s.plans[id]
	return ok && plan.SubjectKey == subject && (plan.Operation.Action.Action == "exec" || plan.Operation.Action.Action == "attach")
}
