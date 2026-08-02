package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
	"github.com/samuelsupe/supek8smcp/internal/runtimeconfig"
)

func TestAuditOutcomeClassifiesStableReasons(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name         string
		err          error
		wantDecision string
		wantReason   string
	}{
		{name: "success", wantDecision: "allow", wantReason: "success"},
		{name: "policy denial", err: policyError("policy_denied", "outside policy"), wantDecision: "deny", wantReason: "policy_denied"},
		{name: "tool denial", err: &toolError{Reason: "unsafe_payload", Message: "payload rejected"}, wantDecision: "deny", wantReason: "unsafe_payload"},
		{name: "kubernetes forbidden", err: apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "web", errors.New("rbac denied")), wantDecision: "deny", wantReason: "kubernetes_forbidden"},
		{name: "wrapped timeout", err: fmt.Errorf("request failed: %w", context.DeadlineExceeded), wantDecision: "error", wantReason: "deadline_exceeded"},
		{name: "unknown error", err: errors.New("unexpected backend failure"), wantDecision: "error", wantReason: "internal_error"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gotDecision, gotReason := auditOutcome(tt.err)
			if gotDecision != tt.wantDecision || gotReason != tt.wantReason {
				t.Fatalf("auditOutcome(%v) = (%q, %q), want (%q, %q)", tt.err, gotDecision, gotReason, tt.wantDecision, tt.wantReason)
			}
		})
	}
}

type auditCaptureHandler struct {
	mu      sync.Mutex
	records []map[string]any
}

func (h *auditCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *auditCaptureHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := map[string]any{
		"message": record.Message,
		"level":   record.Level.String(),
	}
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, attrs)
	h.mu.Unlock()
	return nil
}

func (h *auditCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *auditCaptureHandler) WithGroup(string) slog.Handler { return h }

func (h *auditCaptureHandler) latest() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == 0 {
		return nil
	}
	return h.records[len(h.records)-1]
}

func newAuditTestApp(logger *slog.Logger) *App {
	toolCalls := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_audit_tool_calls_total"}, []string{"tool", "result"})
	toolDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_audit_tool_duration_seconds"}, []string{"tool"})
	authenticationAttempts := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_audit_authentication_attempts_total"}, []string{"decision", "reason"})
	rateLimitRejections := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_audit_rate_limit_rejections_total"}, []string{"reason"})
	auditEvents := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_audit_events_total"}, []string{"event", "tool", "decision", "reason"})
	return &App{
		config: runtimeconfig.Config{
			Name: "demo", Namespace: "mcp-system",
			Spec: mcpv1alpha1.KubernetesMCPServerSpec{Mode: mcpv1alpha1.ModeReadOnly},
		},
		logger:                 logger,
		toolCalls:              toolCalls,
		toolDuration:           toolDuration,
		authenticationAttempts: authenticationAttempts,
		rateLimitRejections:    rateLimitRejections,
		auditEvents:            auditEvents,
	}
}

func TestRecordToolAuditIncludesContextWithoutSensitivePayloads(t *testing.T) {
	t.Parallel()

	handler := &auditCaptureHandler{}
	app := newAuditTestApp(slog.New(handler))
	principal := &Principal{
		Username: "alice", UID: "uid-42", Groups: []string{"team-readers"},
		Token: "token-should-never-be-logged",
	}
	target := auditTarget{
		Action: "patch", APIGroup: "apps", APIVersion: "v1", Resource: "deployments",
		Namespace: "workloads", Name: "web",
	}
	sensitive := "token-should-never-be-logged plan-id-123 confirmation-code-654321 resource-object patch-body command stdin output-content"
	app.recordTool(principal, "k8s.commit", target, time.Now().Add(-time.Millisecond), &toolError{Reason: "policy_denied", Message: sensitive})

	record := handler.latest()
	if record == nil {
		t.Fatal("recordTool() emitted no audit log")
	}
	want := map[string]any{
		"audit_schema":     auditSchemaVersion,
		"actor_username":   "alice",
		"actor_uid":        "uid-42",
		"tool":             "k8s.commit",
		"action":           "patch",
		"api_group":        "apps",
		"api_version":      "v1",
		"resource":         "deployments",
		"target_namespace": "workloads",
		"target_name":      "web",
		"decision":         "deny",
		"reason":           "policy_denied",
	}
	for key, value := range want {
		if got := record[key]; got != value {
			t.Fatalf("audit attribute %q = %#v, want %#v; record=%#v", key, got, value, record)
		}
	}
	if subject, ok := record["actor_subject"].(string); !ok || subject == "" {
		t.Fatalf("actor_subject = %#v, want non-empty string", record["actor_subject"])
	}

	serialized := fmt.Sprint(record)
	for _, forbidden := range strings.Fields(sensitive) {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("audit record contains sensitive payload %q: %s", forbidden, serialized)
		}
	}
	for _, forbiddenKey := range []string{"token", "plan_id", "planId", "confirmation_code", "confirmationCode", "object", "patch_body", "command", "stdin", "output"} {
		if _, ok := record[forbiddenKey]; ok {
			t.Fatalf("audit record unexpectedly contains sensitive field %q: %#v", forbiddenKey, record)
		}
	}
}
