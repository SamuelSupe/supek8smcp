package server

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const auditSchemaVersion = "v1"

type auditTarget struct {
	Action     string
	APIGroup   string
	APIVersion string
	Resource   string
	Namespace  string
	Name       string
	Streaming  bool
}

func (a *App) recordAuthentication(principal *Principal, decision, reason string, started time.Time) {
	a.authenticationAttempts.WithLabelValues(decision, reason).Inc()
	a.auditEvents.WithLabelValues("authentication", "", decision, reason).Inc()
	a.emitAudit(principal, "authentication", "", auditTarget{}, decision, reason, time.Since(started))
}

func (a *App) recordTool(principal *Principal, tool string, target auditTarget, started time.Time, err error) {
	decision, reason := auditOutcome(err)
	result := "ok"
	if decision == "deny" {
		result = "denied"
	} else if err != nil {
		result = "error"
	}
	a.toolCalls.WithLabelValues(tool, result).Inc()
	a.toolDuration.WithLabelValues(tool).Observe(time.Since(started).Seconds())
	a.auditEvents.WithLabelValues("tool_call", tool, decision, reason).Inc()
	a.emitAudit(principal, "tool_call", tool, target, decision, reason, time.Since(started))
}

func (a *App) recordRateLimit(principal *Principal, reason string, started time.Time) {
	a.rateLimitRejections.WithLabelValues(reason).Inc()
	a.auditEvents.WithLabelValues("request", "", "deny", "rate_limited").Inc()
	a.emitAudit(principal, "request", "", auditTarget{}, "deny", "rate_limited", time.Since(started),
		slog.String("rate_limit_reason", reason))
}

func (a *App) emitAudit(
	principal *Principal,
	event, tool string,
	target auditTarget,
	decision, reason string,
	duration time.Duration,
	extra ...slog.Attr,
) {
	attributes := []slog.Attr{
		slog.String("audit_schema", auditSchemaVersion),
		slog.String("event", event),
		slog.String("decision", decision),
		slog.String("reason", reason),
		slog.String("server_namespace", a.config.Namespace),
		slog.String("server_name", a.config.Name),
		slog.String("mode", string(a.config.Spec.Mode)),
		slog.Int64("duration_ms", duration.Milliseconds()),
	}
	if principal != nil {
		subject := principal.IdentityKey()
		if len(subject) > 16 {
			subject = subject[:16]
		}
		attributes = append(attributes,
			slog.String("actor_username", principal.Username),
			slog.String("actor_uid", principal.UID),
			slog.String("actor_subject", subject),
		)
	}
	if tool != "" {
		attributes = append(attributes, slog.String("tool", tool))
	}
	if target.Action != "" {
		attributes = append(attributes, slog.String("action", target.Action))
	}
	if target.APIGroup != "" {
		attributes = append(attributes, slog.String("api_group", target.APIGroup))
	}
	if target.APIVersion != "" {
		attributes = append(attributes, slog.String("api_version", target.APIVersion))
	}
	if target.Resource != "" {
		attributes = append(attributes, slog.String("resource", target.Resource))
	}
	if target.Namespace != "" {
		attributes = append(attributes, slog.String("target_namespace", target.Namespace))
	}
	if target.Name != "" {
		attributes = append(attributes, slog.String("target_name", target.Name))
	}
	if target.Streaming {
		attributes = append(attributes, slog.Bool("streaming", true))
	}
	attributes = append(attributes, extra...)
	a.logger.LogAttrs(context.Background(), slog.LevelInfo, "MCP security audit", attributes...)
}

func auditOutcome(err error) (string, string) {
	if err == nil {
		return "allow", "success"
	}
	var toolErr *toolError
	if errors.As(err, &toolErr) {
		if toolErr.Reason == "plan_capacity" || toolErr.Reason == "unsupported_operation" {
			return "error", toolErr.Reason
		}
		return "deny", toolErr.Reason
	}
	switch {
	case apierrors.IsForbidden(err):
		return "deny", "kubernetes_forbidden"
	case apierrors.IsUnauthorized(err):
		return "deny", "kubernetes_unauthorized"
	case apierrors.IsConflict(err):
		return "error", "kubernetes_conflict"
	case apierrors.IsNotFound(err):
		return "error", "kubernetes_not_found"
	case apierrors.IsTooManyRequests(err):
		return "error", "kubernetes_throttled"
	case apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err):
		return "error", "kubernetes_timeout"
	case apierrors.IsServiceUnavailable(err):
		return "error", "kubernetes_unavailable"
	case errors.Is(err, context.DeadlineExceeded):
		return "error", "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "error", "canceled"
	default:
		return "error", "internal_error"
	}
}

func (a *App) auditTargetForCapability(id, namespace, name string) auditTarget {
	capability, err := a.capabilities.decode(id)
	if err != nil {
		return auditTarget{Namespace: namespace, Name: name}
	}
	if namespace == "" {
		namespace = a.defaultNamespace(capability, namespace)
	}
	resource := capability.Resource
	if capability.Subresource != "" {
		resource += "/" + capability.Subresource
	}
	return auditTarget{
		Action: capability.Action, APIGroup: capability.Group, APIVersion: capability.Version,
		Resource: resource, Namespace: namespace, Name: name,
	}
}

func (a *App) auditTargetForPlan(input PlanInput) auditTarget {
	name := input.Name
	if name == "" && input.Object != nil {
		name, _, _ = unstructured.NestedString(input.Object, "metadata", "name")
	}
	return a.auditTargetForCapability(input.CapabilityID, input.Namespace, name)
}

func auditTargetFromSummary(summary map[string]any) auditTarget {
	return auditTarget{
		Action: stringValue(summary, "action"), APIGroup: stringValue(summary, "group"),
		APIVersion: stringValue(summary, "version"), Resource: stringValue(summary, "resource"),
		Namespace: stringValue(summary, "namespace"), Name: stringValue(summary, "name"),
	}
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}
