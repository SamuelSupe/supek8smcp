package server

import (
	"context"
	"fmt"
	"slices"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
	"github.com/samuelsupe/supek8smcp/internal/runtimeconfig"
)

type Action struct {
	GVR         schema.GroupVersionResource `json:"-"`
	Kind        string                      `json:"kind"`
	Subresource string                      `json:"subresource,omitempty"`
	Verb        string                      `json:"verb"`
	Action      string                      `json:"action"`
	Namespaced  bool                        `json:"namespaced"`
}

func (a Action) ResourceName() string {
	if a.Subresource == "" {
		return a.GVR.Resource
	}
	return a.GVR.Resource + "/" + a.Subresource
}

func (a Action) Mutating() bool {
	return !slices.Contains([]string{"get", "list", "watch"}, a.Verb)
}

func (a Action) Dangerous() bool {
	return a.Action == "delete" || a.Action == "exec" || a.Action == "attach" || a.Action == "force-apply"
}

type Policy struct {
	config runtimeconfig.Config
}

func NewPolicy(config runtimeconfig.Config) *Policy {
	return &Policy{config: config}
}

func (p *Policy) Check(action Action, namespace string) error {
	if !action.Mutating() && action.GVR.Group == "" && action.GVR.Resource == "secrets" &&
		p.config.Spec.Policy.SensitiveReads == mcpv1alpha1.SensitiveReadDeny {
		return policyError("sensitive_read_denied", "Secret reads are disabled by policy")
	}
	if action.Namespaced {
		if namespace == "" {
			return policyError("scope_denied", "namespace is required for namespaced resources")
		}
		if !slices.Contains(p.config.Spec.Scope.Namespaces, namespace) {
			return policyError("scope_denied", fmt.Sprintf("namespace %q is outside the MCP server scope", namespace))
		}
	} else if action.Mutating() {
		if !p.config.Spec.Scope.AllowClusterScopedWrite {
			return policyError("scope_denied", "cluster-scoped writes are disabled")
		}
	} else if !p.config.Spec.Scope.AllowClusterScopedRead {
		return policyError("scope_denied", "cluster-scoped reads are disabled")
	}

	mode := p.config.Spec.Mode
	if mode == mcpv1alpha1.ModeReadOnly && action.Mutating() {
		return policyError("mode_denied", "ReadOnly mode does not permit writes")
	}
	if mode == mcpv1alpha1.ModeSafeWrite {
		if action.Dangerous() || slices.Contains([]string{"delete", "deletecollection"}, action.Verb) {
			return policyError("mode_denied", "operation requires Dangerous mode")
		}
		if hardDeniedInSafeMode(action) {
			return policyError("mode_denied", fmt.Sprintf("%s is blocked in SafeWrite mode", action.ResourceName()))
		}
	}
	if len(p.config.Spec.Policy.Rules) > 0 {
		if !matchesAnyRule(p.config.Spec.Policy.Rules, action) {
			return policyError("policy_denied", "operation is outside policy.rules")
		}
	} else if mode == mcpv1alpha1.ModeSafeWrite && action.Mutating() && !safeDefaultResource(action) {
		return policyError("policy_denied", "resource is not in the SafeWrite default allowlist")
	}
	return nil
}

func (p *Policy) Authorize(ctx context.Context, principal *Principal, action Action, namespace, name string) error {
	review, err := principal.Kubernetes.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
			Group:       action.GVR.Group,
			Version:     action.GVR.Version,
			Resource:    action.GVR.Resource,
			Subresource: action.Subresource,
			Verb:        action.Verb,
			Namespace:   namespace,
			Name:        name,
		}}}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("SelfSubjectAccessReview failed: %w", err)
	}
	if !review.Status.Allowed {
		reason := review.Status.Reason
		if reason == "" {
			reason = "Kubernetes RBAC denied the operation"
		}
		return policyError("rbac_denied", reason)
	}
	return nil
}

func (p *Policy) CheckAndAuthorize(ctx context.Context, principal *Principal, action Action, namespace, name string) error {
	if err := p.Check(action, namespace); err != nil {
		return err
	}
	return p.Authorize(ctx, principal, action, namespace, name)
}

func matchesAnyRule(rules []mcpv1alpha1.CapabilityRule, action Action) bool {
	for _, rule := range rules {
		verbMatches := match(rule.Verbs, action.Verb) || match(rule.Verbs, action.Action)
		if match(rule.APIGroups, action.GVR.Group) && match(rule.Resources, action.ResourceName()) && verbMatches {
			return true
		}
	}
	return false
}

func match(values []string, wanted string) bool {
	return slices.Contains(values, "*") || slices.Contains(values, wanted)
}

func safeDefaultResource(action Action) bool {
	key := action.GVR.Group + "/" + action.GVR.Resource
	switch key {
	case "/configmaps", "/services",
		"apps/deployments", "apps/statefulsets", "apps/daemonsets",
		"batch/jobs", "batch/cronjobs",
		"autoscaling/horizontalpodautoscalers", "policy/poddisruptionbudgets":
		return true
	default:
		return false
	}
}

func hardDeniedInSafeMode(action Action) bool {
	resource := action.GVR.Resource
	if action.Subresource != "" && action.Subresource != "status" && action.Subresource != "scale" {
		return true
	}
	if slices.Contains([]string{
		"secrets", "serviceaccounts", "roles", "rolebindings", "clusterroles", "clusterrolebindings",
		"customresourcedefinitions", "mutatingwebhookconfigurations", "validatingwebhookconfigurations",
		"apiservices", "certificatesigningrequests", "tokenreviews", "subjectaccessreviews", "selfsubjectaccessreviews",
		"namespaces", "nodes", "persistentvolumes", "storageclasses", "priorityclasses", "runtimeclasses",
	}, resource) {
		return true
	}
	return slices.Contains([]string{
		"rbac.authorization.k8s.io", "admissionregistration.k8s.io", "apiextensions.k8s.io",
		"apiregistration.k8s.io", "certificates.k8s.io", "authentication.k8s.io", "authorization.k8s.io",
	}, action.GVR.Group)
}

type toolError struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (e *toolError) Error() string { return e.Reason + ": " + e.Message }

func policyError(reason, message string) error {
	return &toolError{Reason: reason, Message: message}
}
