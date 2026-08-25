package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
	"github.com/samuelsupe/supek8smcp/internal/runtimeconfig"
)

func policyTestConfig(mode mcpv1alpha1.AccessMode, sensitive mcpv1alpha1.SensitiveReadPolicy) runtimeconfig.Config {
	return runtimeconfig.Config{
		Name: "demo", Namespace: "mcp-system",
		Spec: mcpv1alpha1.KubernetesMCPServerSpec{
			Mode:   mode,
			Scope:  mcpv1alpha1.ScopeSpec{Namespaces: []string{"workloads"}},
			Policy: mcpv1alpha1.PolicySpec{SensitiveReads: sensitive},
			Limits: mcpv1alpha1.LimitsSpec{
				RequestTimeout: metav1.Duration{Duration: 30},
				StreamTimeout:  metav1.Duration{Duration: 60},
				ExecTimeout:    metav1.Duration{Duration: 30},
				MaxInputBytes:  1 << 10, MaxOutputBytes: 1 << 10, MaxListItems: 1, MaxConcurrent: 1,
			},
		},
	}
}

func managedTargetPolicyTestConfig() runtimeconfig.Config {
	cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Scope.Namespaces = []string{cfg.Namespace, "other-namespace"}
	cfg.Spec.Scope.AllowClusterScopedRead = true
	cfg.Spec.Scope.AllowClusterScopedWrite = true
	cfg.Spec.Policy.Rules = []mcpv1alpha1.CapabilityRule{{
		APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
	}}
	return cfg
}

func policyTestAction(group, resource, verb, action string, namespaced bool) Action {
	return Action{
		GVR:  schema.GroupVersionResource{Group: group, Version: "v1", Resource: resource},
		Kind: resource, Verb: verb, Action: action, Namespaced: namespaced,
	}
}

func policyReason(err error) string {
	if err == nil {
		return ""
	}
	if tool, ok := err.(*toolError); ok {
		return tool.Reason
	}
	return err.Error()
}

func TestPolicyModesScopesAndSafeWriteDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config runtimeconfig.Config
		action Action
		ns     string
		want   string
	}{
		{
			name:   "read only allows scoped read",
			config: policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "pods", "get", "get", true), ns: "workloads",
		},
		{
			name:   "namespace outside scope is denied",
			config: policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "pods", "get", "get", true), ns: "other",
			want: "scope_denied",
		},
		{
			name:   "cluster read requires explicit scope",
			config: policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "nodes", "list", "list", false),
			want:   "scope_denied",
		},
		{
			name: "cluster read can be enabled independently",
			config: func() runtimeconfig.Config {
				cfg := policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact)
				cfg.Spec.Scope.AllowClusterScopedRead = true
				return cfg
			}(),
			action: policyTestAction("", "nodes", "list", "list", false),
		},
		{
			name:   "read only rejects mutation",
			config: policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "configmaps", "create", "create", true), ns: "workloads",
			want: "mode_denied",
		},
		{
			name:   "safe write allows default configmap mutation",
			config: policyTestConfig(mcpv1alpha1.ModeSafeWrite, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "configmaps", "patch", "patch", true), ns: "workloads",
		},
		{
			name:   "safe write rejects unlisted pod mutation",
			config: policyTestConfig(mcpv1alpha1.ModeSafeWrite, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "pods", "patch", "patch", true), ns: "workloads",
			want: "policy_denied",
		},
		{
			name:   "safe write rejects delete as dangerous",
			config: policyTestConfig(mcpv1alpha1.ModeSafeWrite, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "services", "delete", "delete", true), ns: "workloads",
			want: "mode_denied",
		},
		{
			name:   "safe write hard denies service account mutation",
			config: policyTestConfig(mcpv1alpha1.ModeSafeWrite, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "serviceaccounts", "patch", "patch", true), ns: "workloads",
			want: "mode_denied",
		},
		{
			name: "dangerous allows cluster write only with explicit scope",
			config: func() runtimeconfig.Config {
				cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadRedact)
				cfg.Spec.Scope.AllowClusterScopedWrite = true
				return cfg
			}(),
			action: policyTestAction("", "nodes", "patch", "patch", false),
		},
		{
			name:   "dangerous cluster write remains denied by scope",
			config: policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadRedact),
			action: policyTestAction("", "nodes", "patch", "patch", false),
			want:   "scope_denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewPolicy(tt.config).Check(tt.action, tt.ns)
			if got := policyReason(err); got != tt.want {
				t.Fatalf("Check() reason = %q, want %q (error: %v)", got, tt.want, err)
			}
		})
	}
}

func TestPolicyOperationRequiresBaseResourceGet(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	var reviewedVerbs []string
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		reviewedVerbs = append(reviewedVerbs, review.Spec.ResourceAttributes.Verb)
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Policy.Rules = []mcpv1alpha1.CapabilityRule{{
		APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"patch"},
	}}
	action := policyTestAction("", "configmaps", "patch", "patch", true)
	err := NewPolicy(cfg).CheckAndAuthorizeOperation(
		context.Background(), &Principal{Kubernetes: client}, action, "workloads", "settings",
	)
	if got := policyReason(err); got != "policy_denied" {
		t.Fatalf("CheckAndAuthorizeOperation() reason = %q, want policy_denied (error: %v)", got, err)
	}
	if len(reviewedVerbs) != 0 {
		t.Fatalf("reviewed verbs = %#v, want policy to reject the missing get prerequisite before RBAC checks", reviewedVerbs)
	}
}

func TestExecPreviewResolvesAndStoresDefaultContainer(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker", Namespace: "workloads", UID: "pod-uid", ResourceVersion: "7",
			Annotations: map[string]string{"kubectl.kubernetes.io/default-container": "sidecar"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main"}, {Name: "sidecar"}}},
	}
	operation := Operation{
		Action: Action{
			GVR: schema.GroupVersionResource{Version: "v1", Resource: "pods"}, Kind: "Pod",
			Subresource: "exec", Verb: "create", Action: "exec", Namespaced: true,
		},
		Namespace: "workloads", Name: "worker", Command: []string{"true"},
	}
	app := &App{config: policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)}
	principal := &Principal{
		Kubernetes: k8sfake.NewSimpleClientset(pod),
		Dynamic:    dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
	}
	preview, _, err := app.previewOperation(context.Background(), principal, &operation)
	if err != nil {
		t.Fatalf("previewOperation(exec) error = %v", err)
	}
	if operation.Container != "sidecar" {
		t.Fatalf("planned container = %q, want annotated default sidecar", operation.Container)
	}
	if got := preview.(map[string]any)["container"]; got != "sidecar" {
		t.Fatalf("preview container = %#v, want sidecar", got)
	}
}

func TestNamedListReadAddsResourceNameFieldSelector(t *testing.T) {
	t.Parallel()

	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{{Version: "v1", Resource: "pods"}: "PodList"},
	)
	var capturedSelector string
	dynamicClient.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		capturedSelector = action.(k8stesting.ListAction).GetListRestrictions().Fields.String()
		return true, &unstructured.UnstructuredList{}, nil
	})
	kubernetesClient := k8sfake.NewSimpleClientset()
	kubernetesClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	capability := capabilityFromAction(codec, policyTestAction("", "pods", "list", "list", true), nil)
	cfg := policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact)
	app := &App{config: cfg, policy: NewPolicy(cfg), capabilities: codec}
	_, err = app.read(context.Background(), nil, &Principal{Dynamic: dynamicClient, Kubernetes: kubernetesClient}, ReadInput{
		CapabilityID: capability.ID, Namespace: "workloads", Name: "worker", FieldSelector: "status.phase=Running",
	})
	if err != nil {
		t.Fatalf("read(named list) error = %v", err)
	}
	selector, err := fields.ParseSelector(capturedSelector)
	if err != nil {
		t.Fatalf("captured field selector %q is invalid: %v", capturedSelector, err)
	}
	if name, exact := selector.RequiresExactMatch("metadata.name"); !exact || name != "worker" {
		t.Fatalf("captured field selector = %q, want exact metadata.name=worker", capturedSelector)
	}
	if got, err := namedFieldSelector("", "worker"); err != nil || got != "metadata.name=worker" {
		t.Fatalf("empty named field selector = %q, %v, want metadata.name=worker", got, err)
	}
	if _, err := namedFieldSelector("metadata.name=other", "worker"); policyReason(err) != "invalid_input" {
		t.Fatalf("conflicting named field selector error = %v, want invalid_input", err)
	}
}

func TestPolicyDeniesSecretReads(t *testing.T) {
	t.Parallel()

	action := policyTestAction("", "secrets", "get", "get", true)
	for _, policy := range []mcpv1alpha1.SensitiveReadPolicy{mcpv1alpha1.SensitiveReadDeny, mcpv1alpha1.SensitiveReadRedact} {
		policy := policy
		t.Run(string(policy), func(t *testing.T) {
			cfg := policyTestConfig(mcpv1alpha1.ModeReadOnly, policy)
			err := NewPolicy(cfg).Check(action, "workloads")
			if policy == mcpv1alpha1.SensitiveReadDeny {
				if got := policyReason(err); got != "sensitive_read_denied" {
					t.Fatalf("Check() reason = %q, want sensitive_read_denied", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("redacted secret read rejected: %v", err)
			}
		})
	}
}

func TestPolicyCheckTargetProtectsManagedControlPlaneResources(t *testing.T) {
	t.Parallel()

	cfg := managedTargetPolicyTestConfig()
	policy := NewPolicy(cfg)
	tests := []struct {
		name           string
		action         Action
		namespace      string
		managedNames   []string
		nonManagedName string
	}{
		{
			name: "configmaps", action: policyTestAction("", "configmaps", "patch", "patch", true), namespace: cfg.Namespace,
			managedNames: []string{cfg.Name + "-config", cfg.Name + "-ca"}, nonManagedName: "other-config",
		},
		{
			name: "secrets", action: policyTestAction("", "secrets", "patch", "patch", true), namespace: cfg.Namespace,
			managedNames: []string{cfg.Name + "-tls", "supek8smcp-serving-ca"}, nonManagedName: "other-secret",
		},
		{
			name: "deployments", action: policyTestAction("apps", "deployments", "patch", "patch", true), namespace: cfg.Namespace,
			managedNames: []string{cfg.Name}, nonManagedName: "other-deployment",
		},
		{
			name: "services", action: policyTestAction("", "services", "patch", "patch", true), namespace: cfg.Namespace,
			managedNames: []string{cfg.Name}, nonManagedName: "other-service",
		},
		{
			name: "serviceaccounts", action: policyTestAction("", "serviceaccounts", "patch", "patch", true), namespace: cfg.Namespace,
			managedNames: []string{cfg.Name}, nonManagedName: "other-serviceaccount",
		},
		{
			name: "networkpolicies", action: policyTestAction("networking.k8s.io", "networkpolicies", "patch", "patch", true), namespace: cfg.Namespace,
			managedNames: []string{cfg.Name}, nonManagedName: "other-networkpolicy",
		},
		{
			name: "MCP servers", action: policyTestAction("mcp.supek8smcp.io", "kubernetesmcpservers", "patch", "patch", true), namespace: cfg.Namespace,
			managedNames: []string{cfg.Name, "other-instance"},
		},
		{
			name: "clusterroles", action: policyTestAction("rbac.authorization.k8s.io", "clusterroles", "patch", "patch", false),
			managedNames: []string{"supek8smcp-tokenreviewer"}, nonManagedName: "other-clusterrole",
		},
		{
			name: "clusterrolebindings", action: policyTestAction("rbac.authorization.k8s.io", "clusterrolebindings", "patch", "patch", false),
			managedNames: []string{managedClusterBindingName(cfg.Namespace, cfg.Name)}, nonManagedName: "other-binding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range tt.managedNames {
				if got := policyReason(policy.CheckTarget(tt.action, tt.namespace, name)); got != "managed_resource_denied" {
					t.Errorf("CheckTarget(%q mutation) reason = %q, want managed_resource_denied", name, got)
				}
				read := tt.action
				read.Verb, read.Action = "get", "get"
				if err := policy.CheckTarget(read, tt.namespace, name); err != nil {
					t.Errorf("CheckTarget(%q read) error = %v, want read allowed", name, err)
				}
			}
			if tt.nonManagedName != "" {
				if err := policy.CheckTarget(tt.action, tt.namespace, tt.nonManagedName); err != nil {
					t.Errorf("CheckTarget(%q non-managed mutation) error = %v, want allowed", tt.nonManagedName, err)
				}
			}
		})
	}

	secretAction := policyTestAction("", "secrets", "patch", "patch", true)
	if got := policyReason(policy.CheckTarget(secretAction, "other-namespace", "supek8smcp-serving-ca")); got != "managed_resource_denied" {
		t.Fatalf("cross-namespace serving CA mutation reason = %q, want managed_resource_denied", got)
	}
}

func TestPreviewOperationRejectsOperatorManagedLabelButAllowsUnmanagedDryRun(t *testing.T) {
	t.Parallel()

	action := policyTestAction("", "configmaps", "patch", "patch", true)
	for _, tt := range []struct {
		name              string
		managedByOperator bool
	}{
		{name: "operator managed", managedByOperator: true},
		{name: "unmanaged", managedByOperator: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			labels := map[string]any{"app": "demo"}
			if tt.managedByOperator {
				labels["app.kubernetes.io/managed-by"] = "supek8smcp-operator"
			}
			object := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1", "kind": "ConfigMap",
				"metadata": map[string]any{
					"name": "target", "namespace": "mcp-system", "resourceVersion": "7", "uid": "uid-1", "labels": labels,
				},
				"data": map[string]any{"key": "value"},
			}}
			dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), object)
			principal := &Principal{Dynamic: dynamicClient}
			app := &App{config: runtimeconfig.Config{Spec: mcpv1alpha1.KubernetesMCPServerSpec{Policy: mcpv1alpha1.PolicySpec{SensitiveReads: mcpv1alpha1.SensitiveReadAllow}, Limits: mcpv1alpha1.LimitsSpec{MaxOutputBytes: 1 << 20}}}}
			operation := &Operation{
				Action: action, Namespace: "mcp-system", Name: "target",
				Patch: map[string]any{"data": map[string]any{"key": "updated"}}, PatchType: "merge",
			}
			_, _, err := app.previewOperation(context.Background(), principal, operation)
			if tt.managedByOperator {
				if policyReason(err) != "managed_resource_denied" {
					t.Fatalf("previewOperation() reason = %q, want managed_resource_denied", policyReason(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("previewOperation() unmanaged error = %v, want dry-run allowed", err)
			}
		})
	}
}

func TestValidateSafeJSONPatchAndPayload(t *testing.T) {
	t.Parallel()

	if err := validateSafeJSONPatch([]any{
		map[string]any{"op": "test", "path": "/metadata/resourceVersion", "value": "7"},
		map[string]any{"op": "replace", "path": "/spec/replicas", "value": float64(2)},
	}); err != nil {
		t.Fatalf("safe JSON patch rejected: %v", err)
	}

	for _, path := range []string{
		"/spec/template/spec/containers/0/securityContext/privileged",
		"/spec/template/spec/serviceAccountName",
		"/spec/template/spec/containers/0/ports/0/hostPort",
	} {
		path := path
		t.Run("blocked patch "+path, func(t *testing.T) {
			err := validateSafeJSONPatch([]any{map[string]any{"op": "replace", "path": path, "value": true}})
			if got := policyReason(err); got != "unsafe_payload" {
				t.Fatalf("validateSafeJSONPatch() reason = %q, want unsafe_payload", got)
			}
		})
	}

	for _, tt := range []struct {
		name  string
		patch []any
	}{
		{
			name: "replace spec with hostNetwork",
			patch: []any{map[string]any{
				"op": "replace", "path": "/spec",
				"value": map[string]any{"hostNetwork": true},
			}},
		},
		{
			name: "replace securityContext with privileged",
			patch: []any{map[string]any{
				"op": "replace", "path": "/spec/template/spec/containers/0/securityContext",
				"value": map[string]any{"privileged": true},
			}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyReason(validateSafeJSONPatch(tt.patch)); got != "unsafe_payload" {
				t.Fatalf("validateSafeJSONPatch() reason = %q, want unsafe_payload", got)
			}
		})
	}

	for _, payload := range []map[string]any{
		{"spec": map[string]any{"hostNetwork": true}},
		{"spec": map[string]any{"serviceAccountName": "privileged"}},
		{"spec": map[string]any{"containers": []any{map[string]any{"securityContext": map[string]any{"runAsUser": float64(0)}}}}},
		{"spec": map[string]any{"containers": []any{map[string]any{"securityContext": map[string]any{"runAsNonRoot": false}}}}},
		{"spec": map[string]any{"containers": []any{map[string]any{"securityContext": map[string]any{"allowPrivilegeEscalation": true}}}}},
	} {
		payload := payload
		t.Run("blocked payload", func(t *testing.T) {
			if got := policyReason(validateSafePayload(payload)); got != "unsafe_payload" {
				t.Fatalf("validateSafePayload() reason = %q, want unsafe_payload", got)
			}
		})
	}
}

func TestValidateSafeOperationRejectsDirectSecurityJSONPatch(t *testing.T) {
	t.Parallel()

	action := policyTestAction("apps", "deployments", "patch", "patch", true)
	for _, tt := range []struct {
		name  string
		path  string
		value any
	}{
		{name: "disable runAsNonRoot", path: "/spec/template/spec/containers/0/securityContext/runAsNonRoot", value: false},
		{name: "select root user", path: "/spec/template/spec/containers/0/securityContext/runAsUser", value: float64(0)},
		{name: "unconfined seccomp", path: "/spec/template/spec/securityContext/seccompProfile/type", value: "Unconfined"},
		{name: "unconfined AppArmor", path: "/spec/template/spec/containers/0/securityContext/appArmorProfile/type", value: "Unconfined"},
		{name: "select critical priority class", path: "/spec/template/spec/priorityClassName", value: "system-cluster-critical"},
		{name: "select root fsGroup", path: "/spec/template/spec/securityContext/fsGroup", value: float64(0)},
		{name: "include root supplemental group", path: "/spec/template/spec/securityContext/supplementalGroups/0", value: float64(0)},
		{name: "select ContainerAdministrator", path: "/spec/template/spec/securityContext/windowsOptions/runAsUserName", value: "ContainerAdministrator"},
		{name: "select GMSA credential", path: "/spec/template/spec/securityContext/windowsOptions/gmsaCredentialSpecName", value: "gmsa"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			patch := []any{map[string]any{"op": "replace", "path": tt.path, "value": tt.value}}
			if got := policyReason(validateSafeOperation(action, nil, patch, "json")); got != "unsafe_payload" {
				t.Fatalf("validateSafeOperation() reason = %q, want unsafe_payload", got)
			}
		})
	}
}

func TestValidateSafePayloadRejectsWorkloadIdentityEscalation(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		payload map[string]any
	}{
		{name: "critical priority class", payload: map[string]any{"spec": map[string]any{"priorityClassName": "system-cluster-critical"}}},
		{name: "root fsGroup", payload: map[string]any{"spec": map[string]any{"securityContext": map[string]any{"fsGroup": float64(0)}}}},
		{name: "root supplemental group", payload: map[string]any{"spec": map[string]any{"securityContext": map[string]any{"supplementalGroups": []any{float64(0)}}}}},
		{name: "ContainerAdministrator", payload: map[string]any{"spec": map[string]any{"securityContext": map[string]any{"windowsOptions": map[string]any{"runAsUserName": "ContainerAdministrator"}}}}},
		{name: "GMSA credential", payload: map[string]any{"spec": map[string]any{"securityContext": map[string]any{"windowsOptions": map[string]any{"gmsaCredentialSpecName": "gmsa"}}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyReason(validateSafePayload(tt.payload)); got != "unsafe_payload" {
				t.Fatalf("validateSafePayload() reason = %q, want unsafe_payload", got)
			}
		})
	}
}

func TestValidateSafeTransitionProtectsExistingWorkloadSecurity(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "unchanged", want: ""},
		{
			name: "strengthened capability drop",
			mutate: func(after map[string]any) {
				container := after["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				securityContext := container["securityContext"].(map[string]any)
				securityContext["capabilities"].(map[string]any)["drop"] = []any{"ALL", "NET_RAW"}
			},
			want: "",
		},
		{
			name: "parent containers securityContext replacement",
			mutate: func(after map[string]any) {
				container := after["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				container["securityContext"] = map[string]any{"allowPrivilegeEscalation": false}
			},
			want: "unsafe_payload",
		},
		{
			name: "parent pod securityContext replacement",
			mutate: func(after map[string]any) {
				podSpec := after["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
				podSpec["securityContext"] = map[string]any{"runAsNonRoot": true}
			},
			want: "unsafe_payload",
		},
		{
			name: "parent replacement removes non-root fsGroup",
			mutate: func(after map[string]any) {
				podSpec := after["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
				podSpec["securityContext"] = map[string]any{
					"runAsNonRoot": true, "runAsUser": float64(65532),
					"windowsOptions": map[string]any{"runAsUserName": "ContainerUser"},
				}
			},
			want: "unsafe_payload",
		},
		{
			name: "parent replacement removes ContainerUser",
			mutate: func(after map[string]any) {
				podSpec := after["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
				podSpec["securityContext"] = map[string]any{
					"runAsNonRoot": true, "runAsUser": float64(65532), "fsGroup": float64(65532),
				}
			},
			want: "unsafe_payload",
		},
		{
			name: "update final object removes allowPrivilegeEscalation",
			mutate: func(after map[string]any) {
				container := after["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				delete(container["securityContext"].(map[string]any), "allowPrivilegeEscalation")
			},
			want: "unsafe_payload",
		},
		{
			name: "apply final object removes runAsNonRoot",
			mutate: func(after map[string]any) {
				container := after["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				delete(container["securityContext"].(map[string]any), "runAsNonRoot")
			},
			want: "unsafe_payload",
		},
		{
			name: "apply final object removes capabilities drop",
			mutate: func(after map[string]any) {
				container := after["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
				delete(container["securityContext"].(map[string]any)["capabilities"].(map[string]any), "drop")
			},
			want: "unsafe_payload",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := safeTransitionWorkloadObject()
			after := safeTransitionWorkloadObject()
			if tt.mutate != nil {
				tt.mutate(after)
			}
			if got := policyReason(validateSafeTransition(before, after)); got != tt.want {
				t.Fatalf("validateSafeTransition() reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSafeWriteDryRunRejectsOrdinaryPatchOnRiskyWorkload(t *testing.T) {
	t.Parallel()

	action := policyTestAction("apps", "deployments", "patch", "patch", true)
	patch := []any{
		map[string]any{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "example/server:v2"},
		map[string]any{"op": "replace", "path": "/spec/template/spec/containers/0/command", "value": []any{"server", "--safe"}},
	}
	if err := validateSafeOperation(action, nil, patch, "json"); err != nil {
		t.Fatalf("ordinary image/command patch rejected before dry-run: %v", err)
	}

	for _, tt := range []struct {
		name      string
		mutate    func(map[string]any)
		wantField string
	}{
		{
			name:      "non-default service account",
			wantField: "serviceAccountName",
			mutate: func(podSpec map[string]any) {
				podSpec["serviceAccountName"] = "workload-admin"
			},
		},
		{
			name:      "Secret volume",
			wantField: "secret",
			mutate: func(podSpec map[string]any) {
				podSpec["volumes"] = []any{map[string]any{
					"name": "credentials", "secret": map[string]any{"secretName": "database-credentials"},
				}}
			},
		},
		{
			name:      "hostPath volume",
			wantField: "hostPath",
			mutate: func(podSpec map[string]any) {
				podSpec["volumes"] = []any{map[string]any{
					"name": "host", "hostPath": map[string]any{"path": "/etc"},
				}}
			},
		},
		{
			name:      "privileged container",
			wantField: "privileged",
			mutate: func(podSpec map[string]any) {
				podSpec["containers"].([]any)[0].(map[string]any)["securityContext"] = map[string]any{"privileged": true}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			podSpec := map[string]any{
				"containers": []any{map[string]any{
					"name": "server", "image": "example/server:v1", "command": []any{"server", "--old"},
				}},
			}
			tt.mutate(podSpec)
			object := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "apps/v1", "kind": "Deployment",
				"metadata": map[string]any{"name": "server", "namespace": "workloads", "resourceVersion": "7", "uid": "uid-server"},
				"spec": map[string]any{
					"replicas": float64(1),
					"selector": map[string]any{"matchLabels": map[string]any{"app": "server"}},
					"template": map[string]any{
						"metadata": map[string]any{"labels": map[string]any{"app": "server"}},
						"spec":     podSpec,
					},
				},
			}}
			principal := &Principal{Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), object)}
			app := &App{config: policyTestConfig(mcpv1alpha1.ModeSafeWrite, mcpv1alpha1.SensitiveReadAllow)}
			operation := &Operation{
				Action: action, Namespace: "workloads", Name: "server",
				Patch: patch, PatchType: "json",
			}
			_, _, err := app.previewOperation(context.Background(), principal, operation)
			if policyReason(err) != "unsafe_payload" {
				t.Fatalf("previewOperation() reason = %q, want unsafe_payload (error: %v)", policyReason(err), err)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Fatalf("previewOperation() error = %q, want field %q", err, tt.wantField)
			}
		})
	}
}

func TestSafeWriteCommitRevalidatesRiskyWorkloadDryRun(t *testing.T) {
	t.Parallel()

	action := policyTestAction("apps", "deployments", "patch", "patch", true)
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "server", "namespace": "workloads", "resourceVersion": "7", "uid": "uid-server"},
		"spec": map[string]any{
			"replicas": float64(1),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "server"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "server"}},
				"spec": map[string]any{
					"serviceAccountName": "workload-admin",
					"containers": []any{map[string]any{
						"name": "server", "image": "example/server:v1", "command": []any{"server", "--old"},
						"securityContext": map[string]any{"privileged": true},
					}},
					"volumes": []any{map[string]any{
						"name": "credentials", "secret": map[string]any{"secretName": "database-credentials"},
					}},
				},
			},
		},
	}}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), object)
	kubernetesClient := k8sfake.NewSimpleClientset()
	kubernetesClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	principal := &Principal{Dynamic: dynamicClient, Kubernetes: kubernetesClient}
	cfg := policyTestConfig(mcpv1alpha1.ModeSafeWrite, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Limits.RequestTimeout = metav1.Duration{Duration: time.Minute}
	app := &App{config: cfg, policy: NewPolicy(cfg), plans: NewPlanStore(4)}
	operation := Operation{
		Action: action, Namespace: "workloads", Name: "server", Generation: cfg.Generation,
		Patch: []any{
			map[string]any{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "example/server:v2"},
			map[string]any{"op": "replace", "path": "/spec/template/spec/containers/0/command", "value": []any{"server", "--safe"}},
		}, PatchType: "json",
	}
	planID, confirmationCode, _, err := app.plans.Create(principal.SubjectKey(), operation)
	if err != nil {
		t.Fatalf("plans.Create() error = %v", err)
	}
	if _, err := app.commit(context.Background(), nil, principal, CommitInput{PlanID: planID}); policyReason(err) != "confirmation_required" {
		t.Fatalf("commit() without confirmation error = %q, want confirmation_required", err)
	}
	if _, err := app.commit(context.Background(), nil, principal, CommitInput{PlanID: planID, ConfirmationCode: confirmationCode}); policyReason(err) != "unsafe_payload" {
		t.Fatalf("commit() with confirmation error = %q, want unsafe_payload", err)
	}
}

func safeTransitionWorkloadObject() map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "demo"},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"securityContext": map[string]any{
						"runAsNonRoot":   true,
						"runAsUser":      float64(65532),
						"fsGroup":        float64(65532),
						"windowsOptions": map[string]any{"runAsUserName": "ContainerUser"},
					},
					"containers": []any{map[string]any{
						"name": "server",
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": false,
							"runAsNonRoot":             true,
							"capabilities":             map[string]any{"drop": []any{"ALL"}},
						},
					}},
				},
			},
		},
	}
}

func TestValidateSafeServiceChanges(t *testing.T) {
	t.Parallel()

	action := policyTestAction("", "services", "patch", "patch", true)
	if err := validateSafeOperation(action, map[string]any{"spec": map[string]any{"type": "ClusterIP"}}, map[string]any{"metadata": map[string]any{"labels": map[string]any{"team": "mcp"}}}, "merge"); err != nil {
		t.Fatalf("safe ClusterIP service patch rejected: %v", err)
	}

	for _, object := range []map[string]any{
		{"spec": map[string]any{"type": "NodePort"}},
		{"spec": map[string]any{"externalName": "outside.example"}},
		{"spec": map[string]any{"ports": []any{map[string]any{"nodePort": float64(30080)}}}},
	} {
		object := object
		t.Run("blocked service object", func(t *testing.T) {
			if got := policyReason(validateSafeOperation(action, object, nil, "merge")); got != "unsafe_payload" {
				t.Fatalf("validateSafeOperation() reason = %q, want unsafe_payload", got)
			}
		})
	}

	for _, path := range []string{"/spec/type", "/spec/externalIPs", "/spec/ports/0/nodePort"} {
		path := path
		t.Run("blocked service patch "+path, func(t *testing.T) {
			patch := []any{map[string]any{"op": "replace", "path": path, "value": "NodePort"}}
			if got := policyReason(validateSafeOperation(action, nil, patch, "json")); got != "unsafe_payload" {
				t.Fatalf("validateSafeOperation() reason = %q, want unsafe_payload", got)
			}
		})
	}

	for _, tt := range []struct {
		name  string
		path  string
		value any
	}{
		{
			name:  "replace spec with NodePort",
			path:  "/spec",
			value: map[string]any{"type": "NodePort"},
		},
		{
			name:  "replace spec with ExternalName",
			path:  "/spec",
			value: map[string]any{"type": "ExternalName", "externalName": "outside.example"},
		},
		{
			name:  "replace port with NodePort",
			path:  "/spec/ports/0",
			value: map[string]any{"port": float64(80), "nodePort": float64(30080)},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			patch := []any{map[string]any{"op": "replace", "path": tt.path, "value": tt.value}}
			if got := policyReason(validateSafeOperation(action, nil, patch, "json")); got != "unsafe_payload" {
				t.Fatalf("validateSafeOperation() reason = %q, want unsafe_payload", got)
			}
		})
	}
}

func TestPlanStoreIsOneTimeAndIdentityBound(t *testing.T) {
	t.Parallel()

	store := NewPlanStore(2)
	op := Operation{Action: policyTestAction("apps", "deployments", "patch", "patch", true), Namespace: "workloads", Name: "web"}
	id, code, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := store.Consume(id, "identity-b", code); policyReason(err) != "identity_mismatch" {
		t.Fatalf("wrong identity error = %v, want identity_mismatch", err)
	}
	got, err := store.Consume(id, "identity-a", code)
	if err != nil {
		t.Fatalf("owner Consume() after mismatch error = %v", err)
	}
	if got.Name != op.Name || got.Namespace != op.Namespace {
		t.Fatalf("consumed operation = %#v, want %#v", got, op)
	}
	if _, err := store.Consume(id, "identity-a", code); policyReason(err) != "invalid_plan" {
		t.Fatalf("second consume error = %v, want invalid_plan", err)
	}
}

func TestPlanStoreConfirmationValidationAndLock(t *testing.T) {
	t.Parallel()

	store := NewPlanStore(4)
	op := Operation{Action: policyTestAction("apps", "deployments", "patch", "patch", true), Namespace: "workloads", Name: "web"}
	id, code, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	parsedCode, err := strconv.Atoi(code)
	if err != nil || parsedCode < 100000 || parsedCode > 999999 {
		t.Fatalf("confirmation code = %q, want six digits in [100000,999999]", code)
	}

	for _, malformed := range []string{"12345", "1234567", "12a456", "１２３４５６"} {
		if _, err := store.Consume(id, "identity-a", malformed); policyReason(err) != "invalid_confirmation" {
			t.Fatalf("malformed confirmation %q error = %v, want invalid_confirmation", malformed, err)
		}
	}
	if failures := store.plans[id].ConfirmationFailures; failures != 0 {
		t.Fatalf("malformed confirmation attempts counted as %d failures, want 0", failures)
	}

	wrongCode := "100000"
	if wrongCode == code {
		wrongCode = "100001"
	}
	for attempt := 1; attempt < confirmationMaxAttempts; attempt++ {
		if _, err := store.Consume(id, "identity-a", wrongCode); policyReason(err) != "invalid_confirmation" {
			t.Fatalf("wrong confirmation attempt %d error = %v, want invalid_confirmation", attempt, err)
		}
	}
	if failures := store.plans[id].ConfirmationFailures; failures != confirmationMaxAttempts-1 {
		t.Fatalf("wrong confirmation failures = %d, want %d", failures, confirmationMaxAttempts-1)
	}
	if _, err := store.Consume(id, "identity-a", "12345"); policyReason(err) != "invalid_confirmation" {
		t.Fatalf("malformed confirmation after wrong attempts error = %v, want invalid_confirmation", err)
	}
	if failures := store.plans[id].ConfirmationFailures; failures != confirmationMaxAttempts-1 {
		t.Fatalf("malformed confirmation changed failures to %d, want %d", failures, confirmationMaxAttempts-1)
	}
	if _, err := store.Consume(id, "identity-a", wrongCode); policyReason(err) != "confirmation_locked" {
		t.Fatalf("final wrong confirmation error = %v, want confirmation_locked", err)
	}
	if _, ok := store.plans[id]; ok {
		t.Fatalf("locked plan %q remains in the store", id)
	}
}

func TestPlanStoreConfirmationCodeIsBoundToPlan(t *testing.T) {
	t.Parallel()

	store := NewPlanStore(8)
	op := Operation{Action: policyTestAction("apps", "deployments", "patch", "patch", true), Namespace: "workloads", Name: "web"}
	firstID, firstCode, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	secondID, secondCode, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}
	for secondCode == firstCode {
		secondID, secondCode, _, err = store.Create("identity-a", op)
		if err != nil {
			t.Fatalf("retry Create() after confirmation collision error = %v", err)
		}
	}
	if _, err := store.Consume(secondID, "identity-a", firstCode); policyReason(err) != "invalid_confirmation" {
		t.Fatalf("cross-plan confirmation error = %v, want invalid_confirmation", err)
	}
	if _, err := store.Consume(secondID, "identity-a", secondCode); err != nil {
		t.Fatalf("second plan correct confirmation error = %v", err)
	}
	if _, err := store.Consume(firstID, "identity-a", firstCode); err != nil {
		t.Fatalf("first plan correct confirmation error = %v", err)
	}
}

func TestPlanStoreCorrectConfirmationIsAtomic(t *testing.T) {
	t.Parallel()

	store := NewPlanStore(1)
	op := Operation{Action: policyTestAction("apps", "deployments", "patch", "patch", true), Namespace: "workloads", Name: "web"}
	id, code, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			<-start
			_, err := store.Consume(id, "identity-a", code)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if policyReason(err) != "invalid_plan" {
			t.Fatalf("concurrent Consume() error = %v, want invalid_plan after one success", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent correct confirmations succeeded %d times, want exactly once", successes)
	}
}

func TestPlanStoreExpiredPlanIsRemovedBeforeConfirmation(t *testing.T) {
	t.Parallel()

	store := NewPlanStore(1)
	op := Operation{Action: policyTestAction("apps", "deployments", "patch", "patch", true), Namespace: "workloads", Name: "web"}
	id, code, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	store.plans[id] = func() storedPlan {
		plan := store.plans[id]
		plan.ExpiresAt = time.Now().Add(-time.Second)
		return plan
	}()
	if _, err := store.Consume(id, "identity-a", code); policyReason(err) != "expired_plan" {
		t.Fatalf("expired plan Consume() error = %v, want expired_plan", err)
	}
	if _, ok := store.plans[id]; ok {
		t.Fatalf("expired plan %q remains in the store", id)
	}
}

func confirmationTestPrincipal(t *testing.T) *Principal {
	t.Helper()
	kubernetesClient := k8sfake.NewSimpleClientset()
	kubernetesClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	return &Principal{
		Username: "alice", UID: "uid-a",
		Dynamic:    dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		Kubernetes: kubernetesClient,
	}
}

func TestPlanReturnsHumanConfirmationChallengeForWriteModes(t *testing.T) {
	t.Parallel()

	for _, mode := range []mcpv1alpha1.AccessMode{mcpv1alpha1.ModeSafeWrite, mcpv1alpha1.ModeDangerous} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			cfg := policyTestConfig(mode, mcpv1alpha1.SensitiveReadAllow)
			codec, err := newCapabilityCodec()
			if err != nil {
				t.Fatalf("newCapabilityCodec() error = %v", err)
			}
			app := &App{config: cfg, policy: NewPolicy(cfg), capabilities: codec, plans: NewPlanStore(4)}
			principal := confirmationTestPrincipal(t)
			capability := Capability{Version: "v1", Resource: "configmaps", Kind: "ConfigMap", Action: "create", Verb: "create", Namespaced: true}
			output, err := app.plan(context.Background(), principal, PlanInput{
				CapabilityID: codec.encode(capability), Namespace: "workloads",
				Object: map[string]any{
					"apiVersion": "v1", "kind": "ConfigMap",
					"metadata": map[string]any{"name": "planned-config"},
					"data":     map[string]any{"value": "planned"},
				},
			})
			if err != nil {
				t.Fatalf("plan() error = %v", err)
			}
			if output.PlanID == "" {
				t.Fatal("plan() returned an empty planId")
			}
			if !output.Confirmation.Required {
				t.Fatalf("plan() confirmation.required = false, want true: %#v", output.Confirmation)
			}
			parsedCode, err := strconv.Atoi(output.Confirmation.Code)
			if err != nil || parsedCode < 100000 || parsedCode > 999999 {
				t.Fatalf("plan() confirmation.code = %q, want six digits in [100000,999999]", output.Confirmation.Code)
			}
			instruction := strings.ToLower(output.Confirmation.Instruction)
			if !strings.Contains(instruction, "human") || !strings.Contains(instruction, "later") {
				t.Fatalf("plan() confirmation.instruction = %q, want explicit later human confirmation", output.Confirmation.Instruction)
			}
		})
	}
}

func TestMCPCommitMissingConfirmationReturnsRequired(t *testing.T) {
	t.Parallel()

	app := newAuditTestApp(slog.Default())
	app.config.Spec.Mode = mcpv1alpha1.ModeSafeWrite
	app.plans = NewPlanStore(2)
	principal := confirmationTestPrincipal(t)
	op := Operation{Action: policyTestAction("", "configmaps", "create", "create", true), Namespace: "workloads", Name: "planned-config"}
	planID, _, _, err := app.plans.Create(principal.SubjectKey(), op)
	if err != nil {
		t.Fatalf("plans.Create() error = %v", err)
	}

	server := app.newMCPServer(principal)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "confirmation-test-client", Version: "test"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer clientSession.Close()

	result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: toolCommit, Arguments: map[string]any{"planId": planID},
	})
	if err != nil {
		t.Fatalf("CallTool(k8s.commit) protocol error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("CallTool(k8s.commit) result = %#v, want an error result", result)
	}
	if len(result.Content) != 1 {
		t.Fatalf("k8s.commit error content count = %d, want one structured text item", len(result.Content))
	}
	content, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("k8s.commit error content type = %T, want *mcp.TextContent", result.Content[0])
	}
	var envelope toolErrorOutput
	if err := json.Unmarshal([]byte(content.Text), &envelope); err != nil {
		t.Fatalf("k8s.commit error payload = %s, want structured JSON: %v", content.Text, err)
	}
	if envelope.Code != "confirmation_required" || envelope.Message == "" || envelope.Retryable {
		t.Fatalf("k8s.commit error envelope = %#v, want confirmation_required, message, retryable=false", envelope)
	}
}

func TestMCPHelpErrorUsesStructuredPayload(t *testing.T) {
	t.Parallel()

	app := newAuditTestApp(slog.Default())
	server := app.newMCPServer(&Principal{})
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "error-envelope-test-client", Version: "test"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer clientSession.Close()

	result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: toolHelp, Arguments: map[string]any{"tool": "k8s.not-a-tool"},
	})
	if err != nil {
		t.Fatalf("CallTool(k8s.help) protocol error = %v", err)
	}
	if result == nil || !result.IsError || len(result.Content) != 1 {
		t.Fatalf("CallTool(k8s.help) result = %#v, want one error content item", result)
	}
	content, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("k8s.help error content type = %T, want *mcp.TextContent", result.Content[0])
	}
	var envelope toolErrorOutput
	if err := json.Unmarshal([]byte(content.Text), &envelope); err != nil {
		t.Fatalf("k8s.help error payload = %q, want structured JSON: %v", content.Text, err)
	}
	if envelope.Code != "invalid_input" || envelope.Message == "" || envelope.Retryable {
		t.Fatalf("k8s.help error envelope = %#v, want invalid_input, message, retryable=false", envelope)
	}
}

func TestDecodeCommitInputDistinguishesMissingAndExplicitConfirmation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		arguments  json.RawMessage
		wantReason string
	}{
		{name: "missing field", arguments: json.RawMessage(`{"planId":"plan-1"}`)},
		{name: "explicit empty string", arguments: json.RawMessage(`{"planId":"plan-1","confirmationCode":""}`), wantReason: "invalid_confirmation"},
		{name: "explicit null", arguments: json.RawMessage(`{"planId":"plan-1","confirmationCode":null}`), wantReason: "invalid_confirmation"},
		{name: "malformed digits", arguments: json.RawMessage(`{"planId":"plan-1","confirmationCode":"12345"}`), wantReason: "invalid_confirmation"},
		{name: "valid format", arguments: json.RawMessage(`{"planId":"plan-1","confirmationCode":"123456"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := decodeCommitInput(tt.arguments)
			if got := policyReason(err); got != tt.wantReason {
				t.Fatalf("decodeCommitInput() reason = %q, want %q (error: %v)", got, tt.wantReason, err)
			}
			if input.PlanID != "plan-1" {
				t.Fatalf("decodeCommitInput() planId = %q, want plan-1", input.PlanID)
			}
		})
	}
}

func TestPlanStoreByteBudgetsArePerIdentityAndReleasedOnConsume(t *testing.T) {
	t.Parallel()

	store := NewPlanStore(4)
	op := Operation{Action: policyTestAction("apps", "deployments", "patch", "patch", true), Namespace: "workloads", Name: "web"}
	firstID, firstCode, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("initial Create() error = %v", err)
	}
	planSize := store.plans[firstID].Size
	if planSize <= 0 {
		t.Fatalf("stored plan size = %d, want positive", planSize)
	}
	store.maxBytes = planSize * 2
	store.maxSubjectBytes = planSize

	if _, _, _, err := store.Create("identity-a", op); policyReason(err) != "plan_capacity" {
		t.Fatalf("same-identity byte overflow error = %v, want plan_capacity", err)
	}
	secondID, secondCode, _, err := store.Create("identity-b", op)
	if err != nil {
		t.Fatalf("different identity Create() error = %v, want global budget to allow it", err)
	}

	if _, err := store.Consume(firstID, "identity-a", firstCode); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	thirdID, thirdCode, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("Create() after Consume() error = %v, want released byte budget", err)
	}
	if _, err := store.Consume(thirdID, "identity-a", thirdCode); err != nil {
		t.Fatalf("released plan Consume() error = %v", err)
	}
	if _, err := store.Consume(secondID, "identity-b", secondCode); err != nil {
		t.Fatalf("cleanup Consume() error = %v", err)
	}
}

func TestAddPatchResourceVersionAddsAtomicPrecondition(t *testing.T) {
	t.Parallel()

	merge, err := addPatchResourceVersion(map[string]any{"spec": map[string]any{"replicas": float64(2)}}, "application/merge-patch+json", "9")
	if err != nil {
		t.Fatalf("merge precondition error = %v", err)
	}
	mergeMap, ok := merge.(map[string]any)
	if !ok {
		t.Fatalf("merge precondition type = %T, want map", merge)
	}
	metadata, ok := mergeMap["metadata"].(map[string]any)
	if !ok || metadata["resourceVersion"] != "9" {
		t.Fatalf("merge precondition metadata = %#v, want resourceVersion 9", mergeMap["metadata"])
	}

	jsonPatch, err := addPatchResourceVersion([]any{map[string]any{"op": "replace", "path": "/spec/replicas", "value": float64(3)}}, "application/json-patch+json", "9")
	if err != nil {
		t.Fatalf("JSON precondition error = %v", err)
	}
	operations, ok := jsonPatch.([]any)
	if !ok || len(operations) != 2 {
		t.Fatalf("JSON precondition result = %#v, want two operations", jsonPatch)
	}
	first, ok := operations[0].(map[string]any)
	if !ok || first["op"] != "test" || first["path"] != "/metadata/resourceVersion" || first["value"] != "9" {
		t.Fatalf("JSON precondition operation = %#v", operations[0])
	}
}

func TestRedactSecretHonorsSensitiveReadPolicy(t *testing.T) {
	t.Parallel()

	const (
		dataMarker       = "base64-secret-marker"
		stringDataMarker = "plaintext-secret-marker"
		binaryDataMarker = "binary-secret-marker"
		annotationMarker = "annotation-secret-marker"
	)
	lastApplied := `{"stringData":{"password":"` + annotationMarker + `"}}`
	secret := map[string]any{
		"metadata": map[string]any{
			"name": "db",
			"annotations": map[string]any{
				"kubectl.kubernetes.io/last-applied-configuration": lastApplied,
				"example.com/owner": "annotation-owner-marker",
			},
		},
		"data":       map[string]any{"password": dataMarker},
		"stringData": map[string]any{"password": stringDataMarker},
		"binaryData": map[string]any{"payload": binaryDataMarker},
	}
	original := map[string]any{
		"metadata": map[string]any{
			"name": "db",
			"annotations": map[string]any{
				"kubectl.kubernetes.io/last-applied-configuration": lastApplied,
				"example.com/owner": "annotation-owner-marker",
			},
		},
		"data":       map[string]any{"password": dataMarker},
		"stringData": map[string]any{"password": stringDataMarker},
		"binaryData": map[string]any{"payload": binaryDataMarker},
	}
	action := policyTestAction("", "secrets", "get", "get", true)
	redacted, err := redactResult(secret, action, mcpv1alpha1.SensitiveReadRedact)
	if err != nil {
		t.Fatalf("redactResult() error = %v", err)
	}
	redactedMap := redacted.(map[string]any)
	for _, field := range []string{"data", "stringData", "binaryData"} {
		values := redactedMap[field].(map[string]any)
		for key, value := range values {
			if value != "<redacted>" {
				t.Fatalf("redacted secret %s[%s] = %#v, want <redacted>", field, key, value)
			}
		}
	}
	redactedAnnotations := redactedMap["metadata"].(map[string]any)["annotations"].(map[string]any)
	for key, value := range redactedAnnotations {
		if value != "<redacted>" {
			t.Fatalf("redacted secret annotation %s = %#v, want <redacted>", key, value)
		}
	}

	if !reflect.DeepEqual(secret, original) {
		t.Fatalf("redactResult() mutated input secret = %#v, want %#v", secret, original)
	}

	allowed, err := redactResult(secret, action, mcpv1alpha1.SensitiveReadAllow)
	if err != nil {
		t.Fatalf("Allow redactResult() error = %v", err)
	}
	allowedAnnotations := allowed.(map[string]any)["metadata"].(map[string]any)["annotations"].(map[string]any)
	if allowedAnnotations["kubectl.kubernetes.io/last-applied-configuration"] != "<redacted>" || allowedAnnotations["example.com/owner"] != "annotation-owner-marker" {
		t.Fatalf("Allow redactResult() annotations = %#v, want sensitive assignment redacted and owner preserved", allowedAnnotations)
	}
	if _, err := redactResult(secret, action, mcpv1alpha1.SensitiveReadDeny); policyReason(err) != "sensitive_read_denied" {
		t.Fatalf("deny secret error = %v, want sensitive_read_denied", err)
	}
}

func TestReadOutputShapesAndMetadataControls(t *testing.T) {
	t.Parallel()

	listAction := policyTestAction("", "pods", "list", "list", true)
	getAction := policyTestAction("", "pods", "get", "get", true)
	object := map[string]any{
		"apiVersion": "v1",
		"kind":       "PodList",
		"metadata": map[string]any{
			"continue":        "next-page",
			"resourceVersion": "42",
			"managedFields":   []any{map[string]any{"manager": "controller"}},
			"annotations": map[string]any{
				"example.com/token": "top-secret",
				"example.com/owner": "platform",
				"example.com/key":   "key=top-level-secret",
				"example.com/json":  `{"key":"top-level-json-secret"}`,
			},
		},
		"items": []any{map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name": "worker", "namespace": "workloads", "creationTimestamp": time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339),
				"managedFields": []any{map[string]any{"manager": "controller"}},
				"annotations": map[string]any{
					"example.com/token": "pod-secret", "example.com/owner": "platform",
					"example.com/key": "key=pod-secret", "example.com/json": `{"key":"pod-json-secret"}`,
				},
			},
			"spec": map[string]any{
				"nodeName":   "node-a",
				"containers": []any{map[string]any{"name": "worker"}},
			},
			"status": map[string]any{
				"phase":             "Running",
				"containerStatuses": []any{map[string]any{"ready": true, "restartCount": int64(2)}},
			},
		}},
	}
	redacted, err := redactResult(object, listAction, mcpv1alpha1.SensitiveReadAllow)
	if err != nil {
		t.Fatalf("redactResult() error = %v", err)
	}
	redactedObject := redacted.(map[string]any)
	defaultOptions, err := normalizeReadOutputOptions(listAction, ReadInput{})
	if err != nil {
		t.Fatalf("normalizeReadOutputOptions(default list) error = %v", err)
	}
	if defaultOptions.mode != readOutputSummary || !defaultOptions.omitManagedFields || !defaultOptions.omitAnnotations {
		t.Fatalf("default list output options = %#v, want summary and recursive metadata omission", defaultOptions)
	}
	defaultOutput, err := shapeReadOutput(redactedObject, listAction, defaultOptions)
	if err != nil {
		t.Fatalf("shapeReadOutput(default list) error = %v", err)
	}
	if _, ok := defaultOutput["items"].([]any); !ok {
		t.Fatalf("default list output items = %#v, want summaries", defaultOutput["items"])
	}
	if _, ok := defaultOutput["metadata"].(map[string]any)["managedFields"]; ok {
		t.Fatal("default list output retained top-level metadata.managedFields")
	}
	if _, ok := defaultOutput["metadata"].(map[string]any)["annotations"]; ok {
		t.Fatal("default list output retained top-level metadata.annotations")
	}
	item := defaultOutput["items"].([]any)[0].(map[string]any)
	for _, field := range []string{"spec", "status", "managedFields", "annotations"} {
		if _, ok := item[field]; ok {
			t.Fatalf("default Pod summary retained %q: %#v", field, item)
		}
	}
	if item["name"] != "worker" || item["phase"] != "Running" || item["ready"] != "1/1" || item["restartCount"] != int64(2) {
		t.Fatalf("default Pod summary = %#v, want name/phase/ready/restartCount", item)
	}
	defaultFullOptions, err := normalizeReadOutputOptions(getAction, ReadInput{OutputMode: readOutputFull})
	if err != nil {
		t.Fatalf("normalizeReadOutputOptions(default full) error = %v", err)
	}
	fullObject := redactedObject["items"].([]any)[0].(map[string]any)
	defaultFullOutput, err := shapeReadOutput(fullObject, getAction, defaultFullOptions)
	if err != nil {
		t.Fatalf("shapeReadOutput(default full) error = %v", err)
	}
	defaultFullMetadata := defaultFullOutput["metadata"].(map[string]any)
	if _, ok := defaultFullMetadata["managedFields"]; ok {
		t.Fatal("default full output retained metadata.managedFields")
	}
	if _, ok := defaultFullMetadata["annotations"]; ok {
		t.Fatal("default full output retained metadata.annotations")
	}

	tableOptions, err := normalizeReadOutputOptions(listAction, ReadInput{OutputMode: readOutputTable})
	if err != nil {
		t.Fatalf("normalizeReadOutputOptions(table) error = %v", err)
	}
	if _, err := normalizeReadOutputOptions(listAction, ReadInput{OutputMode: readOutputTable, FieldPaths: []string{"metadata.name"}}); policyReason(err) != "invalid_input" {
		t.Fatalf("table with fieldPaths error = %v, want invalid_input", err)
	}
	tableOutput, err := shapeReadOutput(redactedObject, listAction, tableOptions)
	if err != nil {
		t.Fatalf("shapeReadOutput(table) error = %v", err)
	}
	columns, ok := tableOutput["columns"].([]string)
	if !ok || len(columns) == 0 || columns[0] != "name" {
		t.Fatalf("table columns = %#v, want stable Pod columns beginning with name", tableOutput["columns"])
	}
	rows, ok := tableOutput["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("table rows = %#v, want one row", tableOutput["rows"])
	}
	if _, ok := tableOutput["metadata"].(map[string]any)["annotations"]; ok {
		t.Fatal("table output retained annotations")
	}

	keep := false
	fullOptions, err := normalizeReadOutputOptions(getAction, ReadInput{
		OutputMode:        readOutputFull,
		OmitManagedFields: &keep,
		OmitAnnotations:   &keep,
	})
	if err != nil {
		t.Fatalf("normalizeReadOutputOptions(full) error = %v", err)
	}
	fullOutput, err := shapeReadOutput(fullObject, getAction, fullOptions)
	if err != nil {
		t.Fatalf("shapeReadOutput(full) error = %v", err)
	}
	metadata := fullOutput["metadata"].(map[string]any)
	if _, ok := metadata["managedFields"]; !ok {
		t.Fatal("explicit omitManagedFields=false dropped metadata.managedFields")
	}
	annotations := metadata["annotations"].(map[string]any)
	if annotations["example.com/token"] != "<redacted>" || annotations["example.com/key"] != "<redacted>" || annotations["example.com/json"] != "<redacted>" || annotations["example.com/owner"] != "platform" {
		t.Fatalf("explicit annotations output = %#v, want token/key assignments redacted while metadata retained", annotations)
	}

	fieldOptions, err := normalizeReadOutputOptions(listAction, ReadInput{FieldPaths: []string{"metadata.name", "status.phase", "metadata.name"}})
	if err != nil {
		t.Fatalf("normalizeReadOutputOptions(fieldPaths) error = %v", err)
	}
	if len(fieldOptions.fieldPaths) != 2 {
		t.Fatalf("deduplicated field paths = %#v, want two paths", fieldOptions.fieldPaths)
	}
	projected, err := shapeReadOutput(redactedObject, listAction, fieldOptions)
	if err != nil {
		t.Fatalf("shapeReadOutput(fieldPaths) error = %v", err)
	}
	projectedItem := projected["items"].([]any)[0].(map[string]any)
	if projectedItem["metadata"].(map[string]any)["name"] != "worker" || projectedItem["status"].(map[string]any)["phase"] != "Running" {
		t.Fatalf("projected item = %#v, want metadata.name and status.phase", projectedItem)
	}
	if _, ok := projectedItem["spec"]; ok {
		t.Fatalf("fieldPaths projection retained unrequested spec: %#v", projectedItem)
	}
	if _, err := shapeReadOutput(redactedObject, listAction, readOutputOptions{mode: readOutputFull, fieldPaths: []string{"status.missing"}}); policyReason(err) != "field_path_not_found" {
		t.Fatalf("missing field path error = %v, want field_path_not_found", err)
	}
}

func TestWatchPassesResourceVersionAndPreservesSummaryDiagnostics(t *testing.T) {
	t.Parallel()

	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	action := policyTestAction("", "pods", "watch", "watch", true)
	capabilityID := capabilityFromAction(codec, action, nil).ID

	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{{Version: "v1", Resource: "pods"}: "PodList"},
	)
	watcher := watch.NewRaceFreeFake()
	var requestedResourceVersion string
	dynamicClient.PrependWatchReactor("pods", func(action k8stesting.Action) (bool, watch.Interface, error) {
		requestedResourceVersion = action.(k8stesting.WatchAction).GetWatchRestrictions().ResourceVersion
		pod := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": "worker", "namespace": "workloads", "resourceVersion": "42"},
			"status":   map[string]any{"phase": "Running"},
		}}
		watcher.Add(pod)
		watcher.Error(&metav1.Status{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
			Status:   metav1.StatusFailure,
			Reason:   metav1.StatusReasonExpired,
			Message:  "watch resourceVersion is too old",
			Code:     410,
		})
		watcher.Stop()
		return true, watcher, nil
	})

	kubernetesClient := k8sfake.NewSimpleClientset()
	kubernetesClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	cfg := policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Limits.MaxListItems = 2
	cfg.Spec.Limits.MaxOutputBytes = 1 << 20
	cfg.Spec.Limits.StreamTimeout = metav1.Duration{Duration: time.Second}
	app := &App{config: cfg, policy: NewPolicy(cfg), capabilities: codec}
	output, err := app.read(context.Background(), nil, &Principal{Dynamic: dynamicClient, Kubernetes: kubernetesClient}, ReadInput{
		CapabilityID: capabilityID, Namespace: "workloads", ResourceVersion: "41",
	})
	if err != nil {
		t.Fatalf("read(watch) error = %v", err)
	}
	if requestedResourceVersion != "41" {
		t.Fatalf("watch resourceVersion = %q, want 41", requestedResourceVersion)
	}
	if output["resourceVersion"] != "42" {
		t.Fatalf("watch result resourceVersion = %#v, want last event resourceVersion 42", output["resourceVersion"])
	}
	events, ok := output["events"].([]any)
	if !ok || len(events) != 2 {
		t.Fatalf("watch events = %#v, want one object event and one ERROR event", output["events"])
	}
	objectEvent := events[0].(map[string]any)
	objectSummary := objectEvent["object"].(map[string]any)
	if objectEvent["type"] != string(watch.Added) || objectSummary["resourceVersion"] != "42" {
		t.Fatalf("watch object event = %#v, want ADDED summary with resourceVersion 42", objectEvent)
	}
	errorEvent := events[1].(map[string]any)
	errorSummary := errorEvent["object"].(map[string]any)
	if errorEvent["type"] != string(watch.Error) {
		t.Fatalf("watch error event type = %#v, want ERROR", errorEvent["type"])
	}
	for key, want := range map[string]any{
		"status":  metav1.StatusFailure,
		"reason":  string(metav1.StatusReasonExpired),
		"message": "watch resourceVersion is too old",
		"code":    int64(410),
	} {
		if got := fmt.Sprint(errorSummary[key]); got != fmt.Sprint(want) {
			t.Fatalf("watch ERROR summary[%q] = %#v, want %#v; summary=%#v", key, errorSummary[key], want, errorSummary)
		}
	}
}

func TestPolicyErrorsHaveStableReason(t *testing.T) {
	t.Parallel()

	err := policyError("scope_denied", "namespace is outside scope")
	if !strings.HasPrefix(err.Error(), "scope_denied:") {
		t.Fatalf("policy error string = %q, want reason prefix", err)
	}
}

func TestFollowedLogsRequireDangerousModeBeforeAuthorization(t *testing.T) {
	t.Parallel()

	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	capability := Capability{
		Version: "v1", Resource: "pods", Subresource: "log", Kind: "Pod",
		Action: "logs", Verb: "get", Namespaced: true,
	}
	id := codec.encode(capability)
	for _, mode := range []mcpv1alpha1.AccessMode{mcpv1alpha1.ModeReadOnly, mcpv1alpha1.ModeSafeWrite} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			app := &App{
				config:       runtimeconfig.Config{Namespace: "workloads", Spec: mcpv1alpha1.KubernetesMCPServerSpec{Mode: mode}},
				capabilities: codec,
			}
			_, err := app.read(context.Background(), nil, nil, ReadInput{CapabilityID: id, Namespace: "workloads", Name: "pod", Follow: true})
			if got := policyReason(err); got != "mode_denied" {
				t.Fatalf("followed logs in %s mode error = %q, want mode_denied (error: %v)", mode, got, err)
			}
		})
	}
}

func TestDangerousFollowedLogsStopAtMaxListItemsForEmptyLines(t *testing.T) {
	t.Parallel()

	const maxListItems int64 = 2
	logBody := strings.Repeat("\n", 8)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/selfsubjectaccessreviews"):
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(writer, `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","status":{"allowed":true}}`)
		case strings.Contains(request.URL.Path, "/pods/pod/log"):
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(writer, logBody)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	kubernetesClient, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("kubernetes.NewForConfig() error = %v", err)
	}
	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	capability := Capability{
		Version: "v1", Resource: "pods", Subresource: "log", Kind: "Pod",
		Action: "logs", Verb: "get", Namespaced: true,
	}
	capabilityID := codec.encode(capability)
	cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Limits.MaxListItems = maxListItems
	cfg.Spec.Limits.MaxOutputBytes = 1 << 20
	cfg.Spec.Limits.StreamTimeout = metav1.Duration{Duration: time.Second}
	app := &App{config: cfg, policy: NewPolicy(cfg), capabilities: codec}

	output, err := app.read(context.Background(), nil, &Principal{Kubernetes: kubernetesClient}, ReadInput{
		CapabilityID: capabilityID, Namespace: "workloads", Name: "pod", Container: "main", Follow: true,
	})
	if err != nil {
		t.Fatalf("read(follow logs) error = %v", err)
	}
	logs, ok := output["logs"].([]string)
	if !ok {
		t.Fatalf("read(follow logs) logs = %#v, want []string", output["logs"])
	}
	if len(logs) != int(maxListItems) {
		t.Fatalf("read(follow logs) returned %d lines, want maxListItems=%d", len(logs), maxListItems)
	}
	if truncated, ok := output["truncated"].(bool); !ok || !truncated {
		t.Fatalf("read(follow logs) truncated = %#v, want true after item bound", output["truncated"])
	}
}

func TestDangerousFollowedLogsTruncateOverlongLine(t *testing.T) {
	t.Parallel()

	const maxOutputBytes int64 = 1<<20 + 1024
	logBody := strings.Repeat("x", int(maxOutputBytes+1024)) + "\n"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "/pods/pod/log") {
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(writer, logBody)
		} else {
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	kubernetesClient, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("kubernetes.NewForConfig() error = %v", err)
	}
	cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Limits.MaxOutputBytes = maxOutputBytes
	cfg.Spec.Limits.MaxListItems = 2
	cfg.Spec.Limits.StreamTimeout = metav1.Duration{Duration: time.Second}
	app := &App{config: cfg}

	output, err := app.logs(context.Background(), nil, &Principal{Kubernetes: kubernetesClient}, "workloads", ReadInput{
		Namespace: "workloads", Name: "pod", Container: "main", Follow: true,
	})
	if err != nil {
		t.Fatalf("read(follow logs with overlong line) error = %v, want bounded truncated output", err)
	}
	if truncated, ok := output["truncated"].(bool); !ok || !truncated {
		t.Fatalf("read(follow logs with overlong line) truncated = %#v, want true", output["truncated"])
	}
	if logs, ok := output["logs"].([]string); !ok {
		t.Fatalf("read(follow logs with overlong line) logs = %#v, want []string", output["logs"])
	} else if len(logs) > 1 {
		t.Fatalf("read(follow logs with overlong line) returned %d log lines, want bounded output", len(logs))
	}
}
