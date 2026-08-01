package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	planID, _, err := app.plans.Create(principal.SubjectKey(), operation)
	if err != nil {
		t.Fatalf("plans.Create() error = %v", err)
	}
	if _, err := app.commit(context.Background(), nil, principal, CommitInput{PlanID: planID}); policyReason(err) != "unsafe_payload" {
		t.Fatalf("commit() error = %q, want unsafe_payload", err)
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
	id, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := store.Consume(id, "identity-b"); policyReason(err) != "identity_mismatch" {
		t.Fatalf("wrong identity error = %v, want identity_mismatch", err)
	}
	got, err := store.Consume(id, "identity-a")
	if err != nil {
		t.Fatalf("owner Consume() after mismatch error = %v", err)
	}
	if got.Name != op.Name || got.Namespace != op.Namespace {
		t.Fatalf("consumed operation = %#v, want %#v", got, op)
	}
	if _, err := store.Consume(id, "identity-a"); policyReason(err) != "invalid_plan" {
		t.Fatalf("second consume error = %v, want invalid_plan", err)
	}
}

func TestPlanStoreByteBudgetsArePerIdentityAndReleasedOnConsume(t *testing.T) {
	t.Parallel()

	store := NewPlanStore(4)
	op := Operation{Action: policyTestAction("apps", "deployments", "patch", "patch", true), Namespace: "workloads", Name: "web"}
	firstID, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("initial Create() error = %v", err)
	}
	planSize := store.plans[firstID].Size
	if planSize <= 0 {
		t.Fatalf("stored plan size = %d, want positive", planSize)
	}
	store.maxBytes = planSize * 2
	store.maxSubjectBytes = planSize

	if _, _, err := store.Create("identity-a", op); policyReason(err) != "plan_capacity" {
		t.Fatalf("same-identity byte overflow error = %v, want plan_capacity", err)
	}
	secondID, _, err := store.Create("identity-b", op)
	if err != nil {
		t.Fatalf("different identity Create() error = %v, want global budget to allow it", err)
	}

	if _, err := store.Consume(firstID, "identity-a"); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	thirdID, _, err := store.Create("identity-a", op)
	if err != nil {
		t.Fatalf("Create() after Consume() error = %v, want released byte budget", err)
	}
	if _, err := store.Consume(thirdID, "identity-a"); err != nil {
		t.Fatalf("released plan Consume() error = %v", err)
	}
	if _, err := store.Consume(secondID, "identity-b"); err != nil {
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
	if !reflect.DeepEqual(allowed, secret) {
		t.Fatalf("Allow redactResult() = %#v, want original secret %#v", allowed, secret)
	}
	if _, err := redactResult(secret, action, mcpv1alpha1.SensitiveReadDeny); policyReason(err) != "sensitive_read_denied" {
		t.Fatalf("deny secret error = %v, want sensitive_read_denied", err)
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
		CapabilityID: capabilityID, Namespace: "workloads", Name: "pod", Follow: true,
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
