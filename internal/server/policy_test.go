package server

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

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

	secret := map[string]any{"metadata": map[string]any{"name": "db"}, "data": map[string]any{"password": "c2VjcmV0"}}
	action := policyTestAction("", "secrets", "get", "get", true)
	redacted, err := redactResult(secret, action, mcpv1alpha1.SensitiveReadRedact)
	if err != nil {
		t.Fatalf("redactResult() error = %v", err)
	}
	redactedMap := redacted.(map[string]any)
	if redactedMap["data"].(map[string]any)["password"] != "<redacted>" {
		t.Fatalf("redacted secret = %#v", redactedMap)
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
