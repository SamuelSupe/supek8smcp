package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type helpOutput struct {
	Mode   string            `json:"mode"`
	Tools  []helpToolSummary `json:"tools"`
	Manual *helpManual       `json:"manual"`
}

type helpToolSummary struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

type helpManual struct {
	Name      string            `json:"name"`
	Available bool              `json:"available"`
	Inputs    []json.RawMessage `json:"inputs"`
	Steps     []string          `json:"steps"`
	Example   map[string]any    `json:"example"`
}

type tlsDriftState struct {
	generation       int64
	ready            bool
	readyCondition   bool
	selectorRevision string
	replicas         int32
	replicasSet      bool
}

func TestOrbStackE2E(t *testing.T) {
	if os.Getenv("SUPEK8SMCP_E2E") != "1" {
		t.Skip("set SUPEK8SMCP_E2E=1 (test/e2e/run.sh does this) to run against OrbStack")
	}
	namespace := os.Getenv("SUPEK8SMCP_E2E_NAMESPACE")
	if namespace == "" {
		t.Fatal("SUPEK8SMCP_E2E_NAMESPACE is required; the runner owns the unique namespace")
	}
	if currentContext := strings.TrimSpace(mustKubectl(t, "config", "current-context")); currentContext != "orbstack" {
		t.Fatalf("refusing to run outside OrbStack context (got %q)", currentContext)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	h := &harness{t: t, namespace: namespace, clients: make(map[string]*mcpClient)}
	t.Cleanup(func() {
		for _, client := range h.clients {
			_ = client.session.Close()
			client.stopPF()
		}
	})

	h.assertDurationAdmission(ctx)
	h.applyClientRBAC(ctx)
	h.applyWorkloads(ctx)
	h.createServers(ctx)
	h.assertTLSSecretDrift(ctx, "mcp-e2e-readonly")
	h.assertStableReconcile(ctx, "mcp-e2e-readonly")
	h.assertServiceDriftConverges(ctx, "mcp-e2e-readonly")

	readOnly := h.connectServer(ctx, "mcp-e2e-readonly", 4)
	safeWrite := h.connectServer(ctx, "mcp-e2e-safewrite", 6)
	dangerous := h.connectServer(ctx, "mcp-e2e-dangerous", 6)

	h.readOnlyHelp(ctx, readOnly)
	h.safeWriteConfigMap(ctx, safeWrite)
	h.dangerousRemoteExecution(ctx, dangerous)
	h.dangerousFollowLogs(ctx, dangerous)
	h.secretReadIsRedacted(ctx, dangerous)
	h.assertDangerousAuditLog(ctx)
	h.assertDangerousMetrics(ctx, dangerous)
	h.assertIdentityRateLimit(ctx)
}

func (h *harness) assertDurationAdmission(ctx context.Context) {
	invalid := []struct {
		name     string
		duration string
	}{
		{name: "mcp-e2e-invalid-duration", duration: "definitely-invalid"},
		{name: "mcp-e2e-zero-duration", duration: "0s"},
		{name: "mcp-e2e-negative-duration", duration: "-1s"},
	}
	for _, testCase := range invalid {
		object := map[string]any{
			"apiVersion": "mcp.supek8smcp.io/v1alpha1",
			"kind":       "KubernetesMCPServer",
			"metadata":   map[string]any{"name": testCase.name, "namespace": h.namespace},
			"spec": map[string]any{
				"mode":  "ReadOnly",
				"scope": map[string]any{"namespaces": []string{h.namespace}},
				"limits": map[string]any{
					"requestTimeout": testCase.duration,
				},
			},
		}
		data, err := json.Marshal(object)
		if err != nil {
			h.t.Fatalf("marshal invalid duration object %s: %v", testCase.name, err)
		}
		if _, err := runCommand(ctx, h.t, bytes.NewReader(data), "kubectl", "apply", "-f", "-"); err == nil {
			h.t.Fatalf("CRD admission accepted invalid requestTimeout %q in %s", testCase.duration, testCase.name)
		}
		if _, err := h.tryKubectl(ctx, "get", "kubernetesmcpserver", testCase.name, "-n", h.namespace, "-o", "name"); err == nil {
			h.t.Fatalf("invalid duration object %s entered the Kubernetes API", testCase.name)
		}
		h.t.Logf("CRD admission rejected requestTimeout=%q without creating %s", testCase.duration, testCase.name)
	}
	invalidName := "mcp.e2e-invalid-name"
	object := map[string]any{
		"apiVersion": "mcp.supek8smcp.io/v1alpha1",
		"kind":       "KubernetesMCPServer",
		"metadata":   map[string]any{"name": invalidName, "namespace": h.namespace},
		"spec": map[string]any{
			"mode":  "ReadOnly",
			"scope": map[string]any{"namespaces": []string{h.namespace}},
		},
	}
	data, err := json.Marshal(object)
	if err != nil {
		h.t.Fatalf("marshal invalid metadata.name object %s: %v", invalidName, err)
	}
	if _, err := runCommand(ctx, h.t, bytes.NewReader(data), "kubectl", "apply", "-f", "-"); err == nil {
		h.t.Fatalf("CRD admission accepted metadata.name %q containing a dot", invalidName)
	}
	if _, err := h.tryKubectl(ctx, "get", "kubernetesmcpserver", invalidName, "-n", h.namespace, "-o", "name"); err == nil {
		h.t.Fatalf("invalid metadata.name object %s entered the Kubernetes API", invalidName)
	}
	h.t.Logf("CRD admission rejected metadata.name=%q without creating the object", invalidName)
}

func (h *harness) assertTLSSecretDrift(ctx context.Context, name string) {
	initial, ok := h.tlsDriftState(ctx, name)
	if !ok || !initial.readyCondition || !initial.ready {
		h.t.Fatalf("Server %s was not Ready before TLS Secret drift", name)
	}
	h.kubectl(ctx, "patch", "kubernetesmcpserver", name, "-n", h.namespace, "--type=merge", "-p", `{"spec":{"tls":{"secretName":"mcp-e2e-missing-tls"}}}`)

	disabledCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var disabled tlsDriftState
	for {
		state, stateOK := h.tlsDriftState(disabledCtx, name)
		if stateOK && state.generation > initial.generation && state.readyCondition && !state.ready && state.selectorRevision == "disabled" && state.replicasSet && state.replicas == 0 {
			disabled = state
			h.t.Logf("TLS Secret drift disabled %s: generation=%d Ready=False selectorRevision=%q replicas=%d", name, state.generation, state.selectorRevision, state.replicas)
			break
		}
		select {
		case <-disabledCtx.Done():
			h.t.Fatalf("Server %s did not enter the disabled TLS drift state: %v", name, disabledCtx.Err())
		case <-time.After(2 * time.Second):
		}
	}

	h.kubectl(ctx, "patch", "kubernetesmcpserver", name, "-n", h.namespace, "--type=json", "-p", `[{"op":"remove","path":"/spec/tls/secretName"}]`)
	restoredCtx, restoreCancel := context.WithTimeout(ctx, 90*time.Second)
	defer restoreCancel()
	for {
		state, stateOK := h.tlsDriftState(restoredCtx, name)
		if stateOK && state.generation > disabled.generation && state.readyCondition && state.ready && state.selectorRevision != "" && state.selectorRevision != "disabled" && state.replicasSet && state.replicas >= 1 {
			h.waitServerReady(restoredCtx, name)
			h.t.Logf("TLS Secret restore recovered %s: generation=%d Ready=True selectorRevision=%q replicas=%d", name, state.generation, state.selectorRevision, state.replicas)
			return
		}
		select {
		case <-restoredCtx.Done():
			h.t.Fatalf("Server %s did not recover after restoring managed TLS: %v", name, restoredCtx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

func (h *harness) tlsDriftState(ctx context.Context, name string) (tlsDriftState, bool) {
	serverRaw, err := h.tryKubectl(ctx, "get", "kubernetesmcpserver", name, "-n", h.namespace, "-o", "json")
	if err != nil {
		return tlsDriftState{}, false
	}
	serviceRaw, err := h.tryKubectl(ctx, "get", "service", name, "-n", h.namespace, "-o", "json")
	if err != nil {
		return tlsDriftState{}, false
	}
	deploymentRaw, err := h.tryKubectl(ctx, "get", "deployment", name, "-n", h.namespace, "-o", "json")
	if err != nil {
		return tlsDriftState{}, false
	}
	var server struct {
		Metadata struct {
			Generation int64 `json:"generation"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	}
	var service struct {
		Spec struct {
			Selector map[string]string `json:"selector"`
		} `json:"spec"`
	}
	var deployment struct {
		Spec struct {
			Replicas *int32 `json:"replicas"`
		} `json:"spec"`
	}
	if json.Unmarshal([]byte(serverRaw), &server) != nil || json.Unmarshal([]byte(serviceRaw), &service) != nil || json.Unmarshal([]byte(deploymentRaw), &deployment) != nil {
		return tlsDriftState{}, false
	}
	state := tlsDriftState{
		generation:       server.Metadata.Generation,
		selectorRevision: service.Spec.Selector["mcp.supek8smcp.io/revision"],
	}
	for _, condition := range server.Status.Conditions {
		if condition.Type == "Ready" {
			state.readyCondition = true
			state.ready = condition.Status == "True"
			break
		}
	}
	if deployment.Spec.Replicas != nil {
		state.replicasSet = true
		state.replicas = *deployment.Spec.Replicas
	}
	return state, true
}

func (h *harness) assertStableReconcile(ctx context.Context, name string) {
	beforeGeneration := h.deploymentGeneration(ctx, name)
	annotation := fmt.Sprintf("mcp.supek8smcp.io/e2e-reconcile=%d", time.Now().UnixNano())
	h.kubectl(ctx, "annotate", "kubernetesmcpserver", name, "-n", h.namespace, annotation, "--overwrite")

	stabilityCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	timer := time.NewTimer(8 * time.Second)
	select {
	case <-timer.C:
	case <-stabilityCtx.Done():
		h.t.Fatalf("waiting for annotation-triggered reconcile of %s: %v", name, stabilityCtx.Err())
	}
	h.waitServerReady(stabilityCtx, name)
	afterGeneration := h.deploymentGeneration(stabilityCtx, name)
	if afterGeneration != beforeGeneration {
		h.t.Fatalf("annotation-triggered reconcile changed %s Deployment generation from %d to %d", name, beforeGeneration, afterGeneration)
	}
	h.t.Logf("annotation-triggered reconcile kept %s Ready=True and Deployment generation=%d", name, afterGeneration)
}

func (h *harness) deploymentGeneration(ctx context.Context, name string) int64 {
	raw := h.kubectl(ctx, "get", "deployment", name, "-n", h.namespace, "-o", "json")
	var object struct {
		Metadata struct {
			Generation int64 `json:"generation"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(raw), &object); err != nil {
		h.t.Fatalf("decode Deployment %s: %v", name, err)
	}
	if object.Metadata.Generation < 1 {
		h.t.Fatalf("Deployment %s returned invalid generation %d", name, object.Metadata.Generation)
	}
	return object.Metadata.Generation
}

func (h *harness) assertServiceDriftConverges(ctx context.Context, name string) {
	patched := h.kubectl(ctx, "patch", "service", name, "-n", h.namespace, "--type=merge", "-p", `{"metadata":{"labels":{"app.kubernetes.io/managed-by":null}},"spec":{"type":"NodePort","externalIPs":["192.0.2.10"]}}`, "-o", "json")
	var patchedObject struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			Type        string   `json:"type"`
			ExternalIPs []string `json:"externalIPs"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(patched), &patchedObject); err != nil {
		h.t.Fatalf("decode patched Service %s: %v", name, err)
	}
	if patchedObject.Metadata.Labels["app.kubernetes.io/managed-by"] != "" || patchedObject.Spec.Type != "NodePort" || len(patchedObject.Spec.ExternalIPs) != 1 || patchedObject.Spec.ExternalIPs[0] != "192.0.2.10" {
		h.t.Fatalf("Service %s did not accept the drift patch: managedBy=%q type=%q externalIPs=%v", name, patchedObject.Metadata.Labels["app.kubernetes.io/managed-by"], patchedObject.Spec.Type, patchedObject.Spec.ExternalIPs)
	}

	reconcileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		raw, err := h.tryKubectl(reconcileCtx, "get", "service", name, "-n", h.namespace, "-o", "json")
		if err == nil {
			var service struct {
				Metadata struct {
					Labels map[string]string `json:"labels"`
				} `json:"metadata"`
				Spec struct {
					Type        string   `json:"type"`
					ExternalIPs []string `json:"externalIPs"`
					Ports       []struct {
						NodePort int32 `json:"nodePort"`
					} `json:"ports"`
				} `json:"spec"`
			}
			if json.Unmarshal([]byte(raw), &service) == nil {
				nodePorts := make([]int32, 0, len(service.Spec.Ports))
				allNodePortsZero := len(service.Spec.Ports) > 0
				for _, port := range service.Spec.Ports {
					nodePorts = append(nodePorts, port.NodePort)
					if port.NodePort != 0 {
						allNodePortsZero = false
					}
				}
				managedBy := service.Metadata.Labels["app.kubernetes.io/managed-by"]
				if managedBy == "supek8smcp-operator" && service.Spec.Type == "ClusterIP" && len(service.Spec.ExternalIPs) == 0 && allNodePortsZero {
					h.waitServerReady(reconcileCtx, name)
					h.t.Logf("Service drift converged for %s: managedBy=%s type=%s externalIPs=%v nodePorts=%v Ready=True", name, managedBy, service.Spec.Type, service.Spec.ExternalIPs, nodePorts)
					return
				}
			}
		}
		select {
		case <-reconcileCtx.Done():
			h.t.Fatalf("Service %s did not converge back to ClusterIP without external exposure: %v", name, reconcileCtx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

func (h *harness) readOnlyHelp(ctx context.Context, client *mcpClient) {
	indexResult := h.call(ctx, client, "k8s.help", map[string]any{})
	var index helpOutput
	h.decode(indexResult, &index)
	if index.Mode != "ReadOnly" {
		h.t.Fatalf("ReadOnly k8s.help index mode = %q, want ReadOnly", index.Mode)
	}
	if index.Manual != nil {
		h.t.Fatal("k8s.help index unexpectedly included a detailed manual")
	}
	expectedAvailability := map[string]bool{
		"k8s.help": true, "k8s.search": true, "k8s.describe": true, "k8s.read": true,
		"k8s.plan": false, "k8s.commit": false,
	}
	if len(index.Tools) != len(expectedAvailability) {
		h.t.Fatalf("k8s.help index returned %d tools, want %d", len(index.Tools), len(expectedAvailability))
	}
	for _, summary := range index.Tools {
		want, ok := expectedAvailability[summary.Name]
		if !ok {
			h.t.Fatalf("k8s.help index returned unexpected tool %q", summary.Name)
		}
		if summary.Available != want {
			h.t.Fatalf("k8s.help index availability for %s = %t, want %t", summary.Name, summary.Available, want)
		}
		delete(expectedAvailability, summary.Name)
	}
	if len(expectedAvailability) != 0 {
		h.t.Fatalf("k8s.help index omitted tools: %v", expectedAvailability)
	}

	detailResult := h.call(ctx, client, "k8s.help", map[string]any{"tool": "k8s.read"})
	var detail helpOutput
	h.decode(detailResult, &detail)
	if detail.Mode != "ReadOnly" {
		h.t.Fatalf("ReadOnly k8s.help detail mode = %q, want ReadOnly", detail.Mode)
	}
	if len(detail.Tools) != 0 {
		h.t.Fatalf("k8s.help detail repeated %d index tools, want none", len(detail.Tools))
	}
	if detail.Manual == nil || detail.Manual.Name != "k8s.read" {
		h.t.Fatalf("k8s.help detail returned manual %v, want only k8s.read", detail.Manual)
	}
	if !detail.Manual.Available || len(detail.Manual.Inputs) == 0 || len(detail.Manual.Steps) == 0 || len(detail.Manual.Example) == 0 {
		h.t.Fatalf("k8s.read manual is incomplete: available=%t inputs=%d steps=%d example=%d", detail.Manual.Available, len(detail.Manual.Inputs), len(detail.Manual.Steps), len(detail.Manual.Example))
	}
}

func (h *harness) safeWriteConfigMap(ctx context.Context, client *mcpClient) {
	search := h.call(ctx, client, "k8s.search", map[string]any{
		"query": "configmaps", "action": "create", "namespace": h.namespace, "limit": 50,
	})
	var capabilities searchOutput
	h.decode(search, &capabilities)
	create := findCapability(capabilities.Capabilities, "configmaps", "create")
	if create == nil {
		h.t.Fatal("SafeWrite search did not return a ConfigMap create capability")
	}
	plan := h.call(ctx, client, "k8s.plan", map[string]any{
		"capabilityId": create.ID, "namespace": h.namespace,
		"object": map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": "mcp-e2e-persisted", "labels": map[string]string{"e2e": "safe-write"}},
			"data":     map[string]string{"value": "created-by-safe-write"},
		},
	})
	var planned planOutput
	h.decode(plan, &planned)
	if planned.PlanID == "" {
		h.t.Fatal("SafeWrite plan returned no planId")
	}
	missingConfirmation := map[string]any{"planId": planned.PlanID}
	h.callExpectError(ctx, client, "k8s.commit", missingConfirmation)
	wrongConfirmation := "100000"
	if wrongConfirmation == planned.Confirmation.Code {
		wrongConfirmation = "100001"
	}
	h.callExpectError(ctx, client, "k8s.commit", map[string]any{"planId": planned.PlanID, "confirmationCode": wrongConfirmation})
	h.assertConfigMapAbsent(ctx, "mcp-e2e-persisted")
	h.call(ctx, client, "k8s.commit", h.confirmationCommitArguments(planned))
	h.assertConfigMap(ctx, "mcp-e2e-persisted", "created-by-safe-write")

	search = h.call(ctx, client, "k8s.search", map[string]any{
		"query": "configmaps", "action": "patch", "namespace": h.namespace, "limit": 50,
	})
	h.decode(search, &capabilities)
	patch := findCapability(capabilities.Capabilities, "configmaps", "patch")
	if patch == nil {
		h.t.Fatal("SafeWrite search did not return a ConfigMap patch capability")
	}
	plan = h.call(ctx, client, "k8s.plan", map[string]any{
		"capabilityId": patch.ID, "namespace": h.namespace, "name": "mcp-e2e-persisted",
		"patchType": "merge", "patch": map[string]any{"data": map[string]string{"value": "modified-by-safe-write"}},
	})
	h.decode(plan, &planned)
	wrongConfirmation = "100000"
	if wrongConfirmation == planned.Confirmation.Code {
		wrongConfirmation = "100001"
	}
	h.callExpectError(ctx, client, "k8s.commit", map[string]any{"planId": planned.PlanID, "confirmationCode": wrongConfirmation})
	h.assertConfigMap(ctx, "mcp-e2e-persisted", "created-by-safe-write")
	h.call(ctx, client, "k8s.commit", h.confirmationCommitArguments(planned))
	h.assertConfigMap(ctx, "mcp-e2e-persisted", "modified-by-safe-write")
}

func (h *harness) dangerousRemoteExecution(ctx context.Context, client *mcpClient) {
	search := h.call(ctx, client, "k8s.search", map[string]any{
		"query": "pods", "action": "exec", "namespace": h.namespace, "limit": 50,
	})
	var capabilities searchOutput
	h.decode(search, &capabilities)
	execCapability := findCapability(capabilities.Capabilities, "pods", "exec")
	if execCapability == nil {
		all := h.call(ctx, client, "k8s.search", map[string]any{"query": "pods", "namespace": h.namespace, "limit": 100})
		var allCapabilities searchOutput
		h.decode(all, &allCapabilities)
		h.t.Fatalf("Dangerous search did not return a Pod exec capability (filtered=%v all=%v)", capabilitySummary(capabilities.Capabilities), capabilitySummary(allCapabilities.Capabilities))
	}
	plan := h.call(ctx, client, "k8s.plan", map[string]any{
		"capabilityId": execCapability.ID, "namespace": h.namespace, "name": workerPod,
		"container": "worker", "command": []string{"sh", "-c", "printf exec-ok"}, "timeoutSeconds": 5,
	})
	var planned planOutput
	h.decode(plan, &planned)
	result := h.call(ctx, client, "k8s.commit", h.confirmationCommitArguments(planned))
	var commit struct {
		Result struct {
			Stdout string `json:"stdout"`
			Stderr string `json:"stderr"`
		} `json:"result"`
	}
	h.decode(result, &commit)
	if !strings.Contains(commit.Result.Stdout, "exec-ok") {
		h.t.Fatalf("Dangerous exec did not return expected stdout")
	}

	search = h.call(ctx, client, "k8s.search", map[string]any{
		"query": "pods", "action": "attach", "namespace": h.namespace, "limit": 50,
	})
	h.decode(search, &capabilities)
	attachCapability := findCapability(capabilities.Capabilities, "pods", "attach")
	if attachCapability == nil {
		h.t.Fatalf("Dangerous search did not return a Pod attach capability (got %v)", capabilitySummary(capabilities.Capabilities))
	}
	plan = h.call(ctx, client, "k8s.plan", map[string]any{
		"capabilityId": attachCapability.ID, "namespace": h.namespace, "name": attachPod,
		"container": "attach", "stdin": "attach-input", "timeoutSeconds": 8,
	})
	h.decode(plan, &planned)
	result = h.call(ctx, client, "k8s.commit", h.confirmationCommitArguments(planned))
	h.decode(result, &commit)
	if !strings.Contains(commit.Result.Stdout, "attach-ok") {
		h.t.Fatalf("Dangerous attach did not return expected stdout (stdout=%q stderr=%q)", commit.Result.Stdout, commit.Result.Stderr)
	}
}

func (h *harness) dangerousFollowLogs(ctx context.Context, client *mcpClient) {
	search := h.call(ctx, client, "k8s.search", map[string]any{
		"query": "pods", "action": "logs", "namespace": h.namespace, "limit": 50,
	})
	var capabilities searchOutput
	h.decode(search, &capabilities)
	logsCapability := findCapability(capabilities.Capabilities, "pods", "logs")
	if logsCapability == nil {
		h.t.Fatalf("Dangerous search did not return a Pod logs capability (got %v)", capabilitySummary(capabilities.Capabilities))
	}
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	started := time.Now()
	result := h.call(callCtx, client, "k8s.read", map[string]any{
		"capabilityId": logsCapability.ID, "namespace": h.namespace, "name": workerPod,
		"container": "worker", "follow": true, "tailLines": int64(1),
	})
	elapsed := time.Since(started)
	if elapsed < 2*time.Second || elapsed > 8*time.Second {
		h.t.Fatalf("followed logs ended after %s; expected the 3s server stream timeout", elapsed.Round(100*time.Millisecond))
	}
	var logs struct {
		Logs []string `json:"logs"`
	}
	h.decode(result, &logs)
	if len(logs.Logs) == 0 {
		h.t.Fatal("followed logs returned no streamed lines")
	}
}

func (h *harness) secretReadIsRedacted(ctx context.Context, client *mcpClient) {
	search := h.call(ctx, client, "k8s.search", map[string]any{
		"query": "secrets", "action": "get", "namespace": h.namespace, "limit": 50,
	})
	var capabilities searchOutput
	h.decode(search, &capabilities)
	secretCapability := findCapability(capabilities.Capabilities, "secrets", "get")
	if secretCapability == nil {
		h.t.Fatalf("Dangerous search did not return a Secret get capability (got %v)", capabilitySummary(capabilities.Capabilities))
	}
	result := h.call(ctx, client, "k8s.read", map[string]any{
		"capabilityId": secretCapability.ID, "namespace": h.namespace, "name": secretName,
	})
	raw, err := json.Marshal(result)
	if err != nil {
		h.t.Fatalf("marshal Secret response: %v", err)
	}
	containsMarker := bytes.Contains(raw, []byte(secretMarker))
	var secret map[string]any
	h.decode(result, &secret)
	data, _ := secret["data"].(map[string]any)
	redacted, _ := data["marker"].(string)
	if containsMarker || redacted != "<redacted>" {
		h.t.Fatalf("Secret response did not preserve redaction, or leaked the marker (marker=%t redacted=%t)", containsMarker, redacted == "<redacted>")
	}
}

func (h *harness) assertDangerousAuditLog(ctx context.Context) {
	logs := h.kubectl(ctx, "logs", "deployment/mcp-e2e-dangerous", "-n", h.namespace, "-c", "server")
	for _, required := range []string{
		`"audit_schema":"v1"`,
		`"tool":"k8s.commit"`,
		`"tool":"k8s.read"`,
		`"target_name":"mcp-e2e-worker"`,
		`"target_name":"mcp-e2e-attach"`,
	} {
		if !strings.Contains(logs, required) {
			h.t.Fatalf("Dangerous server audit log is missing %s", required)
		}
	}
	if strings.Contains(logs, h.token) || strings.Contains(logs, secretMarker) {
		h.t.Fatal("Dangerous server audit log contains a bearer token or Secret marker")
	}
}

func (h *harness) assertDangerousMetrics(ctx context.Context, _ *mcpClient) {
	localPort := freePort(h.t)
	stopPF := startPortForwardTo(ctx, h.t, h.namespace, "mcp-e2e-dangerous", localPort, 9090)
	defer stopPF()
	body := h.fetchMetrics(ctx, localPort)
	for _, sample := range []struct {
		name     string
		fragment string
	}{
		{name: "supek8smcp_authentication_attempts_total", fragment: `decision="allow"`},
		{name: "supek8smcp_audit_events_total", fragment: `decision="allow"`},
		{name: "supek8smcp_tool_calls_total", fragment: `result="ok"`},
	} {
		if !metricHasSample(body, sample.name, sample.fragment) {
			h.t.Fatalf("Dangerous /metrics is missing an %s sample containing %s", sample.name, sample.fragment)
		}
	}
}

func (h *harness) assertIdentityRateLimit(ctx context.Context) {
	client, endpoint, stopPF := h.startVerifiedHTTPS(ctx, "mcp-e2e-ratelimit", 8443)
	defer stopPF()
	firstStatus, _ := h.rawHTTPSStatus(ctx, client, endpoint, h.token)
	if firstStatus == http.StatusTooManyRequests {
		h.t.Fatalf("first request for the primary identity was unexpectedly rate-limited")
	}
	secondStatus, retryAfter := h.rawHTTPSStatus(ctx, client, endpoint, h.token)
	if secondStatus != http.StatusTooManyRequests {
		h.t.Fatalf("second request for the primary identity returned HTTP %d, want 429", secondStatus)
	}
	retrySeconds, err := strconv.Atoi(strings.TrimSpace(retryAfter))
	if err != nil || retrySeconds <= 0 {
		h.t.Fatalf("rate-limited response Retry-After = %q, want a positive number", retryAfter)
	}
	secondaryStatus, _ := h.rawHTTPSStatus(ctx, client, endpoint, h.secondaryToken)
	if secondaryStatus == http.StatusTooManyRequests {
		h.t.Fatalf("first request for the secondary identity was unexpectedly rate-limited")
	}
	metricsPort := freePort(h.t)
	metricsStop := startPortForwardTo(ctx, h.t, h.namespace, "mcp-e2e-ratelimit", metricsPort, 9090)
	defer metricsStop()
	metrics := h.fetchMetrics(ctx, metricsPort)
	if !metricHasSample(metrics, "supek8smcp_rate_limit_rejections_total", `reason="identity_rate"`) {
		h.t.Fatal("rate-limit Server /metrics is missing an identity_rate rejection sample")
	}
}

func (h *harness) rawHTTPSStatus(ctx context.Context, client *http.Client, endpoint, token string) (int, string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		h.t.Fatalf("construct raw HTTPS request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		h.t.Fatalf("raw HTTPS request failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode, response.Header.Get("Retry-After")
}

func (h *harness) fetchMetrics(ctx context.Context, localPort int) string {
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/metrics", localPort)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		h.t.Fatalf("construct metrics request: %v", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatalf("GET %s failed: %v", endpoint, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Fatalf("read %s response: %v", endpoint, err)
	}
	if response.StatusCode != http.StatusOK {
		h.t.Fatalf("GET %s returned HTTP %d, want 200", endpoint, response.StatusCode)
	}
	return string(body)
}

func metricHasSample(body, name, fragment string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+"{") && strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}
