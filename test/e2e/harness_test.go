package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	clientServiceAccount          = "mcp-e2e-client"
	secondaryClientServiceAccount = "mcp-e2e-client-2"
	workerPod                     = "mcp-e2e-worker"
	attachPod                     = "mcp-e2e-attach"
	secretName                    = "mcp-e2e-secret"
	secretMarker                  = "mcp-e2e-secret-marker"
)

type harness struct {
	t              *testing.T
	namespace      string
	token          string
	secondaryToken string
	clients        map[string]*mcpClient
}

type mcpClient struct {
	session *mcp.ClientSession
	stopPF  func()
	token   string
}

type capability struct {
	ID          string `json:"id"`
	Group       string `json:"group"`
	Version     string `json:"version"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource"`
	Kind        string `json:"kind"`
	Action      string `json:"action"`
	Verb        string `json:"verb"`
	Namespaced  bool   `json:"namespaced"`
}

type searchOutput struct {
	Capabilities []capability `json:"capabilities"`
}

type planOutput struct {
	PlanID string `json:"planId"`
}

type serverStatus struct {
	Endpoint       string
	CAConfigMap    string
	Ready          bool
	ConditionError string
}

func (h *harness) applyClientRBAC(ctx context.Context) {
	for _, serviceAccount := range []string{clientServiceAccount, secondaryClientServiceAccount} {
		h.apply(ctx, map[string]any{
			"apiVersion": "v1", "kind": "ServiceAccount",
			"metadata": map[string]any{"name": serviceAccount, "namespace": h.namespace},
		})
	}
	h.apply(ctx, map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
		"metadata": map[string]any{"name": "mcp-e2e-client", "namespace": h.namespace},
		"rules": []any{map[string]any{
			"apiGroups": []string{""},
			"resources": []string{"configmaps", "pods", "pods/log", "pods/exec", "pods/attach", "secrets"},
			"verbs":     []string{"get", "list", "watch", "create", "update", "patch"},
		}},
	})
	for _, serviceAccount := range []string{clientServiceAccount, secondaryClientServiceAccount} {
		h.apply(ctx, map[string]any{
			"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
			"metadata": map[string]any{"name": serviceAccount, "namespace": h.namespace},
			"roleRef": map[string]any{
				"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "mcp-e2e-client",
			},
			"subjects": []any{map[string]any{
				"apiGroup": "", "kind": "ServiceAccount", "name": serviceAccount, "namespace": h.namespace,
			}},
		})
	}
	h.token = strings.TrimSpace(h.kubectl(ctx, "create", "token", clientServiceAccount, "-n", h.namespace, "--duration=1h"))
	h.secondaryToken = strings.TrimSpace(h.kubectl(ctx, "create", "token", secondaryClientServiceAccount, "-n", h.namespace, "--duration=10m"))
	if h.token == "" || h.secondaryToken == "" {
		h.t.Fatal("kubectl create token returned an empty token")
	}
}

func (h *harness) applyWorkloads(ctx context.Context) {
	h.apply(ctx, map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "mcp-e2e-input", "namespace": h.namespace},
		"data":     map[string]string{"initial": "before-safe-write"},
	})
	h.apply(ctx, map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata":   map[string]any{"name": secretName, "namespace": h.namespace},
		"stringData": map[string]string{"marker": secretMarker},
	})
	h.apply(ctx, map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": workerPod, "namespace": h.namespace, "labels": map[string]string{"app": "mcp-e2e-worker"},
		},
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name": "worker", "image": "alpine:3.20", "imagePullPolicy": "IfNotPresent",
				"command": []string{"sh", "-c", "i=0; while true; do i=$((i+1)); echo heartbeat-$i; sleep 1; done"},
			}},
		},
	})
	h.apply(ctx, map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": attachPod, "namespace": h.namespace},
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name": "attach", "image": "alpine:3.20", "imagePullPolicy": "IfNotPresent",
				"stdin": true, "stdinOnce": true,
				"command": []string{"sh", "-c", "cat >/dev/null; printf attach-ok"},
			}},
		},
	})
	h.waitPodRunning(ctx, workerPod)
	h.waitPodRunning(ctx, attachPod)
}

func (h *harness) createServers(ctx context.Context) {
	servers := []struct {
		name   string
		mode   string
		limits map[string]any
	}{
		{name: "mcp-e2e-readonly", mode: "ReadOnly", limits: map[string]any{
			"requestsPerMinute": int64(6000), "burst": int64(100),
		}},
		{name: "mcp-e2e-safewrite", mode: "SafeWrite", limits: map[string]any{
			"requestsPerMinute": int64(6000), "burst": int64(100),
		}},
		{name: "mcp-e2e-dangerous", mode: "Dangerous", limits: map[string]any{
			"requestTimeout": "15s", "streamTimeout": "3s", "execTimeout": "8s",
			"requestsPerMinute": int64(6000), "burst": int64(100),
		}},
		{name: "mcp-e2e-ratelimit", mode: "ReadOnly", limits: map[string]any{
			"requestsPerMinute": int64(1), "burst": int64(1),
		}},
	}
	for _, server := range servers {
		spec := map[string]any{
			"mode":          server.mode,
			"scope":         map[string]any{"namespaces": []string{h.namespace}},
			"policy":        map[string]any{"sensitiveReads": "Redact"},
			"networkPolicy": map[string]any{"enabled": false},
		}
		if len(server.limits) > 0 {
			spec["limits"] = server.limits
		}
		h.apply(ctx, map[string]any{
			"apiVersion": "mcp.supek8smcp.io/v1alpha1", "kind": "KubernetesMCPServer",
			"metadata": map[string]any{"name": server.name, "namespace": h.namespace}, "spec": spec,
		})
		h.waitServerReady(ctx, server.name)
	}
}

func (h *harness) connectServer(ctx context.Context, name string, wantTools int) *mcpClient {
	verified, endpoint, stopPF := h.startVerifiedHTTPS(ctx, name, 8443)
	unauthenticatedRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		stopPF()
		h.t.Fatalf("construct unauthenticated request for %s: %v", name, err)
	}
	unauthenticatedResponse, err := verified.Do(unauthenticatedRequest)
	if err != nil {
		stopPF()
		h.t.Fatalf("TLS request without bearer token for %s failed: %v", name, err)
	}
	_, _ = io.Copy(io.Discard, unauthenticatedResponse.Body)
	_ = unauthenticatedResponse.Body.Close()
	if unauthenticatedResponse.StatusCode != http.StatusUnauthorized {
		stopPF()
		h.t.Fatalf("request without bearer token for %s returned HTTP %d, want 401", name, unauthenticatedResponse.StatusCode)
	}
	client := &http.Client{Transport: bearerTransport{base: verified.Transport, token: h.token}, Timeout: 90 * time.Second}
	sdkClient := mcp.NewClient(&mcp.Implementation{Name: "supek8smcp-e2e", Version: "test"}, nil)
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	session, err := sdkClient.Connect(connectCtx, &mcp.StreamableClientTransport{
		Endpoint: endpoint, HTTPClient: client, MaxRetries: 0,
		DisableStandaloneSSE: true,
	}, nil)
	cancel()
	if err != nil {
		stopPF()
		h.t.Fatalf("connect to %s over verified TLS failed: %v", name, err)
	}
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		_ = session.Close()
		stopPF()
		h.t.Fatalf("list tools for %s: %v", name, err)
	}
	got := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		got = append(got, tool.Name)
	}
	sort.Strings(got)
	want := []string{"k8s.describe", "k8s.help", "k8s.read", "k8s.search"}
	if wantTools == 6 {
		want = append(want, "k8s.commit", "k8s.plan")
	}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		_ = session.Close()
		stopPF()
		h.t.Fatalf("%s tool boundary = %v, want exactly %v", name, got, want)
	}
	connected := &mcpClient{session: session, stopPF: stopPF, token: h.token}
	h.clients[name] = connected
	return connected
}

func (h *harness) startVerifiedHTTPS(ctx context.Context, name string, remotePort int) (*http.Client, string, func()) {
	status := h.waitServerReady(ctx, name)
	caData := h.kubectl(ctx, "get", "configmap", status.CAConfigMap, "-n", h.namespace, "-o", "json")
	var caObject struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(caData), &caObject); err != nil {
		h.t.Fatalf("decode CA ConfigMap for %s: %v", name, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caObject.Data["ca.crt"])) {
		h.t.Fatalf("CA ConfigMap for %s did not contain a valid ca.crt", name)
	}
	localPort := freePort(h.t)
	stopPF := startPortForwardTo(ctx, h.t, h.namespace, name, localPort, remotePort)
	serviceDNS := fmt.Sprintf("%s.%s.svc", name, h.namespace)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serviceDNS}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	endpoint := fmt.Sprintf("https://127.0.0.1:%d/mcp", localPort)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, endpoint, stopPF
}

func (h *harness) assertConfigMap(ctx context.Context, name, want string) {
	raw := h.kubectl(ctx, "get", "configmap", name, "-n", h.namespace, "-o", "json")
	var object struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &object); err != nil {
		h.t.Fatalf("decode ConfigMap %s: %v", name, err)
	}
	if object.Data["value"] != want {
		h.t.Fatalf("ConfigMap %s value = %q, want %q", name, object.Data["value"], want)
	}
}

func (h *harness) waitServerReady(ctx context.Context, name string) serverStatus {
	var last serverStatus
	for {
		raw, err := h.tryKubectl(ctx, "get", "kubernetesmcpserver", name, "-n", h.namespace, "-o", "json")
		if err == nil {
			var object struct {
				Status struct {
					Endpoint    string `json:"endpoint"`
					CAConfigMap string `json:"caConfigMapName"`
					Conditions  []struct {
						Type    string `json:"type"`
						Status  string `json:"status"`
						Message string `json:"message"`
					} `json:"conditions"`
				} `json:"status"`
			}
			if json.Unmarshal([]byte(raw), &object) == nil {
				last.Endpoint, last.CAConfigMap = object.Status.Endpoint, object.Status.CAConfigMap
				for _, condition := range object.Status.Conditions {
					if condition.Type == "Ready" {
						last.Ready = condition.Status == "True"
						last.ConditionError = condition.Message
					}
				}
			}
		}
		if last.Ready && last.Endpoint != "" && last.CAConfigMap != "" {
			return last
		}
		select {
		case <-ctx.Done():
			if last.ConditionError != "" {
				h.t.Fatalf("MCP server %s did not become Ready: %s", name, last.ConditionError)
			}
			h.t.Fatalf("MCP server %s did not become Ready before timeout", name)
		case <-time.After(2 * time.Second):
		}
	}
}

func (h *harness) waitPodRunning(ctx context.Context, name string) {
	for {
		raw, err := h.tryKubectl(ctx, "get", "pod", name, "-n", h.namespace, "-o", "json")
		if err == nil {
			var object struct {
				Status struct {
					Phase string `json:"phase"`
				} `json:"status"`
			}
			if json.Unmarshal([]byte(raw), &object) == nil && object.Status.Phase == "Running" {
				return
			}
		}
		select {
		case <-ctx.Done():
			h.t.Fatalf("Pod %s did not become Running before timeout", name)
		case <-time.After(2 * time.Second):
		}
	}
}

func (h *harness) call(ctx context.Context, client *mcpClient, name string, arguments map[string]any) *mcp.CallToolResult {
	result, err := client.session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		h.t.Fatalf("MCP tool %s failed at protocol level: %v", name, err)
	}
	if result == nil || result.IsError {
		h.t.Fatalf("MCP tool %s returned an error result", name)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		h.t.Fatalf("marshal MCP tool %s result: %v", name, err)
	}
	if bytes.Contains(raw, []byte(client.token)) {
		h.t.Fatalf("MCP tool %s echoed the bearer token", name)
	}
	return result
}

func (h *harness) decode(result *mcp.CallToolResult, target any) {
	if result.StructuredContent == nil {
		h.t.Fatal("MCP tool returned no structured content")
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		h.t.Fatalf("marshal structured MCP result: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		h.t.Fatalf("decode structured MCP result: %v", err)
	}
}

func (h *harness) apply(ctx context.Context, object map[string]any) {
	data, err := json.Marshal(object)
	if err != nil {
		h.t.Fatalf("marshal Kubernetes object: %v", err)
	}
	if _, err := runCommand(ctx, h.t, bytes.NewReader(data), "kubectl", "apply", "-f", "-"); err != nil {
		h.t.Fatalf("apply Kubernetes object: %v", err)
	}
}

func (h *harness) kubectl(ctx context.Context, args ...string) string {
	output, err := runCommand(ctx, h.t, nil, "kubectl", args...)
	if err != nil {
		h.t.Fatalf("kubectl %s failed: %v", strings.Join(args, " "), err)
	}
	return output
}

func (h *harness) tryKubectl(ctx context.Context, args ...string) (string, error) {
	return runCommand(ctx, h.t, nil, "kubectl", args...)
}

func mustKubectl(t *testing.T, args ...string) string {
	output, err := runCommand(context.Background(), t, nil, "kubectl", args...)
	if err != nil {
		t.Fatalf("kubectl %s failed: %v", strings.Join(args, " "), err)
	}
	return output
}

func runCommand(ctx context.Context, t *testing.T, stdin io.Reader, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("%s timed out", name)
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("%s: %s", name, sanitize(message))
	}
	return stdout.String(), nil
}

func sanitize(message string) string {
	message = strings.ReplaceAll(message, secretMarker, "<secret-marker>")
	return message
}

func findCapability(capabilities []capability, resource, action string) *capability {
	for index := range capabilities {
		if capabilities[index].Resource == resource && capabilities[index].Action == action && capabilities[index].Subresource == "" {
			copy := capabilities[index]
			return &copy
		}
		if resource == "pods" && capabilities[index].Resource == resource && capabilities[index].Action == action && capabilities[index].Subresource != "" {
			copy := capabilities[index]
			return &copy
		}
	}
	return nil
}

func capabilitySummary(capabilities []capability) []string {
	result := make([]string, 0, len(capabilities))
	for _, item := range capabilities {
		result = append(result, item.Resource+"/"+item.Subresource+":"+item.Action)
	}
	return result
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

func freePort(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func startPortForwardTo(ctx context.Context, t *testing.T, namespace, service string, localPort, remotePort int) func() {
	command := exec.CommandContext(ctx, "kubectl", "-n", namespace, "port-forward", "service/"+service, fmt.Sprintf("%d:%d", localPort, remotePort))
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start port-forward for %s: %v", service, err)
	}
	ready := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 300*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			ready = true
			break
		}
		if command.ProcessState != nil && command.ProcessState.Exited() {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("port-forward for %s did not become ready: %s", service, sanitize(strings.TrimSpace(stderr.String())))
	}
	return func() {
		if command.Process != nil && command.ProcessState == nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}
}
