package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	remotecommandconsts "k8s.io/apimachinery/pkg/util/remotecommand"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

func TestRemoteCommitStreamCapacityPreservesPlan(t *testing.T) {
	app := &App{plans: NewPlanStore(4), admission: newRequestAdmission(2)}
	principal := &Principal{Username: "alice", UID: "uid-a"}
	operation := Operation{
		Action: Action{
			GVR:         schema.GroupVersionResource{Version: "v1", Resource: "pods"},
			Kind:        "Pod",
			Subresource: "exec",
			Verb:        "create",
			Action:      "exec",
			Namespaced:  true,
		},
		Namespace: "workloads", Name: "worker", Command: []string{"true"},
	}
	planID, confirmationCode, _, err := app.plans.Create(principal.SubjectKey(), operation)
	if err != nil {
		t.Fatalf("plans.Create() error = %v", err)
	}
	occupiedRelease, err := app.acquireStream()
	if err != nil {
		t.Fatalf("acquireStream() error = %v", err)
	}

	if _, err := app.commit(context.Background(), nil, principal, CommitInput{PlanID: planID, ConfirmationCode: confirmationCode}); policyReason(err) != "stream_capacity" {
		t.Fatalf("commit() error = %v, want stream_capacity while stream capacity is full", err)
	}
	occupiedRelease()

	got, err := app.plans.Consume(planID, principal.SubjectKey(), confirmationCode)
	if err != nil {
		t.Fatalf("Consume() after releasing stream capacity error = %v, want original plan to remain", err)
	}
	if got.Action.Action != operation.Action.Action || got.Namespace != operation.Namespace || got.Name != operation.Name {
		t.Fatalf("Consume() operation = %#v, want preserved operation %#v", got, operation)
	}
}

func TestRemoteCommitErrorPreservesPartialStreamsForExecAndAttach(t *testing.T) {
	for _, actionName := range []string{"exec", "attach"} {
		actionName := actionName
		t.Run(actionName, func(t *testing.T) {
			server := newRemoteErrorServer()
			defer server.Close()

			base := &rest.Config{Host: server.URL}
			kubernetesClient, err := kubernetes.NewForConfig(base)
			if err != nil {
				t.Fatalf("kubernetes.NewForConfig() error = %v", err)
			}
			principal := &Principal{
				Username: "alice", UID: "uid-a", Config: rest.CopyConfig(base), Kubernetes: kubernetesClient,
				Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
			}
			cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)
			cfg.Spec.Limits.RequestTimeout = metav1.Duration{Duration: 2 * time.Second}
			cfg.Spec.Limits.ExecTimeout = metav1.Duration{Duration: 2 * time.Second}
			cfg.Spec.Limits.MaxOutputBytes = 1 << 10
			app := newAuditTestApp(slog.Default())
			app.config = cfg
			app.policy = NewPolicy(cfg)
			app.plans = NewPlanStore(4)

			action := policyTestAction("", "pods", "create", actionName, true)
			action.Subresource = actionName
			op := Operation{
				Action: action, Namespace: "workloads", Name: "worker", Generation: cfg.Generation,
				Container: "main", Command: []string{"false"},
			}
			if actionName == "attach" {
				op.Command = nil
			}
			planID, confirmationCode, _, err := app.plans.Create(principal.SubjectKey(), op)
			if err != nil {
				t.Fatalf("plans.Create() error = %v", err)
			}
			output, err := app.commit(context.Background(), nil, principal, CommitInput{PlanID: planID, ConfirmationCode: confirmationCode})
			if err == nil {
				t.Fatal("commit() succeeded despite a non-zero remote exit")
			}
			partial, ok := output.Result.(map[string]any)
			if !ok {
				t.Fatalf("commit() result = %#v, want structured partial remote result alongside error %v", output.Result, err)
			}
			if partial["stdout"] != "stdout-before-exit" || partial["stderr"] != "stderr-before-exit" {
				t.Fatalf("commit() partial result = %#v, want stdout/stderr retained", partial)
			}
			if exitError, ok := partial["error"].(string); !ok || !strings.Contains(exitError, "17") {
				t.Fatalf("commit() partial error = %#v, want structured exit status 17", partial["error"])
			}
			if exitCode, ok := partial["exitCode"].(int); !ok || exitCode != 17 {
				t.Fatalf("commit() partial exitCode = %#v, want 17", partial["exitCode"])
			}

			// The MCP-facing error result must carry the same structured partial
			// result; a plain error string is not enough for an operator to act on.
			planID, confirmationCode, _, err = app.plans.Create(principal.SubjectKey(), op)
			if err != nil {
				t.Fatalf("plans.Create(second) error = %v", err)
			}
			mcpServer := app.newMCPServer(principal)
			serverTransport, clientTransport := mcp.NewInMemoryTransports()
			serverSession, err := mcpServer.Connect(context.Background(), serverTransport, nil)
			if err != nil {
				t.Fatalf("server.Connect() error = %v", err)
			}
			defer serverSession.Close()
			client := mcp.NewClient(&mcp.Implementation{Name: "remote-error-test-client", Version: "test"}, nil)
			clientSession, err := client.Connect(context.Background(), clientTransport, nil)
			if err != nil {
				t.Fatalf("client.Connect() error = %v", err)
			}
			defer clientSession.Close()
			result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      toolCommit,
				Arguments: map[string]any{"planId": planID, "confirmationCode": confirmationCode},
			})
			if err != nil {
				t.Fatalf("CallTool(k8s.commit) protocol error = %v", err)
			}
			if result == nil || !result.IsError {
				t.Fatalf("CallTool(k8s.commit) result = %#v, want an error result", result)
			}
			assertStructuredRemoteResult(t, result.StructuredContent)
		})
	}
}

func assertStructuredRemoteResult(t *testing.T, structured any) {
	t.Helper()
	if structured == nil {
		t.Fatal("MCP error result has no structuredContent")
	}
	data, err := json.Marshal(structured)
	if err != nil {
		t.Fatalf("marshal MCP error structuredContent: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode MCP error structuredContent %q: %v", data, err)
	}
	for key, want := range map[string]string{
		"stdout": "stdout-before-exit",
		"stderr": "stderr-before-exit",
	} {
		if got, ok := nestedString(payload, key); !ok || got != want {
			t.Fatalf("MCP error structuredContent[%q] = %q (present=%v), want %q; payload=%#v", key, got, ok, want, payload)
		}
	}
	if exitError, ok := nestedString(payload, "error"); !ok || !strings.Contains(exitError, "17") {
		t.Fatalf("MCP error structuredContent exit error = %q (present=%v), want exit status 17; payload=%#v", exitError, ok, payload)
	}
	if exitCode, ok := nestedNumber(payload, "exitCode"); !ok || exitCode != 17 {
		t.Fatalf("MCP error structuredContent exitCode = %v (present=%v), want 17; payload=%#v", exitCode, ok, payload)
	}
}

func nestedString(value any, key string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if candidate, ok := typed[key].(string); ok {
			return candidate, true
		}
		for _, child := range typed {
			if found, ok := nestedString(child, key); ok {
				return found, true
			}
		}
	case []any:
		for _, child := range typed {
			if found, ok := nestedString(child, key); ok {
				return found, true
			}
		}
	}
	return "", false
}

func nestedNumber(value any, key string) (float64, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if candidate, ok := typed[key].(float64); ok {
			return candidate, true
		}
		for _, child := range typed {
			if found, ok := nestedNumber(child, key); ok {
				return found, true
			}
		}
	case []any:
		for _, child := range typed {
			if found, ok := nestedNumber(child, key); ok {
				return found, true
			}
		}
	}
	return 0, false
}

func newRemoteErrorServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/selfsubjectaccessreviews"):
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(writer, `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","status":{"allowed":true}}`)
		case strings.HasSuffix(request.URL.Path, "/exec"), strings.HasSuffix(request.URL.Path, "/attach"):
			serveRemoteErrorStreams(writer, request)
		default:
			http.NotFound(writer, request)
		}
	}))
}

func serveRemoteErrorStreams(writer http.ResponseWriter, request *http.Request) {
	if _, err := httpstream.Handshake(request, writer, []string{remotecommandconsts.StreamProtocolV4Name}); err != nil {
		return
	}
	upgrader := spdy.NewResponseUpgrader()
	streamCh := make(chan httpstream.Stream, 4)
	conn := upgrader.UpgradeResponse(writer, request, func(stream httpstream.Stream, _ <-chan struct{}) error {
		streamCh <- stream
		return nil
	})
	defer conn.Close()

	var stdout, stderr, status httpstream.Stream
	for received := 0; received < 3; received++ {
		stream := <-streamCh
		switch stream.Headers().Get(corev1.StreamType) {
		case corev1.StreamTypeStdout:
			stdout = stream
		case corev1.StreamTypeStderr:
			stderr = stream
		case corev1.StreamTypeError:
			status = stream
		}
	}
	if stdout == nil || stderr == nil || status == nil {
		return
	}
	_, _ = io.WriteString(stdout, "stdout-before-exit")
	_, _ = io.WriteString(stderr, "stderr-before-exit")
	statusBody, _ := json.Marshal((&apierrors.StatusError{ErrStatus: metav1.Status{
		Status: metav1.StatusFailure,
		Reason: remotecommandconsts.NonZeroExitCodeReason,
		Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{{
			Type: remotecommandconsts.ExitCodeCauseType, Message: "17",
		}}},
		Message: "command terminated with non-zero exit code: 17",
	}}).Status())
	_, _ = status.Write(statusBody)
}
