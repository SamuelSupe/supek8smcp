package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

func (a *App) executeRemote(ctx context.Context, request *mcp.CallToolRequest, principal *Principal, operation Operation) (map[string]any, error) {
	streamCtx, cancel := context.WithTimeout(ctx, a.remoteTimeout(operation.TimeoutSeconds))
	defer cancel()
	verb := "exec"
	post := principal.Kubernetes.CoreV1().RESTClient().Post().Resource("pods").Namespace(operation.Namespace).Name(operation.Name)
	if operation.Action.Action == "attach" {
		verb = "attach"
	}
	post = post.SubResource(verb)
	if verb == "exec" {
		post.VersionedParams(&corev1.PodExecOptions{
			Container: operation.Container, Command: operation.Command, Stdin: operation.Stdin != "", Stdout: true, Stderr: true, TTY: false,
		}, scheme.ParameterCodec)
	} else {
		post.VersionedParams(&corev1.PodAttachOptions{Container: operation.Container, Stdin: operation.Stdin != "", Stdout: true, Stderr: true, TTY: false}, scheme.ParameterCodec)
	}
	executor, err := remotecommand.NewSPDYExecutor(principal.Config, "POST", post.URL())
	if err != nil {
		return nil, fmt.Errorf("create remote executor: %w", err)
	}
	stdout := newProgressBuffer(a.config.Spec.Limits.MaxOutputBytes/2, func(chunk string) { notifyProgress(ctx, request, float64(len(chunk)), 0, chunk) })
	stderr := newProgressBuffer(a.config.Spec.Limits.MaxOutputBytes/2, func(chunk string) { notifyProgress(ctx, request, float64(len(chunk)), 0, chunk) })
	var stdin io.Reader
	if operation.Stdin != "" {
		stdin = strings.NewReader(operation.Stdin)
	}
	err = executor.StreamWithContext(streamCtx, remotecommand.StreamOptions{Stdin: stdin, Stdout: stdout, Stderr: stderr, Tty: false})
	result := map[string]any{"stdout": stdout.String(), "stderr": stderr.String(), "truncated": stdout.Truncated() || stderr.Truncated()}
	if err != nil {
		result["error"] = err.Error()
		var exitError interface{ ExitStatus() int }
		if errors.As(err, &exitError) {
			result["exitCode"] = exitError.ExitStatus()
		}
		return result, fmt.Errorf("remote %s failed: %w", verb, err)
	}
	return result, nil
}

func (a *App) remoteTimeout(seconds int64) time.Duration {
	maximum := a.config.Spec.Limits.ExecTimeout.Duration
	if seconds <= 0 {
		return maximum
	}
	wanted := time.Duration(seconds) * time.Second
	if wanted > maximum {
		return maximum
	}
	return wanted
}

func resolveContainer(pod *corev1.Pod, requested string) (string, error) {
	for _, container := range pod.Spec.Containers {
		if container.Name == requested {
			return container.Name, nil
		}
	}
	if requested != "" {
		return "", policyError("invalid_input", fmt.Sprintf("container %q does not exist", requested))
	}
	if name := pod.Annotations["kubectl.kubernetes.io/default-container"]; name != "" {
		for _, container := range pod.Spec.Containers {
			if container.Name == name {
				return name, nil
			}
		}
	}
	if len(pod.Spec.Containers) > 0 {
		return pod.Spec.Containers[0].Name, nil
	}
	return "", policyError("invalid_input", "Pod has no containers")
}

type progressBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	limit     int64
	truncated bool
	notify    func(string)
}

func newProgressBuffer(limit int64, notify func(string)) *progressBuffer {
	return &progressBuffer{limit: limit, notify: notify}
}

func (b *progressBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(data)
	remaining := b.limit - int64(b.buffer.Len())
	if remaining <= 0 {
		b.truncated = true
		return original, nil
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(data)
	if b.notify != nil && len(data) > 0 {
		b.notify(string(data))
	}
	return original, nil
}

func (b *progressBuffer) String() string  { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.String() }
func (b *progressBuffer) Truncated() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.truncated }
