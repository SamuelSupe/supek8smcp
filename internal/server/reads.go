package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

const kubernetesListPageLimit int64 = 8

type SearchInput struct {
	Query         string `json:"query,omitempty" jsonschema:"kind, resource, API group, category, or action to search for"`
	Action        string `json:"action,omitempty" jsonschema:"optional exact action or Kubernetes verb filter"`
	ExactKind     string `json:"exactKind,omitempty" jsonschema:"optional exact Kubernetes kind filter"`
	ExactResource string `json:"exactResource,omitempty" jsonschema:"optional exact plural resource or resource/subresource filter"`
	APIGroup      string `json:"apiGroup,omitempty" jsonschema:"optional exact API group filter; use core for the core API group"`
	Version       string `json:"version,omitempty" jsonschema:"optional exact API version filter"`
	Namespace     string `json:"namespace,omitempty" jsonschema:"namespace used for scope and RBAC filtering"`
	Name          string `json:"name,omitempty" jsonschema:"optional resource name for Kubernetes roles restricted by resourceNames"`
	Cursor        string `json:"cursor,omitempty" jsonschema:"opaque cursor from a previous response"`
	Limit         int64  `json:"limit,omitempty" jsonschema:"maximum capabilities to return"`
}

type SearchOutput struct {
	Capabilities []Capability `json:"capabilities"`
	NextCursor   string       `json:"nextCursor,omitempty"`
}

func (a *App) search(ctx context.Context, principal *Principal, input SearchInput) (SearchOutput, error) {
	ctx, cancel := a.requestContext(ctx)
	defer cancel()
	items, err := a.catalog.list(ctx, principal)
	if err != nil {
		return SearchOutput{}, err
	}
	limit := input.Limit
	if limit <= 0 || limit > a.config.Spec.Limits.MaxListItems {
		limit = min(a.config.Spec.Limits.MaxListItems, 20)
	}
	capabilities, next, err := searchCatalog(ctx, items, a.policy, principal, catalogSearchFilter{
		Query: input.Query, Action: input.Action, ExactKind: input.ExactKind, ExactResource: input.ExactResource,
		APIGroup: input.APIGroup, Version: input.Version, Namespace: input.Namespace, Name: input.Name,
	}, input.Cursor, limit)
	if err != nil {
		return SearchOutput{}, err
	}
	return SearchOutput{Capabilities: capabilities, NextCursor: next}, nil
}

type DescribeInput struct {
	CapabilityID string `json:"capabilityId" jsonschema:"capability ID returned by k8s.search"`
	Namespace    string `json:"namespace,omitempty" jsonschema:"namespace used for the authorization check"`
	Name         string `json:"name,omitempty" jsonschema:"optional resource name used for the authorization check"`
	FieldPath    string `json:"fieldPath,omitempty" jsonschema:"dot-separated schema field path, such as spec.template.spec"`
	Depth        int    `json:"depth,omitempty" jsonschema:"schema expansion depth from 1 to 6"`
}

type DescribeOutput struct {
	Capability Capability `json:"capability"`
	Schema     any        `json:"schema"`
}

func (a *App) describe(ctx context.Context, principal *Principal, input DescribeInput) (DescribeOutput, error) {
	ctx, cancel := a.requestContext(ctx)
	defer cancel()
	capability, err := a.capabilities.decode(input.CapabilityID)
	if err != nil {
		return DescribeOutput{}, err
	}
	namespace := a.defaultNamespace(capability, input.Namespace)
	if err := a.policy.CheckAndAuthorize(ctx, principal, capability.AsAction(), namespace, input.Name); err != nil {
		return DescribeOutput{}, err
	}
	depth := input.Depth
	if depth <= 0 {
		depth = 2
	}
	if depth > 6 {
		depth = 6
	}
	resourceSchema, err := schemaForCapability(principal, capability, input.FieldPath, depth)
	if err != nil {
		return DescribeOutput{}, err
	}
	return DescribeOutput{Capability: capability, Schema: boundedValue(resourceSchema, a.config.Spec.Limits.MaxOutputBytes/2)}, nil
}

type ReadInput struct {
	CapabilityID      string   `json:"capabilityId" jsonschema:"read capability ID returned by k8s.search"`
	Namespace         string   `json:"namespace,omitempty"`
	Name              string   `json:"name,omitempty"`
	LabelSelector     string   `json:"labelSelector,omitempty"`
	FieldSelector     string   `json:"fieldSelector,omitempty"`
	Cursor            string   `json:"cursor,omitempty" jsonschema:"Kubernetes list continue token"`
	Limit             int64    `json:"limit,omitempty"`
	OutputMode        string   `json:"outputMode,omitempty" jsonschema:"response shape: summary, table, or full; list and watch default to summary while get defaults to full"`
	OmitManagedFields *bool    `json:"omitManagedFields,omitempty" jsonschema:"omit metadata.managedFields recursively; defaults to true"`
	OmitAnnotations   *bool    `json:"omitAnnotations,omitempty" jsonschema:"omit metadata.annotations recursively; defaults to true"`
	FieldPaths        []string `json:"fieldPaths,omitempty" jsonschema:"object-relative dot paths to project; applied to every list item and incompatible with table mode"`
	Follow            bool     `json:"follow,omitempty"`
	Container         string   `json:"container,omitempty"`
	TailLines         *int64   `json:"tailLines,omitempty"`
	SinceSeconds      *int64   `json:"sinceSeconds,omitempty"`
}

func (a *App) read(ctx context.Context, request *mcp.CallToolRequest, principal *Principal, input ReadInput) (map[string]any, error) {
	capability, err := a.capabilities.decode(input.CapabilityID)
	if err != nil {
		return nil, err
	}
	action := capability.AsAction()
	if action.Mutating() || !containsString([]string{"get", "list", "watch", "logs"}, action.Action) {
		return nil, policyError("invalid_capability", "k8s.read only accepts get, list, watch, and logs capabilities")
	}
	outputOptions, err := normalizeReadOutputOptions(action, input)
	if err != nil {
		return nil, err
	}
	if action.Action == "logs" && input.Follow && a.config.Spec.Mode != mcpv1alpha1.ModeDangerous {
		return nil, policyError("mode_denied", "followed log streams require Dangerous mode")
	}
	if action.Action != "watch" && !(action.Action == "logs" && input.Follow) {
		var cancel context.CancelFunc
		ctx, cancel = a.requestContext(ctx)
		defer cancel()
	}
	namespace := a.defaultNamespace(capability, input.Namespace)
	if err := a.policy.CheckAndAuthorize(ctx, principal, action, namespace, input.Name); err != nil {
		return nil, err
	}

	var result map[string]any
	switch action.Action {
	case "get":
		if input.Name == "" {
			return nil, policyError("invalid_input", "name is required for get")
		}
		object, err := dynamicResource(principal, action, namespace).Get(ctx, input.Name, metav1.GetOptions{}, subresources(action)...)
		if err != nil {
			return nil, err
		}
		result = object.Object
	case "list":
		limit := a.kubernetesListLimit(input.Limit)
		list, err := dynamicResource(principal, action, namespace).List(ctx, metav1.ListOptions{
			LabelSelector: input.LabelSelector, FieldSelector: input.FieldSelector, Limit: limit, Continue: input.Cursor,
		})
		if err != nil {
			return nil, err
		}
		result = list.UnstructuredContent()
	case "watch":
		output, err := a.watch(ctx, request, principal, action, namespace, input, outputOptions)
		if err != nil {
			return nil, err
		}
		return boundedOutput(output, a.config.Spec.Limits.MaxOutputBytes), nil
	case "logs":
		output, err := a.logs(ctx, request, principal, namespace, input)
		if err != nil {
			return nil, err
		}
		return boundedOutput(output, a.config.Spec.Limits.MaxOutputBytes), nil
	}
	redacted, err := redactResult(result, action, a.config.Spec.Policy.SensitiveReads)
	if err != nil {
		return nil, err
	}
	output, err := shapeReadOutput(redacted, action, outputOptions)
	if err != nil {
		return nil, err
	}
	return boundedOutput(output, a.config.Spec.Limits.MaxOutputBytes), nil
}

func (a *App) kubernetesListLimit(requested int64) int64 {
	if requested <= 0 || requested > a.config.Spec.Limits.MaxListItems {
		requested = a.config.Spec.Limits.MaxListItems
	}
	return min(requested, kubernetesListPageLimit)
}

func (a *App) watch(ctx context.Context, request *mcp.CallToolRequest, principal *Principal, action Action, namespace string, input ReadInput, outputOptions readOutputOptions) (map[string]any, error) {
	streamCtx, cancel := context.WithTimeout(ctx, a.config.Spec.Limits.StreamTimeout.Duration)
	defer cancel()
	watcher, err := dynamicResource(principal, action, namespace).Watch(streamCtx, metav1.ListOptions{
		LabelSelector: input.LabelSelector, FieldSelector: input.FieldSelector,
	})
	if err != nil {
		return nil, err
	}
	defer watcher.Stop()
	items := make([]any, 0)
	var outputBytes int64
	for len(items) < int(a.config.Spec.Limits.MaxListItems) {
		select {
		case <-streamCtx.Done():
			return map[string]any{"events": items, "ended": streamCtx.Err().Error()}, nil
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return map[string]any{"events": items, "ended": "watch closed"}, nil
			}
			object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(event.Object)
			if err != nil {
				object = map[string]any{"error": err.Error()}
			}
			redacted, err := redactResult(object, action, a.config.Spec.Policy.SensitiveReads)
			if err != nil {
				return nil, err
			}
			shaped, err := shapeReadOutput(redacted, action, outputOptions)
			if err != nil {
				return nil, err
			}
			entry := map[string]any{"type": string(event.Type), "object": shaped}
			entryData, _ := json.Marshal(entry)
			if outputBytes+int64(len(entryData)) > a.config.Spec.Limits.MaxOutputBytes {
				return map[string]any{"events": items, "ended": "output limit reached", "truncated": true}, nil
			}
			outputBytes += int64(len(entryData))
			items = append(items, entry)
			notifyProgress(ctx, request, float64(len(items)), 0, compactProgress(entry, 4096))
		}
	}
	return map[string]any{"events": items, "ended": "item limit reached"}, nil
}

func (a *App) logs(ctx context.Context, request *mcp.CallToolRequest, principal *Principal, namespace string, input ReadInput) (map[string]any, error) {
	if input.Name == "" {
		return nil, policyError("invalid_input", "name is required for logs")
	}
	options := &corev1.PodLogOptions{
		Container: input.Container, Follow: input.Follow, TailLines: input.TailLines, SinceSeconds: input.SinceSeconds,
	}
	logRequest := principal.Kubernetes.CoreV1().Pods(namespace).GetLogs(input.Name, options)
	if !input.Follow {
		reader, err := logRequest.Stream(ctx)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		data, err := io.ReadAll(io.LimitReader(reader, a.config.Spec.Limits.MaxOutputBytes+1))
		if err != nil {
			return nil, err
		}
		truncated := int64(len(data)) > a.config.Spec.Limits.MaxOutputBytes
		data = data[:min(int64(len(data)), a.config.Spec.Limits.MaxOutputBytes)]
		return map[string]any{"logs": string(data), "truncated": truncated}, nil
	}

	streamCtx, cancel := context.WithTimeout(ctx, a.config.Spec.Limits.StreamTimeout.Duration)
	defer cancel()
	reader, err := logRequest.Stream(streamCtx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	scanner := bufio.NewScanner(io.LimitReader(reader, a.config.Spec.Limits.MaxOutputBytes+1))
	buffer := make([]byte, 0, min(a.config.Spec.Limits.MaxOutputBytes, 64<<10))
	scanner.Buffer(buffer, int(min(a.config.Spec.Limits.MaxOutputBytes, 1<<20)))
	var lines []string
	var size int64
	for scanner.Scan() {
		if int64(len(lines)) >= a.config.Spec.Limits.MaxListItems {
			return map[string]any{"logs": lines, "truncated": true}, nil
		}
		line := scanner.Text()
		size += int64(len(line) + 1)
		if size > a.config.Spec.Limits.MaxOutputBytes {
			return map[string]any{"logs": lines, "truncated": true}, nil
		}
		lines = append(lines, line)
		notifyProgress(ctx, request, float64(len(lines)), 0, line)
	}
	if err := scanner.Err(); err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		return nil, err
	}
	return map[string]any{"logs": lines, "truncated": false}, nil
}

func dynamicResource(principal *Principal, action Action, namespace string) dynamic.ResourceInterface {
	resource := principal.Dynamic.Resource(action.GVR)
	if action.Namespaced {
		return resource.Namespace(namespace)
	}
	return resource
}

func subresources(action Action) []string {
	if action.Subresource == "" {
		return nil
	}
	return []string{action.Subresource}
}

func notifyProgress(ctx context.Context, request *mcp.CallToolRequest, progress, total float64, message string) {
	if request == nil || request.Params == nil || request.Params.GetProgressToken() == nil {
		return
	}
	_ = request.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
		ProgressToken: request.Params.GetProgressToken(), Progress: progress, Total: total, Message: message,
	})
}

func compactProgress(value any, limit int) string {
	data, _ := json.Marshal(value)
	if len(data) > limit {
		data = append(data[:limit], []byte("...")...)
	}
	return string(data)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
