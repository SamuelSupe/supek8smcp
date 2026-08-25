package server

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	readOutputSummary = "summary"
	readOutputTable   = "table"
	readOutputFull    = "full"
	maxReadFieldPaths = 32
)

type readOutputOptions struct {
	mode              string
	omitManagedFields bool
	omitAnnotations   bool
	fieldPaths        []string
}

func normalizeReadOutputOptions(action Action, input ReadInput) (readOutputOptions, error) {
	mode := strings.ToLower(strings.TrimSpace(input.OutputMode))
	if mode == "" {
		mode = readOutputFull
		if action.Action == "list" || action.Action == "watch" {
			mode = readOutputSummary
		}
	}
	if mode != readOutputSummary && mode != readOutputTable && mode != readOutputFull {
		return readOutputOptions{}, policyError("invalid_input", "outputMode must be summary, table, or full")
	}
	if action.Action == "logs" && (input.OutputMode != "" || len(input.FieldPaths) > 0 || input.OmitManagedFields != nil || input.OmitAnnotations != nil) {
		return readOutputOptions{}, policyError("invalid_input", "output shaping options are not supported for Pod logs")
	}
	if mode == readOutputTable && len(input.FieldPaths) > 0 {
		return readOutputOptions{}, policyError("invalid_input", "fieldPaths cannot be combined with outputMode=table")
	}
	if len(input.FieldPaths) > maxReadFieldPaths {
		return readOutputOptions{}, policyError("invalid_input", fmt.Sprintf("fieldPaths accepts at most %d paths", maxReadFieldPaths))
	}
	paths := make([]string, 0, len(input.FieldPaths))
	seen := make(map[string]bool, len(input.FieldPaths))
	for _, raw := range input.FieldPaths {
		path := strings.TrimSpace(raw)
		if err := validateReadFieldPath(path); err != nil {
			return readOutputOptions{}, err
		}
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return readOutputOptions{
		mode: mode, omitManagedFields: defaultTrue(input.OmitManagedFields),
		omitAnnotations: defaultTrue(input.OmitAnnotations), fieldPaths: paths,
	}, nil
}

func defaultTrue(value *bool) bool {
	return value == nil || *value
}

func validateReadFieldPath(path string) error {
	if path == "" || len(path) > 256 {
		return policyError("invalid_input", "fieldPaths entries must contain between 1 and 256 characters")
	}
	parts := strings.Split(path, ".")
	if len(parts) > 32 {
		return policyError("invalid_input", fmt.Sprintf("field path %q is too deep", path))
	}
	for _, part := range parts {
		if part == "" || part == "*" || strings.ContainsAny(part, "[]/") {
			return policyError("invalid_input", fmt.Sprintf("field path %q must use dot-separated object keys", path))
		}
	}
	return nil
}

func shapeReadOutput(value any, action Action, options readOutputOptions) (map[string]any, error) {
	cleaned := cleanKubernetesValue(value, options, false)
	object, ok := cleaned.(map[string]any)
	if !ok {
		return nil, policyError("invalid_output", "Kubernetes response is not an object")
	}
	if len(options.fieldPaths) > 0 {
		return projectKubernetesResponse(object, options.fieldPaths)
	}
	switch options.mode {
	case readOutputFull:
		return object, nil
	case readOutputTable:
		return tableKubernetesResponse(object, action), nil
	default:
		return summarizeKubernetesResponse(object, action), nil
	}
}

func cleanKubernetesValue(value any, options readOutputOptions, metadata bool) any {
	switch typed := value.(type) {
	case map[string]any:
		output := make(map[string]any, len(typed))
		for key, child := range typed {
			if metadata && ((key == "managedFields" && options.omitManagedFields) || (key == "annotations" && options.omitAnnotations)) {
				continue
			}
			output[key] = cleanKubernetesValue(child, options, key == "metadata")
		}
		return output
	case []any:
		output := make([]any, len(typed))
		for index, child := range typed {
			output[index] = cleanKubernetesValue(child, options, false)
		}
		return output
	default:
		return value
	}
}

func summarizeKubernetesResponse(object map[string]any, action Action) map[string]any {
	items, isList := object["items"].([]any)
	if !isList {
		return summarizeKubernetesObject(object, action.Kind)
	}
	output := listEnvelope(object)
	summaries := make([]any, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		summaries = append(summaries, summarizeKubernetesObject(item, action.Kind))
	}
	output["items"] = summaries
	return output
}

func summarizeKubernetesObject(object map[string]any, fallbackKind string) map[string]any {
	metadata, _ := object["metadata"].(map[string]any)
	status, _ := object["status"].(map[string]any)
	spec, _ := object["spec"].(map[string]any)
	kind := scalarString(object["kind"])
	if kind == "" {
		kind = fallbackKind
	}
	output := map[string]any{
		"name": scalarString(metadata["name"]), "namespace": scalarString(metadata["namespace"]), "kind": kind,
	}
	if resourceVersion := scalarString(metadata["resourceVersion"]); resourceVersion != "" {
		output["resourceVersion"] = resourceVersion
	}
	if apiVersion := scalarString(object["apiVersion"]); apiVersion != "" {
		output["apiVersion"] = apiVersion
	}
	if age := objectAge(metadata); age != "" {
		output["age"] = age
	}
	switch strings.ToLower(kind) {
	case "pod":
		addPodSummary(output, spec, status)
	case "deployment", "replicaset", "statefulset":
		addWorkloadSummary(output, spec, status)
	case "daemonset":
		copyNumber(output, "desired", status, "desiredNumberScheduled")
		copyNumber(output, "ready", status, "numberReady")
		copyNumber(output, "available", status, "numberAvailable")
		copyNumber(output, "updated", status, "updatedNumberScheduled")
	case "event":
		addEventSummary(output, object)
	case "service":
		copyString(output, "type", spec, "type")
		copyString(output, "clusterIP", spec, "clusterIP")
	case "podmetrics", "nodemetrics":
		copyString(output, "timestamp", object, "timestamp")
		copyString(output, "window", object, "window")
		if containers, ok := object["containers"].([]any); ok {
			output["containers"] = summarizeMetricContainers(containers)
		}
	default:
		copyString(output, "phase", status, "phase")
		copyString(output, "reason", status, "reason")
		addWorkloadSummary(output, spec, status)
	}
	return omitEmptySummaryValues(output)
}

func addPodSummary(output, spec, status map[string]any) {
	copyString(output, "phase", status, "phase")
	copyString(output, "node", spec, "nodeName")
	ready, total, restarts, containerReason := podContainerState(status)
	output["ready"] = fmt.Sprintf("%d/%d", ready, total)
	output["restartCount"] = restarts
	reason := scalarString(status["reason"])
	if reason == "" {
		reason = containerReason
	}
	if reason != "" {
		output["reason"] = reason
	}
}

func podContainerState(status map[string]any) (ready, total, restarts int64, reason string) {
	for _, field := range []string{"initContainerStatuses", "containerStatuses"} {
		items, _ := status[field].([]any)
		if field == "containerStatuses" {
			total = int64(len(items))
		}
		for _, raw := range items {
			container, _ := raw.(map[string]any)
			if field == "containerStatuses" && boolValue(container["ready"]) {
				ready++
			}
			restarts += int64(numberValue(container["restartCount"]))
			if reason == "" {
				reason = containerStateReason(container)
			}
		}
	}
	return ready, total, restarts, reason
}

func containerStateReason(container map[string]any) string {
	state, _ := container["state"].(map[string]any)
	for _, field := range []string{"waiting", "terminated"} {
		value, _ := state[field].(map[string]any)
		if reason := scalarString(value["reason"]); reason != "" {
			return reason
		}
	}
	return ""
}

func addWorkloadSummary(output, spec, status map[string]any) {
	copyNumber(output, "desired", spec, "replicas")
	copyNumber(output, "ready", status, "readyReplicas")
	copyNumber(output, "available", status, "availableReplicas")
	copyNumber(output, "updated", status, "updatedReplicas")
}

func addEventSummary(output, object map[string]any) {
	copyString(output, "type", object, "type")
	copyString(output, "reason", object, "reason")
	copyString(output, "message", object, "message")
	copyNumber(output, "count", object, "count")
	for _, field := range []string{"eventTime", "lastTimestamp", "firstTimestamp"} {
		if value := scalarString(object[field]); value != "" {
			output["lastSeen"] = value
			break
		}
	}
	regarding, _ := object["regarding"].(map[string]any)
	if regarding == nil {
		regarding, _ = object["involvedObject"].(map[string]any)
	}
	if name := scalarString(regarding["name"]); name != "" {
		output["object"] = strings.Trim(strings.Join([]string{scalarString(regarding["kind"]), name}, "/"), "/")
	}
}

func summarizeMetricContainers(items []any) []any {
	output := make([]any, 0, len(items))
	for _, raw := range items {
		container, _ := raw.(map[string]any)
		entry := map[string]any{"name": container["name"]}
		if usage, ok := container["usage"].(map[string]any); ok {
			entry["usage"] = usage
		}
		output = append(output, entry)
	}
	return output
}

func tableKubernetesResponse(object map[string]any, action Action) map[string]any {
	items, isList := object["items"].([]any)
	if !isList {
		items = []any{object}
	}
	kind := action.Kind
	if kind == "" && len(items) > 0 {
		if first, ok := items[0].(map[string]any); ok {
			kind = scalarString(first["kind"])
		}
	}
	columns := summaryTableColumns(kind)
	rows := make([]any, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		summary := summarizeKubernetesObject(item, kind)
		row := make([]any, len(columns))
		for index, column := range columns {
			row[index] = summary[column]
		}
		rows = append(rows, row)
	}
	output := map[string]any{"kind": kind, "columns": columns, "rows": rows}
	if isList {
		if metadata := compactListMetadata(object); len(metadata) > 0 {
			output["metadata"] = metadata
		}
	}
	return output
}

func summaryTableColumns(kind string) []string {
	switch strings.ToLower(kind) {
	case "pod":
		return []string{"name", "namespace", "phase", "ready", "restartCount", "reason", "node", "age"}
	case "deployment", "replicaset", "statefulset", "daemonset":
		return []string{"name", "namespace", "desired", "ready", "available", "updated", "age"}
	case "event":
		return []string{"type", "reason", "object", "message", "count", "lastSeen"}
	case "service":
		return []string{"name", "namespace", "type", "clusterIP", "age"}
	default:
		return []string{"name", "namespace", "kind", "phase", "reason", "age"}
	}
}

func projectKubernetesResponse(object map[string]any, paths []string) (map[string]any, error) {
	items, isList := object["items"].([]any)
	if !isList {
		projected, found := projectObject(object, paths)
		if !found {
			return nil, policyError("field_path_not_found", "none of the requested fieldPaths exist in the object")
		}
		return projected, nil
	}
	output := listEnvelope(object)
	projectedItems := make([]any, 0, len(items))
	foundAny := false
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		projected, found := projectObject(item, paths)
		foundAny = foundAny || found
		projectedItems = append(projectedItems, projected)
	}
	if len(items) > 0 && !foundAny {
		return nil, policyError("field_path_not_found", "none of the requested fieldPaths exist in the list items")
	}
	output["items"] = projectedItems
	return output, nil
}

func projectObject(object map[string]any, paths []string) (map[string]any, bool) {
	output := make(map[string]any, len(paths))
	foundAny := false
	for _, path := range paths {
		parts := strings.Split(path, ".")
		value, found := valueAtPath(object, parts)
		if !found {
			continue
		}
		setValueAtPath(output, parts, value)
		foundAny = true
	}
	return output, foundAny
}

func valueAtPath(value any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return value, true
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	next, exists := object[parts[0]]
	if !exists {
		return nil, false
	}
	return valueAtPath(next, parts[1:])
}

func setValueAtPath(object map[string]any, parts []string, value any) {
	current := object
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
	current[parts[len(parts)-1]] = value
}

func listEnvelope(object map[string]any) map[string]any {
	output := make(map[string]any, 3)
	for _, field := range []string{"apiVersion", "kind"} {
		if value, exists := object[field]; exists {
			output[field] = value
		}
	}
	if metadata := compactListMetadata(object); len(metadata) > 0 {
		output["metadata"] = metadata
	}
	return output
}

func compactListMetadata(object map[string]any) map[string]any {
	metadata, _ := object["metadata"].(map[string]any)
	output := make(map[string]any, 3)
	for _, field := range []string{"continue", "remainingItemCount", "resourceVersion"} {
		if value, exists := metadata[field]; exists && scalarString(value) != "" {
			output[field] = value
		}
	}
	return output
}

func objectAge(metadata map[string]any) string {
	created := scalarString(metadata["creationTimestamp"])
	if created == "" {
		return ""
	}
	timestamp, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return created
	}
	duration := time.Since(timestamp)
	if duration < 0 {
		duration = 0
	}
	switch {
	case duration >= 365*24*time.Hour:
		return strconv.FormatInt(int64(duration/(365*24*time.Hour)), 10) + "y"
	case duration >= 24*time.Hour:
		return strconv.FormatInt(int64(duration/(24*time.Hour)), 10) + "d"
	case duration >= time.Hour:
		return strconv.FormatInt(int64(duration/time.Hour), 10) + "h"
	case duration >= time.Minute:
		return strconv.FormatInt(int64(duration/time.Minute), 10) + "m"
	default:
		return strconv.FormatInt(int64(duration/time.Second), 10) + "s"
	}
}

func omitEmptySummaryValues(input map[string]any) map[string]any {
	for key, value := range input {
		switch typed := value.(type) {
		case string:
			if typed == "" {
				delete(input, key)
			}
		case nil:
			delete(input, key)
		}
	}
	return input
}

func copyString(output map[string]any, outputKey string, input map[string]any, inputKey string) {
	if value := scalarString(input[inputKey]); value != "" {
		output[outputKey] = value
	}
}

func copyNumber(output map[string]any, outputKey string, input map[string]any, inputKey string) {
	if value, exists := input[inputKey]; exists {
		output[outputKey] = numberValue(value)
	}
}

func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(value)
	}
}

func numberValue(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int32:
		return float64(typed)
	case int64:
		return float64(typed)
	default:
		parsed, _ := strconv.ParseFloat(fmt.Sprint(value), 64)
		return parsed
	}
}

func boolValue(value any) bool {
	typed, _ := value.(bool)
	return typed
}
