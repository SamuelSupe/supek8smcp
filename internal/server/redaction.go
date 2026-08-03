package server

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

var (
	sensitiveAnnotationAssignment = regexp.MustCompile(`(?i)(api[._-]?key|token|password|passwd|secret|access[._-]?key|private[._-]?key|client[._-]?secret|credential)[^[:alnum:]]{0,4}[:=]`)
	sensitiveBareKeyAssignment    = regexp.MustCompile(`(?i)(^|[^[:alnum:]_])key[^[:alnum:]]{0,4}[:=]`)
)

func redactResult(value any, action Action, policy mcpv1alpha1.SensitiveReadPolicy) (any, error) {
	result := value
	if action.GVR.Group == "" && action.GVR.Resource == "secrets" {
		if policy == mcpv1alpha1.SensitiveReadDeny {
			return nil, policyError("sensitive_read_denied", "Secret reads are disabled by policy")
		}
		if policy == mcpv1alpha1.SensitiveReadRedact {
			result = redactSecretCollection(value)
		}
	}
	if action.GVR.Group == "" && action.GVR.Resource == "serviceaccounts" && action.Subresource == "token" && policy != mcpv1alpha1.SensitiveReadAllow {
		return nil, policyError("sensitive_read_denied", "ServiceAccount token output requires sensitiveReads=Allow")
	}
	return redactSensitiveAnnotations(result, false), nil
}

func redactSensitiveAnnotations(value any, metadata bool) any {
	switch typed := value.(type) {
	case map[string]any:
		output := make(map[string]any, len(typed))
		for key, child := range typed {
			if metadata && key == "annotations" {
				output[key] = redactAnnotationMap(child)
				continue
			}
			output[key] = redactSensitiveAnnotations(child, key == "metadata")
		}
		return output
	case []any:
		output := make([]any, len(typed))
		for index, child := range typed {
			output[index] = redactSensitiveAnnotations(child, false)
		}
		return output
	default:
		return value
	}
}

func redactAnnotationMap(value any) any {
	annotations, ok := value.(map[string]any)
	if !ok {
		return value
	}
	output := make(map[string]any, len(annotations))
	for key, raw := range annotations {
		text, isString := raw.(string)
		if sensitiveAnnotationName(key) || (isString && (sensitiveAnnotationAssignment.MatchString(text) || sensitiveBareKeyAssignment.MatchString(text))) {
			output[key] = "<redacted>"
			continue
		}
		output[key] = raw
	}
	return output
}

func sensitiveAnnotationName(name string) bool {
	normalized := strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(strings.ToLower(name))
	for _, marker := range []string{"api_key", "apikey", "token", "password", "passwd", "secret", "access_key", "private_key", "client_secret", "credential"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	if normalized == "key" || strings.HasSuffix(normalized, "_key") || strings.Contains(normalized, "_key_") {
		return true
	}
	return false
}

func redactSecretCollection(value any) any {
	object, ok := value.(map[string]any)
	if !ok {
		return value
	}
	if items, ok := object["items"].([]any); ok {
		copy := cloneMap(object)
		redacted := make([]any, 0, len(items))
		for _, item := range items {
			if secret, ok := item.(map[string]any); ok {
				redacted = append(redacted, redactSecret(secret))
			} else {
				redacted = append(redacted, item)
			}
		}
		copy["items"] = redacted
		return copy
	}
	return redactSecret(object)
}

func redactSecret(secret map[string]any) map[string]any {
	copy := cloneMap(secret)
	for _, field := range []string{"data", "stringData", "binaryData"} {
		values, ok := copy[field].(map[string]any)
		if !ok {
			continue
		}
		redacted := make(map[string]any, len(values))
		for key := range values {
			redacted[key] = "<redacted>"
		}
		copy[field] = redacted
	}
	metadata, ok := copy["metadata"].(map[string]any)
	if !ok {
		return copy
	}
	annotations, ok := metadata["annotations"].(map[string]any)
	if !ok {
		return copy
	}
	redactedAnnotations := make(map[string]any, len(annotations))
	for key := range annotations {
		redactedAnnotations[key] = "<redacted>"
	}
	metadata = cloneMap(metadata)
	metadata["annotations"] = redactedAnnotations
	copy["metadata"] = metadata
	return copy
}

func cloneMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func boundedOutput(value map[string]any, limit int64) map[string]any {
	bounded := boundedValue(value, limit)
	if output, ok := bounded.(map[string]any); ok {
		return output
	}
	return map[string]any{"value": bounded}
}

func boundedValue(value any, limit int64) any {
	data, err := json.Marshal(value)
	if err != nil || int64(len(data)) <= limit {
		return value
	}
	previewBytes := (limit - 256) * 3 / 4
	if previewBytes < 0 {
		previewBytes = 0
	}
	if previewBytes > int64(len(data)) {
		previewBytes = int64(len(data))
	}
	return map[string]any{
		"truncated":       true,
		"originalBytes":   len(data),
		"previewEncoding": "base64-json-prefix",
		"preview":         base64.RawStdEncoding.EncodeToString(data[:previewBytes]),
	}
}
