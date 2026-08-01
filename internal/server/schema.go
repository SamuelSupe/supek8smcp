package server

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/openapi3"
)

func schemaForCapability(principal *Principal, capability Capability, fieldPath string, depth int) (any, error) {
	root := openapi3.NewRoot(principal.Discovery.OpenAPIV3())
	document, err := root.GVSpecAsMap(schema.GroupVersion{Group: capability.Group, Version: capability.Version})
	if err != nil {
		return nil, fmt.Errorf("load OpenAPI v3 schema: %w", err)
	}
	components, _ := document["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	var selected map[string]any
	for _, raw := range schemas {
		candidate, ok := raw.(map[string]any)
		if !ok || !schemaMatchesGVK(candidate, capability) {
			continue
		}
		selected = candidate
		break
	}
	if selected == nil {
		return map[string]any{"available": false, "reason": "resource has no structural OpenAPI v3 schema"}, nil
	}
	expanded := expandSchema(selected, schemas, depth, map[string]bool{})
	if fieldPath == "" {
		return expanded, nil
	}
	current, ok := expanded.(map[string]any)
	if !ok {
		return nil, policyError("schema_path_not_found", "schema root is not an object")
	}
	for _, part := range strings.Split(fieldPath, ".") {
		properties, _ := current["properties"].(map[string]any)
		next, ok := properties[part].(map[string]any)
		if !ok {
			return nil, policyError("schema_path_not_found", fmt.Sprintf("field path %q does not exist", fieldPath))
		}
		current = next
	}
	return current, nil
}

func schemaMatchesGVK(candidate map[string]any, capability Capability) bool {
	extensions, _ := candidate["x-kubernetes-group-version-kind"].([]any)
	for _, raw := range extensions {
		gvk, _ := raw.(map[string]any)
		group, _ := gvk["group"].(string)
		version, _ := gvk["version"].(string)
		kind, _ := gvk["kind"].(string)
		if group == capability.Group && version == capability.Version && kind == capability.Kind {
			return true
		}
	}
	return false
}

func expandSchema(value any, schemas map[string]any, depth int, seen map[string]bool) any {
	if depth < 0 {
		return map[string]any{"truncated": true}
	}
	if array, ok := value.([]any); ok {
		expanded := make([]any, len(array))
		for index, item := range array {
			expanded[index] = expandSchema(item, schemas, depth, seen)
		}
		return expanded
	}
	object, ok := value.(map[string]any)
	if !ok {
		return value
	}
	if reference, ok := object["$ref"].(string); ok && strings.HasPrefix(reference, "#/components/schemas/") {
		name := strings.TrimPrefix(reference, "#/components/schemas/")
		if seen[name] {
			return map[string]any{"$ref": reference, "recursive": true}
		}
		if target, exists := schemas[name]; exists {
			copySeen := make(map[string]bool, len(seen)+1)
			for key, enabled := range seen {
				copySeen[key] = enabled
			}
			copySeen[name] = true
			return expandSchema(target, schemas, depth, copySeen)
		}
	}
	result := make(map[string]any, len(object))
	for key, child := range object {
		switch key {
		case "properties":
			properties, _ := child.(map[string]any)
			expanded := make(map[string]any, len(properties))
			for property, propertySchema := range properties {
				expanded[property] = expandSchema(propertySchema, schemas, depth-1, seen)
			}
			result[key] = expanded
		case "items", "additionalProperties", "oneOf", "anyOf", "allOf":
			result[key] = expandSchema(child, schemas, depth-1, seen)
		default:
			result[key] = child
		}
	}
	return result
}
