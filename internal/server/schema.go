package server

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/openapi3"
)

const maxSchemaExpansionNodes = 10_000

func schemaForCapability(principal *Principal, capability Capability, fieldPath string, depth int) (any, error) {
	root := openapi3.NewRoot(principal.Discovery.OpenAPIV3())
	document, err := root.GVSpecAsMap(schema.GroupVersion{Group: capability.Group, Version: capability.Version})
	if err != nil {
		return nil, fmt.Errorf("load OpenAPI v3 schema: %w", err)
	}
	return schemaFromDocument(document, capability, fieldPath, depth)
}

func schemaFromDocument(document map[string]any, capability Capability, fieldPath string, depth int) (any, error) {
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
	if fieldPath != "" {
		current := selected
		for _, part := range strings.Split(fieldPath, ".") {
			next, ok := schemaProperty(current, part, schemas, map[string]bool{})
			if !ok {
				return nil, policyError("schema_path_not_found", fmt.Sprintf("field path %q does not exist", fieldPath))
			}
			current = next
		}
		selected = current
	}
	budget := &schemaExpansionBudget{remaining: maxSchemaExpansionNodes}
	return expandSchema(selected, schemas, depth, map[string]bool{}, budget), nil
}

func schemaProperty(current map[string]any, name string, schemas map[string]any, seenRefs map[string]bool) (map[string]any, bool) {
	if properties, ok := current["properties"].(map[string]any); ok {
		if property, ok := properties[name].(map[string]any); ok {
			return property, true
		}
	}

	if reference, _ := current["$ref"].(string); strings.HasPrefix(reference, "#/components/schemas/") && !seenRefs[reference] {
		seenRefs[reference] = true
		if target, ok := schemas[strings.TrimPrefix(reference, "#/components/schemas/")].(map[string]any); ok {
			if property, found := schemaProperty(target, name, schemas, seenRefs); found {
				delete(seenRefs, reference)
				return property, true
			}
		}
		delete(seenRefs, reference)
	}

	for _, combinator := range []string{"allOf", "oneOf", "anyOf"} {
		branches, _ := current[combinator].([]any)
		matches := make([]any, 0, len(branches))
		for _, raw := range branches {
			branch, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			property, found := schemaProperty(branch, name, schemas, seenRefs)
			if found {
				matches = append(matches, property)
			}
		}
		switch len(matches) {
		case 0:
			continue
		case 1:
			return matches[0].(map[string]any), true
		default:
			return map[string]any{combinator: matches}, true
		}
	}
	return nil, false
}

type schemaExpansionBudget struct {
	remaining int
}

func (b *schemaExpansionBudget) take() bool {
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

func schemaTruncated() map[string]any {
	return map[string]any{"truncated": true, "reason": "schema expansion budget reached"}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func expandSchema(value any, schemas map[string]any, depth int, seen map[string]bool, budget *schemaExpansionBudget) any {
	if depth < 0 || !budget.take() {
		return schemaTruncated()
	}
	if array, ok := value.([]any); ok {
		expanded := make([]any, 0, min(len(array), budget.remaining))
		for _, item := range array {
			if budget.remaining <= 0 {
				expanded = append(expanded, schemaTruncated())
				break
			}
			expanded = append(expanded, expandSchema(item, schemas, depth, seen, budget))
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
			return expandSchema(target, schemas, depth, copySeen, budget)
		}
	}
	result := make(map[string]any, min(len(object), budget.remaining))
	for _, key := range sortedMapKeys(object) {
		if budget.remaining <= 0 {
			result["x-supek8smcp-truncated"] = true
			break
		}
		child := object[key]
		switch key {
		case "properties":
			properties, _ := child.(map[string]any)
			expanded := make(map[string]any, min(len(properties), budget.remaining))
			for _, property := range sortedMapKeys(properties) {
				if budget.remaining <= 0 {
					expanded["x-supek8smcp-truncated"] = schemaTruncated()
					break
				}
				expanded[property] = expandSchema(properties[property], schemas, depth-1, seen, budget)
			}
			result[key] = expanded
		case "items", "additionalProperties", "oneOf", "anyOf", "allOf":
			result[key] = expandSchema(child, schemas, depth-1, seen, budget)
		default:
			if !budget.take() {
				result["x-supek8smcp-truncated"] = true
				return result
			}
			result[key] = child
		}
	}
	return result
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
