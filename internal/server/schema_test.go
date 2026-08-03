package server

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/openapi"
	"k8s.io/client-go/openapi/openapitest"
)

func TestCommitInputSchemaRequiresConfirmationCode(t *testing.T) {
	t.Parallel()

	schema, err := newCommitInputSchema()
	if err != nil {
		t.Fatalf("newCommitInputSchema() error = %v", err)
	}
	if !containsString(schema.Required, "planId") {
		t.Fatalf("CommitInput schema required fields = %v, want planId", schema.Required)
	}
	if !containsString(schema.Required, "confirmationCode") {
		t.Fatalf("CommitInput schema required fields = %v, want confirmationCode", schema.Required)
	}
	confirmation, ok := schema.Properties["confirmationCode"]
	if !ok || confirmation.Type != "string" {
		t.Fatalf("CommitInput confirmationCode schema = %#v, want string property", confirmation)
	}
	if confirmation.Pattern != confirmationCodePattern {
		t.Fatalf("CommitInput confirmationCode pattern = %q, want %q", confirmation.Pattern, confirmationCodePattern)
	}
}

type schemaTestDiscovery struct {
	discovery.DiscoveryInterface
	client openapi.Client
}

func (d *schemaTestDiscovery) OpenAPIV3() openapi.Client {
	return d.client
}

func newSchemaTestPrincipal(t *testing.T, document map[string]any) *Principal {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal OpenAPI document: %v", err)
	}
	client := openapitest.NewFakeClient()
	client.PathsMap["apis/apps/v1"] = openapitest.FakeGroupVersion{GVSpec: data}
	return &Principal{Discovery: &schemaTestDiscovery{client: client}}
}

func schemaTestCapability() Capability {
	return Capability{Group: "apps", Version: "v1", Kind: "Deployment"}
}

func TestSchemaForCapabilityFieldPathPrunesSiblingBranches(t *testing.T) {
	t.Parallel()

	rootProperties := map[string]any{
		"metadata": map[string]any{"$ref": "#/components/schemas/HugeBranch"},
		"spec":     map[string]any{"$ref": "#/components/schemas/SmallSpec"},
	}
	for index := 0; index < 2048; index++ {
		rootProperties[fmt.Sprintf("unrelated-%04d", index)] = map[string]any{
			"$ref": "#/components/schemas/HugeBranch",
		}
	}
	document := map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"io.k8s.apps.v1.Deployment": map[string]any{
					"type": "object",
					"x-kubernetes-group-version-kind": []any{map[string]any{
						"group": "apps", "version": "v1", "kind": "Deployment",
					}},
					"properties": rootProperties,
				},
				"SmallSpec": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"replicas": map[string]any{"type": "integer"},
						"selector": map[string]any{"type": "string"},
					},
				},
				"HugeBranch": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"nested": map[string]any{"$ref": "#/components/schemas/HugeBranch"},
					},
				},
			},
		},
	}

	got, err := schemaForCapability(newSchemaTestPrincipal(t, document), schemaTestCapability(), "spec", 4)
	if err != nil {
		t.Fatalf("schemaForCapability() error = %v", err)
	}
	result, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("schemaForCapability() result type = %T, want map", got)
	}
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expanded target schema properties type = %T, want map", result["properties"])
	}
	for _, name := range []string{"replicas", "selector"} {
		if _, ok := properties[name]; !ok {
			t.Fatalf("expanded target schema omitted %q: %#v", name, properties)
		}
	}
	for _, name := range []string{"metadata", "unrelated-0000", "unrelated-2047"} {
		if _, ok := result[name]; ok {
			t.Fatalf("field-path result retained root sibling %q: %#v", name, result)
		}
		if _, ok := properties[name]; ok {
			t.Fatalf("field-path result retained root sibling %q under properties: %#v", name, properties)
		}
	}
}

func TestSchemaForCapabilityFieldPathTraversesCombinatorsAndRefs(t *testing.T) {
	t.Parallel()

	document := map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"io.k8s.apps.v1.Deployment": map[string]any{
					"type": "object",
					"x-kubernetes-group-version-kind": []any{map[string]any{
						"group": "apps", "version": "v1", "kind": "Deployment",
					}},
					"properties": map[string]any{
						"spec": map[string]any{"allOf": []any{
							map[string]any{"$ref": "#/components/schemas/DeploymentSpec"},
							map[string]any{"$ref": "#/components/schemas/DeploymentStrategy"},
						}},
					},
				},
				"DeploymentSpec": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"template": map[string]any{"$ref": "#/components/schemas/PodTemplate"},
					},
				},
				"DeploymentStrategy": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"strategy": map[string]any{"oneOf": []any{
							map[string]any{"$ref": "#/components/schemas/RollingStrategy"},
							map[string]any{"$ref": "#/components/schemas/RecreateStrategy"},
						}},
					},
				},
				"RollingStrategy": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"mode":           map[string]any{"type": "string", "enum": []any{"RollingUpdate"}},
						"maxUnavailable": map[string]any{"type": "string"},
					},
				},
				"RecreateStrategy": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"mode":   map[string]any{"type": "string", "enum": []any{"Recreate"}},
						"paused": map[string]any{"type": "boolean"},
					},
				},
				"PodTemplate": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"spec": map[string]any{"anyOf": []any{
							map[string]any{"$ref": "#/components/schemas/PodSpecA"},
							map[string]any{"$ref": "#/components/schemas/PodSpecB"},
						}},
					},
				},
				"PodSpecA": map[string]any{
					"type":       "object",
					"properties": map[string]any{"containers": map[string]any{"type": "array"}},
				},
				"PodSpecB": map[string]any{
					"type":       "object",
					"properties": map[string]any{"containers": map[string]any{"type": "array", "x-source": "fallback"}},
				},
			},
		},
	}
	principal := newSchemaTestPrincipal(t, document)
	tests := []struct {
		name       string
		fieldPath  string
		combinator string
		wantCount  int
	}{
		{name: "allOf ref then anyOf ref", fieldPath: "spec.template.spec.containers", combinator: "anyOf", wantCount: 2},
		{name: "allOf ref then oneOf ref", fieldPath: "spec.strategy.mode", combinator: "oneOf", wantCount: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := schemaForCapability(principal, schemaTestCapability(), tt.fieldPath, 8)
			if err != nil {
				t.Fatalf("schemaForCapability(%q) error = %v", tt.fieldPath, err)
			}
			result, ok := got.(map[string]any)
			if !ok {
				t.Fatalf("schemaForCapability(%q) result type = %T, want map", tt.fieldPath, got)
			}
			branches, ok := result[tt.combinator].([]any)
			if !ok || len(branches) != tt.wantCount {
				t.Fatalf("schemaForCapability(%q) %s branches = %#v, want %d", tt.fieldPath, tt.combinator, result[tt.combinator], tt.wantCount)
			}
		})
	}
}

func TestSchemaForCapabilityExpansionBudgetTruncatesDeterministically(t *testing.T) {
	t.Parallel()

	propertyCount := maxSchemaExpansionNodes + 512
	rootProperties := make(map[string]any, propertyCount)
	for index := 0; index < propertyCount; index++ {
		rootProperties[fmt.Sprintf("field-%05d", index)] = map[string]any{"type": "string"}
	}
	document := map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"io.k8s.apps.v1.Deployment": map[string]any{
					"type": "object",
					"x-kubernetes-group-version-kind": []any{map[string]any{
						"group": "apps", "version": "v1", "kind": "Deployment",
					}},
					"properties": rootProperties,
				},
			},
		},
	}
	principal := newSchemaTestPrincipal(t, document)
	first, err := schemaForCapability(principal, schemaTestCapability(), "", 64)
	if err != nil {
		t.Fatalf("first schemaForCapability() error = %v", err)
	}
	second, err := schemaForCapability(principal, schemaTestCapability(), "", 64)
	if err != nil {
		t.Fatalf("second schemaForCapability() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("budgeted schema expansion is not deterministic")
	}
	if !containsSchemaTruncation(first) {
		t.Fatalf("budgeted schema expansion omitted a truncation marker: %#v", first)
	}
	resultNodes := schemaNodeCount(first)
	sourceNodes := schemaNodeCount(document)
	if resultNodes >= sourceNodes {
		t.Fatalf("budgeted result node count = %d, source node count = %d; expansion was not bounded", resultNodes, sourceNodes)
	}
	if resultNodes > maxSchemaExpansionNodes*2 {
		t.Fatalf("budgeted result node count = %d, exceeds bounded expansion size", resultNodes)
	}
	result, ok := first.(map[string]any)
	if !ok {
		t.Fatalf("budgeted schema result type = %T, want map", first)
	}
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		t.Fatalf("budgeted schema properties type = %T, want map", result["properties"])
	}
	if len(properties) >= propertyCount {
		t.Fatalf("budgeted schema expanded %d of %d properties; expected an output bound", len(properties), propertyCount)
	}
}

func TestSchemaForCapabilityRecursiveRefTerminates(t *testing.T) {
	t.Parallel()

	const recursiveRef = "#/components/schemas/Node"
	document := map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"io.k8s.apps.v1.Deployment": map[string]any{
					"type": "object",
					"x-kubernetes-group-version-kind": []any{map[string]any{
						"group": "apps", "version": "v1", "kind": "Deployment",
					}},
					"properties": map[string]any{
						"spec": map[string]any{"$ref": recursiveRef},
					},
				},
				"Node": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"next": map[string]any{"$ref": recursiveRef},
					},
				},
			},
		},
	}

	got, err := schemaForCapability(newSchemaTestPrincipal(t, document), schemaTestCapability(), "spec", 16)
	if err != nil {
		t.Fatalf("schemaForCapability() error = %v", err)
	}
	result, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("schemaForCapability() result type = %T, want map", got)
	}
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		t.Fatalf("recursive schema properties type = %T, want map", result["properties"])
	}
	next, ok := properties["next"].(map[string]any)
	if !ok {
		t.Fatalf("recursive schema next type = %T, want map", properties["next"])
	}
	if next["$ref"] != recursiveRef || next["recursive"] != true {
		t.Fatalf("recursive reference result = %#v, want $ref=%q and recursive=true", next, recursiveRef)
	}
	if nodes := schemaNodeCount(got); nodes > 32 {
		t.Fatalf("recursive schema expansion produced %d nodes, want a bounded result", nodes)
	}
}

func containsSchemaTruncation(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		if current["truncated"] == true {
			return true
		}
		if _, ok := current["x-supek8smcp-truncated"]; ok {
			return true
		}
		for _, child := range current {
			if containsSchemaTruncation(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsSchemaTruncation(child) {
				return true
			}
		}
	}
	return false
}

func schemaNodeCount(value any) int {
	count := 1
	switch current := value.(type) {
	case map[string]any:
		for _, child := range current {
			count += schemaNodeCount(child)
		}
	case []any:
		for _, child := range current {
			count += schemaNodeCount(child)
		}
	}
	return count
}
