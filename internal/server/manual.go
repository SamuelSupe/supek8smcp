package server

import (
	"strings"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

const (
	toolHelp     = "k8s.help"
	toolSearch   = "k8s.search"
	toolDescribe = "k8s.describe"
	toolRead     = "k8s.read"
	toolPlan     = "k8s.plan"
	toolCommit   = "k8s.commit"
)

type HelpInput struct {
	Tool string `json:"tool,omitempty" jsonschema:"exact tool name to load; omit for the compact tool index"`
}

type HelpOutput struct {
	Mode     mcpv1alpha1.AccessMode `json:"mode"`
	Usage    string                 `json:"usage"`
	Workflow []string               `json:"workflow,omitempty"`
	Tools    []ToolManualSummary    `json:"tools,omitempty"`
	Manual   *ToolManual            `json:"manual,omitempty"`
}

type ToolManualSummary struct {
	Name           string            `json:"name"`
	Purpose        string            `json:"purpose"`
	Available      bool              `json:"available"`
	DetailsRequest map[string]string `json:"detailsRequest"`
}

type ToolManual struct {
	Name      string                   `json:"name"`
	Purpose   string                   `json:"purpose"`
	Available bool                     `json:"available"`
	Modes     []mcpv1alpha1.AccessMode `json:"modes"`
	Inputs    []ToolManualInput        `json:"inputs"`
	Steps     []string                 `json:"steps"`
	Returns   []string                 `json:"returns"`
	Safety    []string                 `json:"safety"`
	Example   map[string]any           `json:"example"`
}

type ToolManualInput struct {
	Name        string `json:"name"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

var allAccessModes = []mcpv1alpha1.AccessMode{
	mcpv1alpha1.ModeReadOnly,
	mcpv1alpha1.ModeSafeWrite,
	mcpv1alpha1.ModeDangerous,
}

var writeAccessModes = []mcpv1alpha1.AccessMode{
	mcpv1alpha1.ModeSafeWrite,
	mcpv1alpha1.ModeDangerous,
}

var toolManuals = []ToolManual{
	{
		Name: toolHelp, Purpose: "Load this built-in manual as a compact index or one detailed tool guide.", Modes: allAccessModes,
		Inputs: []ToolManualInput{
			{Name: "tool", Description: "Exact tool name from the index. Omit it to list the manual topics."},
		},
		Steps: []string{
			"Call without arguments to get a compact index and current-mode availability.",
			"Call again with one exact tool name to load only that detailed guide.",
		},
		Returns: []string{"The current server mode and either the compact index or one detailed manual."},
		Safety:  []string{"The manual is static and does not access the Kubernetes API, but the MCP request still requires Kubernetes bearer authentication."},
		Example: map[string]any{"tool": toolRead},
	},
	{
		Name: toolSearch, Purpose: "Discover signed Kubernetes capabilities allowed by server policy and the caller's Kubernetes RBAC.", Modes: allAccessModes,
		Inputs: []ToolManualInput{
			{Name: "query", Description: "Optional kind, resource, API group, category, or action text."},
			{Name: "action", Description: "Optional logical action or Kubernetes verb filter."},
			{Name: "namespace", Description: "Namespace used for scope and RBAC filtering."},
			{Name: "name", Description: "Optional resource name; supply it when the Kubernetes Role limits access with resourceNames."},
			{Name: "cursor", Description: "Opaque nextCursor from the previous search response."},
			{Name: "limit", Description: "Maximum results for this page, bounded by server limits."},
		},
		Steps: []string{
			"Search before every describe, read, or plan workflow.",
			"Choose a capability whose action matches the intended operation.",
			"Pass its capability id unchanged to the next tool and follow nextCursor when present.",
		},
		Returns: []string{"Authorized capability summaries with signed ids and an optional nextCursor."},
		Safety: []string{
			"Results are already intersected with mode, scope, policy, and Kubernetes RBAC.",
			"A missing capability can mean insufficient policy or RBAC; it does not prove the Kubernetes resource is absent.",
		},
		Example: map[string]any{"query": "deployments", "action": "get", "namespace": "platform", "limit": 20},
	},
	{
		Name: toolDescribe, Purpose: "Load a bounded OpenAPI v3 schema fragment for one capability.", Modes: allAccessModes,
		Inputs: []ToolManualInput{
			{Name: "capabilityId", Required: true, Description: "Signed id returned by k8s.search."},
			{Name: "namespace", Description: "Namespace used for authorization; defaults to the first configured scope when applicable."},
			{Name: "name", Description: "Optional resource name used for authorization."},
			{Name: "fieldPath", Description: "Optional dot-separated field path such as spec.template.spec."},
			{Name: "depth", Description: "Schema expansion depth from 1 to 6; defaults to 2."},
		},
		Steps: []string{
			"Obtain the capability from k8s.search.",
			"Start with a shallow schema and request a fieldPath or greater depth only when needed.",
		},
		Returns: []string{"The selected capability and a bounded schema fragment, or an explicit unavailable marker when no structural schema exists."},
		Safety: []string{
			"Describe performs policy and Kubernetes authorization checks but does not read or mutate a resource instance.",
			"fieldPath is selected before expansion; schema expansion is capped at 10,000 nodes and reports truncation when the budget is reached.",
		},
		Example: map[string]any{"capabilityId": "<from-k8s.search>", "namespace": "platform", "fieldPath": "spec.template.spec", "depth": 2},
	},
	{
		Name: toolRead, Purpose: "Execute one authorized get, list, watch, or Pod logs capability.", Modes: allAccessModes,
		Inputs: []ToolManualInput{
			{Name: "capabilityId", Required: true, Description: "Read capability id returned by k8s.search."},
			{Name: "namespace", Description: "Target namespace for namespaced resources."},
			{Name: "name", Description: "Required for get and Pod logs actions."},
			{Name: "labelSelector", Description: "Kubernetes label selector for list."},
			{Name: "fieldSelector", Description: "Kubernetes field selector for list."},
			{Name: "cursor", Description: "Kubernetes continue token returned by a previous list."},
			{Name: "limit", Description: "Requested list page size; the effective Kubernetes page is also capped at 8 items."},
			{Name: "follow", Description: "Stream Pod logs when true; this requires Dangerous mode."},
			{Name: "container", Description: "Container name for Pod logs."},
			{Name: "tailLines", Description: "Optional number of recent log lines."},
			{Name: "sinceSeconds", Description: "Optional relative Pod log start time."},
		},
		Steps: []string{
			"Search for the exact get, list, watch, or logs capability.",
			"Supply the namespace and action-specific filters or name.",
			"Use returned list cursors instead of increasing limits; consume streaming results until the configured timeout.",
		},
		Returns: []string{"A bounded Kubernetes object, list page, watch events, or Pod log lines."},
		Safety: []string{
			"Secret output follows sensitiveReads policy and is redacted by default.",
			"follow=true is available only in Dangerous mode and remains bounded by streamTimeout, maxListItems, and maxOutputBytes.",
		},
		Example: map[string]any{"capabilityId": "<get-capability-from-k8s.search>", "namespace": "platform", "name": "web"},
	},
	{
		Name: toolPlan, Purpose: "Authorize and preview one write, scale, restart, exec, or attach operation without committing it.", Modes: writeAccessModes,
		Inputs: []ToolManualInput{
			{Name: "capabilityId", Required: true, Description: "Write capability id returned by k8s.search."},
			{Name: "namespace", Description: "Target namespace for namespaced resources."},
			{Name: "name", Description: "Existing target name; create may take it from object.metadata.name."},
			{Name: "object", Description: "Complete Kubernetes object for create, update, or server-side apply."},
			{Name: "patch", Description: "Merge object or JSON Patch array for a patch capability."},
			{Name: "patchType", Description: "merge or json; defaults to merge."},
			{Name: "replicas", Description: "Desired replica count for scale."},
			{Name: "command", Description: "Bounded command for Dangerous exec."},
			{Name: "container", Description: "Container for exec or attach."},
			{Name: "stdin", Description: "Bounded stdin for Dangerous attach."},
			{Name: "timeoutSeconds", Description: "Requested exec or attach timeout, capped by server policy."},
			{Name: "gracePeriodSeconds", Description: "Optional grace period for delete."},
			{Name: "force", Description: "Force server-side apply; Dangerous mode only."},
		},
		Steps: []string{
			"Search for the exact write capability and inspect its schema when constructing an object.",
			"Call plan once and review operation, preview, and warnings.",
			"Pass the returned planId to k8s.commit within two minutes using the same Kubernetes identity.",
		},
		Returns: []string{"A one-time planId, expiry, safe operation summary, bounded preview, and warnings."},
		Safety: []string{
			"Plan does not persist the requested change; Kubernetes dry-run and policy checks still apply.",
			"SafeWrite blocks dangerous actions and unsafe payloads; exec, attach, delete, force apply, and cluster writes require Dangerous mode and explicit policy scope.",
			"Do not log, cache, share, or retry a planId as though it were idempotent.",
		},
		Example: map[string]any{
			"capabilityId": "<patch-capability-from-k8s.search>", "namespace": "platform", "name": "web",
			"patchType": "merge", "patch": map[string]any{"metadata": map[string]any{"labels": map[string]any{"managed-by": "mcp"}}},
		},
	},
	{
		Name: toolCommit, Purpose: "Consume one unexpired plan and execute it after rechecking identity, policy, RBAC, and resource preconditions.", Modes: writeAccessModes,
		Inputs: []ToolManualInput{
			{Name: "planId", Required: true, Description: "One-time id returned by k8s.plan."},
		},
		Steps: []string{
			"Review the k8s.plan response before committing.",
			"Commit once, within two minutes, with the same authenticated Kubernetes identity.",
			"If commit is rejected or the target changed, search and create a new plan instead of replaying the old id.",
		},
		Returns: []string{"A safe operation summary and bounded execution result."},
		Safety: []string{
			"Commit can persist a mutation or run Dangerous exec/attach; treat it as the execution boundary.",
			"Plans are one-time and identity-bound. Policy, RBAC, generation, UID, and resourceVersion preconditions are rechecked.",
		},
		Example: map[string]any{"planId": "<from-k8s.plan>"},
	},
}

func (a *App) help(input HelpInput) (HelpOutput, error) {
	requested := strings.TrimSpace(input.Tool)
	if requested == "" {
		summaries := make([]ToolManualSummary, 0, len(toolManuals))
		for _, manual := range toolManuals {
			summaries = append(summaries, ToolManualSummary{
				Name: manual.Name, Purpose: manual.Purpose, Available: manualAvailable(manual, a.config.Spec.Mode),
				DetailsRequest: map[string]string{"tool": manual.Name},
			})
		}
		return HelpOutput{
			Mode:  a.config.Spec.Mode,
			Usage: "Call k8s.help again with one detailsRequest to load only that guide. available reflects the current server mode.",
			Workflow: []string{
				"Discover an authorized capability with k8s.search.",
				"Use k8s.describe only when schema detail is needed.",
				"Use k8s.read for reads, or k8s.plan then k8s.commit for writes.",
			},
			Tools: summaries,
		}, nil
	}
	for _, definition := range toolManuals {
		if definition.Name != requested {
			continue
		}
		manual := definition
		manual.Available = manualAvailable(manual, a.config.Spec.Mode)
		return HelpOutput{
			Mode: a.config.Spec.Mode, Usage: "Use the manual fields as guidance, then call the named tool with an action-appropriate capability.",
			Manual: &manual,
		}, nil
	}
	return HelpOutput{}, policyError("invalid_input", "tool must be an exact supported name from the k8s.help index")
}

func manualAvailable(manual ToolManual, mode mcpv1alpha1.AccessMode) bool {
	for _, allowed := range manual.Modes {
		if allowed == mode {
			return true
		}
	}
	return false
}
