package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

type PlanInput struct {
	CapabilityID       string         `json:"capabilityId" jsonschema:"write capability ID returned by k8s.search"`
	Namespace          string         `json:"namespace,omitempty"`
	Name               string         `json:"name,omitempty"`
	Object             map[string]any `json:"object,omitempty" jsonschema:"complete or server-side apply Kubernetes object"`
	Patch              any            `json:"patch,omitempty" jsonschema:"JSON merge or JSON patch body"`
	PatchType          string         `json:"patchType,omitempty" jsonschema:"merge or json; default merge"`
	Replicas           *int64         `json:"replicas,omitempty"`
	Command            []string       `json:"command,omitempty"`
	Container          string         `json:"container,omitempty"`
	Stdin              string         `json:"stdin,omitempty"`
	TimeoutSeconds     int64          `json:"timeoutSeconds,omitempty"`
	GracePeriodSeconds *int64         `json:"gracePeriodSeconds,omitempty"`
	Force              bool           `json:"force,omitempty"`
}

type PlanOutput struct {
	PlanID       string                `json:"planId"`
	ExpiresAt    string                `json:"expiresAt"`
	Operation    map[string]any        `json:"operation"`
	Preview      any                   `json:"preview,omitempty"`
	Warnings     []string              `json:"warnings,omitempty"`
	Confirmation ConfirmationChallenge `json:"confirmation"`
}

type ConfirmationChallenge struct {
	Required    bool   `json:"required"`
	Code        string `json:"code"`
	Instruction string `json:"instruction"`
}

const humanConfirmationInstruction = "Show the operation preview and this code to the human. Do not call k8s.commit until the human repeats the code in a later user message."

func (a *App) plan(ctx context.Context, principal *Principal, input PlanInput) (PlanOutput, error) {
	ctx, cancel := a.requestContext(ctx)
	defer cancel()
	capability, err := a.capabilities.decode(input.CapabilityID)
	if err != nil {
		return PlanOutput{}, err
	}
	action := capability.AsAction()
	if !action.Mutating() || !containsString([]string{"create", "apply", "patch", "update", "delete", "scale", "restart", "exec", "attach"}, action.Action) {
		return PlanOutput{}, policyError("invalid_capability", "k8s.plan requires a supported write capability")
	}
	namespace := a.defaultNamespace(capability, input.Namespace)
	name := input.Name
	if name == "" && input.Object != nil {
		name, _, _ = unstructured.NestedString(input.Object, "metadata", "name")
	}
	if action.Action != "create" && name == "" {
		return PlanOutput{}, policyError("invalid_input", "name is required for this operation")
	}
	if input.Force && a.config.Spec.Mode != mcpv1alpha1.ModeDangerous {
		return PlanOutput{}, policyError("mode_denied", "force apply requires Dangerous mode")
	}
	if err := a.policy.CheckAndAuthorize(ctx, principal, action, namespace, name); err != nil {
		return PlanOutput{}, err
	}
	if a.config.Spec.Mode == mcpv1alpha1.ModeSafeWrite {
		if err := validateSafeOperation(action, input.Object, input.Patch, input.PatchType); err != nil {
			return PlanOutput{}, err
		}
	}

	operation := Operation{
		Action: action, Namespace: namespace, Name: name, Object: input.Object, Patch: input.Patch,
		PatchType: input.PatchType, Replicas: input.Replicas, Command: append([]string(nil), input.Command...),
		Container: input.Container, Stdin: input.Stdin, TimeoutSeconds: input.TimeoutSeconds,
		GracePeriod: input.GracePeriodSeconds, Force: input.Force, Generation: a.config.Generation,
	}
	preview, warnings, err := a.previewOperation(ctx, principal, &operation)
	if err != nil {
		return PlanOutput{}, err
	}
	id, confirmationCode, expires, err := a.plans.Create(principal.SubjectKey(), operation)
	if err != nil {
		return PlanOutput{}, err
	}
	return PlanOutput{
		PlanID: id, ExpiresAt: expires.UTC().Format(time.RFC3339),
		Operation: operationSummary(operation), Preview: boundedValue(preview, a.config.Spec.Limits.MaxOutputBytes/2), Warnings: warnings,
		Confirmation: ConfirmationChallenge{Required: true, Code: confirmationCode, Instruction: humanConfirmationInstruction},
	}, nil
}

type CommitInput struct {
	PlanID           string `json:"planId" jsonschema:"unexpired one-time plan ID returned by k8s.plan"`
	ConfirmationCode string `json:"confirmationCode" jsonschema:"six-digit code repeated by a human after reviewing the k8s.plan response"`
}

type CommitOutput struct {
	Operation map[string]any `json:"operation"`
	Result    any            `json:"result,omitempty"`
}

func (a *App) commit(ctx context.Context, request *mcp.CallToolRequest, principal *Principal, input CommitInput) (CommitOutput, error) {
	operation, err := a.plans.Consume(input.PlanID, principal.SubjectKey(), input.ConfirmationCode)
	if err != nil {
		return CommitOutput{}, err
	}
	output := CommitOutput{Operation: operationSummary(operation)}
	timeout := a.config.Spec.Limits.RequestTimeout.Duration
	if operation.Action.Action == "exec" || operation.Action.Action == "attach" {
		timeout = a.remoteTimeout(operation.TimeoutSeconds)
	}
	ctx, cancel := timeoutContext(ctx, timeout)
	defer cancel()
	if operation.Generation != a.config.Generation {
		return output, policyError("stale_plan", "server policy changed after the plan was created")
	}
	if err := a.policy.CheckAndAuthorize(ctx, principal, operation.Action, operation.Namespace, operation.Name); err != nil {
		return output, err
	}
	if err := a.checkOperationPreconditions(ctx, principal, operation); err != nil {
		return output, err
	}
	if a.config.Spec.Mode == mcpv1alpha1.ModeSafeWrite {
		validationOperation := operation
		if _, _, err := a.previewOperation(ctx, principal, &validationOperation); err != nil {
			return output, err
		}
	}
	result, err := a.executeOperation(ctx, request, principal, operation)
	if err != nil {
		return output, err
	}
	redacted, err := redactResult(result, operation.Action, a.config.Spec.Policy.SensitiveReads)
	if err != nil {
		return output, err
	}
	output.Result = boundedValue(redacted, a.config.Spec.Limits.MaxOutputBytes/2)
	return output, nil
}

func (a *App) previewOperation(ctx context.Context, principal *Principal, operation *Operation) (any, []string, error) {
	action := operation.Action
	resource := dynamicResource(principal, action, operation.Namespace)
	dryRun := []string{metav1.DryRunAll}
	var preview any
	var previous any
	var warnings []string

	switch action.Action {
	case "create":
		object, err := operationObject(operation)
		if err != nil {
			return nil, nil, err
		}
		if object.GetName() == "" {
			return nil, nil, policyError("invalid_input", "object.metadata.name is required")
		}
		if operation.Name == "" {
			operation.Name = object.GetName()
		}
		if _, err := resource.Get(ctx, operation.Name, metav1.GetOptions{}); err == nil {
			return nil, nil, policyError("conflict", "resource already exists")
		} else if !apierrors.IsNotFound(err) {
			return nil, nil, err
		}
		operation.ExpectedAbsent = true
		created, err := resource.Create(ctx, object, metav1.CreateOptions{DryRun: dryRun})
		if err != nil {
			return nil, nil, err
		}
		preview = created.Object
	case "apply":
		object, err := operationObject(operation)
		if err != nil {
			return nil, nil, err
		}
		if object.GetName() == "" {
			return nil, nil, policyError("invalid_input", "object.metadata.name is required")
		}
		operation.Name = object.GetName()
		if current, err := resource.Get(ctx, operation.Name, metav1.GetOptions{}); err == nil {
			if err := rejectOperatorManaged(current.GetLabels()); err != nil {
				return nil, nil, err
			}
			previous = current.Object
			operation.TargetUID = string(current.GetUID())
			operation.ResourceVersion = current.GetResourceVersion()
		} else if apierrors.IsNotFound(err) {
			return nil, nil, policyError("invalid_input", "apply target does not exist; use a create capability so creation remains atomic")
		} else {
			return nil, nil, err
		}
		object.SetResourceVersion(operation.ResourceVersion)
		operation.Object = object.Object
		data, _ := json.Marshal(object.Object)
		force := operation.Force
		applied, err := resource.Patch(ctx, operation.Name, types.ApplyPatchType, data, metav1.PatchOptions{
			DryRun: dryRun, FieldManager: "supek8smcp", Force: &force,
		})
		if err != nil {
			return nil, nil, err
		}
		preview = applied.Object
	case "patch", "scale", "restart":
		current, err := resource.Get(ctx, operation.Name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, err
		}
		if err := rejectOperatorManaged(current.GetLabels()); err != nil {
			return nil, nil, err
		}
		if action.Action != "scale" {
			previous = current.Object
		}
		operation.TargetUID = string(current.GetUID())
		operation.ResourceVersion = current.GetResourceVersion()
		patchType, data, subresources, err := preparePatch(operation)
		if err != nil {
			return nil, nil, err
		}
		patched, err := resource.Patch(ctx, operation.Name, patchType, data, metav1.PatchOptions{DryRun: dryRun, FieldManager: "supek8smcp"}, subresources...)
		if err != nil {
			return nil, nil, err
		}
		preview = patched.Object
	case "update":
		current, err := resource.Get(ctx, operation.Name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, err
		}
		if err := rejectOperatorManaged(current.GetLabels()); err != nil {
			return nil, nil, err
		}
		previous = current.Object
		operation.TargetUID = string(current.GetUID())
		operation.ResourceVersion = current.GetResourceVersion()
		object, err := operationObject(operation)
		if err != nil {
			return nil, nil, err
		}
		object.SetResourceVersion(current.GetResourceVersion())
		operation.Object = object.Object
		updated, err := resource.Update(ctx, object, metav1.UpdateOptions{DryRun: dryRun, FieldManager: "supek8smcp"})
		if err != nil {
			return nil, nil, err
		}
		preview = updated.Object
	case "delete":
		current, err := resource.Get(ctx, operation.Name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, err
		}
		if err := rejectOperatorManaged(current.GetLabels()); err != nil {
			return nil, nil, err
		}
		operation.TargetUID = string(current.GetUID())
		operation.ResourceVersion = current.GetResourceVersion()
		uid := current.GetUID()
		rv := current.GetResourceVersion()
		if err := resource.Delete(ctx, operation.Name, metav1.DeleteOptions{
			DryRun: dryRun, GracePeriodSeconds: operation.GracePeriod,
			Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv},
		}); err != nil {
			return nil, nil, err
		}
		preview = map[string]any{"apiVersion": current.GetAPIVersion(), "kind": current.GetKind(), "metadata": map[string]any{"name": current.GetName(), "uid": uid, "resourceVersion": rv}}
	case "exec", "attach":
		pod, err := principal.Kubernetes.CoreV1().Pods(operation.Namespace).Get(ctx, operation.Name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, err
		}
		if err := rejectOperatorManaged(pod.Labels); err != nil {
			return nil, nil, err
		}
		operation.TargetUID = string(pod.UID)
		operation.ResourceVersion = pod.ResourceVersion
		if err := validateContainer(pod, operation.Container); err != nil {
			return nil, nil, err
		}
		if action.Action == "exec" && len(operation.Command) == 0 {
			return nil, nil, policyError("invalid_input", "command is required for exec")
		}
		preview = map[string]any{
			"pod": operation.Name, "uid": pod.UID, "container": selectedContainer(pod, operation.Container),
			"command": operation.Command, "stdinBytes": len(operation.Stdin), "tty": false,
		}
		warnings = append(warnings, "remote execution cannot be server-side dry-run; commit will open the stream after rechecking the Pod UID and RBAC")
	default:
		return nil, nil, policyError("unsupported_operation", "operation is not implemented")
	}
	if a.config.Spec.Mode == mcpv1alpha1.ModeSafeWrite {
		if err := validateSafeTransition(previous, preview); err != nil {
			return nil, nil, err
		}
		if action.GVR.Group == "" && action.GVR.Resource == "services" {
			if object, ok := preview.(map[string]any); ok {
				if err := validateSafeServiceChange(object, nil, ""); err != nil {
					return nil, nil, err
				}
			}
		}
	}
	preview, err := redactResult(preview, action, a.config.Spec.Policy.SensitiveReads)
	return preview, warnings, err
}

func rejectOperatorManaged(labels map[string]string) error {
	if labels["app.kubernetes.io/managed-by"] == "supek8smcp-operator" {
		return policyError("managed_resource_denied", "operator-managed resources may not be mutated through Kubernetes MCP")
	}
	return nil
}

func (a *App) executeOperation(ctx context.Context, request *mcp.CallToolRequest, principal *Principal, operation Operation) (map[string]any, error) {
	action := operation.Action
	resource := dynamicResource(principal, action, operation.Namespace)
	switch action.Action {
	case "create":
		object, err := operationObject(&operation)
		if err != nil {
			return nil, err
		}
		created, err := resource.Create(ctx, object, metav1.CreateOptions{FieldManager: "supek8smcp"})
		if err != nil {
			return nil, err
		}
		return created.Object, nil
	case "apply":
		object, err := operationObject(&operation)
		if err != nil {
			return nil, err
		}
		object.SetResourceVersion(operation.ResourceVersion)
		data, _ := json.Marshal(object.Object)
		force := operation.Force
		applied, err := resource.Patch(ctx, operation.Name, types.ApplyPatchType, data, metav1.PatchOptions{FieldManager: "supek8smcp", Force: &force})
		if err != nil {
			return nil, err
		}
		return applied.Object, nil
	case "patch", "scale", "restart":
		patchType, data, subresources, err := preparePatch(&operation)
		if err != nil {
			return nil, err
		}
		patched, err := resource.Patch(ctx, operation.Name, patchType, data, metav1.PatchOptions{FieldManager: "supek8smcp"}, subresources...)
		if err != nil {
			return nil, err
		}
		return patched.Object, nil
	case "update":
		object, err := operationObject(&operation)
		if err != nil {
			return nil, err
		}
		object.SetResourceVersion(operation.ResourceVersion)
		updated, err := resource.Update(ctx, object, metav1.UpdateOptions{FieldManager: "supek8smcp"})
		if err != nil {
			return nil, err
		}
		return updated.Object, nil
	case "delete":
		uid := types.UID(operation.TargetUID)
		rv := operation.ResourceVersion
		err := resource.Delete(ctx, operation.Name, metav1.DeleteOptions{GracePeriodSeconds: operation.GracePeriod, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
		if err != nil {
			return nil, err
		}
		return map[string]any{"deleted": true, "name": operation.Name, "uid": operation.TargetUID}, nil
	case "exec", "attach":
		return a.executeRemote(ctx, request, principal, operation)
	default:
		return nil, policyError("unsupported_operation", "operation is not implemented")
	}
}

func (a *App) checkOperationPreconditions(ctx context.Context, principal *Principal, operation Operation) error {
	resource := dynamicResource(principal, operation.Action, operation.Namespace)
	if operation.ExpectedAbsent {
		_, err := resource.Get(ctx, operation.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return policyError("conflict", "resource was created after the plan")
	}
	if operation.TargetUID == "" {
		return nil
	}
	current, err := resource.Get(ctx, operation.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(current.GetUID()) != operation.TargetUID || current.GetResourceVersion() != operation.ResourceVersion {
		return policyError("conflict", "resource changed after the plan; create a new plan")
	}
	return nil
}

func operationObject(operation *Operation) (*unstructured.Unstructured, error) {
	if operation.Object == nil {
		return nil, policyError("invalid_input", "object is required")
	}
	data, err := json.Marshal(operation.Object)
	if err != nil {
		return nil, policyError("invalid_input", "object is not valid JSON")
	}
	copy := map[string]any{}
	if err := json.Unmarshal(data, &copy); err != nil {
		return nil, err
	}
	object := &unstructured.Unstructured{Object: copy}
	object.SetGroupVersionKind(schema.GroupVersionKind{Group: operation.Action.GVR.Group, Version: operation.Action.GVR.Version, Kind: operation.Action.Kind})
	if operation.Name != "" {
		object.SetName(operation.Name)
	}
	if operation.Action.Namespaced {
		object.SetNamespace(operation.Namespace)
	}
	return object, nil
}

func preparePatch(operation *Operation) (types.PatchType, []byte, []string, error) {
	var body any = operation.Patch
	patchType := types.MergePatchType
	var subresources []string
	switch operation.Action.Action {
	case "scale":
		if operation.Replicas == nil {
			return "", nil, nil, policyError("invalid_input", "replicas is required for scale")
		}
		body = map[string]any{"spec": map[string]any{"replicas": *operation.Replicas}}
		subresources = []string{"scale"}
	case "restart":
		if operation.Patch == nil {
			body = map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]any{"mcp.supek8smcp.io/restartedAt": time.Now().UTC().Format(time.RFC3339Nano)}}}}}
			operation.Patch = body
		} else {
			body = operation.Patch
		}
	case "patch":
		if body == nil {
			return "", nil, nil, policyError("invalid_input", "patch is required")
		}
		if operation.PatchType == "json" {
			patchType = types.JSONPatchType
		}
		if operation.PatchType != "" && operation.PatchType != "merge" && operation.PatchType != "json" {
			return "", nil, nil, policyError("invalid_input", "patchType must be merge or json")
		}
	}
	if operation.ResourceVersion != "" {
		var err error
		body, err = addPatchResourceVersion(body, patchType, operation.ResourceVersion)
		if err != nil {
			return "", nil, nil, err
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", nil, nil, policyError("invalid_input", "patch is not valid JSON")
	}
	return patchType, data, subresources, nil
}

func addPatchResourceVersion(body any, patchType types.PatchType, resourceVersion string) (any, error) {
	if patchType == types.JSONPatchType {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, policyError("invalid_input", "JSON patch is not valid JSON")
		}
		var operations []any
		if err := json.Unmarshal(data, &operations); err != nil {
			return nil, policyError("invalid_input", "JSON patch must be an array")
		}
		precondition := map[string]any{"op": "test", "path": "/metadata/resourceVersion", "value": resourceVersion}
		return append([]any{precondition}, operations...), nil
	}
	object, ok := body.(map[string]any)
	if !ok {
		return nil, policyError("invalid_input", "merge patch must be an object")
	}
	copy := cloneMap(object)
	metadata, _ := copy["metadata"].(map[string]any)
	metadata = cloneMap(metadata)
	metadata["resourceVersion"] = resourceVersion
	copy["metadata"] = metadata
	return copy, nil
}

func operationSummary(operation Operation) map[string]any {
	return map[string]any{
		"action": operation.Action.Action, "verb": operation.Action.Verb,
		"group": operation.Action.GVR.Group, "version": operation.Action.GVR.Version,
		"resource": operation.Action.ResourceName(), "namespace": operation.Namespace,
		"name": operation.Name, "targetUID": operation.TargetUID, "resourceVersion": operation.ResourceVersion,
	}
}
