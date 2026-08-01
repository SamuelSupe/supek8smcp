package server

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

func validateSafePayload(value any) error {
	return walkPayload(value, "")
}

func validateSafeOperation(action Action, object map[string]any, patch any, patchType string) error {
	if object != nil {
		if err := validateSafePayload(object); err != nil {
			return err
		}
	}
	if patch != nil {
		if err := validateSafePayload(patch); err != nil {
			return err
		}
		if patchType == "json" {
			if err := validateSafeJSONPatch(patch); err != nil {
				return err
			}
		}
	}
	if action.GVR.Group == "" && action.GVR.Resource == "services" {
		if err := validateSafeServiceChange(object, patch, patchType); err != nil {
			return err
		}
	}
	return nil
}

func validateSafeJSONPatch(value any) error {
	operations, ok := value.([]any)
	if !ok {
		return policyError("invalid_input", "JSON patch must be an array")
	}
	for _, raw := range operations {
		operation, ok := raw.(map[string]any)
		if !ok {
			return policyError("invalid_input", "JSON patch entries must be objects")
		}
		op, _ := operation["op"].(string)
		path, _ := operation["path"].(string)
		if !slices.Contains([]string{"add", "remove", "replace", "test"}, op) || path == "" {
			return policyError("unsafe_payload", "SafeWrite JSON patch only permits add, remove, replace, and test with an explicit path")
		}
		segments, err := decodeJSONPointer(path)
		if err != nil {
			return err
		}
		if unsafePatchSegments(segments) {
			return policyError("unsafe_payload", fmt.Sprintf("JSON patch path %q is blocked in SafeWrite mode", path))
		}
		if patchValue, exists := operation["value"]; exists {
			if err := walkPayload(patchValue, strings.Join(segments, ".")); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeJSONPointer(path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, policyError("invalid_input", "JSON patch path must be an absolute JSON pointer")
	}
	rawSegments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	segments := make([]string, len(rawSegments))
	for index, raw := range rawSegments {
		var decoded strings.Builder
		for offset := 0; offset < len(raw); offset++ {
			if raw[offset] != '~' {
				decoded.WriteByte(raw[offset])
				continue
			}
			if offset+1 >= len(raw) || (raw[offset+1] != '0' && raw[offset+1] != '1') {
				return nil, policyError("invalid_input", "JSON patch path contains an invalid escape")
			}
			offset++
			if raw[offset] == '0' {
				decoded.WriteByte('~')
			} else {
				decoded.WriteByte('/')
			}
		}
		segments[index] = decoded.String()
	}
	return segments, nil
}

func unsafePatchSegments(segments []string) bool {
	blocked := []string{
		"hostNetwork", "hostPID", "hostIPC", "hostPath", "hostPort", "privileged",
		"allowPrivilegeEscalation", "capabilities", "ephemeralContainers", "serviceAccountName",
		"serviceAccountToken", "automountServiceAccountToken", "shareProcessNamespace", "nodeName",
		"runtimeClassName", "sysctls", "procMount", "hostProcess", "seLinuxOptions", "secret",
		"secretRef", "secretKeyRef", "securityContext", "runAsUser", "runAsGroup", "runAsNonRoot",
		"readOnlyRootFilesystem", "seccompProfile", "appArmorProfile", "priorityClassName", "fsGroup",
		"supplementalGroups", "runAsUserName", "gmsaCredentialSpec", "gmsaCredentialSpecName",
	}
	for _, segment := range segments {
		lower := strings.ToLower(segment)
		if slices.Contains(blocked, segment) || strings.Contains(lower, "apparmor") || strings.Contains(lower, "seccomp") {
			return true
		}
	}
	return false
}

func validateSafeServiceChange(object map[string]any, patch any, patchType string) error {
	if spec, ok := object["spec"].(map[string]any); ok {
		if err := validateSafeServiceSpec(spec); err != nil {
			return err
		}
	}
	if patchType == "json" {
		if operations, ok := patch.([]any); ok {
			for _, raw := range operations {
				operation, _ := raw.(map[string]any)
				path, _ := operation["path"].(string)
				segments, err := decodeJSONPointer(path)
				if err != nil {
					return err
				}
				if err := validateSafeServicePatchValue(segments, operation["value"]); err != nil {
					return policyError("unsafe_payload", fmt.Sprintf("Service patch path %q is blocked in SafeWrite mode: %s", path, err.Error()))
				}
			}
		}
		return nil
	}
	if patchMap, ok := patch.(map[string]any); ok {
		if spec, ok := patchMap["spec"].(map[string]any); ok {
			return validateSafeServiceSpec(spec)
		}
	}
	return nil
}

func validateSafeServiceSpec(spec map[string]any) error {
	if serviceType, _ := spec["type"].(string); serviceType != "" && serviceType != "ClusterIP" {
		return policyError("unsafe_payload", "SafeWrite only permits ClusterIP Services")
	}
	for _, field := range []string{"externalName", "externalIPs", "loadBalancerIP", "loadBalancerClass"} {
		if value, exists := spec[field]; exists && nonEmptyValue(value) {
			return policyError("unsafe_payload", fmt.Sprintf("Service spec.%s is blocked in SafeWrite mode", field))
		}
	}
	if err := validateSafeServicePorts(spec["ports"]); err != nil {
		return err
	}
	if healthCheckNodePort, ok := numeric(spec["healthCheckNodePort"]); ok && healthCheckNodePort > 0 {
		return policyError("unsafe_payload", "Service healthCheckNodePort is blocked in SafeWrite mode")
	}
	return nil
}

func validateSafeServicePatchValue(segments []string, value any) error {
	if len(segments) == 0 || segments[0] != "spec" {
		return nil
	}
	if len(segments) == 1 {
		if spec, ok := value.(map[string]any); ok {
			return validateSafeServiceSpec(spec)
		}
		return nil
	}
	switch segments[1] {
	case "type", "externalName", "externalIPs", "loadBalancerIP", "loadBalancerClass", "healthCheckNodePort":
		return fmt.Errorf("spec.%s may change Service exposure", segments[1])
	case "ports":
		if slices.Contains(segments[2:], "nodePort") {
			return fmt.Errorf("Service nodePort may not be changed")
		}
		if len(segments) == 2 {
			return validateSafeServicePorts(value)
		}
		if len(segments) == 3 {
			return validateSafeServicePort(value)
		}
	}
	return nil
}

func validateSafeServicePorts(value any) error {
	ports, ok := value.([]any)
	if !ok {
		return nil
	}
	for _, port := range ports {
		if err := validateSafeServicePort(port); err != nil {
			return err
		}
	}
	return nil
}

func validateSafeServicePort(value any) error {
	port, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if nodePort, ok := numeric(port["nodePort"]); ok && nodePort > 0 {
		return policyError("unsafe_payload", "Service nodePort is blocked in SafeWrite mode")
	}
	return nil
}

func nonEmptyValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return typed != ""
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func walkPayload(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if err := validatePayloadField(path, key, child); err != nil {
				return err
			}
			childPath := strings.TrimPrefix(path+"."+key, ".")
			if err := walkPayload(child, childPath); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range typed {
			if err := walkPayload(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePayloadField(path, key string, child any) error {
	childPath := strings.TrimPrefix(path+"."+key, ".")
	inSpec := path == "spec" || strings.HasPrefix(path, "spec.") || strings.Contains(path, ".spec.")
	switch key {
	case "hostNetwork", "hostPID", "hostIPC", "privileged", "allowPrivilegeEscalation", "automountServiceAccountToken", "shareProcessNamespace", "hostProcess":
		if enabled, _ := child.(bool); inSpec && enabled {
			return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
		}
	case "readOnlyRootFilesystem":
		if enabled, ok := child.(bool); inSpec && ok && !enabled {
			return policyError("unsafe_payload", childPath+" may not disable the read-only root filesystem")
		}
	case "hostPath", "ephemeralContainers", "serviceAccountToken", "secret", "secretRef", "secretKeyRef", "sysctls", "seLinuxOptions":
		if inSpec && child != nil {
			return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
		}
	case "serviceAccountName":
		if name, _ := child.(string); inSpec && name != "" && name != "default" {
			return policyError("unsafe_payload", childPath+" may not select a non-default ServiceAccount")
		}
	case "hostPort":
		if port, ok := numeric(child); inSpec && ok && port > 0 {
			return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
		}
	case "runAsUser", "runAsGroup":
		if user, ok := numeric(child); inSpec && ok && user == 0 {
			return policyError("unsafe_payload", childPath+" may not select root")
		}
	case "fsGroup":
		if group, ok := numeric(child); inSpec && ok && group == 0 {
			return policyError("unsafe_payload", childPath+" may not select the root group")
		}
	case "supplementalGroups":
		if inSpec && containsNumeric(child, 0) {
			return policyError("unsafe_payload", childPath+" may not include the root group")
		}
	case "runAsNonRoot":
		if enabled, ok := child.(bool); inSpec && ok && !enabled {
			return policyError("unsafe_payload", childPath+" may not disable non-root enforcement")
		}
	case "nodeName", "runtimeClassName", "priorityClassName", "procMount", "gmsaCredentialSpec", "gmsaCredentialSpecName":
		if text, _ := child.(string); inSpec && text != "" {
			return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
		}
	case "runAsUserName":
		if name, _ := child.(string); inSpec && name != "" && !strings.EqualFold(name, "ContainerUser") {
			return policyError("unsafe_payload", childPath+" may only select ContainerUser")
		}
	case "add":
		if strings.HasSuffix(path, "capabilities") {
			return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
		}
	case "type":
		if strings.HasSuffix(path, "seccompProfile") || strings.HasSuffix(path, "appArmorProfile") {
			if profile, _ := child.(string); strings.EqualFold(profile, "Unconfined") {
				return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
			}
		}
	}
	lowerKey := strings.ToLower(key)
	if (strings.Contains(lowerKey, "apparmor") || strings.Contains(lowerKey, "seccomp")) && strings.EqualFold(fmt.Sprint(child), "unconfined") {
		return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
	}
	return nil
}

func validateSafeTransition(before, after any) error {
	if err := validateSafePayload(after); err != nil {
		return err
	}
	if before == nil {
		return nil
	}
	return walkSecurityTransition(before, after, "")
}

func walkSecurityTransition(before, after any, path string) error {
	switch current := before.(type) {
	case map[string]any:
		next, _ := after.(map[string]any)
		for key, previousValue := range current {
			childPath := strings.TrimPrefix(path+"."+key, ".")
			nextValue, exists := next[key]
			inSpec := path == "spec" || strings.HasPrefix(path, "spec.") || strings.Contains(path, ".spec.")
			if err := validateSecurityControlTransition(key, previousValue, nextValue, exists, childPath, inSpec); err != nil {
				return err
			}
			if err := walkSecurityTransition(previousValue, nextValue, childPath); err != nil {
				return err
			}
		}
	case []any:
		next, _ := after.([]any)
		for index, previousValue := range current {
			nextValue, exists := matchingListValue(previousValue, next, index)
			if !exists {
				continue
			}
			if err := walkSecurityTransition(previousValue, nextValue, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSecurityControlTransition(key string, before, after any, exists bool, path string, inSpec bool) error {
	if !inSpec {
		return nil
	}
	weakened := false
	switch key {
	case "allowPrivilegeEscalation", "automountServiceAccountToken":
		value, ok := before.(bool)
		weakened = ok && !value && (!exists || !isBool(after, false))
	case "runAsNonRoot", "readOnlyRootFilesystem":
		value, ok := before.(bool)
		weakened = ok && value && (!exists || !isBool(after, true))
	case "runAsUser", "runAsGroup", "fsGroup":
		value, ok := numeric(before)
		next, nextOK := numeric(after)
		weakened = ok && value != 0 && (!exists || !nextOK || next == 0)
	case "runAsUserName":
		value, ok := before.(string)
		next, nextOK := after.(string)
		weakened = ok && strings.EqualFold(value, "ContainerUser") && (!exists || !nextOK || !strings.EqualFold(next, "ContainerUser"))
	case "serviceAccountName", "runtimeClassName":
		value, ok := before.(string)
		next, nextOK := after.(string)
		weakened = ok && value != "" && (!exists || !nextOK || next != value)
	case "capabilities":
		weakened = !preservesDroppedCapabilities(before, after)
	case "seccompProfile", "appArmorProfile":
		weakened = protectiveProfile(before) && (!exists || !reflect.DeepEqual(before, after))
	case "seLinuxOptions":
		weakened = before != nil && (!exists || !reflect.DeepEqual(before, after))
	default:
		lower := strings.ToLower(key)
		if strings.Contains(lower, "apparmor") || strings.Contains(lower, "seccomp") {
			value, ok := before.(string)
			weakened = ok && value != "" && !strings.EqualFold(value, "unconfined") && (!exists || !reflect.DeepEqual(before, after))
		}
	}
	if !weakened {
		return nil
	}
	return policyError("unsafe_payload", path+" may not weaken an existing workload security control in SafeWrite mode")
}

func matchingListValue(previous any, next []any, index int) (any, bool) {
	if previousMap, ok := previous.(map[string]any); ok {
		if name, _ := previousMap["name"].(string); name != "" {
			for _, candidate := range next {
				candidateMap, _ := candidate.(map[string]any)
				if candidateMap["name"] == name {
					return candidate, true
				}
			}
		}
	}
	if index >= len(next) {
		return nil, false
	}
	return next[index], true
}

func isBool(value any, wanted bool) bool {
	actual, ok := value.(bool)
	return ok && actual == wanted
}

func protectiveProfile(value any) bool {
	profile, ok := value.(map[string]any)
	if !ok {
		return false
	}
	profileType, _ := profile["type"].(string)
	return profileType != "" && !strings.EqualFold(profileType, "unconfined")
}

func preservesDroppedCapabilities(before, after any) bool {
	beforeMap, ok := before.(map[string]any)
	if !ok {
		return true
	}
	required := stringSet(beforeMap["drop"])
	if len(required) == 0 {
		return true
	}
	afterMap, ok := after.(map[string]any)
	if !ok {
		return false
	}
	present := stringSet(afterMap["drop"])
	for capability := range required {
		if !present[capability] {
			return false
		}
	}
	return true
}

func stringSet(value any) map[string]bool {
	result := map[string]bool{}
	switch items := value.(type) {
	case []any:
		for _, item := range items {
			if text, ok := item.(string); ok {
				result[text] = true
			}
		}
	case []string:
		for _, item := range items {
			result[item] = true
		}
	}
	return result
}

func numeric(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	default:
		return 0, false
	}
}

func containsNumeric(value any, wanted float64) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if number, ok := numeric(item); ok && number == wanted {
			return true
		}
	}
	return false
}
