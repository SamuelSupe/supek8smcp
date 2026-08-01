package server

import (
	"fmt"
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
		if unsafePatchPath(path) {
			return policyError("unsafe_payload", fmt.Sprintf("JSON patch path %q is blocked in SafeWrite mode", path))
		}
	}
	return nil
}

func unsafePatchPath(path string) bool {
	blocked := []string{
		"hostNetwork", "hostPID", "hostIPC", "hostPath", "hostPort", "privileged",
		"allowPrivilegeEscalation", "capabilities", "ephemeralContainers", "serviceAccountName",
		"serviceAccountToken", "automountServiceAccountToken", "shareProcessNamespace", "nodeName",
		"runtimeClassName", "sysctls", "procMount", "hostProcess", "seLinuxOptions", "secret",
		"secretRef", "secretKeyRef",
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		segment = strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
		if slices.Contains(blocked, segment) {
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
				forbidden := []string{"/spec/type", "/spec/externalName", "/spec/externalIPs", "/spec/loadBalancerIP", "/spec/loadBalancerClass", "/nodePort", "/healthCheckNodePort"}
				for _, fragment := range forbidden {
					if strings.Contains(path, fragment) {
						return policyError("unsafe_payload", fmt.Sprintf("Service patch path %q is blocked in SafeWrite mode", path))
					}
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
	if ports, ok := spec["ports"].([]any); ok {
		for _, raw := range ports {
			port, _ := raw.(map[string]any)
			if nodePort, ok := numeric(port["nodePort"]); ok && nodePort > 0 {
				return policyError("unsafe_payload", "Service nodePort is blocked in SafeWrite mode")
			}
		}
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
			childPath := strings.TrimPrefix(path+"."+key, ".")
			inSpec := path == "spec" || strings.HasPrefix(path, "spec.") || strings.Contains(path, ".spec.")
			switch key {
			case "hostNetwork", "hostPID", "hostIPC", "privileged", "allowPrivilegeEscalation", "automountServiceAccountToken", "shareProcessNamespace", "hostProcess":
				if enabled, _ := child.(bool); inSpec && enabled {
					return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
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
			case "runAsUser":
				if user, ok := numeric(child); inSpec && ok && user == 0 {
					return policyError("unsafe_payload", childPath+" may not select root")
				}
			case "runAsNonRoot":
				if enabled, ok := child.(bool); inSpec && ok && !enabled {
					return policyError("unsafe_payload", childPath+" may not disable non-root enforcement")
				}
			case "nodeName", "runtimeClassName", "procMount":
				if text, _ := child.(string); inSpec && text != "" {
					return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
				}
			case "add":
				if strings.HasSuffix(path, "capabilities") {
					return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
				}
			case "type":
				if strings.HasSuffix(path, "seccompProfile") {
					if profile, _ := child.(string); profile == "Unconfined" {
						return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
					}
				}
			}
			if strings.Contains(strings.ToLower(key), "apparmor") && strings.EqualFold(fmt.Sprint(child), "unconfined") {
				return policyError("unsafe_payload", childPath+" is blocked in SafeWrite mode")
			}
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
