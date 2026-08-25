package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const searchAuthorizationCheckLimit = 100

type catalogSearchFilter struct {
	Query         string
	Action        string
	ExactKind     string
	ExactResource string
	APIGroup      string
	Version       string
	Namespace     string
	Name          string
}

type catalogCache struct {
	mu        sync.Mutex
	refreshMu sync.Mutex
	loadedAt  time.Time
	items     []Capability
	cacheTime time.Duration
	codec     *capabilityCodec
}

func newCatalogCache(codec *capabilityCodec) *catalogCache {
	return &catalogCache{cacheTime: 5 * time.Minute, codec: codec}
}

func (c *catalogCache) list(ctx context.Context, principal *Principal) ([]Capability, error) {
	c.mu.Lock()
	if time.Since(c.loadedAt) < c.cacheTime && len(c.items) > 0 {
		items := append([]Capability(nil), c.items...)
		c.mu.Unlock()
		return items, nil
	}
	stale := append([]Capability(nil), c.items...)
	c.mu.Unlock()

	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.Lock()
	if time.Since(c.loadedAt) < c.cacheTime && len(c.items) > 0 {
		items := append([]Capability(nil), c.items...)
		c.mu.Unlock()
		return items, nil
	}
	stale = append([]Capability(nil), c.items...)
	c.mu.Unlock()

	groups, discovered, err := principal.Discovery.ServerGroupsAndResources()
	resources := preferredResourceLists(groups, discovered)
	if err != nil {
		if len(stale) > 0 {
			return stale, nil
		}
		if len(resources) == 0 {
			return nil, fmt.Errorf("discover Kubernetes resources: %w", err)
		}
	}

	type resourceInfo struct {
		kind       string
		namespaced bool
		categories []string
		verbs      map[string]bool
	}
	baseResources := make(map[string]resourceInfo)
	for _, list := range resources {
		gv, parseErr := schema.ParseGroupVersion(list.GroupVersion)
		if parseErr != nil {
			continue
		}
		for _, resource := range list.APIResources {
			if strings.Contains(resource.Name, "/") {
				continue
			}
			verbs := make(map[string]bool, len(resource.Verbs))
			for _, verb := range resource.Verbs {
				verbs[verb] = true
			}
			baseResources[gv.String()+"/"+resource.Name] = resourceInfo{
				kind: resource.Kind, namespaced: resource.Namespaced, categories: resource.Categories, verbs: verbs,
			}
		}
	}

	var capabilities []Capability
	for _, list := range resources {
		gv, parseErr := schema.ParseGroupVersion(list.GroupVersion)
		if parseErr != nil {
			continue
		}
		for _, resource := range list.APIResources {
			parts := strings.SplitN(resource.Name, "/", 2)
			base := parts[0]
			subresource := ""
			if len(parts) == 2 {
				subresource = parts[1]
			}
			info, ok := baseResources[gv.String()+"/"+base]
			if !ok {
				info = resourceInfo{kind: resource.Kind, namespaced: resource.Namespaced, categories: resource.Categories, verbs: map[string]bool{}}
			}
			for _, verb := range resource.Verbs {
				if subresource == "" && !slices.Contains([]string{"get", "list", "watch", "create", "update", "patch", "delete"}, verb) {
					continue
				}
				actionName := verb
				actionVerb := verb
				switch subresource {
				case "log":
					if verb != "get" {
						continue
					}
					actionName = "logs"
				case "exec", "attach":
					if verb != "create" {
						continue
					}
					actionName = subresource
				case "scale":
					if verb != "patch" {
						continue
					}
					actionName = "scale"
				default:
					if subresource != "" {
						continue
					}
				}
				action := Action{
					GVR:  schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: base},
					Kind: info.kind, Subresource: subresource, Verb: actionVerb, Action: actionName, Namespaced: info.namespaced,
				}
				capabilities = append(capabilities, capabilityFromAction(c.codec, action, info.categories))
			}
			if subresource == "" && info.verbs["patch"] && gv.Group == "apps" &&
				(resource.Name == "deployments" || resource.Name == "statefulsets" || resource.Name == "daemonsets") {
				action := Action{
					GVR:  schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: resource.Name},
					Kind: info.kind, Verb: "patch", Action: "restart", Namespaced: info.namespaced,
				}
				capabilities = append(capabilities, capabilityFromAction(c.codec, action, info.categories))
			}
			if subresource == "" && info.verbs["patch"] {
				action := Action{
					GVR:  schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: resource.Name},
					Kind: info.kind, Verb: "patch", Action: "apply", Namespaced: info.namespaced,
				}
				capabilities = append(capabilities, capabilityFromAction(c.codec, action, info.categories))
			}
		}
	}
	sort.Slice(capabilities, func(i, j int) bool {
		left := capabilities[i]
		right := capabilities[j]
		return left.Group+"/"+left.Version+"/"+left.Resource+"/"+left.Action < right.Group+"/"+right.Version+"/"+right.Resource+"/"+right.Action
	})
	if err == nil {
		c.mu.Lock()
		retained := make([]Capability, 0, len(capabilities)+len(c.items))
		retained = append(retained, capabilities...)
		retained = append(retained, c.items...)
		c.codec.retain(retained)
		c.items = capabilities
		c.loadedAt = time.Now()
		c.mu.Unlock()
	}
	return append([]Capability(nil), capabilities...), nil
}

func preferredResourceLists(groups []*metav1.APIGroup, resources []*metav1.APIResourceList) []*metav1.APIResourceList {
	preferred := make(map[string]string, len(groups))
	for _, group := range groups {
		if group == nil {
			continue
		}
		groupVersion := group.PreferredVersion.GroupVersion
		if groupVersion == "" && group.PreferredVersion.Version != "" {
			groupVersion = schema.GroupVersion{Group: group.Name, Version: group.PreferredVersion.Version}.String()
		}
		if groupVersion != "" {
			preferred[group.Name] = groupVersion
		}
	}
	selected := make([]*metav1.APIResourceList, 0, len(resources))
	for _, resourceList := range resources {
		if resourceList == nil {
			continue
		}
		groupVersion, err := schema.ParseGroupVersion(resourceList.GroupVersion)
		wanted, known := preferred[groupVersion.Group]
		if err == nil && (!known || wanted == resourceList.GroupVersion) {
			selected = append(selected, resourceList)
		}
	}
	return selected
}

func searchCatalog(
	ctx context.Context,
	items []Capability,
	policy *Policy,
	principal *Principal,
	filter catalogSearchFilter,
	cursor string,
	limit int64,
) ([]Capability, string, error) {
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	wantedAction := strings.TrimSpace(filter.Action)
	wantedGroup := strings.TrimSpace(filter.APIGroup)
	if strings.EqualFold(wantedGroup, "core") {
		wantedGroup = ""
	}
	start, err := decodeCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	var filtered []Capability
	for _, capability := range items {
		if wantedAction != "" && !strings.EqualFold(capability.Action, wantedAction) && !strings.EqualFold(capability.Verb, wantedAction) {
			continue
		}
		if filter.ExactKind != "" && !strings.EqualFold(capability.Kind, strings.TrimSpace(filter.ExactKind)) {
			continue
		}
		if filter.ExactResource != "" && !matchesExactResource(capability, strings.TrimSpace(filter.ExactResource)) {
			continue
		}
		if filter.APIGroup != "" && !strings.EqualFold(capability.Group, wantedGroup) {
			continue
		}
		if filter.Version != "" && !strings.EqualFold(capability.Version, strings.TrimSpace(filter.Version)) {
			continue
		}
		haystack := strings.ToLower(strings.Join([]string{capability.Group, capability.Version, capability.Resource, capability.Kind, capability.Action, strings.Join(capability.Categories, " ")}, " "))
		if query != "" && !strings.Contains(haystack, query) {
			continue
		}
		filtered = append(filtered, capability)
	}
	if start > len(filtered) {
		return nil, "", policyError("invalid_cursor", "cursor is outside the result set")
	}
	result := make([]Capability, 0, limit)
	index := start
	authorizationChecks := 0
	for index < len(filtered) && int64(len(result)) < limit {
		capability := filtered[index]
		action := capability.AsAction()
		targetNamespace := filter.Namespace
		if action.Namespaced && targetNamespace == "" && len(policy.config.Spec.Scope.Namespaces) > 0 {
			targetNamespace = policy.config.Spec.Scope.Namespaces[0]
		}
		if authorizationChecks >= searchAuthorizationCheckLimit {
			break
		}
		authorizationChecks++
		index++
		if err := policy.CheckAndAuthorizeOperation(ctx, principal, action, targetNamespace, filter.Name); err != nil {
			continue
		}
		result = append(result, capability)
	}
	next := ""
	if index < len(filtered) {
		next = encodeCursor(index)
	}
	return result, next, nil
}

func matchesExactResource(capability Capability, wanted string) bool {
	if strings.EqualFold(capability.Resource, wanted) {
		return true
	}
	return capability.Subresource != "" && strings.EqualFold(capability.Resource+"/"+capability.Subresource, wanted)
}

func encodeCursor(index int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(index)))
}

func decodeCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, policyError("invalid_cursor", "cursor is not valid")
	}
	index, err := strconv.Atoi(string(data))
	if err != nil || index < 0 {
		return 0, policyError("invalid_cursor", "cursor is not valid")
	}
	return index, nil
}
