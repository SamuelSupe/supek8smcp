package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

func TestCapabilityCodecRoundTripAndTamperRejection(t *testing.T) {
	t.Parallel()

	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	want := Capability{
		Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment",
		Action: "patch", Verb: "patch", Namespaced: true,
	}
	id := codec.encode(want)
	got, err := codec.decode(id)
	if err != nil {
		t.Fatalf("decode(round trip) error = %v", err)
	}
	if got.ID != id || got.Group != want.Group || got.Resource != want.Resource || got.Namespaced != want.Namespaced || got.Action != want.Action {
		t.Fatalf("decode(round trip) = %#v, want fields from %#v", got, want)
	}

	parts := strings.Split(id, ".")
	if len(parts) != 2 {
		t.Fatalf("encoded capability = %q, want payload.signature", id)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var tampered Capability
	if err := json.Unmarshal(payload, &tampered); err != nil {
		t.Fatalf("decode payload JSON: %v", err)
	}
	tampered.Resource = "pods"
	tamperedPayload, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("encode tampered payload: %v", err)
	}
	tamperedID := base64.RawURLEncoding.EncodeToString(tamperedPayload) + "." + parts[1]
	if _, err := codec.decode(tamperedID); policyReason(err) != "invalid_capability" {
		t.Fatalf("tampered resource decode error = %v, want invalid_capability", err)
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signatureBytes[0] ^= 1
	mutatedSignature := base64.RawURLEncoding.EncodeToString(signatureBytes)
	if _, err := codec.decode(parts[0] + "." + mutatedSignature); policyReason(err) != "invalid_capability" {
		t.Fatalf("tampered signature decode error = %v, want invalid_capability", err)
	}
}

func TestPreferredResourceListsKeepsPreferredSubresourcesAndUnknownGroups(t *testing.T) {
	t.Parallel()

	groups := []*metav1.APIGroup{
		{
			Name:             "",
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "v1", Version: "v1"},
		},
		{
			Name:             "apps",
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "apps/v1", Version: "v1"},
		},
	}
	resources := []*metav1.APIResourceList{
		{GroupVersion: "apps/v1beta1", APIResources: []metav1.APIResource{{Name: "deployments"}}},
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "pods"}, {Name: "pods/exec"}, {Name: "pods/log"},
			},
		},
		{GroupVersion: "apps/v1", APIResources: []metav1.APIResource{{Name: "deployments"}}},
		{GroupVersion: "example.com/v1", APIResources: []metav1.APIResource{{Name: "widgets"}}},
		{GroupVersion: "example.com/v1beta1", APIResources: []metav1.APIResource{{Name: "widgets"}}},
	}

	got := preferredResourceLists(groups, resources)
	byGroupVersion := make(map[string]*metav1.APIResourceList, len(got))
	for _, list := range got {
		byGroupVersion[list.GroupVersion] = list
	}
	for _, groupVersion := range []string{"v1", "apps/v1", "example.com/v1", "example.com/v1beta1"} {
		if byGroupVersion[groupVersion] == nil {
			t.Fatalf("preferredResourceLists() omitted %s; got %#v", groupVersion, byGroupVersion)
		}
	}
	if _, ok := byGroupVersion["apps/v1beta1"]; ok {
		t.Fatalf("preferredResourceLists() retained non-preferred apps/v1beta1")
	}
	for _, name := range []string{"pods", "pods/exec", "pods/log"} {
		found := false
		for _, resource := range byGroupVersion["v1"].APIResources {
			if resource.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("preferred core resource list omitted %s: %#v", name, byGroupVersion["v1"].APIResources)
		}
	}
}

func TestPreferredResourceListsWithoutGroupMetadataKeepsAllVersions(t *testing.T) {
	t.Parallel()

	resources := []*metav1.APIResourceList{
		{GroupVersion: "apps/v1beta1"},
		{GroupVersion: "apps/v1"},
		{GroupVersion: "example.com/v1beta1"},
	}
	got := preferredResourceLists(nil, resources)
	if !slices.Equal(got, resources) {
		t.Fatalf("preferredResourceLists(nil, resources) = %#v, want original list %#v", got, resources)
	}
}

type blockingCatalogDiscovery struct {
	discovery.DiscoveryInterface
	entered   chan struct{}
	release   <-chan struct{}
	groups    []*metav1.APIGroup
	resources []*metav1.APIResourceList
}

func (d *blockingCatalogDiscovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	d.entered <- struct{}{}
	<-d.release
	return d.groups, d.resources, nil
}

type catalogDiscoveryResponse struct {
	groups    []*metav1.APIGroup
	resources []*metav1.APIResourceList
	err       error
}

type scriptedCatalogDiscovery struct {
	discovery.DiscoveryInterface
	mu        sync.Mutex
	responses []catalogDiscoveryResponse
	calls     int
}

func (d *scriptedCatalogDiscovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	d.mu.Lock()
	index := d.calls
	d.calls++
	if index >= len(d.responses) {
		index = len(d.responses) - 1
	}
	response := d.responses[index]
	d.mu.Unlock()
	return response.groups, response.resources, response.err
}

func (d *scriptedCatalogDiscovery) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func catalogTestGroups(groupVersions ...string) []*metav1.APIGroup {
	groups := make([]*metav1.APIGroup, 0, len(groupVersions))
	for _, groupVersion := range groupVersions {
		gv, err := schema.ParseGroupVersion(groupVersion)
		if err != nil {
			panic(err)
		}
		groups = append(groups, &metav1.APIGroup{
			Name:             gv.Group,
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: groupVersion, Version: gv.Version},
		})
	}
	return groups
}

func catalogTestResources(groupVersion string, resources ...metav1.APIResource) *metav1.APIResourceList {
	return &metav1.APIResourceList{GroupVersion: groupVersion, APIResources: resources}
}

func catalogHasResource(items []Capability, resource string) bool {
	for _, item := range items {
		if item.Resource == resource {
			return true
		}
	}
	return false
}

func TestCatalogCachePartialDiscoveryDoesNotPopulateCache(t *testing.T) {
	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	partialResources := []*metav1.APIResourceList{
		catalogTestResources("v1", metav1.APIResource{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}}),
	}
	fullResources := []*metav1.APIResourceList{
		partialResources[0],
		catalogTestResources("apps/v1", metav1.APIResource{Name: "deployments", Kind: "Deployment", Namespaced: true, Verbs: []string{"get"}}),
	}
	discoveryClient := &scriptedCatalogDiscovery{responses: []catalogDiscoveryResponse{
		{groups: catalogTestGroups("v1", "apps/v1"), resources: partialResources, err: errors.New("partial discovery")},
		{groups: catalogTestGroups("v1", "apps/v1"), resources: fullResources},
	}}
	cache := newCatalogCache(codec)
	principal := &Principal{Discovery: discoveryClient}

	partial, err := cache.list(context.Background(), principal)
	if err != nil {
		t.Fatalf("partial catalogCache.list() error = %v, want partial result", err)
	}
	if !catalogHasResource(partial, "pods") || catalogHasResource(partial, "deployments") {
		t.Fatalf("partial catalogCache.list() resources = %#v, want pods only", partial)
	}
	if len(cache.items) != 0 || !cache.loadedAt.IsZero() {
		t.Fatalf("partial discovery populated cache: items=%#v loadedAt=%v", cache.items, cache.loadedAt)
	}

	complete, err := cache.list(context.Background(), principal)
	if err != nil {
		t.Fatalf("complete catalogCache.list() error = %v", err)
	}
	if discoveryClient.callCount() != 2 {
		t.Fatalf("discovery call count = %d, want partial and complete calls", discoveryClient.callCount())
	}
	if !catalogHasResource(complete, "pods") || !catalogHasResource(complete, "deployments") {
		t.Fatalf("complete catalogCache.list() resources = %#v, want pods and deployments", complete)
	}
	if !reflect.DeepEqual(cache.items, complete) || cache.loadedAt.IsZero() {
		t.Fatalf("complete discovery did not populate cache: items=%#v loadedAt=%v", cache.items, cache.loadedAt)
	}
}

func TestCatalogCacheExpiredSnapshotSurvivesPartialAndFailedDiscovery(t *testing.T) {
	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	stale := []Capability{
		capabilityFromAction(codec, Action{
			GVR:  schema.GroupVersionResource{Version: "v1", Resource: "pods"},
			Kind: "Pod", Verb: "get", Action: "get", Namespaced: true,
		}, nil),
		capabilityFromAction(codec, Action{
			GVR:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			Kind: "Deployment", Verb: "list", Action: "list", Namespaced: true,
		}, nil),
	}
	staleLoadedAt := time.Unix(1, 0)
	discoveryClient := &scriptedCatalogDiscovery{responses: []catalogDiscoveryResponse{
		{
			groups:    catalogTestGroups("v1"),
			resources: []*metav1.APIResourceList{catalogTestResources("v1", metav1.APIResource{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}})},
			err:       errors.New("partial discovery"),
		},
		{err: errors.New("discovery unavailable")},
	}}
	cache := newCatalogCache(codec)
	cache.items = append([]Capability(nil), stale...)
	cache.loadedAt = staleLoadedAt
	principal := &Principal{Discovery: discoveryClient}

	for attempt, wantReason := range []string{"partial", "failed"} {
		got, err := cache.list(context.Background(), principal)
		if err != nil {
			t.Fatalf("%s discovery catalogCache.list() error = %v, want stale snapshot", wantReason, err)
		}
		if !reflect.DeepEqual(got, stale) {
			t.Fatalf("%s discovery returned %#v, want stale %#v", wantReason, got, stale)
		}
		if !reflect.DeepEqual(cache.items, stale) || !cache.loadedAt.Equal(staleLoadedAt) {
			t.Fatalf("%s discovery polluted stale cache on attempt %d: items=%#v loadedAt=%v", wantReason, attempt+1, cache.items, cache.loadedAt)
		}
	}
	if discoveryClient.callCount() != 2 {
		t.Fatalf("discovery call count = %d, want partial and failed attempts", discoveryClient.callCount())
	}
}

func TestCatalogCacheConcurrentColdLoadsDoNotSerializeDiscovery(t *testing.T) {
	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	release := make(chan struct{})
	discoveryClient := &blockingCatalogDiscovery{
		entered: make(chan struct{}, 2), release: release,
		groups: []*metav1.APIGroup{{
			Name:             "",
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "v1", Version: "v1"},
		}},
		resources: []*metav1.APIResourceList{{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}}},
		}},
	}
	principal := &Principal{Discovery: discoveryClient}
	cache := newCatalogCache(codec)
	results := make(chan struct {
		items []Capability
		err   error
	}, 2)
	var start sync.WaitGroup
	start.Add(1)
	go func() {
		start.Done()
		items, err := cache.list(context.Background(), principal)
		results <- struct {
			items []Capability
			err   error
		}{items: items, err: err}
	}()
	start.Wait()

	waitForDiscovery := func() bool {
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-discoveryClient.entered:
			return true
		case <-timer.C:
			return false
		}
	}
	if !waitForDiscovery() {
		close(release)
		<-results
		t.Fatal("first catalog discovery call did not start")
	}

	start.Add(1)
	go func() {
		start.Done()
		items, err := cache.list(context.Background(), principal)
		results <- struct {
			items []Capability
			err   error
		}{items: items, err: err}
	}()
	start.Wait()
	secondEntered := waitForDiscovery()
	close(release)
	first, second := <-results, <-results
	if !secondEntered {
		t.Fatalf("second catalog discovery call did not start while first was blocked; first=%#v second=%#v", first, second)
	}
	for index, result := range []struct {
		items []Capability
		err   error
	}{first, second} {
		if result.err != nil {
			t.Fatalf("catalogCache.list() call %d error = %v", index+1, result.err)
		}
		if len(result.items) == 0 {
			t.Fatalf("catalogCache.list() call %d returned no capabilities", index+1)
		}
	}
}

func TestSearchCatalogPassesNameToSelfSubjectAccessReview(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	var reviewedName string
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(k8stesting.CreateAction)
		if !ok {
			return false, nil, nil
		}
		review := create.GetObject().(*authorizationv1.SelfSubjectAccessReview)
		if review.Spec.ResourceAttributes != nil {
			reviewedName = review.Spec.ResourceAttributes.Name
		}
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: reviewedName == "web"},
		}, nil
	})

	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	capability := capabilityFromAction(codec, policyTestAction("", "pods", "get", "get", true), nil)
	principal := &Principal{Kubernetes: client}
	result, _, err := searchCatalog(
		context.Background(), []Capability{capability}, NewPolicy(policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact)),
		principal, "pods", "get", "workloads", "web", "", 1,
	)
	if err != nil {
		t.Fatalf("searchCatalog() error = %v", err)
	}
	if reviewedName != "web" {
		t.Fatalf("SelfSubjectAccessReview resource name = %q, want web", reviewedName)
	}
	if len(result) != 1 || result[0].Resource != "pods" || result[0].Action != "get" {
		t.Fatalf("searchCatalog() result = %#v, want the named get capability", result)
	}
}

func TestSearchCatalogSkipsManagedMutationWithoutSelfSubjectAccessReview(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	ssarCount := 0
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssarCount++
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	capability := Capability{
		Version: "v1", Resource: "configmaps", Kind: "ConfigMap",
		Action: "patch", Verb: "patch", Namespaced: true,
	}
	policy := NewPolicy(managedTargetPolicyTestConfig())
	result, cursor, err := searchCatalog(
		context.Background(), []Capability{capability}, policy, &Principal{Kubernetes: client},
		"", "", policy.config.Namespace, policy.config.Name+"-config", "", 1,
	)
	if err != nil {
		t.Fatalf("searchCatalog() error = %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("searchCatalog() returned %#v for managed mutation, want no capability", result)
	}
	if cursor != "" {
		t.Fatalf("searchCatalog() cursor = %q, want empty after skipping managed mutation", cursor)
	}
	if ssarCount != 0 {
		t.Fatalf("managed mutation triggered %d SelfSubjectAccessReview checks, want 0", ssarCount)
	}
}

func TestSearchCatalogBoundsAuthorizationChecksAndAdvancesCursor(t *testing.T) {
	t.Parallel()

	const capabilityCount = searchAuthorizationCheckLimit + 1
	items := make([]Capability, capabilityCount)
	for index := range items {
		items[index] = Capability{
			Version: "v1", Resource: fmt.Sprintf("pods-%03d", index), Kind: "Pod",
			Action: "get", Verb: "get", Namespaced: true,
		}
	}
	client := k8sfake.NewSimpleClientset()
	ssarCount := 0
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssarCount++
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: false, Reason: "denied by test"},
		}, nil
	})
	principal := &Principal{Kubernetes: client}
	policy := NewPolicy(policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact))

	first, cursor, err := searchCatalog(context.Background(), items, policy, principal, "", "", "workloads", "", "", 200)
	if err != nil {
		t.Fatalf("first searchCatalog() error = %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("first searchCatalog() returned %#v, want all RBAC-denied", first)
	}
	if ssarCount != searchAuthorizationCheckLimit {
		t.Fatalf("first search SSAR count = %d, want %d", ssarCount, searchAuthorizationCheckLimit)
	}
	if cursor == "" {
		t.Fatal("first search returned empty cursor after authorization budget was exhausted")
	}

	second, nextCursor, err := searchCatalog(context.Background(), items, policy, principal, "", "", "workloads", "", cursor, 200)
	if err != nil {
		t.Fatalf("cursor searchCatalog() error = %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("cursor searchCatalog() returned %#v, want all RBAC-denied", second)
	}
	if ssarCount != capabilityCount {
		t.Fatalf("cursor search SSAR count = %d, want %d total checks", ssarCount, capabilityCount)
	}
	if nextCursor != "" {
		t.Fatalf("cursor search returned nextCursor %q after exhausting capabilities", nextCursor)
	}
}
