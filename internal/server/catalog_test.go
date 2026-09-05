package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	if !strings.HasPrefix(id, "cap_") {
		t.Fatalf("encoded capability = %q, want short cap_ handle", id)
	}
	if len(id) <= len("cap_") || len(id) > 32 {
		t.Fatalf("encoded capability length = %d (%q), want a bounded short handle", len(id), id)
	}
	got, err := codec.decode(id)
	if err != nil {
		t.Fatalf("decode(round trip) error = %v", err)
	}
	if got.ID != id || got.Group != want.Group || got.Resource != want.Resource || got.Namespaced != want.Namespaced || got.Action != want.Action {
		t.Fatalf("decode(round trip) = %#v, want fields from %#v", got, want)
	}

	mutated := id[:len(id)-1] + "A"
	if mutated == id {
		mutated = id[:len(id)-1] + "B"
	}
	if _, err := codec.decode(mutated); policyReason(err) != "invalid_capability" {
		t.Fatalf("mutated short handle decode error = %v, want invalid_capability", err)
	}
	if _, err := codec.decode(id + "x"); policyReason(err) != "invalid_capability" {
		t.Fatalf("extended short handle decode error = %v, want invalid_capability", err)
	}
	legacy := base64.RawURLEncoding.EncodeToString([]byte(`{"resource":"pods"}`)) + ".invalid"
	if _, err := codec.decode(legacy); policyReason(err) != "invalid_capability" {
		t.Fatalf("legacy payload handle decode error = %v, want invalid_capability", err)
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
	if !reflect.DeepEqual(cache.lastPartial, partial) {
		t.Fatalf("partial discovery lastPartial = %#v, want %#v", cache.lastPartial, partial)
	}
	if !cache.retryAt.After(time.Now()) {
		t.Fatalf("partial discovery retryAt = %v, want a future retry time", cache.retryAt)
	}
	cache.retryAt = time.Time{}

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
	if !cache.retryAt.IsZero() || cache.lastPartial != nil {
		t.Fatalf("successful discovery retained failure state: retryAt=%v lastPartial=%#v", cache.retryAt, cache.lastPartial)
	}
}

func TestCatalogCacheFailureBackoffAvoidsImmediateRefresh(t *testing.T) {
	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	partialResources := []*metav1.APIResourceList{
		catalogTestResources("v1", metav1.APIResource{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}}),
	}
	fullResources := []*metav1.APIResourceList{
		catalogTestResources("v1", metav1.APIResource{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}}),
		catalogTestResources("apps/v1", metav1.APIResource{Name: "deployments", Kind: "Deployment", Namespaced: true, Verbs: []string{"get"}}),
	}
	discoveryClient := &scriptedCatalogDiscovery{responses: []catalogDiscoveryResponse{
		{groups: catalogTestGroups("v1", "apps/v1"), resources: partialResources, err: errors.New("temporary discovery outage")},
		{groups: catalogTestGroups("v1", "apps/v1"), resources: fullResources},
	}}
	cache := newCatalogCache(codec)
	principal := &Principal{Discovery: discoveryClient}

	first, err := cache.list(context.Background(), principal)
	if err != nil || len(first) != 1 || first[0].Resource != "pods" {
		t.Fatalf("partial catalogCache.list() = %#v, %v, want the partial pods snapshot", first, err)
	}
	second, err := cache.list(context.Background(), principal)
	if err != nil {
		t.Fatalf("backoff catalogCache.list() error = %v, want the saved partial snapshot", err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("backoff catalogCache.list() = %#v, want saved partial %#v", second, first)
	}
	if discoveryClient.callCount() != 1 {
		t.Fatalf("backoff discovery call count = %d, want no immediate retry", discoveryClient.callCount())
	}

	cache.retryAt = time.Time{}
	complete, err := cache.list(context.Background(), principal)
	if err != nil || len(complete) != 2 || !catalogHasResource(complete, "deployments") {
		t.Fatalf("post-backoff catalogCache.list() = %#v, %v, want complete catalog", complete, err)
	}
	if discoveryClient.callCount() != 2 {
		t.Fatalf("post-backoff discovery call count = %d, want second refresh", discoveryClient.callCount())
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
		cache.retryAt = time.Time{}
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

func TestCatalogCacheConcurrentColdLoadsShareOneDiscovery(t *testing.T) {
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
	select {
	case <-discoveryClient.entered:
		close(release)
		<-results
		<-results
		t.Fatal("second catalog discovery started while the first refresh was blocked")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	first, second := <-results, <-results
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
	select {
	case <-discoveryClient.entered:
		t.Fatal("shared cold load performed a second discovery after the first refresh completed")
	default:
	}
}

func TestCatalogCacheRefreshWaitHonorsContextCancellation(t *testing.T) {
	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseDiscovery := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseDiscovery)
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
	cache := newCatalogCache(codec)
	principal := &Principal{Discovery: discoveryClient}
	firstResult := make(chan error, 1)
	go func() {
		_, err := cache.list(context.Background(), principal)
		firstResult <- err
	}()
	select {
	case <-discoveryClient.entered:
	case <-time.After(time.Second):
		releaseDiscovery()
		t.Fatal("first catalog discovery call did not start")
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	secondStarted := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		close(secondStarted)
		_, err := cache.list(waitCtx, principal)
		secondResult <- err
	}()
	<-secondStarted
	select {
	case err := <-secondResult:
		if !errors.Is(err, context.DeadlineExceeded) {
			releaseDiscovery()
			t.Fatalf("waiting catalogCache.list() error = %v, want context deadline", err)
		}
	case <-time.After(time.Second):
		releaseDiscovery()
		t.Fatal("waiting catalogCache.list() did not honor context cancellation")
	}

	releaseDiscovery()
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first catalogCache.list() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first catalogCache.list() did not finish after discovery release")
	}
	select {
	case <-discoveryClient.entered:
		t.Fatal("waiting catalogCache.list() started a second discovery refresh")
	default:
	}
}

func TestCatalogCacheRefreshRetainsPreviousHandles(t *testing.T) {
	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	discoveryClient := &scriptedCatalogDiscovery{responses: []catalogDiscoveryResponse{
		{
			groups: catalogTestGroups("v1"),
			resources: []*metav1.APIResourceList{catalogTestResources("v1",
				metav1.APIResource{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}},
			)},
		},
		{
			groups: catalogTestGroups("apps/v1"),
			resources: []*metav1.APIResourceList{catalogTestResources("apps/v1",
				metav1.APIResource{Name: "deployments", Kind: "Deployment", Namespaced: true, Verbs: []string{"get"}},
			)},
		},
	}}
	cache := newCatalogCache(codec)
	cache.cacheTime = 0
	principal := &Principal{Discovery: discoveryClient}

	first, err := cache.list(context.Background(), principal)
	if err != nil || len(first) != 1 {
		t.Fatalf("first catalogCache.list() = %#v, %v, want one capability", first, err)
	}
	second, err := cache.list(context.Background(), principal)
	if err != nil || len(second) != 1 || second[0].Resource != "deployments" {
		t.Fatalf("second catalogCache.list() = %#v, %v, want deployment capability", second, err)
	}
	if _, err := codec.decode(first[0].ID); err != nil {
		t.Fatalf("previous snapshot capability %q became invalid after refresh: %v", first[0].ID, err)
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
		principal, catalogSearchFilter{Query: "pods", Action: "get", Namespace: "workloads", Name: "web"}, "", 1,
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

func TestSearchCatalogPropagatesAuthorizationServiceError(t *testing.T) {
	t.Parallel()

	upstreamErr := errors.New("authorization API returned HTTP 503")
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, upstreamErr
	})
	capability := Capability{
		Version: "v1", Resource: "pods", Kind: "Pod",
		Action: "get", Verb: "get", Namespaced: true,
	}
	policy := NewPolicy(policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact))
	_, _, err := searchCatalog(
		context.Background(), []Capability{capability}, policy, &Principal{Kubernetes: client},
		catalogSearchFilter{Namespace: "workloads"}, "", 1,
	)
	if err == nil || !errors.Is(err, upstreamErr) {
		t.Fatalf("searchCatalog() error = %v, want the authorization service error", err)
	}
}

func TestSearchCatalogPropagatesAuthorizationEvaluationError(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{
				EvaluationError: "authorization webhook failed",
			},
		}, nil
	})
	capability := Capability{
		Version: "v1", Resource: "pods", Kind: "Pod",
		Action: "get", Verb: "get", Namespaced: true,
	}
	policy := NewPolicy(policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact))
	_, _, err := searchCatalog(
		context.Background(), []Capability{capability}, policy, &Principal{Kubernetes: client},
		catalogSearchFilter{Namespace: "workloads"}, "", 1,
	)
	if err == nil || !apierrors.IsServiceUnavailable(err) {
		t.Fatalf("searchCatalog() error = %v, want service-unavailable authorization evaluation error", err)
	}
}

func TestSearchCatalogPropagatesContextCancellation(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	items := []Capability{
		{Version: "v1", Resource: "pods", Kind: "Pod", Action: "get", Verb: "get", Namespaced: true},
		{Version: "v1", Resource: "services", Kind: "Service", Action: "get", Verb: "get", Namespaced: true},
	}
	policy := NewPolicy(policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact))
	_, _, err := searchCatalog(ctx, items, policy, &Principal{Kubernetes: client}, catalogSearchFilter{Namespace: "workloads"}, "", 2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("searchCatalog() error = %v, want context cancellation", err)
	}
}

func TestSearchCatalogDeduplicatesAuthorizationReviewsWithinRequest(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	reviewed := make(map[string]int)
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		attrs := review.Spec.ResourceAttributes
		key := strings.Join([]string{attrs.Group, attrs.Version, attrs.Resource, attrs.Subresource, attrs.Verb, attrs.Namespace, attrs.Name}, "\x00")
		reviewed[key]++
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Policy.Rules = []mcpv1alpha1.CapabilityRule{{
		APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
	}}
	policy := NewPolicy(cfg)
	principal := &Principal{Kubernetes: client}
	items := []Capability{
		{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Action: "patch", Verb: "patch", Namespaced: true},
		{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Action: "apply", Verb: "patch", Namespaced: true},
		{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Action: "restart", Verb: "patch", Namespaced: true},
		{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Action: "get", Verb: "get", Namespaced: true},
	}
	result, next, err := searchCatalog(context.Background(), items, policy, principal, catalogSearchFilter{Namespace: "workloads", Name: "web"}, "", 10)
	if err != nil {
		t.Fatalf("searchCatalog() error = %v", err)
	}
	if next != "" || len(result) != len(items) {
		t.Fatalf("searchCatalog() = %#v, next=%q; want all four equivalent capabilities", result, next)
	}
	patchKey := strings.Join([]string{"apps", "v1", "deployments", "", "patch", "workloads", "web"}, "\x00")
	getKey := strings.Join([]string{"apps", "v1", "deployments", "", "get", "workloads", "web"}, "\x00")
	if reviewed[patchKey] != 1 || reviewed[getKey] != 1 || len(reviewed) != 2 {
		t.Fatalf("SSAR reviews = %#v, want one patch and one get prerequisite review", reviewed)
	}

	if err := policy.CheckAndAuthorizeOperation(context.Background(), principal, items[0].AsAction(), "workloads", "web"); err != nil {
		t.Fatalf("fresh operation authorization error = %v", err)
	}
	if reviewed[patchKey] != 2 || reviewed[getKey] != 2 {
		t.Fatalf("post-search SSAR reviews = %#v, want commit-style fresh patch/get reviews", reviewed)
	}
}

func TestSearchCatalogOmitsWriteWithoutPolicyGetPermission(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	ssarCount := 0
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssarCount++
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Policy.Rules = []mcpv1alpha1.CapabilityRule{{
		APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"patch"},
	}}
	capability := Capability{
		Version: "v1", Resource: "configmaps", Kind: "ConfigMap",
		Action: "patch", Verb: "patch", Namespaced: true,
	}
	result, _, err := searchCatalog(
		context.Background(), []Capability{capability}, NewPolicy(cfg), &Principal{Kubernetes: client},
		catalogSearchFilter{Namespace: "workloads", Name: "settings"}, "", 1,
	)
	if err != nil {
		t.Fatalf("searchCatalog() error = %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("searchCatalog() returned write without policy get permission: %#v", result)
	}
	if ssarCount != 0 {
		t.Fatalf("SelfSubjectAccessReview count = %d, want policy to reject the missing get prerequisite first", ssarCount)
	}
}

func TestSearchCatalogOmitsWriteWithoutRBACGetPermission(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	var reviewedVerbs []string
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		verb := review.Spec.ResourceAttributes.Verb
		reviewedVerbs = append(reviewedVerbs, verb)
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: verb == "patch"},
		}, nil
	})
	capability := Capability{
		Version: "v1", Resource: "configmaps", Kind: "ConfigMap",
		Action: "patch", Verb: "patch", Namespaced: true,
	}
	cfg := policyTestConfig(mcpv1alpha1.ModeDangerous, mcpv1alpha1.SensitiveReadAllow)
	cfg.Spec.Policy.Rules = []mcpv1alpha1.CapabilityRule{{
		APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
	}}
	result, _, err := searchCatalog(
		context.Background(), []Capability{capability}, NewPolicy(cfg), &Principal{Kubernetes: client},
		catalogSearchFilter{Namespace: "workloads", Name: "settings"}, "", 1,
	)
	if err != nil {
		t.Fatalf("searchCatalog() error = %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("searchCatalog() returned write without RBAC get permission: %#v", result)
	}
	if !reflect.DeepEqual(reviewedVerbs, []string{"patch", "get"}) {
		t.Fatalf("reviewed verbs = %#v, want patch and prerequisite get", reviewedVerbs)
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
		catalogSearchFilter{Namespace: policy.config.Namespace, Name: policy.config.Name + "-config"}, "", 1,
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

	first, cursor, err := searchCatalog(context.Background(), items, policy, principal, catalogSearchFilter{Namespace: "workloads"}, "", 200)
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

	second, nextCursor, err := searchCatalog(context.Background(), items, policy, principal, catalogSearchFilter{Namespace: "workloads"}, cursor, 200)
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

func TestSearchCatalogExactCapabilityFilters(t *testing.T) {
	t.Parallel()

	items := []Capability{
		{Version: "v1", Resource: "pods", Kind: "Pod", Action: "get", Verb: "get", Namespaced: true},
		{Version: "v1", Resource: "pods", Subresource: "log", Kind: "Pod", Action: "logs", Verb: "get", Namespaced: true},
		{Version: "v1", Resource: "podmetrics", Kind: "PodMetrics", Action: "get", Verb: "get", Namespaced: true},
		{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Action: "get", Verb: "get", Namespaced: true},
		{Group: "apps", Version: "v1beta1", Resource: "deployments", Kind: "Deployment", Action: "get", Verb: "get", Namespaced: true},
	}
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
		}, nil
	})
	policy := NewPolicy(policyTestConfig(mcpv1alpha1.ModeReadOnly, mcpv1alpha1.SensitiveReadRedact))
	principal := &Principal{Kubernetes: client}
	tests := []struct {
		name   string
		filter catalogSearchFilter
		want   []struct{ group, version, resource, subresource, kind, action string }
	}{
		{
			name:   "exact kind",
			filter: catalogSearchFilter{ExactKind: "pod", Namespace: "workloads"},
			want: []struct{ group, version, resource, subresource, kind, action string }{
				{version: "v1", resource: "pods", kind: "Pod", action: "get"},
				{version: "v1", resource: "pods", subresource: "log", kind: "Pod", action: "logs"},
			},
		},
		{
			name:   "exact resource subresource",
			filter: catalogSearchFilter{ExactResource: "pods/log", Namespace: "workloads"},
			want: []struct{ group, version, resource, subresource, kind, action string }{
				{version: "v1", resource: "pods", subresource: "log", kind: "Pod", action: "logs"},
			},
		},
		{
			name:   "exact action",
			filter: catalogSearchFilter{Action: "logs", Namespace: "workloads"},
			want: []struct{ group, version, resource, subresource, kind, action string }{
				{version: "v1", resource: "pods", subresource: "log", kind: "Pod", action: "logs"},
			},
		},
		{
			name:   "core api group",
			filter: catalogSearchFilter{APIGroup: "core", Namespace: "workloads"},
			want: []struct{ group, version, resource, subresource, kind, action string }{
				{version: "v1", resource: "pods", kind: "Pod", action: "get"},
				{version: "v1", resource: "pods", subresource: "log", kind: "Pod", action: "logs"},
				{version: "v1", resource: "podmetrics", kind: "PodMetrics", action: "get"},
			},
		},
		{
			name:   "exact api group",
			filter: catalogSearchFilter{APIGroup: "apps", Namespace: "workloads"},
			want: []struct{ group, version, resource, subresource, kind, action string }{
				{group: "apps", version: "v1", resource: "deployments", kind: "Deployment", action: "get"},
				{group: "apps", version: "v1beta1", resource: "deployments", kind: "Deployment", action: "get"},
			},
		},
		{
			name:   "exact version",
			filter: catalogSearchFilter{Version: "v1beta1", Namespace: "workloads"},
			want: []struct{ group, version, resource, subresource, kind, action string }{
				{group: "apps", version: "v1beta1", resource: "deployments", kind: "Deployment", action: "get"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := searchCatalog(context.Background(), items, policy, principal, tt.filter, "", 20)
			if err != nil {
				t.Fatalf("searchCatalog() error = %v", err)
			}
			if next != "" {
				t.Fatalf("searchCatalog() next cursor = %q, want empty", next)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("searchCatalog() returned %d capabilities (%#v), want %d (%#v)", len(got), got, len(tt.want), tt.want)
			}
			for index, want := range tt.want {
				capability := got[index]
				if capability.Group != want.group || capability.Version != want.version || capability.Resource != want.resource || capability.Subresource != want.subresource || capability.Kind != want.kind || capability.Action != want.action {
					t.Errorf("result[%d] = %#v, want group=%q version=%q resource=%q subresource=%q kind=%q action=%q", index, capability, want.group, want.version, want.resource, want.subresource, want.kind, want.action)
				}
			}
		})
	}
}
