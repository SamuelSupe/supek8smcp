package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
	"github.com/samuelsupe/supek8smcp/internal/runtimeconfig"
)

func TestPrincipalSubjectKeyCanonicalizesGroupsAndExtra(t *testing.T) {
	t.Parallel()

	left := &Principal{
		Username: "alice", UID: "uid-1",
		Groups: []string{"system:authenticated", "team-readers"},
		Extra: map[string]authenticationv1.ExtraValue{
			"scopes": {"read", "cluster"},
			"tenant": {"one"},
		},
	}
	right := &Principal{
		Username: "alice", UID: "uid-1",
		Groups: []string{"team-readers", "system:authenticated"},
		Extra: map[string]authenticationv1.ExtraValue{
			"tenant": {"one"},
			"scopes": {"cluster", "read"},
		},
	}
	if left.SubjectKey() != right.SubjectKey() {
		t.Fatalf("subject key changed with group/extra ordering: %q != %q", left.SubjectKey(), right.SubjectKey())
	}

	right.Extra["tenant"] = authenticationv1.ExtraValue{"two"}
	if left.SubjectKey() == right.SubjectKey() {
		t.Fatal("subject key did not change when TokenReview Extra value changed")
	}
}

func TestPrincipalIdentityKeyIgnoresGroupsExtraAndToken(t *testing.T) {
	t.Parallel()

	base := &Principal{
		Username: "alice",
		UID:      "uid-1",
		Groups:   []string{"system:authenticated"},
		Extra: map[string]authenticationv1.ExtraValue{
			"tenant": {"one"},
		},
		Token: "token-a",
	}
	variants := []*Principal{
		{
			Username: "alice", UID: "uid-1",
			Groups: []string{"team-readers", "system:authenticated"},
			Extra: map[string]authenticationv1.ExtraValue{
				"tenant": {"two"}, "scopes": {"read"},
			},
			Token: "token-b",
		},
		{
			Username: "alice", UID: "uid-1", Token: "",
		},
	}
	for index, variant := range variants {
		if got, want := variant.IdentityKey(), base.IdentityKey(); got != want {
			t.Fatalf("variant %d IdentityKey() = %q, want stable key %q", index, got, want)
		}
	}
	if base.SubjectKey() == variants[0].SubjectKey() {
		t.Fatal("SubjectKey() did not change when groups/extra changed")
	}
}

func TestAuthenticatorReadinessChecksTokenReviewAccess(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	var reviewedToken string
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		reviewedToken = review.Spec.Token
		return true, &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Error: "invalid bearer token"},
		}, nil
	})
	authenticator := &Authenticator{base: &rest.Config{BearerToken: "server-token"}, reviewer: client}
	if err := authenticator.Ready(context.Background()); err == nil {
		t.Fatal("Ready() succeeded when TokenReview returned status.error")
	} else if !strings.Contains(err.Error(), "invalid bearer token") {
		t.Fatalf("Ready() error = %v, want TokenReview status.error to be preserved", err)
	}
	if reviewedToken != "server-token" {
		t.Fatalf("readiness TokenReview token = %q, want server bearer token", reviewedToken)
	}

	deniedClient := k8sfake.NewSimpleClientset()
	deniedClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("tokenreviews is forbidden")
	})
	if err := (&Authenticator{base: &rest.Config{BearerToken: "server-token"}, reviewer: deniedClient}).Ready(context.Background()); err == nil {
		t.Fatal("Ready() succeeded when TokenReview access was denied")
	}
}

func TestAuthenticatorTokenReviewStatusErrorIsRetryable(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Error: "authentication webhook unavailable"},
		}, nil
	})

	principal, err := (&Authenticator{reviewer: client}).Authenticate(context.Background(), "caller-token")
	if principal != nil {
		t.Fatalf("Authenticate() principal = %#v, want nil on TokenReview status.error", principal)
	}
	var authErr *authenticationError
	if !errors.As(err, &authErr) {
		t.Fatalf("Authenticate() error = %v, want authenticationError", err)
	}
	if authErr.reason != "tokenreview_error" {
		t.Fatalf("Authenticate() error reason = %q, want tokenreview_error for retryable infrastructure failure", authErr.reason)
	}
	if !strings.Contains(err.Error(), "authentication webhook unavailable") {
		t.Fatalf("Authenticate() error = %v, want TokenReview status.error detail", err)
	}
}

func TestAuthenticationMiddlewareMarksTokenReviewStatusErrorRetryable(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Error: "authentication webhook unavailable"},
		}, nil
	})
	app := newAuditTestApp(slog.Default())
	app.authenticator = &Authenticator{reviewer: client}
	app.semaphore = make(chan struct{}, 1)
	handler := app.authenticationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("authentication middleware called downstream handler after TokenReview status.error")
	}))
	request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer caller-token")
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, request)
	if writer.Code != http.StatusServiceUnavailable {
		t.Fatalf("authentication middleware status = %d, want %d", writer.Code, http.StatusServiceUnavailable)
	}
	var payload toolErrorOutput
	if err := json.Unmarshal(writer.Body.Bytes(), &payload); err != nil {
		t.Fatalf("authentication middleware response = %q, want structured JSON: %v", writer.Body.String(), err)
	}
	if payload.Code != "tokenreview_error" || !payload.Retryable {
		t.Fatalf("authentication middleware payload = %#v, want tokenreview_error/retryable=true", payload)
	}
}

func TestAuthenticationMiddlewareGlobalRateLimitRejectsBeforeTokenReview(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset()
	tokenReviews := 0
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		tokenReviews++
		return true, &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Authenticated: true},
		}, nil
	})
	app := newAuditTestApp(slog.Default())
	app.authenticator = &Authenticator{reviewer: client}
	app.globalLimiter = rate.NewLimiter(0, 0)
	handler := app.authenticationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("authentication middleware called downstream handler after global rate rejection")
	}))
	request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer caller-token")
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, request)
	if writer.Code != http.StatusTooManyRequests {
		t.Fatalf("authentication middleware status = %d, want %d", writer.Code, http.StatusTooManyRequests)
	}
	var payload toolErrorOutput
	if err := json.Unmarshal(writer.Body.Bytes(), &payload); err != nil {
		t.Fatalf("authentication middleware response = %q, want structured JSON: %v", writer.Body.String(), err)
	}
	if payload.Code != "global_rate" || !payload.Retryable {
		t.Fatalf("authentication middleware payload = %#v, want global_rate/retryable=true", payload)
	}
	if tokenReviews != 0 {
		t.Fatalf("TokenReview calls = %d, want zero when global rate limit is exhausted", tokenReviews)
	}
}

func TestAuthenticatorTokenReviewUsesConfiguredTimeoutWithoutCallerDeadline(t *testing.T) {
	const requestTimeout = 100 * time.Millisecond
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	defer func() {
		close(release)
		server.Close()
	}()

	authenticator, err := NewAuthenticator(&rest.Config{Host: server.URL}, requestTimeout, requestTimeout)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	startedAt := time.Now()
	result := make(chan error, 1)
	go func() {
		_, err := authenticator.Authenticate(context.Background(), "token")
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TokenReview request did not reach test server")
	}

	var authErr *authenticationError
	select {
	case err := <-result:
		if !errors.As(err, &authErr) || authErr.reason != "tokenreview_error" {
			t.Fatalf("Authenticate() error = %v, want tokenreview_error", err)
		}
		if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
			t.Fatalf("Authenticate() took %s, want configured timeout to bound caller without deadline", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Authenticate() did not honor the configured TokenReview timeout")
	}
}

func TestAuthenticatorDiscoveryUsesRequestTimeoutAfterTokenReview(t *testing.T) {
	const requestTimeout = 100 * time.Millisecond
	startedDiscovery := make(chan struct{})
	releaseDiscovery := make(chan struct{})
	var discoveryStarted sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/tokenreviews") {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(writer, `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"user":{"username":"alice","uid":"uid-1"}}}`)
			return
		}
		discoveryStarted.Do(func() { close(startedDiscovery) })
		select {
		case <-request.Context().Done():
		case <-releaseDiscovery:
		}
	}))
	defer func() {
		close(releaseDiscovery)
		server.Close()
	}()

	authenticator, err := NewAuthenticator(&rest.Config{Host: server.URL}, requestTimeout, 5*time.Second)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	principal, err := authenticator.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	startedAt := time.Now()
	result := make(chan error, 1)
	go func() {
		_, _, err := principal.Discovery.ServerGroupsAndResources()
		result <- err
	}()
	select {
	case <-startedDiscovery:
	case <-time.After(time.Second):
		t.Fatal("discovery request did not reach test server")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("ServerGroupsAndResources() succeeded against blocked discovery endpoint")
		}
		if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
			t.Fatalf("ServerGroupsAndResources() took %s, want request timeout to bound context.TODO request", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServerGroupsAndResources() did not honor the configured request timeout")
	}
}

func TestPrincipalDiscoveryForContextPropagatesCancellation(t *testing.T) {
	startedDiscovery := make(chan struct{})
	var discoveryStarted sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/tokenreviews") {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(writer, `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"user":{"username":"alice","uid":"uid-1"}}}`)
			return
		}
		discoveryStarted.Do(func() { close(startedDiscovery) })
		<-request.Context().Done()
	}))
	defer server.Close()

	authenticator, err := NewAuthenticator(&rest.Config{Host: server.URL}, time.Second, time.Second)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	principal, err := authenticator.Authenticate(context.Background(), "caller-token")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if principal.discoveryConfig == nil {
		t.Fatal("Authenticate() did not retain a discovery config for request-scoped clients")
	}

	ctx, cancel := context.WithCancel(context.Background())
	discoveryClient, err := principal.discoveryForContext(ctx)
	if err != nil {
		cancel()
		t.Fatalf("discoveryForContext() error = %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := discoveryClient.ServerGroupsAndResources()
		result <- err
	}()
	select {
	case <-startedDiscovery:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("request-scoped discovery call did not reach the test server")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("discoveryForContext() call error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("discoveryForContext() call did not stop after context cancellation")
	}
}

func TestAuthenticatorDiscoveryUsesResponseLimit(t *testing.T) {
	const requestTimeout = time.Second
	discoveryHit := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/tokenreviews") {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(writer, `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"user":{"username":"alice","uid":"uid-1"}}}`)
			return
		}
		select {
		case discoveryHit <- request.URL.Path:
		default:
		}
		// The oversized Content-Length lets the response limiter reject the
		// response before a large body is allocated or decoded.
		writer.Header().Set("Content-Length", strconv.FormatInt(maxDelegatedResourceResponseBytes+1, 10))
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	authenticator, err := NewAuthenticator(&rest.Config{Host: server.URL}, requestTimeout, requestTimeout)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	principal, err := authenticator.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	_, _, err = principal.Discovery.ServerGroupsAndResources()
	if err == nil {
		t.Fatal("ServerGroupsAndResources() succeeded despite oversized discovery response")
	}
	if !strings.Contains(err.Error(), errDelegatedResourceResponseTooLarge.Error()) {
		t.Fatalf("ServerGroupsAndResources() error = %v, want delegated response size error", err)
	}
	select {
	case path := <-discoveryHit:
		if path != "/api" && path != "/apis" {
			t.Fatalf("oversized response came from path %q, want Kubernetes discovery endpoint", path)
		}
	default:
		t.Fatal("discovery client did not request an API discovery endpoint")
	}
}

func TestResponseLimitTransportRejectsKnownOversizeAndClosesBody(t *testing.T) {
	t.Parallel()

	const limit = int64(4)
	body := &trackedReadCloser{Reader: strings.NewReader("12345")}
	transport := &responseLimitTransport{
		next: testRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, ContentLength: 5, Body: body}, nil
		}),
		limit: limit,
	}
	response, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "http://kubernetes.test/api", nil))
	if response != nil {
		t.Fatalf("RoundTrip() response = %#v, want nil for known oversize body", response)
	}
	if !errors.Is(err, errDelegatedResourceResponseTooLarge) {
		t.Fatalf("RoundTrip() error = %v, want delegated response size error", err)
	}
	if !body.closed {
		t.Fatal("known oversize response body was not closed")
	}
}

func TestResponseLimitTransportBoundsUnknownLengthBody(t *testing.T) {
	t.Parallel()

	const limit = int64(4)
	body := &trackedReadCloser{Reader: strings.NewReader("12345")}
	transport := &responseLimitTransport{
		next: testRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:       http.StatusOK,
				ContentLength:    -1,
				TransferEncoding: []string{"chunked"},
				Body:             body,
			}, nil
		}),
		limit: limit,
	}
	response, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "http://kubernetes.test/api", nil))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v, want unknown-length response to be wrapped", err)
	}
	data, readErr := io.ReadAll(response.Body)
	if !errors.Is(readErr, errDelegatedResourceResponseTooLarge) {
		t.Fatalf("ReadAll() error = %v, want delegated response size error", readErr)
	}
	if int64(len(data)) != limit {
		t.Fatalf("ReadAll() returned %d bytes, want bounded limit %d", len(data), limit)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("response body Close() error = %v", err)
	}
	if !body.closed {
		t.Fatal("unknown-length response body was not closed by consumer")
	}
}

func TestConfigWithResponseLimitPreservesWrapTransportAndSkipsWatches(t *testing.T) {
	t.Parallel()

	var previousCalls int
	base := &rest.Config{
		WrapTransport: func(next http.RoundTripper) http.RoundTripper {
			previousCalls++
			return testRoundTripper(func(request *http.Request) (*http.Response, error) {
				return next.RoundTrip(request)
			})
		},
	}
	config := configWithResponseLimit(base, 4)
	if config.WrapTransport == nil {
		t.Fatal("configWithResponseLimit() removed WrapTransport")
	}
	for _, watch := range []string{"true", "1"} {
		watch := watch
		t.Run("watch="+watch, func(t *testing.T) {
			body := &trackedReadCloser{Reader: strings.NewReader("12345")}
			underlying := testRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, ContentLength: 5, Body: body}, nil
			})
			transport := config.WrapTransport(underlying)
			request := httptest.NewRequest(http.MethodGet, "http://kubernetes.test/api?watch="+watch, nil)
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatalf("RoundTrip() error = %v, want watch response to bypass size limit", err)
			}
			if response.Body != body {
				t.Fatal("watch response body was wrapped despite watch=true/1")
			}
			data, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("ReadAll(watch) error = %v", err)
			}
			if string(data) != "12345" {
				t.Fatalf("ReadAll(watch) = %q, want complete response", data)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatalf("watch response body Close() error = %v", err)
			}
			if !body.closed {
				t.Fatal("watch response body was not closed")
			}
		})
	}
	if previousCalls != 2 {
		t.Fatalf("previous WrapTransport calls = %d, want one per wrapped request", previousCalls)
	}
}

func TestKubernetesListLimitCapsPagesAndRespectsSmallerBounds(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		maxItems  int64
		requested int64
		want      int64
	}{
		{name: "default request uses page cap", maxItems: 100, requested: 0, want: 8},
		{name: "large request uses page cap", maxItems: 100, requested: 100, want: 8},
		{name: "smaller request is preserved", maxItems: 100, requested: 3, want: 3},
		{name: "CR max below page cap", maxItems: 5, requested: 100, want: 5},
		{name: "default request respects CR max", maxItems: 5, requested: 0, want: 5},
		{name: "request below CR max", maxItems: 5, requested: 2, want: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{config: runtimeconfig.Config{Spec: mcpv1alpha1.KubernetesMCPServerSpec{
				Limits: mcpv1alpha1.LimitsSpec{MaxListItems: tt.maxItems},
			}}}
			got := app.kubernetesListLimit(tt.requested)
			if got > 8 {
				t.Fatalf("kubernetesListLimit() = %d, exceeds page bound 8", got)
			}
			if got != tt.want {
				t.Fatalf("kubernetesListLimit(%d) with CR max %d = %d, want %d", tt.requested, tt.maxItems, got, tt.want)
			}
		})
	}
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type trackedReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackedReadCloser) Close() error {
	r.closed = true
	return nil
}
