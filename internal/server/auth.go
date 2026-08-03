package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const maxDelegatedResourceResponseBytes int64 = 8 << 20

var errDelegatedResourceResponseTooLarge = errors.New("delegated Kubernetes API response exceeds the configured limit")

type Principal struct {
	Username   string
	UID        string
	Groups     []string
	Extra      map[string]authenticationv1.ExtraValue
	Token      string
	Config     *rest.Config
	Dynamic    dynamic.Interface
	Discovery  discovery.DiscoveryInterface
	Kubernetes kubernetes.Interface
}

func (p *Principal) IdentityKey() string {
	h := sha256.New()
	h.Write([]byte(p.Username))
	h.Write([]byte{0})
	h.Write([]byte(p.UID))
	return hex.EncodeToString(h.Sum(nil))
}

func (p *Principal) SubjectKey() string {
	h := sha256.New()
	h.Write([]byte(p.Username))
	h.Write([]byte{0})
	h.Write([]byte(p.UID))
	groups := append([]string(nil), p.Groups...)
	sort.Strings(groups)
	for _, group := range groups {
		h.Write([]byte{0})
		h.Write([]byte(group))
	}
	extraKeys := make([]string, 0, len(p.Extra))
	for key := range p.Extra {
		extraKeys = append(extraKeys, key)
	}
	sort.Strings(extraKeys)
	for _, key := range extraKeys {
		h.Write([]byte{0})
		h.Write([]byte(key))
		values := append([]string(nil), p.Extra[key]...)
		sort.Strings(values)
		for _, value := range values {
			h.Write([]byte{0})
			h.Write([]byte(value))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

type Authenticator struct {
	base             *rest.Config
	reviewer         kubernetes.Interface
	requestTimeout   time.Duration
	operationTimeout time.Duration
}

type authenticationError struct {
	reason string
	cause  error
}

func (e *authenticationError) Error() string {
	if e.cause == nil {
		return e.reason
	}
	return e.reason + ": " + e.cause.Error()
}

func (e *authenticationError) Unwrap() error { return e.cause }

func NewAuthenticator(base *rest.Config, requestTimeout, operationTimeout time.Duration) (*Authenticator, error) {
	reviewer, err := kubernetes.NewForConfig(configWithTimeout(base, requestTimeout))
	if err != nil {
		return nil, fmt.Errorf("create TokenReview client: %w", err)
	}
	return &Authenticator{
		base: rest.CopyConfig(base), reviewer: reviewer,
		requestTimeout: requestTimeout, operationTimeout: operationTimeout,
	}, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, token string) (*Principal, error) {
	review, err := a.reviewer.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, &authenticationError{reason: "tokenreview_error", cause: err}
	}
	if !review.Status.Authenticated {
		if review.Status.Error != "" {
			return nil, &authenticationError{reason: "invalid_token", cause: errors.New(review.Status.Error)}
		}
		return nil, &authenticationError{reason: "invalid_token"}
	}

	config := configWithTimeout(a.base, a.operationTimeout)
	config.BearerToken = token
	config.BearerTokenFile = ""
	config.Username = ""
	config.Password = ""
	config.Impersonate = rest.ImpersonationConfig{}
	config.UserAgent = "supek8smcp/delegated-user"

	dynamicClient, err := dynamic.NewForConfig(configWithResponseLimit(config, maxDelegatedResourceResponseBytes))
	if err != nil {
		return nil, &authenticationError{reason: "delegated_client_error", cause: err}
	}
	discoveryConfig := configWithTimeout(config, a.requestTimeout)
	discoveryConfig = configWithResponseLimit(discoveryConfig, maxDelegatedResourceResponseBytes)
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(discoveryConfig)
	if err != nil {
		return nil, &authenticationError{reason: "delegated_client_error", cause: err}
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, &authenticationError{reason: "delegated_client_error", cause: err}
	}
	return &Principal{
		Username:   review.Status.User.Username,
		UID:        review.Status.User.UID,
		Groups:     append([]string(nil), review.Status.User.Groups...),
		Extra:      review.Status.User.Extra,
		Token:      token,
		Config:     config,
		Dynamic:    dynamicClient,
		Discovery:  discoveryClient,
		Kubernetes: kubeClient,
	}, nil
}

func configWithTimeout(base *rest.Config, timeout time.Duration) *rest.Config {
	config := rest.CopyConfig(base)
	if config.Timeout <= 0 || config.Timeout > timeout {
		config.Timeout = timeout
	}
	return config
}

func configWithResponseLimit(base *rest.Config, limit int64) *rest.Config {
	config := rest.CopyConfig(base)
	previous := config.WrapTransport
	config.WrapTransport = func(transport http.RoundTripper) http.RoundTripper {
		if previous != nil {
			transport = previous(transport)
		}
		return &responseLimitTransport{next: transport, limit: limit}
	}
	return config
}

type responseLimitTransport struct {
	next  http.RoundTripper
	limit int64
}

func (t *responseLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if isWatchRequest(request) {
		return response, nil
	}
	if response.ContentLength > t.limit {
		_ = response.Body.Close()
		return nil, errDelegatedResourceResponseTooLarge
	}
	response.Body = &responseLimitBody{ReadCloser: response.Body, remaining: t.limit}
	return response, nil
}

func isWatchRequest(request *http.Request) bool {
	value := request.URL.Query().Get("watch")
	return value == "1" || strings.EqualFold(value, "true")
}

type responseLimitBody struct {
	io.ReadCloser
	remaining int64
	exceeded  bool
}

func (b *responseLimitBody) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if b.exceeded {
		return 0, errDelegatedResourceResponseTooLarge
	}
	if b.remaining == 0 {
		var probe [1]byte
		read, err := b.ReadCloser.Read(probe[:])
		if read > 0 {
			b.exceeded = true
			return 0, errDelegatedResourceResponseTooLarge
		}
		return 0, err
	}
	if int64(len(buffer)) > b.remaining+1 {
		buffer = buffer[:b.remaining+1]
	}
	read, err := b.ReadCloser.Read(buffer)
	if int64(read) > b.remaining {
		read = int(b.remaining)
		b.remaining = 0
		b.exceeded = true
		return read, errDelegatedResourceResponseTooLarge
	}
	b.remaining -= int64(read)
	return read, err
}

type principalContextKey struct{}

func principalFromRequest(request *http.Request) *Principal {
	principal, _ := request.Context().Value(principalContextKey{}).(*Principal)
	return principal
}

func (a *App) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		if request.Header.Get("Origin") != "" {
			a.recordAuthentication(nil, "deny", "browser_origin", started)
			writeStructuredHTTPError(writer, http.StatusForbidden, "browser_origin", "browser Origin requests are not accepted", false)
			return
		}
		header := request.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= len("Bearer ") {
			a.recordAuthentication(nil, "deny", "missing_bearer", started)
			writer.Header().Set("WWW-Authenticate", `Bearer realm="kubernetes"`)
			writeStructuredHTTPError(writer, http.StatusUnauthorized, "missing_bearer", "Kubernetes bearer token required", false)
			return
		}
		queueCtx, queueCancel := a.requestContext(request.Context())
		select {
		case a.semaphore <- struct{}{}:
			queueCancel()
			defer func() { <-a.semaphore }()
		case <-queueCtx.Done():
			queueCancel()
			a.recordAuthentication(nil, "error", "concurrency_timeout", started)
			writer.Header().Set("Retry-After", "1")
			writeStructuredHTTPError(writer, http.StatusServiceUnavailable, "concurrency_timeout", "server concurrency limit reached", true)
			return
		}
		authCtx, cancel := a.requestContext(request.Context())
		principal, err := a.authenticator.Authenticate(authCtx, strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
		cancel()
		if err != nil {
			decision, reason, status := "deny", "invalid_token", http.StatusUnauthorized
			var authErr *authenticationError
			if errors.As(err, &authErr) && authErr.reason != "invalid_token" {
				decision, reason, status = "error", authErr.reason, http.StatusServiceUnavailable
			}
			a.recordAuthentication(nil, decision, reason, started)
			if status == http.StatusUnauthorized {
				writer.Header().Set("WWW-Authenticate", `Bearer realm="kubernetes", error="invalid_token"`)
				writeStructuredHTTPError(writer, status, reason, "invalid Kubernetes bearer token", false)
			} else {
				writeStructuredHTTPError(writer, status, reason, "Kubernetes authentication service unavailable", true)
			}
			return
		}
		a.recordAuthentication(principal, "allow", "authenticated", started)
		if allowed, reason := a.rateLimiter.Allow(principal.IdentityKey(), time.Now()); !allowed {
			a.recordRateLimit(principal, reason, started)
			writer.Header().Set("Retry-After", strconv.Itoa(a.rateLimiter.RetryAfterSeconds()))
			writeStructuredHTTPError(writer, http.StatusTooManyRequests, reason, "authenticated identity rate limit exceeded", true)
			return
		}
		ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}
