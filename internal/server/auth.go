package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

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
	base     *rest.Config
	reviewer kubernetes.Interface
}

func NewAuthenticator(base *rest.Config) (*Authenticator, error) {
	reviewer, err := kubernetes.NewForConfig(base)
	if err != nil {
		return nil, fmt.Errorf("create TokenReview client: %w", err)
	}
	return &Authenticator{base: rest.CopyConfig(base), reviewer: reviewer}, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, token string) (*Principal, error) {
	review, err := a.reviewer.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("TokenReview failed: %w", err)
	}
	if !review.Status.Authenticated {
		if review.Status.Error != "" {
			return nil, fmt.Errorf("token rejected: %s", review.Status.Error)
		}
		return nil, fmt.Errorf("token rejected")
	}

	config := rest.CopyConfig(a.base)
	config.BearerToken = token
	config.BearerTokenFile = ""
	config.Username = ""
	config.Password = ""
	config.Impersonate = rest.ImpersonationConfig{}
	config.UserAgent = "supek8smcp/delegated-user"

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create discovery client: %w", err)
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
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

type principalContextKey struct{}

func principalFromRequest(request *http.Request) *Principal {
	principal, _ := request.Context().Value(principalContextKey{}).(*Principal)
	return principal
}

func (a *App) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Origin") != "" {
			http.Error(writer, "browser Origin requests are not accepted", http.StatusForbidden)
			return
		}
		header := request.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= len("Bearer ") {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="kubernetes"`)
			http.Error(writer, "Kubernetes bearer token required", http.StatusUnauthorized)
			return
		}
		select {
		case a.semaphore <- struct{}{}:
			defer func() { <-a.semaphore }()
		case <-request.Context().Done():
			return
		}
		authCtx, cancel := a.requestContext(request.Context())
		principal, err := a.authenticator.Authenticate(authCtx, strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
		cancel()
		if err != nil {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="kubernetes", error="invalid_token"`)
			http.Error(writer, "invalid Kubernetes bearer token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}
