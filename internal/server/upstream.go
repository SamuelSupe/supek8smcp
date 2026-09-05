package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

type runtimeMetrics struct {
	stages   *prometheus.HistogramVec
	upstream *prometheus.CounterVec
	caches   *prometheus.CounterVec
}

func newRuntimeMetrics(registry *prometheus.Registry) *runtimeMetrics {
	m := &runtimeMetrics{
		stages:   prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "supek8smcp_stage_duration_seconds", Help: "Request queue and Kubernetes HTTP stage latency.", Buckets: prometheus.DefBuckets}, []string{"stage"}),
		upstream: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "supek8smcp_upstream_requests_total", Help: "Kubernetes HTTP requests by stage and outcome."}, []string{"stage", "result"}),
		caches:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "supek8smcp_cache_requests_total", Help: "Metadata cache outcomes."}, []string{"cache", "result"}),
	}
	registry.MustRegister(m.stages, m.upstream, m.caches)
	return m
}

func (m *runtimeMetrics) cache(name, result string) {
	if m != nil {
		m.caches.WithLabelValues(name, result).Inc()
	}
}

func (m *runtimeMetrics) observe(stage string, started time.Time) {
	if m != nil {
		m.stages.WithLabelValues(stage).Observe(time.Since(started).Seconds())
	}
}

type upstreamTransport struct {
	next    http.RoundTripper
	metrics *runtimeMetrics
}

func (t *upstreamTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	path := request.URL.Path
	stage := "resource"
	switch {
	case strings.HasSuffix(path, "/tokenreviews"):
		stage = "authentication"
	case strings.HasSuffix(path, "/selfsubjectaccessreviews"):
		stage = "authorization"
	case strings.HasPrefix(path, "/openapi/"):
		stage = "openapi"
	case path == "/api" || path == "/apis" || (strings.HasPrefix(path, "/api/") && strings.Count(path, "/") == 2) || (strings.HasPrefix(path, "/apis/") && strings.Count(path, "/") <= 3):
		stage = "discovery"
	}
	started := time.Now()
	response, err := t.next.RoundTrip(request)
	t.metrics.observe(stage, started)
	result := "ok"
	if err != nil || response.StatusCode >= 400 {
		result = "error"
	}
	t.metrics.upstream.WithLabelValues(stage, result).Inc()
	return response, err
}

func (p *Principal) discoveryForContext(ctx context.Context) (discovery.DiscoveryInterface, error) {
	if p.discoveryConfig == nil {
		return p.Discovery, nil
	}
	config := rest.CopyConfig(p.discoveryConfig)
	config.Wrap(func(next http.RoundTripper) http.RoundTripper { return &contextTransport{next: next, ctx: ctx} })
	return discovery.NewDiscoveryClientForConfig(config)
}

// Discovery/OpenAPI interfaces do not accept a context. Preserve the HTTP
// client's own timeout while also cancelling every request with the tool call.
type contextTransport struct {
	next http.RoundTripper
	ctx  context.Context
}

func (t *contextTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	release := func() { stop(); cancel() }
	response, err := t.next.RoundTrip(request.Clone(ctx))
	if err != nil {
		release()
		return nil, err
	}
	response.Body = &contextBody{ReadCloser: response.Body, release: release}
	return response, nil
}

type contextBody struct {
	io.ReadCloser
	release func()
}

func (b *contextBody) Close() error { defer b.release(); return b.ReadCloser.Close() }
