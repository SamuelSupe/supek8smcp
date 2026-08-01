package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/rest"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
	"github.com/samuelsupe/supek8smcp/internal/runtimeconfig"
)

type Options struct {
	ConfigPath     string
	ListenAddress  string
	MetricsAddress string
	CertFile       string
	KeyFile        string
	Version        string
	Logger         *slog.Logger
}

type App struct {
	config        runtimeconfig.Config
	authenticator *Authenticator
	policy        *Policy
	catalog       *catalogCache
	capabilities  *capabilityCodec
	plans         *PlanStore
	semaphore     chan struct{}
	logger        *slog.Logger
	version       string
	registry      *prometheus.Registry
	toolCalls     *prometheus.CounterVec
	toolDuration  *prometheus.HistogramVec
}

func Run(ctx context.Context, opts Options) error {
	config, err := runtimeconfig.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	base, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("load in-cluster configuration: %w", err)
	}
	app, err := NewApp(config, base, opts.Version, opts.Logger)
	if err != nil {
		return err
	}
	return app.Serve(ctx, opts)
}

func NewApp(config runtimeconfig.Config, base *rest.Config, version string, logger *slog.Logger) (*App, error) {
	authenticator, err := NewAuthenticator(base)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	capabilities, err := newCapabilityCodec()
	if err != nil {
		return nil, err
	}
	registry := prometheus.NewRegistry()
	toolCalls := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "supek8smcp_tool_calls_total", Help: "MCP tool calls by tool and result.",
	}, []string{"tool", "result"})
	toolDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "supek8smcp_tool_duration_seconds", Help: "MCP tool execution duration.", Buckets: prometheus.DefBuckets,
	}, []string{"tool"})
	registry.MustRegister(toolCalls, toolDuration, prometheus.NewGoCollector())
	return &App{
		config: config, authenticator: authenticator, policy: NewPolicy(config), catalog: newCatalogCache(capabilities), capabilities: capabilities,
		plans: NewPlanStore(1024), semaphore: make(chan struct{}, config.Spec.Limits.MaxConcurrent),
		logger: logger, version: version, registry: registry, toolCalls: toolCalls, toolDuration: toolDuration,
	}, nil
}

func (a *App) Serve(ctx context.Context, opts Options) error {
	mcpTransport := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		principal := principalFromRequest(request)
		if principal == nil {
			return nil
		}
		return a.newMCPServer(principal)
	}, &mcp.StreamableHTTPOptions{Stateless: true, Logger: a.logger})

	mcpMux := http.NewServeMux()
	mcpMux.Handle("/mcp", a.authenticationMiddleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, a.config.Spec.Limits.MaxInputBytes)
		mcpTransport.ServeHTTP(writer, request)
	})))
	mcpMux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) { http.NotFound(writer, nil) })

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(a.registry, promhttp.HandlerOpts{}))
	metricsMux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	metricsMux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })

	mcpHTTP := &http.Server{
		Addr: opts.ListenAddress, Handler: mcpMux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	metricsHTTP := &http.Server{
		Addr: opts.MetricsAddress, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
	}

	errorsCh := make(chan error, 2)
	go func() {
		a.logger.Info("MCP server listening", "address", opts.ListenAddress, "mode", a.config.Spec.Mode)
		errorsCh <- mcpHTTP.ListenAndServeTLS(opts.CertFile, opts.KeyFile)
	}()
	go func() {
		a.logger.Info("metrics server listening", "address", opts.MetricsAddress)
		errorsCh <- metricsHTTP.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = mcpHTTP.Shutdown(shutdownCtx)
		_ = metricsHTTP.Shutdown(shutdownCtx)
		return nil
	case err := <-errorsCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (a *App) newMCPServer(principal *Principal) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "supek8smcp", Version: a.version}, &mcp.ServerOptions{})
	readOnly := true
	closedWorld := false
	mcp.AddTool(server, &mcp.Tool{
		Name: "k8s.search", Title: "Search Kubernetes capabilities",
		Description: "Search API resources and actions that are both within this MCP server policy and authorized by the caller's Kubernetes RBAC.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input SearchInput) (*mcp.CallToolResult, SearchOutput, error) {
		started := time.Now()
		output, err := a.search(ctx, principal, input)
		a.recordTool("k8s.search", started, err)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name: "k8s.describe", Title: "Describe Kubernetes capability",
		Description: "Load a bounded OpenAPI v3 schema fragment for a capability returned by k8s.search.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input DescribeInput) (*mcp.CallToolResult, DescribeOutput, error) {
		started := time.Now()
		output, err := a.describe(ctx, principal, input)
		a.recordTool("k8s.describe", started, err)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name: "k8s.read", Title: "Read Kubernetes resource",
		Description: "Run an authorized get, list, watch, or Pod log capability with bounded output.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &readOnly},
	}, func(ctx context.Context, request *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, map[string]any, error) {
		started := time.Now()
		output, err := a.read(ctx, request, principal, input)
		a.recordTool("k8s.read", started, err)
		return nil, output, err
	})
	if a.config.Spec.Mode != mcpv1alpha1.ModeReadOnly {
		destructive := false
		mcp.AddTool(server, &mcp.Tool{
			Name: "k8s.plan", Title: "Plan Kubernetes change",
			Description: "Authorize and server-side dry-run a write or prepare a bounded remote execution. Returns a two-minute one-time plan ID; it never persists the requested change.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &destructive, OpenWorldHint: &readOnly},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, input PlanInput) (*mcp.CallToolResult, PlanOutput, error) {
			started := time.Now()
			output, err := a.plan(ctx, principal, input)
			a.recordTool("k8s.plan", started, err)
			return nil, output, err
		})
		destructive = true
		mcp.AddTool(server, &mcp.Tool{
			Name: "k8s.commit", Title: "Commit Kubernetes change",
			Description: "Consume an unexpired one-time plan after rechecking policy, Kubernetes RBAC, identity, and resource preconditions.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &readOnly},
		}, func(ctx context.Context, request *mcp.CallToolRequest, input CommitInput) (*mcp.CallToolResult, CommitOutput, error) {
			started := time.Now()
			output, err := a.commit(ctx, request, principal, input)
			a.recordTool("k8s.commit", started, err)
			return nil, output, err
		})
	}
	return server
}

func (a *App) recordTool(tool string, started time.Time, err error) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	a.toolCalls.WithLabelValues(tool, result).Inc()
	a.toolDuration.WithLabelValues(tool).Observe(time.Since(started).Seconds())
}

func (a *App) defaultNamespace(capability Capability, namespace string) string {
	if namespace != "" || !capability.Namespaced {
		return namespace
	}
	if len(a.config.Spec.Scope.Namespaces) > 0 {
		return a.config.Spec.Scope.Namespaces[0]
	}
	return a.config.Namespace
}
