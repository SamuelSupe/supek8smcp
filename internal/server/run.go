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
	config                 runtimeconfig.Config
	authenticator          *Authenticator
	policy                 *Policy
	catalog                *catalogCache
	capabilities           *capabilityCodec
	plans                  *PlanStore
	semaphore              chan struct{}
	rateLimiter            *identityRateLimiter
	logger                 *slog.Logger
	version                string
	registry               *prometheus.Registry
	toolCalls              *prometheus.CounterVec
	toolDuration           *prometheus.HistogramVec
	authenticationAttempts *prometheus.CounterVec
	rateLimitRejections    *prometheus.CounterVec
	auditEvents            *prometheus.CounterVec
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
	if err := runtimeconfig.Validate(config); err != nil {
		return nil, fmt.Errorf("validate server configuration: %w", err)
	}
	authenticator, err := NewAuthenticator(
		base,
		config.Spec.Limits.RequestTimeout.Duration,
		max(
			config.Spec.Limits.RequestTimeout.Duration,
			config.Spec.Limits.StreamTimeout.Duration,
			config.Spec.Limits.ExecTimeout.Duration,
		),
	)
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
	authenticationAttempts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "supek8smcp_authentication_attempts_total", Help: "MCP authentication attempts by decision and stable reason.",
	}, []string{"decision", "reason"})
	rateLimitRejections := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "supek8smcp_rate_limit_rejections_total", Help: "Authenticated MCP requests rejected by the per-identity limiter.",
	}, []string{"reason"})
	auditEvents := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "supek8smcp_audit_events_total", Help: "Security audit events by event, tool, decision, and stable reason.",
	}, []string{"event", "tool", "decision", "reason"})
	registry.MustRegister(toolCalls, toolDuration, authenticationAttempts, rateLimitRejections, auditEvents, prometheus.NewGoCollector())
	return &App{
		config: config, authenticator: authenticator, policy: NewPolicy(config), catalog: newCatalogCache(capabilities), capabilities: capabilities,
		plans: NewPlanStore(1024), semaphore: make(chan struct{}, config.Spec.Limits.MaxConcurrent),
		rateLimiter: newIdentityRateLimiter(config.Spec.Limits.RequestsPerMinute, config.Spec.Limits.Burst),
		logger:      logger, version: version, registry: registry, toolCalls: toolCalls, toolDuration: toolDuration,
		authenticationAttempts: authenticationAttempts, rateLimitRejections: rateLimitRejections, auditEvents: auditEvents,
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
		if !prepareMCPRequestBody(writer, request) {
			return
		}
		mcpTransport.ServeHTTP(writer, request)
	})))
	mcpMux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) { http.NotFound(writer, nil) })

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(a.registry, promhttp.HandlerOpts{}))
	metricsMux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	metricsMux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })

	mcpHTTP := &http.Server{
		Addr: opts.ListenAddress, Handler: mcpMux,
		ReadTimeout: a.config.Spec.Limits.RequestTimeout.Duration, ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout: a.serverWriteTimeout(), IdleTimeout: 90 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	metricsHTTP := &http.Server{
		Addr: opts.MetricsAddress, Handler: metricsMux,
		ReadTimeout: 10 * time.Second, ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
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
		Name: toolHelp, Title: "Kubernetes MCP tool manual",
		Description: "Load the built-in tool manual progressively: omit tool for a compact index, then request one exact tool name for detailed usage.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, func(_ context.Context, _ *mcp.CallToolRequest, input HelpInput) (*mcp.CallToolResult, HelpOutput, error) {
		started := time.Now()
		output, err := a.help(input)
		a.recordTool(principal, toolHelp, auditTarget{}, started, err)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name: toolSearch, Title: "Search Kubernetes capabilities",
		Description: "Search API resources and actions that are both within this MCP server policy and authorized by the caller's Kubernetes RBAC.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input SearchInput) (*mcp.CallToolResult, SearchOutput, error) {
		started := time.Now()
		output, err := a.search(ctx, principal, input)
		a.recordTool(principal, toolSearch, auditTarget{}, started, err)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name: toolDescribe, Title: "Describe Kubernetes capability",
		Description: "Load a bounded OpenAPI v3 schema fragment for a capability returned by k8s.search.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input DescribeInput) (*mcp.CallToolResult, DescribeOutput, error) {
		started := time.Now()
		output, err := a.describe(ctx, principal, input)
		target := a.auditTargetForCapability(input.CapabilityID, input.Namespace, input.Name)
		a.recordTool(principal, toolDescribe, target, started, err)
		return nil, output, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name: toolRead, Title: "Read Kubernetes resource",
		Description: "Run an authorized get, list, watch, or Pod log capability with bounded output.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &readOnly},
	}, func(ctx context.Context, request *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, map[string]any, error) {
		started := time.Now()
		output, err := a.read(ctx, request, principal, input)
		target := a.auditTargetForCapability(input.CapabilityID, input.Namespace, input.Name)
		target.Streaming = input.Follow || target.Action == "watch"
		a.recordTool(principal, toolRead, target, started, err)
		return nil, output, err
	})
	if a.config.Spec.Mode != mcpv1alpha1.ModeReadOnly {
		destructive := false
		mcp.AddTool(server, &mcp.Tool{
			Name: toolPlan, Title: "Plan Kubernetes change",
			Description: "Authorize and server-side dry-run a write or prepare a bounded remote execution. Returns a two-minute one-time plan ID; it never persists the requested change.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &destructive, OpenWorldHint: &readOnly},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, input PlanInput) (*mcp.CallToolResult, PlanOutput, error) {
			started := time.Now()
			output, err := a.plan(ctx, principal, input)
			target := auditTargetFromSummary(output.Operation)
			if target.Action == "" {
				target = a.auditTargetForPlan(input)
			}
			a.recordTool(principal, toolPlan, target, started, err)
			return nil, output, err
		})
		destructive = true
		mcp.AddTool(server, &mcp.Tool{
			Name: toolCommit, Title: "Commit Kubernetes change",
			Description: "Consume an unexpired one-time plan after rechecking policy, Kubernetes RBAC, identity, and resource preconditions.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &readOnly},
		}, func(ctx context.Context, request *mcp.CallToolRequest, input CommitInput) (*mcp.CallToolResult, CommitOutput, error) {
			started := time.Now()
			output, err := a.commit(ctx, request, principal, input)
			target := auditTargetFromSummary(output.Operation)
			target.Streaming = target.Action == "exec" || target.Action == "attach"
			a.recordTool(principal, toolCommit, target, started, err)
			return nil, output, err
		})
	}
	return server
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
