package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
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
	admission              *requestAdmission
	globalLimiter          *rate.Limiter
	metrics                *runtimeMetrics
	schemas                *schemaCache
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
	registry := prometheus.NewRegistry()
	metrics := newRuntimeMetrics(registry)
	base = rest.CopyConfig(base)
	base.Wrap(func(next http.RoundTripper) http.RoundTripper {
		return &upstreamTransport{next: next, metrics: metrics}
	})
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
		Name: "supek8smcp_rate_limit_rejections_total", Help: "MCP requests rejected by global rate or identity limits.",
	}, []string{"reason"})
	auditEvents := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "supek8smcp_audit_events_total", Help: "Security audit events by event, tool, decision, and stable reason.",
	}, []string{"event", "tool", "decision", "reason"})
	registry.MustRegister(toolCalls, toolDuration, authenticationAttempts, rateLimitRejections, auditEvents, prometheus.NewGoCollector())
	app := &App{
		config: config, authenticator: authenticator, policy: NewPolicy(config), catalog: newCatalogCache(capabilities), capabilities: capabilities,
		metrics: metrics, schemas: newSchemaCache(metrics), admission: newRequestAdmission(int(config.Spec.Limits.MaxConcurrent)),
		globalLimiter: rate.NewLimiter(rate.Limit(float64(config.Spec.Limits.RequestsPerMinute)*float64(config.Spec.Limits.MaxConcurrent)/60), int(config.Spec.Limits.Burst*config.Spec.Limits.MaxConcurrent)),
		plans:         NewPlanStore(1024), semaphore: make(chan struct{}, config.Spec.Limits.MaxConcurrent),
		rateLimiter: newIdentityRateLimiter(config.Spec.Limits.RequestsPerMinute, config.Spec.Limits.Burst),
		logger:      logger, version: version, registry: registry, toolCalls: toolCalls, toolDuration: toolDuration,
		authenticationAttempts: authenticationAttempts, rateLimitRejections: rateLimitRejections, auditEvents: auditEvents,
	}
	app.catalog.metrics = metrics
	registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "supek8smcp_schema_cache_bytes", Help: "Estimated retained OpenAPI document bytes."}, func() float64 {
			app.schemas.mu.Lock()
			defer app.schemas.mu.Unlock()
			return float64(app.schemas.bytes)
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "supek8smcp_active_streams", Help: "Currently admitted watch, followed log, exec and attach calls."}, func() float64 { return float64(len(app.admission.streams)) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "supek8smcp_active_requests", Help: "Requests holding a concurrency slot."}, func() float64 { return float64(len(app.semaphore)) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "supek8smcp_plan_store_bytes", Help: "Estimated bytes retained by pending plans, including expired plans awaiting pruning."}, func() float64 { app.plans.mu.Lock(); defer app.plans.mu.Unlock(); return float64(app.plans.usedBytes) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "supek8smcp_catalog_age_seconds", Help: "Age of the last complete discovery snapshot; zero before the first load."}, func() float64 {
			app.catalog.mu.Lock()
			defer app.catalog.mu.Unlock()
			if app.catalog.loadedAt.IsZero() {
				return 0
			}
			return time.Since(app.catalog.loadedAt).Seconds()
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "supek8smcp_catalog_degraded", Help: "Whether the most recent discovery refresh failed or was partial."}, func() float64 {
			app.catalog.mu.Lock()
			defer app.catalog.mu.Unlock()
			if !app.catalog.retryAt.IsZero() {
				return 1
			}
			return 0
		}),
	)
	return app, nil
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
	authenticatedMCP := a.authenticationMiddleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, a.config.Spec.Limits.MaxInputBytes)
		if !prepareMCPRequestBody(writer, request) {
			return
		}
		mcpTransport.ServeHTTP(writer, request)
	}))
	mcpMux.HandleFunc("/mcp", func(writer http.ResponseWriter, request *http.Request) {
		if serveStatelessSessionClose(writer, request) {
			return
		}
		authenticatedMCP.ServeHTTP(writer, request)
	})
	mcpMux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		writeStructuredHTTPError(writer, http.StatusNotFound, "not_found", "endpoint not found", false)
	})

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(a.registry, promhttp.HandlerOpts{}))
	metricsMux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	metricsMux.HandleFunc("/readyz", func(writer http.ResponseWriter, request *http.Request) {
		if err := a.authenticator.Ready(request.Context()); err != nil {
			writeStructuredHTTPError(writer, http.StatusServiceUnavailable, "tokenreview_unavailable", "delegated authentication is unavailable", true)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})

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
	server.AddReceivingMiddleware(structuredToolErrorMiddleware)
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
		Description: "Search API resources and actions with optional exact kind/resource/group/version filters; results are within server policy and caller RBAC and use compact cap_ handles.",
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
		Description: "Run an authorized get, list, watch, or Pod log capability with bounded summary, table, projected, or full output; annotations and managedFields are omitted by default.",
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
			Description: "Authorize and preview a write without persisting it. Returns a one-time plan and six-digit code; stop and wait until a human repeats the code in a later user message.",
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
		commitInputSchema, err := newCommitInputSchema()
		if err != nil {
			panic(fmt.Sprintf("build k8s.commit input schema: %v", err))
		}
		commitOutputSchema, err := jsonschema.For[CommitOutput](nil)
		if err != nil {
			panic(fmt.Sprintf("build k8s.commit output schema: %v", err))
		}
		server.AddTool(&mcp.Tool{
			Name: toolCommit, Title: "Commit Kubernetes change",
			Description: "Execute an unexpired one-time plan only after a human has repeated its six-digit confirmation code; policy, RBAC, identity, and resource preconditions are rechecked.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &readOnly},
			InputSchema: commitInputSchema, OutputSchema: commitOutputSchema,
		}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			started := time.Now()
			input, err := decodeCommitInput(request.Params.Arguments)
			if err != nil {
				a.recordTool(principal, toolCommit, auditTarget{}, started, err)
				result := &mcp.CallToolResult{}
				result.SetError(err)
				return result, nil
			}
			output, err := a.commit(ctx, request, principal, input)
			target := auditTargetFromSummary(output.Operation)
			target.Streaming = target.Action == "exec" || target.Action == "attach"
			a.recordTool(principal, toolCommit, target, started, err)
			result := &mcp.CallToolResult{}
			if err != nil {
				result.SetError(err)
				return result, nil
			}
			encoded, err := json.Marshal(output)
			if err != nil {
				return nil, fmt.Errorf("marshal k8s.commit output: %w", err)
			}
			result.StructuredContent = json.RawMessage(encoded)
			result.Content = []mcp.Content{&mcp.TextContent{Text: string(encoded)}}
			return result, nil
		})
	}
	return server
}

func decodeCommitInput(arguments json.RawMessage) (CommitInput, error) {
	var input CommitInput
	if len(arguments) == 0 {
		return input, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(arguments, &fields); err != nil {
		return input, policyError("invalid_input", "k8s.commit arguments must match the published schema")
	}
	if err := json.Unmarshal(arguments, &input); err != nil {
		var typeError *json.UnmarshalTypeError
		if errors.As(err, &typeError) && typeError.Field == "confirmationCode" {
			return input, policyError("invalid_confirmation", "confirmation code must be exactly six digits")
		}
		return input, policyError("invalid_input", "k8s.commit arguments must match the published schema")
	}
	if rawCode, present := fields["confirmationCode"]; present {
		var code string
		if err := json.Unmarshal(rawCode, &code); err != nil || !validConfirmationCode(code) {
			return input, policyError("invalid_confirmation", "confirmation code must be exactly six digits")
		}
	}
	return input, nil
}

func newCommitInputSchema() (*jsonschema.Schema, error) {
	schema, err := jsonschema.For[CommitInput](nil)
	if err != nil {
		return nil, err
	}
	confirmation, ok := schema.Properties["confirmationCode"]
	if !ok {
		return nil, errors.New("confirmationCode property is missing")
	}
	confirmation.Pattern = confirmationCodePattern
	return schema, nil
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
