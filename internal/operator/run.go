package operator

import (
	"context"
	"fmt"
	"log/slog"

	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

type Options struct {
	ServerImage       string
	OperatorNamespace string
	MetricsAddress    string
	HealthAddress     string
	LeaderElection    bool
	Logger            *slog.Logger
}

func Run(ctx context.Context, opts Options) error {
	scheme := clientgoscheme.Scheme
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register MCP API: %w", err)
	}
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: opts.MetricsAddress},
		HealthProbeBindAddress: opts.HealthAddress,
		LeaderElection:         opts.LeaderElection,
		LeaderElectionID:       "operator.mcp.supek8smcp.io",
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	reconciler := &KubernetesMCPServerReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		ServerImage:       opts.ServerImage,
		OperatorNamespace: opts.OperatorNamespace,
		Logger:            opts.Logger,
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &mcpv1alpha1.KubernetesMCPServer{}, tlsSecretIndexKey, func(object client.Object) []string {
		server := object.(*mcpv1alpha1.KubernetesMCPServer)
		if server.Spec.TLS.SecretName == "" {
			return nil
		}
		return []string{server.Spec.TLS.SecretName}
	}); err != nil {
		return fmt.Errorf("index configured TLS Secrets: %w", err)
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup controller: %w", err)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}

	if opts.Logger != nil {
		opts.Logger.Info("starting operator", "serverImage", opts.ServerImage, "namespace", opts.OperatorNamespace)
	}
	return mgr.Start(ctx)
}
