package operator

import (
	"context"
	"fmt"
	"log/slog"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
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
	managedSelector := labels.SelectorFromSet(labels.Set{
		"app.kubernetes.io/managed-by": "supek8smcp-operator",
	})
	uncachedObjects := []client.Object{
		&corev1.Secret{}, &rbacv1.ClusterRole{}, &rbacv1.ClusterRoleBinding{},
		&corev1.ServiceAccount{}, &corev1.Service{}, &corev1.ConfigMap{},
		&appsv1.Deployment{}, &networkingv1.NetworkPolicy{},
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			&corev1.ServiceAccount{}:      {Label: managedSelector},
			&corev1.Service{}:             {Label: managedSelector},
			&corev1.ConfigMap{}:           {Label: managedSelector},
			&appsv1.Deployment{}:          {Label: managedSelector},
			&networkingv1.NetworkPolicy{}: {Label: managedSelector},
		}},
		Client:                 client.Options{Cache: &client.CacheOptions{DisableFor: uncachedObjects}},
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
