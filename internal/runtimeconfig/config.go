package runtimeconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

	corev1 "k8s.io/api/core/v1"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

type Config struct {
	Name       string                              `json:"name"`
	Namespace  string                              `json:"namespace"`
	Generation int64                               `json:"generation"`
	Spec       mcpv1alpha1.KubernetesMCPServerSpec `json:"spec"`
}

func FromResource(server *mcpv1alpha1.KubernetesMCPServer) Config {
	copy := server.DeepCopy()
	copy.Default()
	return Config{
		Name:       copy.Name,
		Namespace:  copy.Namespace,
		Generation: copy.Generation,
		Spec:       copy.Spec,
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read server config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode server config: %w", err)
	}
	if cfg.Name == "" || cfg.Namespace == "" {
		return Config{}, fmt.Errorf("server config requires name and namespace")
	}
	resource := &mcpv1alpha1.KubernetesMCPServer{Spec: cfg.Spec}
	resource.Namespace = cfg.Namespace
	resource.Default()
	cfg.Spec = resource.Spec
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Marshal(cfg Config) ([]byte, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode server config: %w", err)
	}
	return data, nil
}

func Validate(cfg Config) error {
	if cfg.Name == "" || cfg.Namespace == "" {
		return fmt.Errorf("server config requires name and namespace")
	}
	if !slices.Contains([]mcpv1alpha1.AccessMode{mcpv1alpha1.ModeReadOnly, mcpv1alpha1.ModeSafeWrite, mcpv1alpha1.ModeDangerous}, cfg.Spec.Mode) {
		return fmt.Errorf("unsupported access mode %q", cfg.Spec.Mode)
	}
	if cfg.Spec.Scope.AllowClusterScopedWrite && cfg.Spec.Mode != mcpv1alpha1.ModeDangerous {
		return fmt.Errorf("cluster-scoped writes require Dangerous mode")
	}
	if len(cfg.Spec.Scope.Namespaces) == 0 {
		return fmt.Errorf("server config requires at least one namespace")
	}
	for _, namespace := range cfg.Spec.Scope.Namespaces {
		if namespace == "" {
			return fmt.Errorf("server config namespace scope may not contain an empty name")
		}
	}
	if !slices.Contains([]mcpv1alpha1.SensitiveReadPolicy{
		mcpv1alpha1.SensitiveReadRedact, mcpv1alpha1.SensitiveReadDeny, mcpv1alpha1.SensitiveReadAllow,
	}, cfg.Spec.Policy.SensitiveReads) {
		return fmt.Errorf("unsupported sensitiveReads policy %q", cfg.Spec.Policy.SensitiveReads)
	}
	if cfg.Spec.Limits.RequestTimeout.Duration <= 0 || cfg.Spec.Limits.StreamTimeout.Duration <= 0 || cfg.Spec.Limits.ExecTimeout.Duration <= 0 {
		return fmt.Errorf("request, stream, and exec timeouts must be positive")
	}
	if cfg.Spec.Limits.MaxInputBytes < 1024 || cfg.Spec.Limits.MaxInputBytes > 10<<20 {
		return fmt.Errorf("maxInputBytes must be between 1024 and 10485760")
	}
	if cfg.Spec.Limits.MaxOutputBytes < 1024 || cfg.Spec.Limits.MaxOutputBytes > 50<<20 {
		return fmt.Errorf("maxOutputBytes must be between 1024 and 52428800")
	}
	if cfg.Spec.Limits.MaxListItems < 1 || cfg.Spec.Limits.MaxListItems > 1000 {
		return fmt.Errorf("maxListItems must be between 1 and 1000")
	}
	if cfg.Spec.Limits.MaxConcurrent < 1 || cfg.Spec.Limits.MaxConcurrent > 32 {
		return fmt.Errorf("maxConcurrent must be between 1 and 32")
	}
	if cfg.Spec.Limits.RequestsPerMinute < 1 || cfg.Spec.Limits.RequestsPerMinute > 6000 {
		return fmt.Errorf("requestsPerMinute must be between 1 and 6000")
	}
	if cfg.Spec.Limits.Burst < 1 || cfg.Spec.Limits.Burst > 1000 {
		return fmt.Errorf("burst must be between 1 and 1000")
	}
	resources := cfg.Spec.ServerResources()
	for name, request := range resources.Requests {
		if request.Sign() < 0 {
			return fmt.Errorf("resource request %s must not be negative", name)
		}
		if limit, ok := resources.Limits[name]; ok && request.Cmp(limit) > 0 {
			return fmt.Errorf("resource request %s exceeds its limit", name)
		}
	}
	for name, limit := range resources.Limits {
		if limit.Sign() <= 0 {
			return fmt.Errorf("resource limit %s must be positive", name)
		}
	}
	// Reserve space for plans, schema cache, and process overhead, plus decoded
	// upstream objects and serialization copies for every concurrent request.
	required := int64(128<<20) + int64(cfg.Spec.Limits.MaxConcurrent)*(16<<20+4*(cfg.Spec.Limits.MaxInputBytes+cfg.Spec.Limits.MaxOutputBytes))
	memory := resources.Limits[corev1.ResourceMemory]
	if memory.Value() < required {
		return fmt.Errorf("server memory limit must be at least %d bytes for the configured concurrency and input/output budgets", required)
	}
	return nil
}
