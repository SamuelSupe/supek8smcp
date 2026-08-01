package runtimeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

func TestLoadAppliesRuntimeDefaults(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"name":"demo","namespace":"mcp-system"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Spec.Mode != mcpv1alpha1.ModeReadOnly {
		t.Fatalf("default mode = %q, want %q", cfg.Spec.Mode, mcpv1alpha1.ModeReadOnly)
	}
	if got := cfg.Spec.Scope.Namespaces; len(got) != 1 || got[0] != "mcp-system" {
		t.Fatalf("default namespace scope = %#v, want [mcp-system]", got)
	}
	if cfg.Spec.Policy.SensitiveReads != mcpv1alpha1.SensitiveReadRedact {
		t.Fatalf("default sensitiveReads = %q, want %q", cfg.Spec.Policy.SensitiveReads, mcpv1alpha1.SensitiveReadRedact)
	}
	if got, want := cfg.Spec.Limits.RequestTimeout.Duration, 30*time.Second; got != want {
		t.Fatalf("default request timeout = %s, want %s", got, want)
	}
	if got, want := cfg.Spec.Limits.StreamTimeout.Duration, 60*time.Second; got != want {
		t.Fatalf("default stream timeout = %s, want %s", got, want)
	}
	if got, want := cfg.Spec.Limits.ExecTimeout.Duration, 30*time.Second; got != want {
		t.Fatalf("default exec timeout = %s, want %s", got, want)
	}
	if got, want := cfg.Spec.Limits.MaxInputBytes, int64(256<<10); got != want {
		t.Fatalf("default max input bytes = %d, want %d", got, want)
	}
	if got, want := cfg.Spec.Limits.MaxOutputBytes, int64(1<<20); got != want {
		t.Fatalf("default max output bytes = %d, want %d", got, want)
	}
	if got, want := cfg.Spec.Limits.MaxListItems, int64(100); got != want {
		t.Fatalf("default max list items = %d, want %d", got, want)
	}
	if got, want := cfg.Spec.Limits.MaxConcurrent, int32(4); got != want {
		t.Fatalf("default max concurrent = %d, want %d", got, want)
	}
}

func TestLoadRejectsInvalidModeAndLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "invalid mode",
			content: `{"name":"demo","namespace":"mcp-system","spec":{"mode":"WideOpen"}}`,
			wantErr: `unsupported access mode "WideOpen"`,
		},
		{
			name:    "too small input limit",
			content: `{"name":"demo","namespace":"mcp-system","spec":{"limits":{"maxInputBytes":1023}}}`,
			wantErr: "maxInputBytes must be between",
		},
		{
			name:    "negative timeout",
			content: `{"name":"demo","namespace":"mcp-system","spec":{"limits":{"requestTimeout":"-1s"}}}`,
			wantErr: "timeouts must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
