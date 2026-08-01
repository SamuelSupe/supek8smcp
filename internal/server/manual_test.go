package server

import (
	"testing"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
	"github.com/samuelsupe/supek8smcp/internal/runtimeconfig"
)

func manualTestApp(mode mcpv1alpha1.AccessMode) *App {
	return &App{config: runtimeconfig.Config{Spec: mcpv1alpha1.KubernetesMCPServerSpec{Mode: mode}}}
}

func TestHelpIndexAndDetailsAreProgressive(t *testing.T) {
	t.Parallel()

	app := manualTestApp(mcpv1alpha1.ModeReadOnly)
	index, err := app.help(HelpInput{})
	if err != nil {
		t.Fatalf("help(index) error = %v", err)
	}
	if index.Manual != nil {
		t.Fatalf("help(index) returned a detailed Manual: %#v", index.Manual)
	}
	if len(index.Tools) == 0 || len(index.Workflow) == 0 {
		t.Fatalf("help(index) = %#v, want compact tools and workflow index", index)
	}
	for _, summary := range index.Tools {
		if summary.Name == "" || summary.DetailsRequest["tool"] != summary.Name {
			t.Fatalf("help(index) summary = %#v, want an exact details request", summary)
		}
	}

	details, err := app.help(HelpInput{Tool: toolRead})
	if err != nil {
		t.Fatalf("help(details) error = %v", err)
	}
	if details.Manual == nil || details.Manual.Name != toolRead {
		t.Fatalf("help(details) Manual = %#v, want %s", details.Manual, toolRead)
	}
	if len(details.Tools) != 0 {
		t.Fatalf("help(details) returned index tools: %#v", details.Tools)
	}
}

func TestHelpAvailabilityFollowsAccessMode(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		mode       mcpv1alpha1.AccessMode
		writeTools bool
	}{
		{name: "read only", mode: mcpv1alpha1.ModeReadOnly},
		{name: "safe write", mode: mcpv1alpha1.ModeSafeWrite, writeTools: true},
		{name: "dangerous", mode: mcpv1alpha1.ModeDangerous, writeTools: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			index, err := manualTestApp(tt.mode).help(HelpInput{})
			if err != nil {
				t.Fatalf("help(index) error = %v", err)
			}
			available := make(map[string]bool, len(index.Tools))
			for _, summary := range index.Tools {
				available[summary.Name] = summary.Available
			}
			for _, name := range []string{toolHelp, toolSearch, toolDescribe, toolRead} {
				if !available[name] {
					t.Fatalf("mode %s marks %s unavailable; summaries = %#v", tt.mode, name, available)
				}
			}
			for _, name := range []string{toolPlan, toolCommit} {
				if available[name] != tt.writeTools {
					t.Fatalf("mode %s marks %s available=%t, want %t", tt.mode, name, available[name], tt.writeTools)
				}
			}
		})
	}
}

func TestHelpRejectsUnknownExactTool(t *testing.T) {
	t.Parallel()

	_, err := manualTestApp(mcpv1alpha1.ModeReadOnly).help(HelpInput{Tool: "k8s.unknown"})
	if got := policyReason(err); got != "invalid_input" {
		t.Fatalf("help(unknown tool) reason = %q, want invalid_input (error: %v)", got, err)
	}
}
