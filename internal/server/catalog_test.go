package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilityCodecRoundTripAndTamperRejection(t *testing.T) {
	t.Parallel()

	codec, err := newCapabilityCodec()
	if err != nil {
		t.Fatalf("newCapabilityCodec() error = %v", err)
	}
	want := Capability{
		Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment",
		Action: "patch", Verb: "patch", Namespaced: true,
	}
	id := codec.encode(want)
	got, err := codec.decode(id)
	if err != nil {
		t.Fatalf("decode(round trip) error = %v", err)
	}
	if got.ID != id || got.Group != want.Group || got.Resource != want.Resource || got.Namespaced != want.Namespaced || got.Action != want.Action {
		t.Fatalf("decode(round trip) = %#v, want fields from %#v", got, want)
	}

	parts := strings.Split(id, ".")
	if len(parts) != 2 {
		t.Fatalf("encoded capability = %q, want payload.signature", id)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var tampered Capability
	if err := json.Unmarshal(payload, &tampered); err != nil {
		t.Fatalf("decode payload JSON: %v", err)
	}
	tampered.Resource = "pods"
	tamperedPayload, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("encode tampered payload: %v", err)
	}
	tamperedID := base64.RawURLEncoding.EncodeToString(tamperedPayload) + "." + parts[1]
	if _, err := codec.decode(tamperedID); policyReason(err) != "invalid_capability" {
		t.Fatalf("tampered resource decode error = %v, want invalid_capability", err)
	}

	mutatedSignature := parts[1]
	last := mutatedSignature[len(mutatedSignature)-1]
	if last == 'A' {
		mutatedSignature = mutatedSignature[:len(mutatedSignature)-1] + "B"
	} else {
		mutatedSignature = mutatedSignature[:len(mutatedSignature)-1] + "A"
	}
	if _, err := codec.decode(parts[0] + "." + mutatedSignature); policyReason(err) != "invalid_capability" {
		t.Fatalf("tampered signature decode error = %v, want invalid_capability", err)
	}
}
