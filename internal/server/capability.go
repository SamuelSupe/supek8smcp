package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Capability struct {
	ID          string   `json:"id"`
	Group       string   `json:"group,omitempty"`
	Version     string   `json:"version"`
	Resource    string   `json:"resource"`
	Subresource string   `json:"subresource,omitempty"`
	Kind        string   `json:"kind"`
	Action      string   `json:"action"`
	Verb        string   `json:"verb"`
	Namespaced  bool     `json:"namespaced"`
	Categories  []string `json:"categories,omitempty"`
}

func capabilityFromAction(codec *capabilityCodec, action Action, categories []string) Capability {
	capability := Capability{
		Group:       action.GVR.Group,
		Version:     action.GVR.Version,
		Resource:    action.GVR.Resource,
		Subresource: action.Subresource,
		Kind:        action.Kind,
		Action:      action.Action,
		Verb:        action.Verb,
		Namespaced:  action.Namespaced,
		Categories:  categories,
	}
	capability.ID = codec.encode(capability)
	return capability
}

func (c Capability) AsAction() Action {
	return Action{
		GVR:  schema.GroupVersionResource{Group: c.Group, Version: c.Version, Resource: c.Resource},
		Kind: c.Kind, Subresource: c.Subresource, Verb: c.Verb, Action: c.Action, Namespaced: c.Namespaced,
	}
}

type capabilityCodec struct {
	key [32]byte
}

func newCapabilityCodec() (*capabilityCodec, error) {
	codec := &capabilityCodec{}
	if _, err := rand.Read(codec.key[:]); err != nil {
		return nil, fmt.Errorf("generate capability signing key: %w", err)
	}
	return codec, nil
}

func (c *capabilityCodec) encode(capability Capability) string {
	copy := capability
	copy.ID = ""
	data, _ := json.Marshal(copy)
	payload := base64.RawURLEncoding.EncodeToString(data)
	signature := c.sign([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (c *capabilityCodec) decode(id string) (Capability, error) {
	parts := strings.Split(id, ".")
	if len(parts) != 2 {
		return Capability{}, policyError("invalid_capability", "capability ID is not valid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, c.sign([]byte(parts[0]))) {
		return Capability{}, policyError("invalid_capability", "capability ID is not valid")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Capability{}, policyError("invalid_capability", "capability ID is not valid")
	}
	var capability Capability
	if err := json.Unmarshal(data, &capability); err != nil {
		return Capability{}, policyError("invalid_capability", "capability ID is not valid")
	}
	if capability.Version == "" || capability.Resource == "" || capability.Action == "" || capability.Verb == "" {
		return Capability{}, policyError("invalid_capability", "capability ID is incomplete")
	}
	capability.ID = id
	return capability, nil
}

func (c *capabilityCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key[:])
	mac.Write(payload)
	return mac.Sum(nil)
}
