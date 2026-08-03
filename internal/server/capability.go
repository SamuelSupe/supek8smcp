package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

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
	key     [32]byte
	mu      sync.RWMutex
	handles map[string]capabilityHandle
}

type capabilityHandle struct {
	payload    string
	capability Capability
}

func newCapabilityCodec() (*capabilityCodec, error) {
	codec := &capabilityCodec{handles: make(map[string]capabilityHandle)}
	if _, err := rand.Read(codec.key[:]); err != nil {
		return nil, fmt.Errorf("generate capability signing key: %w", err)
	}
	return codec, nil
}

func (c *capabilityCodec) encode(capability Capability) string {
	copy := capability
	copy.ID = ""
	data, _ := json.Marshal(copy)
	payload := string(data)
	digest := c.sign(data)

	c.mu.Lock()
	defer c.mu.Unlock()
	for bytes := 12; bytes <= len(digest); bytes += 4 {
		id := "cap_" + base64.RawURLEncoding.EncodeToString(digest[:bytes])
		if existing, found := c.handles[id]; found && existing.payload != payload {
			continue
		}
		copy.ID = id
		c.handles[id] = capabilityHandle{payload: payload, capability: copy}
		return id
	}
	panic("capability handle collision across full HMAC digest")
}

func (c *capabilityCodec) decode(id string) (Capability, error) {
	if !strings.HasPrefix(id, "cap_") {
		return Capability{}, policyError("invalid_capability", "capability ID is not valid")
	}
	c.mu.RLock()
	entry, found := c.handles[id]
	c.mu.RUnlock()
	if !found {
		return Capability{}, policyError("invalid_capability", "capability ID is unknown or expired; call k8s.search again")
	}
	capability := entry.capability
	capability.ID = id
	return capability, nil
}

func (c *capabilityCodec) retain(capabilities []Capability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current := make(map[string]capabilityHandle, len(capabilities))
	for _, capability := range capabilities {
		if handle, found := c.handles[capability.ID]; found {
			current[capability.ID] = handle
		}
	}
	c.handles = current
}

func (c *capabilityCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key[:])
	mac.Write(payload)
	return mac.Sum(nil)
}
