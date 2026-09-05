package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/openapi3"
)

const schemaCacheMaxBytes = 32 << 20

type schemaCacheKey struct {
	credential [32]byte
	gv         schema.GroupVersion
}
type schemaCacheEntry struct {
	document map[string]any
	expires  time.Time
	bytes    int64
}
type schemaCache struct {
	mu      sync.Mutex
	entries map[schemaCacheKey]schemaCacheEntry
	bytes   int64
	metrics *runtimeMetrics
}

func newSchemaCache(metrics *runtimeMetrics) *schemaCache {
	return &schemaCache{entries: make(map[schemaCacheKey]schemaCacheEntry), metrics: metrics}
}

func (a *App) schemaForCapability(ctx context.Context, principal *Principal, capability Capability, fieldPath string, depth int) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	document, err := a.schemas.load(ctx, principal, schema.GroupVersion{Group: capability.Group, Version: capability.Version})
	if err != nil {
		return nil, err
	}
	return schemaFromDocument(document, capability, fieldPath, depth)
}

func (c *schemaCache) load(ctx context.Context, principal *Principal, gv schema.GroupVersion) (map[string]any, error) {
	// Bind metadata reuse to both the reviewed subject and the exact credential;
	// tokens are never retained in the cache. Each describe still performs SSAR.
	key := schemaCacheKey{credential: sha256.Sum256([]byte(principal.SubjectKey() + "\x00" + principal.Token)), gv: gv}
	if c != nil && principal.Token != "" {
		c.mu.Lock()
		for key, entry := range c.entries {
			if time.Now().After(entry.expires) {
				delete(c.entries, key)
				c.bytes -= entry.bytes
			}
		}
		entry, ok := c.entries[key]
		c.mu.Unlock()
		if ok {
			c.metrics.cache("schema", "hit")
			return entry.document, nil
		}
	}
	if c != nil {
		c.metrics.cache("schema", "miss")
	}
	started := time.Now()
	if c != nil {
		defer c.metrics.observe("schema_load", started)
	}
	discoveryClient, err := principal.discoveryForContext(ctx)
	if err != nil {
		return nil, err
	}
	document, err := openapi3.NewRoot(discoveryClient.OpenAPIV3()).GVSpecAsMap(gv)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("load OpenAPI v3 schema: %w", err)
	}
	if c != nil && principal.Token != "" {
		encoded, err := json.Marshal(document)
		if err == nil {
			size := int64(len(encoded)) * 4
			c.mu.Lock()
			if _, exists := c.entries[key]; !exists && len(c.entries) < 64 && size <= schemaCacheMaxBytes-c.bytes {
				c.entries[key] = schemaCacheEntry{document: document, expires: time.Now().Add(5 * time.Minute), bytes: size}
				c.bytes += size
			}
			c.mu.Unlock()
		}
	}
	return document, nil
}
