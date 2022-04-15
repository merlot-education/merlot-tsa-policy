// Package regocache implements in-memory caching of
// compiled and prepared Rego queries. It also
// implements a function to purge the cache when
// external data changes have happened.
package regocache

import (
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

type Cache struct {
	mu    sync.RWMutex
	cache map[string]*rego.PreparedEvalQuery
}

func New() *Cache {
	return &Cache{
		cache: map[string]*rego.PreparedEvalQuery{},
	}
}

func (c *Cache) Set(key string, query *rego.PreparedEvalQuery) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = query
}

func (c *Cache) Get(key string) (query *rego.PreparedEvalQuery, found bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.cache[key]
	return v, ok
}

// Purge deletes all cache values.
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = map[string]*rego.PreparedEvalQuery{}
}

// PolicyDataChange triggers purge on the cache.
func (c *Cache) PolicyDataChange() {
	c.Purge()
}
