package regocache_test

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"

	"code.vereign.com/gaiax/tsa/policy/internal/regocache"
	"code.vereign.com/gaiax/tsa/policy/internal/service/policy"
)

const regoPolicy = `
	package test

	allow {
		input.val == 1
	}
`

func TestNew(t *testing.T) {
	cache := regocache.New()
	assert.Implements(t, (*policy.RegoCache)(nil), cache)
}

func TestCache_SetAndGet(t *testing.T) {
	q1, err := rego.New(
		rego.Module("filename.rego", regoPolicy),
		rego.Query("data"),
	).PrepareForEval(context.Background())
	assert.NoError(t, err)

	cache := regocache.New()
	cache.Set("query1", &q1)

	q2, ok := cache.Get("query1")
	assert.True(t, ok)
	assert.Equal(t, q1, *q2)
}

func TestCache_Purge(t *testing.T) {
	q1, err := rego.New(
		rego.Module("filename.rego", regoPolicy),
		rego.Query("data"),
	).PrepareForEval(context.Background())
	assert.NoError(t, err)

	cache := regocache.New()
	cache.Set("query1", &q1)

	cache.Purge()
	q2, ok := cache.Get("query1")
	assert.False(t, ok)
	assert.Nil(t, q2)
}

func TestCache_PolicyDataChange(t *testing.T) {
	q1, err := rego.New(
		rego.Module("filename.rego", regoPolicy),
		rego.Query("data"),
	).PrepareForEval(context.Background())
	assert.NoError(t, err)

	cache := regocache.New()
	cache.Set("query1", &q1)

	cache.PolicyDataChange()
	q2, ok := cache.Get("query1")
	assert.False(t, ok)
	assert.Nil(t, q2)
}
