package regofunc_test

import (
	"net/http"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/regofunc"
)

func TestList(t *testing.T) {
	funcs := regofunc.List()
	assert.Len(t, funcs, 0)

	cacheFuncs := regofunc.NewCacheFuncs("localhost:8080", http.DefaultClient)
	regofunc.Register("cacheGet", rego.Function3(cacheFuncs.CacheGetFunc()))
	regofunc.Register("cacheSet", rego.Function3(cacheFuncs.CacheGetFunc()))

	funcs = regofunc.List()
	assert.Len(t, funcs, 2)
}
