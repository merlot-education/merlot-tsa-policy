package regoext

import (
	"fmt"
	"net/http"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

type CacheExt struct {
	path string
}

func NewCacheExt(path string) *CacheExt {
	return &CacheExt{path: path}
}

func (ce *CacheExt) GetCacheFunc() (*rego.Function, rego.Builtin3) {
	return &rego.Function{
			Name:    "cache.get",
			Decl:    types.NewFunction(types.Args(types.S, types.S, types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, a, b, c *ast.Term) (*ast.Term, error) {

			var key, namespace, scope string

			if err := ast.As(a.Value, &key); err != nil {
				return nil, err
			} else if err = ast.As(b.Value, &namespace); err != nil {
				return nil, err
			} else if err = ast.As(c.Value, &scope); err != nil {
				return nil, err
			}

			req, err := http.NewRequest("GET", ce.path+"/v1/cache", nil)
			req.Header = http.Header{
				"x-cache-key":       []string{key},
				"x-cache-namespace": []string{namespace},
				"x-cache-scope":     []string{scope},
			}
			if err != nil {
				return nil, err
			}

			resp, err := http.DefaultClient.Do(req.WithContext(bctx.Context))
			if err != nil {
				return nil, err
			}

			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf(resp.Status)
			}

			v, err := ast.ValueFromReader(resp.Body)
			if err != nil {
				return nil, err
			}

			return ast.NewTerm(v), nil
		}
}
