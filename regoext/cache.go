package regoext

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

const (
	Success string = "success"
)

type CacheParams struct {
	Key       string
	Namespace string
	Scope     string
}

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

func (ce *CacheExt) SetCacheFunc() (*rego.Function, rego.Builtin4) {
	return &rego.Function{
			Name:    "cache.set",
			Decl:    types.NewFunction(types.Args(types.S, types.S, types.S, types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, k, n, s, d *ast.Term) (*ast.Term, error) {
			var key, namespace, scope, data string

			if err := ast.As(k.Value, &key); err != nil {
				return nil, err
			} else if err = ast.As(n.Value, &namespace); err != nil {
				return nil, err
			} else if err = ast.As(s.Value, &scope); err != nil {
				return nil, err
			} else if err = ast.As(d.Value, &data); err != nil {
				return nil, err
			}

			type Response struct {
				Result string `json:"result"`
			}
			r := &Response{Success}

			payloadBuf := bytes.NewBufferString(data)

			req, err := http.NewRequest("POST", ce.path+"/v1/cache", payloadBuf)
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

			if resp.StatusCode != http.StatusCreated {
				return nil, err
			}

			var val ast.Value
			val, err = ast.InterfaceToValue(r)
			if err != nil {
				return nil, err
			}

			return ast.NewTerm(val), nil
		}
}
