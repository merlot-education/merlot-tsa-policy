package regofunc

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

type PubkeyFuncs struct {
	signerAddr string
	httpClient *http.Client
}

func NewPubkeyFuncs(signerAddr string, httpClient *http.Client) *PubkeyFuncs {
	return &PubkeyFuncs{
		signerAddr: signerAddr,
		httpClient: httpClient,
	}
}

func (pf *PubkeyFuncs) GetKeyFunc() (*rego.Function, rego.Builtin1) {
	return &rego.Function{
			Name:    "keys.get",
			Decl:    types.NewFunction(types.Args(types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, keyname *ast.Term) (*ast.Term, error) {
			var key string
			if err := ast.As(keyname.Value, &key); err != nil {
				return nil, fmt.Errorf("invalid keyname: %s", err)
			}

			if strings.TrimSpace(key) == "" {
				return nil, fmt.Errorf("empty keyname")
			}

			uri, err := url.ParseRequestURI(pf.signerAddr + "/v1/keys/" + key)
			if err != nil {
				return nil, err
			}

			req, err := http.NewRequest("GET", uri.String(), nil)
			if err != nil {
				return nil, err
			}

			resp, err := pf.httpClient.Do(req.WithContext(bctx.Context))
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close() // nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("unexpected response from signer: %s", resp.Status)
			}

			v, err := ast.ValueFromReader(resp.Body)
			if err != nil {
				return nil, err
			}

			return ast.NewTerm(v), nil
		}
}

func (pf *PubkeyFuncs) GetAllKeysFunc() (*rego.Function, rego.BuiltinDyn) {
	return &rego.Function{
			Name:    "keys.getAll",
			Decl:    types.NewFunction(nil, types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {
			uri, err := url.ParseRequestURI(pf.signerAddr + "/v1/keys")
			if err != nil {
				return nil, err
			}

			req, err := http.NewRequest("GET", uri.String(), nil)
			if err != nil {
				return nil, err
			}

			resp, err := pf.httpClient.Do(req.WithContext(bctx.Context))
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close() // nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("unexpected response from signer: %s", resp.Status)
			}

			v, err := ast.ValueFromReader(resp.Body)
			if err != nil {
				return nil, err
			}

			return ast.NewTerm(v), nil
		}
}
