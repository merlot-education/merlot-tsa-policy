package regofunc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

type SignerFuncs struct {
	signerAddr string
	httpClient *http.Client
}

func NewSignerFuncs(signerAddr string, httpClient *http.Client) *SignerFuncs {
	return &SignerFuncs{
		signerAddr: signerAddr,
		httpClient: httpClient,
	}
}

func (sf *SignerFuncs) GetKeyFunc() (*rego.Function, rego.Builtin1) {
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

			uri, err := url.ParseRequestURI(sf.signerAddr + "/v1/keys/" + key)
			if err != nil {
				return nil, err
			}

			req, err := http.NewRequest("GET", uri.String(), nil)
			if err != nil {
				return nil, err
			}

			resp, err := sf.httpClient.Do(req.WithContext(bctx.Context))
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

func (sf *SignerFuncs) GetAllKeysFunc() (*rego.Function, rego.BuiltinDyn) {
	return &rego.Function{
			Name:    "keys.getAll",
			Decl:    types.NewFunction(nil, types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {
			uri, err := url.ParseRequestURI(sf.signerAddr + "/v1/keys")
			if err != nil {
				return nil, err
			}

			req, err := http.NewRequest("GET", uri.String(), nil)
			if err != nil {
				return nil, err
			}

			resp, err := sf.httpClient.Do(req.WithContext(bctx.Context))
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

func (sf *SignerFuncs) IssuerDID() (*rego.Function, rego.BuiltinDyn) {
	return &rego.Function{
			Name:    "issuer",
			Decl:    types.NewFunction(nil, types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {
			uri, err := url.ParseRequestURI(sf.signerAddr + "/v1/issuerDID")
			if err != nil {
				return nil, err
			}

			req, err := http.NewRequest("GET", uri.String(), nil)
			if err != nil {
				return nil, err
			}

			resp, err := sf.httpClient.Do(req.WithContext(bctx.Context))
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

func (sf *SignerFuncs) CreateProof() (*rego.Function, rego.Builtin1) {
	return &rego.Function{
			Name:    "proof.create",
			Decl:    types.NewFunction(types.Args(types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, credential *ast.Term) (*ast.Term, error) {
			// cred represents verifiable credential or presentation
			var cred map[string]interface{}
			if err := ast.As(credential.Value, &cred); err != nil {
				return nil, fmt.Errorf("invalid credential: %s", err)
			}

			if cred["type"] == nil {
				return nil, fmt.Errorf("credential data does not specify type: must be VerifiablePresentation or VerifiableCredential")
			}

			credType, ok := cred["type"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid credential type, string is expected")
			}

			var createProofPath string
			switch credType {
			case "VerifiableCredential":
				createProofPath = "/v1/credential/proof"
			case "VerifiablePresentation":
				createProofPath = "/v1/presentation/proof"
			default:
				return nil, fmt.Errorf("unknown credential type: %q", credType)
			}

			jsonCred, err := json.Marshal(cred)
			if err != nil {
				return nil, err
			}

			req, err := http.NewRequest("POST", sf.signerAddr+createProofPath, bytes.NewReader(jsonCred))
			if err != nil {
				return nil, err
			}

			resp, err := sf.httpClient.Do(req.WithContext(bctx.Context))
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close() // nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("unexpected response from signer: %d", resp.StatusCode)
			}

			v, err := ast.ValueFromReader(resp.Body)
			if err != nil {
				return nil, err
			}

			return ast.NewTerm(v), nil
		}
}

func (sf *SignerFuncs) VerifyProof() (*rego.Function, rego.Builtin1) {
	return &rego.Function{
			Name:    "proof.verify",
			Decl:    types.NewFunction(types.Args(types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, credential *ast.Term) (*ast.Term, error) {
			// cred represents verifiable credential or presentation
			var cred map[string]interface{}
			if err := ast.As(credential.Value, &cred); err != nil {
				return nil, fmt.Errorf("invalid credential: %s", err)
			}

			if cred["type"] == nil {
				return nil, fmt.Errorf("credential data does not specify type: must be VerifiablePresentation or VerifiableCredential")
			}

			credType, ok := cred["type"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid credential type, string is expected")
			}

			if cred["proof"] == nil {
				return nil, fmt.Errorf("credential data does contain proof section")
			}

			var verifyProofPath string
			switch credType {
			case "VerifiableCredential":
				verifyProofPath = "/v1/credential/verify"
			case "VerifiablePresentation":
				verifyProofPath = "/v1/presentation/verify"
			default:
				return nil, fmt.Errorf("unknown credential type: %q", credType)
			}

			jsonCred, err := json.Marshal(cred)
			if err != nil {
				return nil, err
			}

			req, err := http.NewRequest("POST", sf.signerAddr+verifyProofPath, bytes.NewReader(jsonCred))
			if err != nil {
				return nil, err
			}

			resp, err := sf.httpClient.Do(req.WithContext(bctx.Context))
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close() // nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("unexpected response from signer: %d", resp.StatusCode)
			}

			var result struct {
				Valid bool `json:"valid"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return nil, fmt.Errorf("failed to decode response from signer: %v", err)
			}

			if !result.Valid {
				return nil, fmt.Errorf("proof is invalid")
			}

			return ast.NewTerm(ast.Boolean(true)), nil
		}
}
