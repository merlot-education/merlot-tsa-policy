package regofunc

import (
	"fmt"
	"net/http"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"code.vereign.com/gaiax/tsa/golib/ocm"
)

type OcmFuncs struct {
	client *ocm.Client
}

func NewOcmFuncs(ocmAddr string, httpClient *http.Client) *OcmFuncs {
	ocmClient := ocm.New(ocmAddr, ocm.WithHTTPClient(httpClient))

	return &OcmFuncs{client: ocmClient}
}

func (of *OcmFuncs) GetLoginProofInvitation() (*rego.Function, rego.Builtin1) {
	return &rego.Function{
			Name:    "ocm.getLoginProofInvitation",
			Decl:    types.NewFunction(types.Args(types.A), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, types *ast.Term) (*ast.Term, error) {
			var credTypes []string

			if err := ast.As(types.Value, &credTypes); err != nil {
				return nil, fmt.Errorf("invalid credential types array: %s", err)
			}

			res, err := of.client.GetLoginProofInvitation(bctx.Context, credTypes)
			if err != nil {
				return nil, err
			}

			type result struct {
				Link      string `json:"link"`
				RequestId string `json:"requestId"`
			}
			var val ast.Value
			val, err = ast.InterfaceToValue(result{
				Link:      res.Data.PresentationMessage,
				RequestId: res.Data.PresentationID,
			})
			if err != nil {
				return nil, err
			}

			return ast.NewTerm(val), nil
		}
}

func (of *OcmFuncs) GetLoginProofResult() (*rego.Function, rego.Builtin1) {
	return &rego.Function{
			Name:    "ocm.getLoginProofResult",
			Decl:    types.NewFunction(types.Args(types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, id *ast.Term) (*ast.Term, error) {
			var presentationId string

			if err := ast.As(id.Value, &presentationId); err != nil {
				return nil, fmt.Errorf("invalid presentationId: %s", err)
			}

			res, err := of.client.GetLoginProofResult(bctx.Context, presentationId)
			if err != nil {
				return nil, err
			}

			var val ast.Value
			val, err = ast.InterfaceToValue(res.Data.Claims)
			if err != nil {
				return nil, err
			}

			return ast.NewTerm(val), nil
		}
}
