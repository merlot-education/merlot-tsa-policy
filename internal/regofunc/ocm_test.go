package regofunc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"

	"code.vereign.com/gaiax/tsa/policy/internal/regofunc"
)

func TestGetLoginProofInvitationSuccess(t *testing.T) {
	expected := `{"link":"https://ocm:443/ocm/didcomm/?d_m=eyJAdHlwZSI","requestId":"2cf01406-b15f-4960-a6a7-7bc62cd37a3c"}`
	ocmResponse := `{
		"statusCode": 201,
		"message": "Presentation request send successfully",
		"data": {
			"presentationId": "2cf01406-b15f-4960-a6a7-7bc62cd37a3c",			
			"presentationMessage": "https://ocm:443/ocm/didcomm/?d_m=eyJAdHlwZSI"
		}
	}`

	ocmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, ocmResponse)
	}))
	defer ocmSrv.Close()

	ocmFuncs := regofunc.NewOcmFuncs(ocmSrv.URL, http.DefaultClient)

	r := rego.New(
		rego.Query(`ocm.getLoginProofInvitation(["openid", "profile"])`),
		rego.Function1(ocmFuncs.GetLoginProofInvitation()),
		rego.StrictBuiltinErrors(true),
	)

	resultSet, err := r.Eval(context.Background())
	assert.NoError(t, err)

	resultBytes, err := json.Marshal(resultSet[0].Expressions[0].Value)
	assert.NoError(t, err)
	assert.Equal(t, expected, string(resultBytes))
}

func TestGetLoginProofInvitationErr(t *testing.T) {
	ocmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"key":"value"}`)
	}))
	defer ocmSrv.Close()

	ocmFuncs := regofunc.NewOcmFuncs(ocmSrv.URL, http.DefaultClient)

	r := rego.New(
		rego.Query(`ocm.getLoginProofInvitation("openid")`),
		rego.Function1(ocmFuncs.GetLoginProofInvitation()),
		rego.StrictBuiltinErrors(true),
	)

	resultSet, err := r.Eval(context.Background())
	assert.Error(t, err)
	assert.Empty(t, resultSet)
	assert.Contains(t, err.Error(), "cannot unmarshal string into Go value of type []string")
}

func TestGetLoginProofResult(t *testing.T) {
	expected := `{"family_name":"Doe","name":"John"}`
	ocmResponse := `{
		"statusCode": 200,
		"data": {
			"state": "done",
			"data": [
				{
					"credentialSubject": {
						"family_name":"Doe"
					}
				},
				{
					"credentialSubject": {
						"name":"John"
					}
				}
			]
		}
	}`

	ocmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, ocmResponse)
	}))
	defer ocmSrv.Close()

	ocmFuncs := regofunc.NewOcmFuncs(ocmSrv.URL, http.DefaultClient)

	r := rego.New(
		rego.Query(`ocm.getLoginProofResult("2cf01406-b15f-4960-a6a7-7bc62cd37a3c")`),
		rego.Function1(ocmFuncs.GetLoginProofResult()),
		rego.StrictBuiltinErrors(true),
	)

	resultSet, err := r.Eval(context.Background())
	assert.NoError(t, err)

	resultBytes, err := json.Marshal(resultSet[0].Expressions[0].Value)
	assert.NoError(t, err)
	assert.Equal(t, expected, string(resultBytes))
}
