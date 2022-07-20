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

func TestGetKeyFunc(t *testing.T) {
	expected := `{"key1":"key1 data"}`
	signerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, expected)
	}))
	defer signerSrv.Close()

	keysFuncs := regofunc.NewSignerFuncs(signerSrv.URL, http.DefaultClient)
	r := rego.New(
		rego.Query(`keys.get("key1")`),
		rego.Function1(keysFuncs.GetKeyFunc()),
		rego.StrictBuiltinErrors(true),
	)
	resultSet, err := r.Eval(context.Background())
	assert.NoError(t, err)

	resultBytes, err := json.Marshal(resultSet[0].Expressions[0].Value)
	assert.NoError(t, err)
	assert.Equal(t, expected, string(resultBytes))
}

func TestGetKeyFuncError(t *testing.T) {
	signerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer signerSrv.Close()

	keysFuncs := regofunc.NewSignerFuncs(signerSrv.URL, http.DefaultClient)
	r := rego.New(
		rego.Query(`keys.get("key1")`),
		rego.Function1(keysFuncs.GetKeyFunc()),
		rego.StrictBuiltinErrors(true),
	)
	resultSet, err := r.Eval(context.Background())
	assert.Nil(t, resultSet)
	assert.Error(t, err)

	expectedError := `keys.get("key1"): eval_builtin_error: keys.get: unexpected response from signer: 404 Not Found`
	assert.Equal(t, expectedError, err.Error())
}

func TestGetAllKeysFunc(t *testing.T) {
	expected := `[{"key1":"key1 data"},{"key2":"key2 data"}]`
	signerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, expected)
	}))
	defer signerSrv.Close()

	keysFuncs := regofunc.NewSignerFuncs(signerSrv.URL, http.DefaultClient)
	r := rego.New(
		rego.Query(`keys.getAll()`),
		rego.FunctionDyn(keysFuncs.GetAllKeysFunc()),
		rego.StrictBuiltinErrors(true),
	)
	resultSet, err := r.Eval(context.Background())
	assert.NoError(t, err)

	resultBytes, err := json.Marshal(resultSet[0].Expressions[0].Value)
	assert.NoError(t, err)
	assert.Equal(t, expected, string(resultBytes))
}

func TestIssuerDID(t *testing.T) {
	expected := `{"did":"did:web:123"}`
	signerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, expected)
	}))
	defer signerSrv.Close()

	keysFuncs := regofunc.NewSignerFuncs(signerSrv.URL, http.DefaultClient)
	r := rego.New(
		rego.Query(`issuer()`),
		rego.FunctionDyn(keysFuncs.IssuerDID()),
		rego.StrictBuiltinErrors(true),
	)
	resultSet, err := r.Eval(context.Background())
	assert.NoError(t, err)

	resultBytes, err := json.Marshal(resultSet[0].Expressions[0].Value)
	assert.NoError(t, err)
	assert.Equal(t, expected, string(resultBytes))
}

func TestCreateProof(t *testing.T) {
	tests := []struct {
		name               string
		input              map[string]interface{}
		signerResponseCode int
		errtext            string
	}{
		{
			name:    "missing credential type",
			input:   map[string]interface{}{"vc": "data"},
			errtext: "credential data does not specify type",
		},
		{
			name:    "unknown credential type",
			input:   map[string]interface{}{"type": "non-existing-type"},
			errtext: "unknown credential type",
		},
		{
			name:               "signer returns error for VC",
			input:              map[string]interface{}{"type": "VerifiableCredential"},
			signerResponseCode: http.StatusBadRequest,
			errtext:            "400 Bad Request",
		},
		{
			name:               "signer returns error for VP",
			input:              map[string]interface{}{"type": "VerifiablePresentation"},
			signerResponseCode: http.StatusBadRequest,
			errtext:            "400 Bad Request",
		},
		{
			name:               "signer returns successfully",
			input:              map[string]interface{}{"type": "VerifiableCredential"},
			signerResponseCode: http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := `{"vc":"data"}`
			signerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.signerResponseCode)
				_, _ = fmt.Fprint(w, expected)
			}))
			defer signerSrv.Close()

			keysFuncs := regofunc.NewSignerFuncs(signerSrv.URL, http.DefaultClient)
			query, err := rego.New(
				rego.Query(`proof.create(input)`),
				rego.Function1(keysFuncs.CreateProof()),
				rego.StrictBuiltinErrors(true),
			).PrepareForEval(context.Background())
			assert.NoError(t, err)

			resultSet, err := query.Eval(context.Background(), rego.EvalInput(test.input))
			if err != nil {
				assert.Contains(t, err.Error(), test.errtext)
			} else {
				assert.NotEmpty(t, resultSet)
				assert.NotEmpty(t, resultSet[0].Expressions)
				resultBytes, err := json.Marshal(resultSet[0].Expressions[0].Value)
				assert.NoError(t, err)
				assert.Equal(t, expected, string(resultBytes))
			}
		})
	}
}

func TestVerifyProof(t *testing.T) {
	tests := []struct {
		name               string
		input              map[string]interface{}
		signerResponseCode int
		errtext            string
	}{
		{
			name:    "invalid credential",
			input:   nil,
			errtext: "credential data does not specify type",
		},
		{
			name:    "missing credential type",
			input:   map[string]interface{}{"vc": "data"},
			errtext: "credential data does not specify type",
		},
		{
			name:               "credential type is not string",
			input:              map[string]interface{}{"type": 123},
			signerResponseCode: http.StatusBadRequest,
			errtext:            "invalid credential type, string is expected",
		},
		{
			name:    "missing proof section",
			input:   map[string]interface{}{"type": "VerifiableCredential"},
			errtext: "credential data does contain proof section",
		},
		{
			name:    "unknown credential type",
			input:   map[string]interface{}{"proof": "iamhere", "type": "non-existing-type"},
			errtext: "unknown credential type",
		},
		{
			name:               "signer returns error for VC",
			input:              map[string]interface{}{"proof": "iamhere", "type": "VerifiableCredential"},
			signerResponseCode: http.StatusBadRequest,
			errtext:            "400 Bad Request",
		},
		{
			name:               "signer returns error for VP",
			input:              map[string]interface{}{"proof": "iamhere", "type": "VerifiablePresentation"},
			signerResponseCode: http.StatusBadRequest,
			errtext:            "400 Bad Request",
		},
		{
			name:               "signer returns successfully",
			input:              map[string]interface{}{"proof": "iamhere", "type": "VerifiableCredential"},
			signerResponseCode: http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := `{"valid":true}`
			signerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.signerResponseCode)
				_, _ = fmt.Fprint(w, expected)
			}))
			defer signerSrv.Close()

			keysFuncs := regofunc.NewSignerFuncs(signerSrv.URL, http.DefaultClient)
			query, err := rego.New(
				rego.Query(`proof.verify(input)`),
				rego.Function1(keysFuncs.VerifyProof()),
				rego.StrictBuiltinErrors(true),
			).PrepareForEval(context.Background())
			assert.NoError(t, err)

			resultSet, err := query.Eval(context.Background(), rego.EvalInput(test.input))
			if err != nil {
				assert.NotEmpty(t, test.errtext, "test case must contain error, but doesn't")
				assert.Contains(t, err.Error(), test.errtext)
			} else {
				assert.NotEmpty(t, resultSet)
				assert.NotEmpty(t, resultSet[0].Expressions)
				valid, ok := resultSet[0].Expressions[0].Value.(bool)
				assert.True(t, ok)
				assert.True(t, valid)
			}
		})
	}
}
