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

	keysFuncs := regofunc.NewPubkeyFuncs(signerSrv.URL, http.DefaultClient)
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

	keysFuncs := regofunc.NewPubkeyFuncs(signerSrv.URL, http.DefaultClient)
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

	keysFuncs := regofunc.NewPubkeyFuncs(signerSrv.URL, http.DefaultClient)
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

	keysFuncs := regofunc.NewPubkeyFuncs(signerSrv.URL, http.DefaultClient)
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
