package regofunc_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/regofunc"
)

func TestToURLFunc(t *testing.T) {
	tests := []struct {
		// test input
		name      string
		regoQuery string
		// expected result
		res     string
		errText string
	}{
		{
			name:      "DID is empty",
			regoQuery: `url_from_did("")`,
			errText:   "DID cannot be empty",
		},
		{
			name:      "invalid DID",
			regoQuery: `url_from_did("invalid-did")`,
			errText:   "invalid DID, host is not found",
		},
		{
			name:      "invalid DID Method",
			regoQuery: `url_from_did("did:sov:123456qwerty")`,
			errText:   "invalid DID, method is unknown",
		},
		{
			name:      "transformation success with DID containing domain only",
			regoQuery: `url_from_did("did:web:w3c-ccg.github.io")`,
			res:       "\"https://w3c-ccg.github.io/.well-known/did.json\"",
		},
		{
			name:      "transformation success with DID containing domain and path",
			regoQuery: `url_from_did("did:web:w3c-ccg.github.io:user:alice")`,
			res:       "\"https://w3c-ccg.github.io/user/alice/did.json\"",
		},
		{
			name:      "transformation success with DID containing network port",
			regoQuery: `url_from_did("did:web:example.com%3A3000:user:alice")`,
			res:       "\"https://example.com:3000/user/alice/did.json\"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			DIDTransformerFuncs := regofunc.NewDIDTransformerFuncs()

			r := rego.New(
				rego.Query(test.regoQuery),
				rego.Function1(DIDTransformerFuncs.ToURLFunc()),
				rego.StrictBuiltinErrors(true),
			)
			resultSet, err := r.Eval(context.Background())

			if err == nil {
				resultBytes, err := json.Marshal(resultSet[0].Expressions[0].Value)
				assert.NoError(t, err)
				assert.Equal(t, test.res, string(resultBytes))
			} else {
				assert.ErrorContains(t, err, test.errText)
			}
		})
	}
}

func TestFromURLFunc(t *testing.T) {
	tests := []struct {
		// test input
		name      string
		regoQuery string
		// expected result
		res     string
		errText string
	}{
		{
			name:      "empty URL",
			regoQuery: `did_from_url("")`,
			errText:   "URL cannot be empty",
		},
		{
			name:      "URL containing special characters",
			regoQuery: `did_from_url("example.com\nH1234")`,
			errText:   "cannot parse URL",
		},
		{
			name:      "URL does not contain secure protocol (https)",
			regoQuery: `did_from_url("example.com")`,
			errText:   "invalid URL for did:web method",
		},
		{
			name:      "URL does not contain valid domain",
			regoQuery: `did_from_url("https://")`,
			errText:   "invalid URL for did:web method",
		},
		{
			name:      "transformation success with URL containing domain only",
			regoQuery: `did_from_url("https://w3c-ccg.github.io/.well-known/did.json")`,
			res:       "\"did:web:w3c-ccg.github.io\"",
		},
		{
			name:      "transformation success with URL containing domain with path",
			regoQuery: `did_from_url("https://w3c-ccg.github.io/user/alice/did.json")`,
			res:       "\"did:web:w3c-ccg.github.io:user:alice\"",
		},
		{
			name:      "transformation success with URL containing network port",
			regoQuery: `did_from_url("https://example.com:3000/user/alice/did.json")`,
			res:       "\"did:web:example.com%3A3000:user:alice\"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			DIDTransformerFuncs := regofunc.NewDIDTransformerFuncs()

			r := rego.New(
				rego.Query(test.regoQuery),
				rego.Function1(DIDTransformerFuncs.FromURLFunc()),
				rego.StrictBuiltinErrors(true),
			)
			resultSet, err := r.Eval(context.Background())

			if err == nil {
				resultBytes, err := json.Marshal(resultSet[0].Expressions[0].Value)
				assert.NoError(t, err)
				assert.Equal(t, test.res, string(resultBytes))
			} else {
				assert.ErrorContains(t, err, test.errText)
			}
		})
	}
}
