package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"code.vereign.com/gaiax/tsa/golib/errors"
	goapolicy "code.vereign.com/gaiax/tsa/policy/gen/policy"
	"code.vereign.com/gaiax/tsa/policy/internal/service/policy"
	"code.vereign.com/gaiax/tsa/policy/internal/service/policy/policyfakes"
	"code.vereign.com/gaiax/tsa/policy/internal/storage"
)

func TestNew(t *testing.T) {
	storage := &policyfakes.FakeStorage{}
	regocache := &policyfakes.FakeRegoCache{}
	svc := policy.New(storage, regocache, zap.NewNop())
	assert.Implements(t, (*goapolicy.Service)(nil), svc)
}

func TestService_Evaluate(t *testing.T) {
	// prepare test policy source code that will be evaluated
	testPolicy := `package testgroup.example allow { input.msg == "yes" }`

	// prepare test query that can be retrieved from rego cache
	testQuery, err := rego.New(
		rego.Module("example.rego", testPolicy),
		rego.Query("data.testgroup.example"),
	).PrepareForEval(context.Background())
	assert.NoError(t, err)

	// prepare test request to be used in tests
	testReq := func() *goapolicy.EvaluateRequest {
		return &goapolicy.EvaluateRequest{
			Group:      "testgroup",
			PolicyName: "example",
			Version:    "1.0",
			Input:      map[string]interface{}{"msg": "yes"},
		}
	}

	tests := []struct {
		// test input
		name      string
		req       *goapolicy.EvaluateRequest
		storage   policy.Storage
		regocache policy.RegoCache

		// expected result
		res     *goapolicy.EvaluateResult
		errkind errors.Kind
		errtext string
	}{
		{
			name: "prepared query is found in cache",
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*rego.PreparedEvalQuery, bool) {
					q := testQuery
					return &q, true
				},
			},
			res: &goapolicy.EvaluateResult{Result: map[string]interface{}{"allow": true}},
		},
		{
			name: "policy is not found",
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*rego.PreparedEvalQuery, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return nil, errors.New(errors.NotFound)
				},
			},
			res:     nil,
			errkind: errors.NotFound,
			errtext: "not found",
		},
		{
			name: "error getting policy from storage",
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*rego.PreparedEvalQuery, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return nil, errors.New("some error")
				},
			},
			res:     nil,
			errkind: errors.Unknown,
			errtext: "some error",
		},
		{
			name: "policy is locked",
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*rego.PreparedEvalQuery, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{Locked: true}, nil
				},
			},
			res:     nil,
			errkind: errors.Forbidden,
			errtext: "policy is locked",
		},
		{
			name: "policy is found in storage and isn't locked",
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*rego.PreparedEvalQuery, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{
						Name:       "example",
						Group:      "testgroup",
						Version:    "1.0",
						Rego:       testPolicy,
						Locked:     false,
						LastUpdate: time.Now(),
					}, nil
				},
			},
			res: &goapolicy.EvaluateResult{Result: map[string]interface{}{"allow": true}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc := policy.New(test.storage, test.regocache, zap.NewNop())
			res, err := svc.Evaluate(context.Background(), test.req)
			if err == nil {
				assert.Empty(t, test.errtext)
				assert.Equal(t, test.res, res)
			} else {
				e, ok := err.(*errors.Error)
				assert.True(t, ok)

				assert.Contains(t, e.Error(), test.errtext)
				assert.Equal(t, test.errkind, e.Kind)
				assert.Equal(t, test.res, res)
			}
		})
	}
}
