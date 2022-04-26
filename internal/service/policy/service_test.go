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
	"code.vereign.com/gaiax/tsa/policy/internal/regofunc"
	"code.vereign.com/gaiax/tsa/policy/internal/service/policy"
	"code.vereign.com/gaiax/tsa/policy/internal/service/policy/policyfakes"
	"code.vereign.com/gaiax/tsa/policy/internal/storage"
)

func TestNew(t *testing.T) {
	storage := &policyfakes.FakeStorage{}
	regocache := &policyfakes.FakeRegoCache{}
	regofuncs := regofunc.New("https://example.com")
	svc := policy.New(storage, regocache, regofuncs, zap.NewNop())
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
		res     interface{}
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
			res: map[string]interface{}{"allow": true},
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
			res: map[string]interface{}{"allow": true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regofuncs := regofunc.New("https://example.com")
			svc := policy.New(test.storage, test.regocache, regofuncs, zap.NewNop())
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

func TestService_Lock(t *testing.T) {
	// prepare test request to be used in tests
	testReq := func() *goapolicy.LockRequest {
		return &goapolicy.LockRequest{
			Group:      "testgroup",
			PolicyName: "example",
			Version:    "1.0",
		}
	}

	tests := []struct {
		name    string
		req     *goapolicy.LockRequest
		storage policy.Storage

		errkind errors.Kind
		errtext string
	}{
		{
			name: "policy is not found",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return nil, errors.New(errors.NotFound)
				},
			},
			errkind: errors.NotFound,
			errtext: "not found",
		},
		{
			name: "error getting policy from storage",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return nil, errors.New("some error")
				},
			},
			errkind: errors.Unknown,
			errtext: "some error",
		},
		{
			name: "policy is already locked",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{Locked: true}, nil
				},
			},
			errkind: errors.Forbidden,
			errtext: "policy is already locked",
		},
		{
			name: "fail to lock policy",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{Locked: false}, nil
				},
				SetPolicyLockStub: func(ctx context.Context, name, group, version string, lock bool) error {
					return errors.New(errors.Internal, "error locking policy")
				},
			},
			errkind: errors.Internal,
			errtext: "error locking policy",
		},
		{
			name: "policy is locked successfully",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{Locked: false}, nil
				},
				SetPolicyLockStub: func(ctx context.Context, name, group, version string, lock bool) error {
					return nil
				},
			},
			errtext: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regofuncs := regofunc.New("https://example.com")
			svc := policy.New(test.storage, nil, regofuncs, zap.NewNop())
			err := svc.Lock(context.Background(), test.req)
			if err == nil {
				assert.Empty(t, test.errtext)
			} else {
				e, ok := err.(*errors.Error)
				assert.True(t, ok)

				assert.Contains(t, e.Error(), test.errtext)
				assert.Equal(t, test.errkind, e.Kind)
			}
		})
	}
}

func TestService_Unlock(t *testing.T) {
	// prepare test request to be used in tests
	testReq := func() *goapolicy.UnlockRequest {
		return &goapolicy.UnlockRequest{
			Group:      "testgroup",
			PolicyName: "example",
			Version:    "1.0",
		}
	}

	tests := []struct {
		name    string
		req     *goapolicy.UnlockRequest
		storage policy.Storage

		errkind errors.Kind
		errtext string
	}{
		{
			name: "policy is not found",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return nil, errors.New(errors.NotFound)
				},
			},
			errkind: errors.NotFound,
			errtext: "not found",
		},
		{
			name: "error getting policy from storage",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return nil, errors.New("some error")
				},
			},
			errkind: errors.Unknown,
			errtext: "some error",
		},
		{
			name: "policy is unlocked",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{Locked: false}, nil
				},
			},
			errkind: errors.Forbidden,
			errtext: "policy is unlocked",
		},
		{
			name: "fail to unlock policy",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{Locked: true}, nil
				},
				SetPolicyLockStub: func(ctx context.Context, name, group, version string, lock bool) error {
					return errors.New(errors.Internal, "error unlocking policy")
				},
			},
			errkind: errors.Internal,
			errtext: "error unlocking policy",
		},
		{
			name: "policy is unlocked successfully",
			req:  testReq(),
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{Locked: true}, nil
				},
				SetPolicyLockStub: func(ctx context.Context, name, group, version string, lock bool) error {
					return nil
				},
			},
			errtext: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regofuncs := regofunc.New("https://example.com")
			svc := policy.New(test.storage, nil, regofuncs, zap.NewNop())
			err := svc.Unlock(context.Background(), test.req)
			if err == nil {
				assert.Empty(t, test.errtext)
			} else {
				e, ok := err.(*errors.Error)
				assert.True(t, ok)

				assert.Contains(t, e.Error(), test.errtext)
				assert.Equal(t, test.errkind, e.Kind)
			}
		})
	}
}
