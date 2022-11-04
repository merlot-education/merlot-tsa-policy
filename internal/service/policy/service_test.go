package policy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/golib/errors"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/golib/ptr"
	goapolicy "gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/gen/policy"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/header"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/service/policy"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/service/policy/policyfakes"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/storage"
)

func TestNew(t *testing.T) {
	svc := policy.New(nil, nil, nil, zap.NewNop())
	assert.Implements(t, (*goapolicy.Service)(nil), svc)
}

func TestService_Evaluate(t *testing.T) {
	testPolicy := &storage.Policy{
		Filename:   "policy.rego",
		Name:       "example",
		Group:      "testgroup",
		Version:    "1.0",
		Rego:       `package testgroup.example default allow = false allow { input.msg == "yes" }`,
		Locked:     false,
		LastUpdate: time.Now(),
	}

	// prepare test policy source code for the case when policy result must contain only the
	// value of a blank variable assignment
	testPolicyBlankAssignment := `package testgroup.example _ = {"hello":"world"}`

	// prepare test policy using static json data during evaluation
	testPolicyWithStaticData := `package testgroup.example default allow = false allow { data.msg == "hello world" }`

	// prepare test policy accessing headers during evaluation
	testPolicyAccessingHeaders := `package testgroup.example token := get_header("Authorization")`

	// prepare test request to be used in tests
	testReq := func() *goapolicy.EvaluateRequest {
		input := map[string]interface{}{"msg": "yes"}
		var body interface{} = input

		return &goapolicy.EvaluateRequest{
			Group:      "testgroup",
			PolicyName: "example",
			Version:    "1.0",
			Input:      &body,
			TTL:        ptr.Int(30),
		}
	}

	// prepare test request with empty body
	testEmptyReq := func() *goapolicy.EvaluateRequest {
		var body interface{}

		return &goapolicy.EvaluateRequest{
			Group:      "testgroup",
			PolicyName: "example",
			Version:    "1.0",
			Input:      &body,
			TTL:        ptr.Int(30),
		}
	}

	// prepare http.Request for tests
	httpReq := func() *http.Request {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "my-token")
		return req
	}

	// prepare context containing headers
	ctxWithHeaders := func() context.Context {
		ctx := header.ToContext(context.Background(), httpReq())
		return ctx
	}

	tests := []struct {
		// test input
		name      string
		ctx       context.Context
		req       *goapolicy.EvaluateRequest
		storage   policy.Storage
		regocache policy.RegoCache
		cache     policy.Cache
		// expected result
		res     *goapolicy.EvaluateResult
		errkind errors.Kind
		errtext string
	}{
		{
			name: "policy is found in policyCache",
			ctx:  ctxWithHeaders(),
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
					return testPolicy, true
				},
			},
			cache: &policyfakes.FakeCache{
				SetStub: func(ctx context.Context, s string, s2 string, s3 string, bytes []byte, i int) error {
					return nil
				},
			},
			res: &goapolicy.EvaluateResult{
				Result: map[string]interface{}{"allow": true},
			},
		},
		{
			name: "policy is not found",
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
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
				GetStub: func(key string) (*storage.Policy, bool) {
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
				GetStub: func(key string) (*storage.Policy, bool) {
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
			ctx:  ctxWithHeaders(),
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return testPolicy, nil
				},
			},
			cache: &policyfakes.FakeCache{
				SetStub: func(ctx context.Context, s string, s2 string, s3 string, bytes []byte, i int) error {
					return nil
				},
			},
			res: &goapolicy.EvaluateResult{
				Result: map[string]interface{}{"allow": true},
			},
		},
		{
			name: "policy is executed successfully, but storing the result in cache fails",
			ctx:  ctxWithHeaders(),
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return testPolicy, nil
				},
			},
			cache: &policyfakes.FakeCache{
				SetStub: func(ctx context.Context, s string, s2 string, s3 string, bytes []byte, i int) error {
					return errors.New("some error")
				},
			},
			errkind: errors.Unknown,
			errtext: "error storing policy result in cache",
		},
		{
			name: "policy with blank variable assignment is evaluated successfully",
			ctx:  ctxWithHeaders(),
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{
						Name:       "example",
						Group:      "testgroup",
						Version:    "1.0",
						Rego:       testPolicyBlankAssignment,
						Locked:     false,
						LastUpdate: time.Now(),
					}, nil
				},
			},
			cache: &policyfakes.FakeCache{
				SetStub: func(ctx context.Context, s string, s2 string, s3 string, bytes []byte, i int) error {
					return nil
				},
			},
			res: &goapolicy.EvaluateResult{
				Result: map[string]interface{}{"hello": "world"},
			},
		},
		{
			name: "policy is evaluated successfully with TTL sent in the request headers",
			ctx:  ctxWithHeaders(),
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{
						Name:       "example",
						Group:      "testgroup",
						Version:    "1.0",
						Rego:       testPolicyBlankAssignment,
						Locked:     false,
						LastUpdate: time.Now(),
					}, nil
				},
			},
			cache: &policyfakes.FakeCache{
				SetStub: func(ctx context.Context, s string, s2 string, s3 string, bytes []byte, i int) error {
					return nil
				},
			},
			res: &goapolicy.EvaluateResult{
				Result: map[string]interface{}{"hello": "world"},
			},
		},
		{
			name: "policy using static json data is evaluated successfully",
			ctx:  ctxWithHeaders(),
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{
						Name:       "example",
						Group:      "testgroup",
						Version:    "1.0",
						Rego:       testPolicyWithStaticData,
						Data:       `{"msg": "hello world"}`,
						Locked:     false,
						LastUpdate: time.Now(),
					}, nil
				},
			},
			cache: &policyfakes.FakeCache{
				SetStub: func(ctx context.Context, s string, s2 string, s3 string, bytes []byte, i int) error {
					return nil
				},
			},
			res: &goapolicy.EvaluateResult{
				Result: map[string]interface{}{"allow": true},
			},
		},
		{
			name: "policy accessing headers is evaluated successfully",
			ctx:  ctxWithHeaders(),
			req:  testReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return &storage.Policy{
						Name:       "example",
						Group:      "testgroup",
						Version:    "1.0",
						Rego:       testPolicyAccessingHeaders,
						Locked:     false,
						LastUpdate: time.Now(),
					}, nil
				},
			},
			cache: &policyfakes.FakeCache{
				SetStub: func(ctx context.Context, s string, s2 string, s3 string, bytes []byte, i int) error {
					return nil
				},
			},
			res: &goapolicy.EvaluateResult{
				Result: map[string]interface{}{"token": "my-token"},
			},
		},
		{
			name: "policy with empty input is evaluated successfully",
			ctx:  ctxWithHeaders(),
			req:  testEmptyReq(),
			regocache: &policyfakes.FakeRegoCache{
				GetStub: func(key string) (*storage.Policy, bool) {
					return nil, false
				},
			},
			storage: &policyfakes.FakeStorage{
				PolicyStub: func(ctx context.Context, s string, s2 string, s3 string) (*storage.Policy, error) {
					return testPolicy, nil
				},
			},
			cache: &policyfakes.FakeCache{
				SetStub: func(ctx context.Context, s string, s2 string, s3 string, bytes []byte, i int) error {
					return nil
				},
			},
			res: &goapolicy.EvaluateResult{
				Result: map[string]interface{}{"allow": false},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc := policy.New(test.storage, test.regocache, test.cache, zap.NewNop())
			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx
			}
			res, err := svc.Evaluate(ctx, test.req)
			if err == nil {
				assert.Empty(t, test.errtext)
				assert.NotNil(t, res)

				assert.Equal(t, test.res.Result, res.Result)
				assert.NotEmpty(t, res.ETag)
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
			svc := policy.New(test.storage, nil, nil, zap.NewNop())
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
			svc := policy.New(test.storage, nil, nil, zap.NewNop())
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
