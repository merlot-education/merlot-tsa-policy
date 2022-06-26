// Code generated by goa v3.7.0, DO NOT EDIT.
//
// policy service
//
// Command:
// $ goa gen code.vereign.com/gaiax/tsa/policy/design

package policy

import (
	"context"
)

// Policy Service provides evaluation of policies through Open Policy Agent.
type Service interface {
	// Evaluate executes a policy with the given 'data' as input.
	Evaluate(context.Context, *EvaluateRequest) (res *EvaluateResult, err error)
	// Lock a policy so that it cannot be evaluated.
	Lock(context.Context, *LockRequest) (err error)
	// Unlock a policy so it can be evaluated again.
	Unlock(context.Context, *UnlockRequest) (err error)
}

// ServiceName is the name of the service as defined in the design. This is the
// same value that is set in the endpoint request contexts under the ServiceKey
// key.
const ServiceName = "policy"

// MethodNames lists the service method names as defined in the design. These
// are the same values that are set in the endpoint request contexts under the
// MethodKey key.
var MethodNames = [3]string{"Evaluate", "Lock", "Unlock"}

// EvaluateRequest is the payload type of the policy service Evaluate method.
type EvaluateRequest struct {
	// Policy group.
	Group string
	// Policy name.
	PolicyName string
	// Policy version.
	Version string
	// Input data passed to the policy execution runtime.
	Input interface{}
	// Identifier created by external system and passed as parameter to overwrite
	// the randomly generated evaluationID.
	EvaluationID *string
}

// EvaluateResult is the result type of the policy service Evaluate method.
type EvaluateResult struct {
	// Arbitrary JSON response.
	Result interface{}
	// ETag contains unique identifier of the policy evaluation and can be used to
	// later retrieve the results from Cache.
	ETag string
}

// LockRequest is the payload type of the policy service Lock method.
type LockRequest struct {
	// Policy group.
	Group string
	// Policy name.
	PolicyName string
	// Policy version.
	Version string
}

// UnlockRequest is the payload type of the policy service Unlock method.
type UnlockRequest struct {
	// Policy group.
	Group string
	// Policy name.
	PolicyName string
	// Policy version.
	Version string
}
