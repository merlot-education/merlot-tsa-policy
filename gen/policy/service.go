// Code generated by goa v3.12.3, DO NOT EDIT.
//
// policy service
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

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
	// List policies from storage with optional filters.
	ListPolicies(context.Context, *PoliciesRequest) (res *PoliciesResult, err error)
	// Subscribe for policy change notifications by registering webhook callbacks
	// which the policy service will call.
	SubscribeForPolicyChange(context.Context, *SubscribeRequest) (res any, err error)
}

// ServiceName is the name of the service as defined in the design. This is the
// same value that is set in the endpoint request contexts under the ServiceKey
// key.
const ServiceName = "policy"

// MethodNames lists the service method names as defined in the design. These
// are the same values that are set in the endpoint request contexts under the
// MethodKey key.
var MethodNames = [5]string{"Evaluate", "Lock", "Unlock", "ListPolicies", "SubscribeForPolicyChange"}

// EvaluateRequest is the payload type of the policy service Evaluate method.
type EvaluateRequest struct {
	// Policy repository.
	Repository string
	// Policy group.
	Group string
	// Policy name.
	PolicyName string
	// Policy version.
	Version string
	// Input data passed to the policy execution runtime.
	Input any
	// Identifier created by external system and passed as parameter to overwrite
	// the randomly generated evaluationID.
	EvaluationID *string
	// TTL for storing policy result in cache
	TTL *int
}

// EvaluateResult is the result type of the policy service Evaluate method.
type EvaluateResult struct {
	// Arbitrary JSON response.
	Result any
	// ETag contains unique identifier of the policy evaluation and can be used to
	// later retrieve the results from Cache.
	ETag string
}

// LockRequest is the payload type of the policy service Lock method.
type LockRequest struct {
	// Policy repository.
	Repository string
	// Policy group.
	Group string
	// Policy name.
	PolicyName string
	// Policy version.
	Version string
}

// PoliciesRequest is the payload type of the policy service ListPolicies
// method.
type PoliciesRequest struct {
	Locked     *bool
	Rego       *bool
	Data       *bool
	DataConfig *bool
}

// PoliciesResult is the result type of the policy service ListPolicies method.
type PoliciesResult struct {
	// JSON array of policies.
	Policies []*Policy
}

type Policy struct {
	// Policy repository.
	Repository string
	// Policy name.
	PolicyName string
	// Policy group.
	Group string
	// Policy version.
	Version string
	// Policy rego source code.
	Rego *string
	// Policy static data.
	Data *string
	// Policy static data optional configuration.
	DataConfig *string
	// Locked specifies if the policy is locked or allowed to execute.
	Locked bool
	// Last update (Unix timestamp).
	LastUpdate int64
}

// SubscribeRequest is the payload type of the policy service
// SubscribeForPolicyChange method.
type SubscribeRequest struct {
	// Subscriber webhook url.
	WebhookURL string
	// Name of the subscriber for policy.
	Subscriber string
	// Policy repository.
	Repository string
	// Policy name.
	PolicyName string
	// Policy group.
	Group string
	// Policy version.
	Version string
}

// UnlockRequest is the payload type of the policy service Unlock method.
type UnlockRequest struct {
	// Policy repository.
	Repository string
	// Policy group.
	Group string
	// Policy name.
	PolicyName string
	// Policy version.
	Version string
}
