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
	// Evaluate implements Evaluate.
	Evaluate(context.Context, *EvaluateRequest) (res *EvaluateResult, err error)
}

// ServiceName is the name of the service as defined in the design. This is the
// same value that is set in the endpoint request contexts under the ServiceKey
// key.
const ServiceName = "policy"

// MethodNames lists the service method names as defined in the design. These
// are the same values that are set in the endpoint request contexts under the
// MethodKey key.
var MethodNames = [1]string{"Evaluate"}

// EvaluateRequest is the payload type of the policy service Evaluate method.
type EvaluateRequest struct {
	// Policy group
	Group string
	// Policy name
	PolicyName string
	// Policy version
	Version string
	// Data passed as input to the policy execution runtime
	Data interface{}
}

// EvaluateResult is the result type of the policy service Evaluate method.
type EvaluateResult struct {
	// Arbitrary JSON response.
	Result interface{}
}
