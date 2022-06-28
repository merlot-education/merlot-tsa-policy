// Code generated by goa v3.7.0, DO NOT EDIT.
//
// policy HTTP client types
//
// Command:
// $ goa gen code.vereign.com/gaiax/tsa/policy/design

package client

import (
	policy "code.vereign.com/gaiax/tsa/policy/gen/policy"
)

// NewEvaluateResultOK builds a "policy" service "Evaluate" endpoint result
// from a HTTP "OK" response.
func NewEvaluateResultOK(body interface{}, eTag string) *policy.EvaluateResult {
	v := body
	res := &policy.EvaluateResult{
		Result: v,
	}
	res.ETag = eTag

	return res
}
