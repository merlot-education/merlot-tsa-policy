// Code generated by goa v3.7.0, DO NOT EDIT.
//
// HTTP request path constructors for the policy service.
//
// Command:
// $ goa gen code.vereign.com/gaiax/tsa/policy/design

package client

import (
	"fmt"
)

// EvaluatePolicyPath returns the URL path to the policy service Evaluate HTTP endpoint.
func EvaluatePolicyPath(group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/evaluation", group, policyName, version)
}

// EvaluatePolicyPath2 returns the URL path to the policy service Evaluate HTTP endpoint.
func EvaluatePolicyPath2(group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/evaluation", group, policyName, version)
}

// LockPolicyPath returns the URL path to the policy service Lock HTTP endpoint.
func LockPolicyPath(group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/lock", group, policyName, version)
}

// UnlockPolicyPath returns the URL path to the policy service Unlock HTTP endpoint.
func UnlockPolicyPath(group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/lock", group, policyName, version)
}
