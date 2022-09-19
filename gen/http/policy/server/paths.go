// Code generated by goa v3.8.5, DO NOT EDIT.
//
// HTTP request path constructors for the policy service.
//
// Command:
// $ goa gen
// gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/design

package server

import (
	"fmt"
)

// EvaluatePolicyPath returns the URL path to the policy service Evaluate HTTP endpoint.
func EvaluatePolicyPath(group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/evaluation/did.json", group, policyName, version)
}

// EvaluatePolicyPath2 returns the URL path to the policy service Evaluate HTTP endpoint.
func EvaluatePolicyPath2(group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/evaluation", group, policyName, version)
}

// EvaluatePolicyPath3 returns the URL path to the policy service Evaluate HTTP endpoint.
func EvaluatePolicyPath3(group string, policyName string, version string) string {
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
