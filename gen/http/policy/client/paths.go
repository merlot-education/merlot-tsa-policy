// Code generated by goa v3.14.0, DO NOT EDIT.
//
// HTTP request path constructors for the policy service.
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package client

import (
	"fmt"
)

// EvaluatePolicyPath returns the URL path to the policy service Evaluate HTTP endpoint.
func EvaluatePolicyPath(repository string, group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/%v/evaluation/did.json", repository, group, policyName, version)
}

// EvaluatePolicyPath2 returns the URL path to the policy service Evaluate HTTP endpoint.
func EvaluatePolicyPath2(repository string, group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/%v/evaluation", repository, group, policyName, version)
}

// EvaluatePolicyPath3 returns the URL path to the policy service Evaluate HTTP endpoint.
func EvaluatePolicyPath3(repository string, group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/%v/evaluation", repository, group, policyName, version)
}

// LockPolicyPath returns the URL path to the policy service Lock HTTP endpoint.
func LockPolicyPath(repository string, group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/%v/lock", repository, group, policyName, version)
}

// UnlockPolicyPath returns the URL path to the policy service Unlock HTTP endpoint.
func UnlockPolicyPath(repository string, group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/%v/lock", repository, group, policyName, version)
}

// ExportBundlePolicyPath returns the URL path to the policy service ExportBundle HTTP endpoint.
func ExportBundlePolicyPath(repository string, group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/%v/export", repository, group, policyName, version)
}

// ImportBundlePolicyPath returns the URL path to the policy service ImportBundle HTTP endpoint.
func ImportBundlePolicyPath() string {
	return "/policy/import"
}

// PolicyPublicKeyPolicyPath returns the URL path to the policy service PolicyPublicKey HTTP endpoint.
func PolicyPublicKeyPolicyPath(repository string, group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/%v/key", repository, group, policyName, version)
}

// ListPoliciesPolicyPath returns the URL path to the policy service ListPolicies HTTP endpoint.
func ListPoliciesPolicyPath() string {
	return "/v1/policies"
}

// SubscribeForPolicyChangePolicyPath returns the URL path to the policy service SubscribeForPolicyChange HTTP endpoint.
func SubscribeForPolicyChangePolicyPath(repository string, group string, policyName string, version string) string {
	return fmt.Sprintf("/policy/%v/%v/%v/%v/notifychange", repository, group, policyName, version)
}
