// Code generated by goa v3.12.3, DO NOT EDIT.
//
// policy HTTP client types
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package client

import (
	policy "gitlab.eclipse.org/eclipse/xfsc/tsa/policy/gen/policy"
	goa "goa.design/goa/v3/pkg"
)

// SubscribeForPolicyChangeRequestBody is the type of the "policy" service
// "SubscribeForPolicyChange" endpoint HTTP request body.
type SubscribeForPolicyChangeRequestBody struct {
	// Subscriber webhook url.
	WebhookURL string `form:"webhook_url" json:"webhook_url" xml:"webhook_url"`
	// Name of the subscriber for policy.
	Subscriber string `form:"subscriber" json:"subscriber" xml:"subscriber"`
}

// ListPoliciesResponseBody is the type of the "policy" service "ListPolicies"
// endpoint HTTP response body.
type ListPoliciesResponseBody struct {
	// JSON array of policies.
	Policies []*PolicyResponseBody `form:"policies,omitempty" json:"policies,omitempty" xml:"policies,omitempty"`
}

// PolicyResponseBody is used to define fields on response body types.
type PolicyResponseBody struct {
	// Policy repository.
	Repository *string `form:"repository,omitempty" json:"repository,omitempty" xml:"repository,omitempty"`
	// Policy name.
	PolicyName *string `form:"policyName,omitempty" json:"policyName,omitempty" xml:"policyName,omitempty"`
	// Policy group.
	Group *string `form:"group,omitempty" json:"group,omitempty" xml:"group,omitempty"`
	// Policy version.
	Version *string `form:"version,omitempty" json:"version,omitempty" xml:"version,omitempty"`
	// Policy rego source code.
	Rego *string `form:"rego,omitempty" json:"rego,omitempty" xml:"rego,omitempty"`
	// Policy static data.
	Data *string `form:"data,omitempty" json:"data,omitempty" xml:"data,omitempty"`
	// Policy static data optional configuration.
	DataConfig *string `form:"dataConfig,omitempty" json:"dataConfig,omitempty" xml:"dataConfig,omitempty"`
	// Locked specifies if the policy is locked or allowed to execute.
	Locked *bool `form:"locked,omitempty" json:"locked,omitempty" xml:"locked,omitempty"`
	// Last update (Unix timestamp).
	LastUpdate *int64 `form:"lastUpdate,omitempty" json:"lastUpdate,omitempty" xml:"lastUpdate,omitempty"`
}

// NewSubscribeForPolicyChangeRequestBody builds the HTTP request body from the
// payload of the "SubscribeForPolicyChange" endpoint of the "policy" service.
func NewSubscribeForPolicyChangeRequestBody(p *policy.SubscribeRequest) *SubscribeForPolicyChangeRequestBody {
	body := &SubscribeForPolicyChangeRequestBody{
		WebhookURL: p.WebhookURL,
		Subscriber: p.Subscriber,
	}
	return body
}

// NewEvaluateResultOK builds a "policy" service "Evaluate" endpoint result
// from a HTTP "OK" response.
func NewEvaluateResultOK(body any, eTag string) *policy.EvaluateResult {
	v := body
	res := &policy.EvaluateResult{
		Result: v,
	}
	res.ETag = eTag

	return res
}

// NewListPoliciesPoliciesResultOK builds a "policy" service "ListPolicies"
// endpoint result from a HTTP "OK" response.
func NewListPoliciesPoliciesResultOK(body *ListPoliciesResponseBody) *policy.PoliciesResult {
	v := &policy.PoliciesResult{}
	v.Policies = make([]*policy.Policy, len(body.Policies))
	for i, val := range body.Policies {
		v.Policies[i] = unmarshalPolicyResponseBodyToPolicyPolicy(val)
	}

	return v
}

// ValidateListPoliciesResponseBody runs the validations defined on
// ListPoliciesResponseBody
func ValidateListPoliciesResponseBody(body *ListPoliciesResponseBody) (err error) {
	if body.Policies == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("policies", "body"))
	}
	for _, e := range body.Policies {
		if e != nil {
			if err2 := ValidatePolicyResponseBody(e); err2 != nil {
				err = goa.MergeErrors(err, err2)
			}
		}
	}
	return
}

// ValidatePolicyResponseBody runs the validations defined on PolicyResponseBody
func ValidatePolicyResponseBody(body *PolicyResponseBody) (err error) {
	if body.Repository == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("repository", "body"))
	}
	if body.Group == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("group", "body"))
	}
	if body.PolicyName == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("policyName", "body"))
	}
	if body.Version == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("version", "body"))
	}
	if body.Locked == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("locked", "body"))
	}
	if body.LastUpdate == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("lastUpdate", "body"))
	}
	return
}
