// Code generated by goa v3.12.3, DO NOT EDIT.
//
// policy HTTP server types
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package server

import (
	"unicode/utf8"

	policy "gitlab.eclipse.org/eclipse/xfsc/tsa/policy/gen/policy"
	goa "goa.design/goa/v3/pkg"
)

// SubscribeForPolicyChangeRequestBody is the type of the "policy" service
// "SubscribeForPolicyChange" endpoint HTTP request body.
type SubscribeForPolicyChangeRequestBody struct {
	// Subscriber webhook url.
	WebhookURL *string `form:"webhook_url,omitempty" json:"webhook_url,omitempty" xml:"webhook_url,omitempty"`
	// Name of the subscriber for policy.
	Subscriber *string `form:"subscriber,omitempty" json:"subscriber,omitempty" xml:"subscriber,omitempty"`
}

// ListPoliciesResponseBody is the type of the "policy" service "ListPolicies"
// endpoint HTTP response body.
type ListPoliciesResponseBody struct {
	// JSON array of policies.
	Policies []*PolicyResponseBody `form:"policies" json:"policies" xml:"policies"`
}

// PolicyResponseBody is used to define fields on response body types.
type PolicyResponseBody struct {
	// Policy repository.
	Repository string `form:"repository" json:"repository" xml:"repository"`
	// Policy name.
	PolicyName string `form:"policyName" json:"policyName" xml:"policyName"`
	// Policy group.
	Group string `form:"group" json:"group" xml:"group"`
	// Policy version.
	Version string `form:"version" json:"version" xml:"version"`
	// Policy rego source code.
	Rego *string `form:"rego,omitempty" json:"rego,omitempty" xml:"rego,omitempty"`
	// Policy static data.
	Data *string `form:"data,omitempty" json:"data,omitempty" xml:"data,omitempty"`
	// Policy static data optional configuration.
	DataConfig *string `form:"dataConfig,omitempty" json:"dataConfig,omitempty" xml:"dataConfig,omitempty"`
	// Locked specifies if the policy is locked or allowed to execute.
	Locked bool `form:"locked" json:"locked" xml:"locked"`
	// Last update (Unix timestamp).
	LastUpdate int64 `form:"lastUpdate" json:"lastUpdate" xml:"lastUpdate"`
}

// NewListPoliciesResponseBody builds the HTTP response body from the result of
// the "ListPolicies" endpoint of the "policy" service.
func NewListPoliciesResponseBody(res *policy.PoliciesResult) *ListPoliciesResponseBody {
	body := &ListPoliciesResponseBody{}
	if res.Policies != nil {
		body.Policies = make([]*PolicyResponseBody, len(res.Policies))
		for i, val := range res.Policies {
			body.Policies[i] = marshalPolicyPolicyToPolicyResponseBody(val)
		}
	} else {
		body.Policies = []*PolicyResponseBody{}
	}
	return body
}

// NewEvaluateRequest builds a policy service Evaluate endpoint payload.
func NewEvaluateRequest(body any, repository string, group string, policyName string, version string, evaluationID *string, ttl *int) *policy.EvaluateRequest {
	v := body
	res := &policy.EvaluateRequest{
		Input: &v,
	}
	res.Repository = repository
	res.Group = group
	res.PolicyName = policyName
	res.Version = version
	res.EvaluationID = evaluationID
	res.TTL = ttl

	return res
}

// NewLockRequest builds a policy service Lock endpoint payload.
func NewLockRequest(repository string, group string, policyName string, version string) *policy.LockRequest {
	v := &policy.LockRequest{}
	v.Repository = repository
	v.Group = group
	v.PolicyName = policyName
	v.Version = version

	return v
}

// NewUnlockRequest builds a policy service Unlock endpoint payload.
func NewUnlockRequest(repository string, group string, policyName string, version string) *policy.UnlockRequest {
	v := &policy.UnlockRequest{}
	v.Repository = repository
	v.Group = group
	v.PolicyName = policyName
	v.Version = version

	return v
}

// NewExportBundleRequest builds a policy service ExportBundle endpoint payload.
func NewExportBundleRequest(repository string, group string, policyName string, version string) *policy.ExportBundleRequest {
	v := &policy.ExportBundleRequest{}
	v.Repository = repository
	v.Group = group
	v.PolicyName = policyName
	v.Version = version

	return v
}

// NewListPoliciesPoliciesRequest builds a policy service ListPolicies endpoint
// payload.
func NewListPoliciesPoliciesRequest(locked *bool, rego *bool, data *bool, dataConfig *bool) *policy.PoliciesRequest {
	v := &policy.PoliciesRequest{}
	v.Locked = locked
	v.Rego = rego
	v.Data = data
	v.DataConfig = dataConfig

	return v
}

// NewSubscribeForPolicyChangeSubscribeRequest builds a policy service
// SubscribeForPolicyChange endpoint payload.
func NewSubscribeForPolicyChangeSubscribeRequest(body *SubscribeForPolicyChangeRequestBody, repository string, group string, policyName string, version string) *policy.SubscribeRequest {
	v := &policy.SubscribeRequest{
		WebhookURL: *body.WebhookURL,
		Subscriber: *body.Subscriber,
	}
	v.Repository = repository
	v.Group = group
	v.PolicyName = policyName
	v.Version = version

	return v
}

// ValidateSubscribeForPolicyChangeRequestBody runs the validations defined on
// SubscribeForPolicyChangeRequestBody
func ValidateSubscribeForPolicyChangeRequestBody(body *SubscribeForPolicyChangeRequestBody) (err error) {
	if body.WebhookURL == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("webhook_url", "body"))
	}
	if body.Subscriber == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("subscriber", "body"))
	}
	if body.WebhookURL != nil {
		err = goa.MergeErrors(err, goa.ValidateFormat("body.webhook_url", *body.WebhookURL, goa.FormatURI))
	}
	if body.Subscriber != nil {
		if utf8.RuneCountInString(*body.Subscriber) < 3 {
			err = goa.MergeErrors(err, goa.InvalidLengthError("body.subscriber", *body.Subscriber, utf8.RuneCountInString(*body.Subscriber), 3, true))
		}
	}
	if body.Subscriber != nil {
		if utf8.RuneCountInString(*body.Subscriber) > 100 {
			err = goa.MergeErrors(err, goa.InvalidLengthError("body.subscriber", *body.Subscriber, utf8.RuneCountInString(*body.Subscriber), 100, false))
		}
	}
	return
}
