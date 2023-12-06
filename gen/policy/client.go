// Code generated by goa v3.14.0, DO NOT EDIT.
//
// policy client
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package policy

import (
	"context"
	"io"

	goa "goa.design/goa/v3/pkg"
)

// Client is the "policy" service client.
type Client struct {
	EvaluateEndpoint                 goa.Endpoint
	ValidateEndpoint                 goa.Endpoint
	LockEndpoint                     goa.Endpoint
	UnlockEndpoint                   goa.Endpoint
	ExportBundleEndpoint             goa.Endpoint
	ImportBundleEndpoint             goa.Endpoint
	PolicyPublicKeyEndpoint          goa.Endpoint
	ListPoliciesEndpoint             goa.Endpoint
	SubscribeForPolicyChangeEndpoint goa.Endpoint
}

// NewClient initializes a "policy" service client given the endpoints.
func NewClient(evaluate, validate, lock, unlock, exportBundle, importBundle, policyPublicKey, listPolicies, subscribeForPolicyChange goa.Endpoint) *Client {
	return &Client{
		EvaluateEndpoint:                 evaluate,
		ValidateEndpoint:                 validate,
		LockEndpoint:                     lock,
		UnlockEndpoint:                   unlock,
		ExportBundleEndpoint:             exportBundle,
		ImportBundleEndpoint:             importBundle,
		PolicyPublicKeyEndpoint:          policyPublicKey,
		ListPoliciesEndpoint:             listPolicies,
		SubscribeForPolicyChangeEndpoint: subscribeForPolicyChange,
	}
}

// Evaluate calls the "Evaluate" endpoint of the "policy" service.
func (c *Client) Evaluate(ctx context.Context, p *EvaluateRequest) (res *EvaluateResult, err error) {
	var ires any
	ires, err = c.EvaluateEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(*EvaluateResult), nil
}

// Validate calls the "Validate" endpoint of the "policy" service.
func (c *Client) Validate(ctx context.Context, p *EvaluateRequest) (res *EvaluateResult, err error) {
	var ires any
	ires, err = c.ValidateEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(*EvaluateResult), nil
}

// Lock calls the "Lock" endpoint of the "policy" service.
func (c *Client) Lock(ctx context.Context, p *LockRequest) (err error) {
	_, err = c.LockEndpoint(ctx, p)
	return
}

// Unlock calls the "Unlock" endpoint of the "policy" service.
func (c *Client) Unlock(ctx context.Context, p *UnlockRequest) (err error) {
	_, err = c.UnlockEndpoint(ctx, p)
	return
}

// ExportBundle calls the "ExportBundle" endpoint of the "policy" service.
func (c *Client) ExportBundle(ctx context.Context, p *ExportBundleRequest) (res *ExportBundleResult, resp io.ReadCloser, err error) {
	var ires any
	ires, err = c.ExportBundleEndpoint(ctx, p)
	if err != nil {
		return
	}
	o := ires.(*ExportBundleResponseData)
	return o.Result, o.Body, nil
}

// ImportBundle calls the "ImportBundle" endpoint of the "policy" service.
func (c *Client) ImportBundle(ctx context.Context, p *ImportBundlePayload, req io.ReadCloser) (res any, err error) {
	var ires any
	ires, err = c.ImportBundleEndpoint(ctx, &ImportBundleRequestData{Payload: p, Body: req})
	if err != nil {
		return
	}
	return ires.(any), nil
}

// PolicyPublicKey calls the "PolicyPublicKey" endpoint of the "policy" service.
func (c *Client) PolicyPublicKey(ctx context.Context, p *PolicyPublicKeyRequest) (res any, err error) {
	var ires any
	ires, err = c.PolicyPublicKeyEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(any), nil
}

// ListPolicies calls the "ListPolicies" endpoint of the "policy" service.
func (c *Client) ListPolicies(ctx context.Context, p *PoliciesRequest) (res *PoliciesResult, err error) {
	var ires any
	ires, err = c.ListPoliciesEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(*PoliciesResult), nil
}

// SubscribeForPolicyChange calls the "SubscribeForPolicyChange" endpoint of
// the "policy" service.
func (c *Client) SubscribeForPolicyChange(ctx context.Context, p *SubscribeRequest) (res any, err error) {
	var ires any
	ires, err = c.SubscribeForPolicyChangeEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(any), nil
}
