// Code generated by goa v3.14.0, DO NOT EDIT.
//
// policy client HTTP transport
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package client

import (
	"context"
	"net/http"

	policy "gitlab.eclipse.org/eclipse/xfsc/tsa/policy/gen/policy"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// Client lists the policy service endpoint HTTP clients.
type Client struct {
	// Evaluate Doer is the HTTP client used to make requests to the Evaluate
	// endpoint.
	EvaluateDoer goahttp.Doer

	// Validate Doer is the HTTP client used to make requests to the Validate
	// endpoint.
	ValidateDoer goahttp.Doer

	// Lock Doer is the HTTP client used to make requests to the Lock endpoint.
	LockDoer goahttp.Doer

	// Unlock Doer is the HTTP client used to make requests to the Unlock endpoint.
	UnlockDoer goahttp.Doer

	// ExportBundle Doer is the HTTP client used to make requests to the
	// ExportBundle endpoint.
	ExportBundleDoer goahttp.Doer

	// ListPolicies Doer is the HTTP client used to make requests to the
	// ListPolicies endpoint.
	ListPoliciesDoer goahttp.Doer

	// SubscribeForPolicyChange Doer is the HTTP client used to make requests to
	// the SubscribeForPolicyChange endpoint.
	SubscribeForPolicyChangeDoer goahttp.Doer

	// RestoreResponseBody controls whether the response bodies are reset after
	// decoding so they can be read again.
	RestoreResponseBody bool

	scheme  string
	host    string
	encoder func(*http.Request) goahttp.Encoder
	decoder func(*http.Response) goahttp.Decoder
}

// NewClient instantiates HTTP clients for all the policy service servers.
func NewClient(
	scheme string,
	host string,
	doer goahttp.Doer,
	enc func(*http.Request) goahttp.Encoder,
	dec func(*http.Response) goahttp.Decoder,
	restoreBody bool,
) *Client {
	return &Client{
		EvaluateDoer:                 doer,
		ValidateDoer:                 doer,
		LockDoer:                     doer,
		UnlockDoer:                   doer,
		ExportBundleDoer:             doer,
		ListPoliciesDoer:             doer,
		SubscribeForPolicyChangeDoer: doer,
		RestoreResponseBody:          restoreBody,
		scheme:                       scheme,
		host:                         host,
		decoder:                      dec,
		encoder:                      enc,
	}
}

// Evaluate returns an endpoint that makes HTTP requests to the policy service
// Evaluate server.
func (c *Client) Evaluate() goa.Endpoint {
	var (
		encodeRequest  = EncodeEvaluateRequest(c.encoder)
		decodeResponse = DecodeEvaluateResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildEvaluateRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.EvaluateDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("policy", "Evaluate", err)
		}
		return decodeResponse(resp)
	}
}

// Validate returns an endpoint that makes HTTP requests to the policy service
// Validate server.
func (c *Client) Validate() goa.Endpoint {
	var (
		encodeRequest  = EncodeValidateRequest(c.encoder)
		decodeResponse = DecodeValidateResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildValidateRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.ValidateDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("policy", "Validate", err)
		}
		return decodeResponse(resp)
	}
}

// Lock returns an endpoint that makes HTTP requests to the policy service Lock
// server.
func (c *Client) Lock() goa.Endpoint {
	var (
		decodeResponse = DecodeLockResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildLockRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.LockDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("policy", "Lock", err)
		}
		return decodeResponse(resp)
	}
}

// Unlock returns an endpoint that makes HTTP requests to the policy service
// Unlock server.
func (c *Client) Unlock() goa.Endpoint {
	var (
		decodeResponse = DecodeUnlockResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildUnlockRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.UnlockDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("policy", "Unlock", err)
		}
		return decodeResponse(resp)
	}
}

// ExportBundle returns an endpoint that makes HTTP requests to the policy
// service ExportBundle server.
func (c *Client) ExportBundle() goa.Endpoint {
	var (
		decodeResponse = DecodeExportBundleResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildExportBundleRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.ExportBundleDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("policy", "ExportBundle", err)
		}
		res, err := decodeResponse(resp)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		return &policy.ExportBundleResponseData{Result: res.(*policy.ExportBundleResult), Body: resp.Body}, nil
	}
}

// ListPolicies returns an endpoint that makes HTTP requests to the policy
// service ListPolicies server.
func (c *Client) ListPolicies() goa.Endpoint {
	var (
		encodeRequest  = EncodeListPoliciesRequest(c.encoder)
		decodeResponse = DecodeListPoliciesResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildListPoliciesRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.ListPoliciesDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("policy", "ListPolicies", err)
		}
		return decodeResponse(resp)
	}
}

// SubscribeForPolicyChange returns an endpoint that makes HTTP requests to the
// policy service SubscribeForPolicyChange server.
func (c *Client) SubscribeForPolicyChange() goa.Endpoint {
	var (
		encodeRequest  = EncodeSubscribeForPolicyChangeRequest(c.encoder)
		decodeResponse = DecodeSubscribeForPolicyChangeResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildSubscribeForPolicyChangeRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.SubscribeForPolicyChangeDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("policy", "SubscribeForPolicyChange", err)
		}
		return decodeResponse(resp)
	}
}
