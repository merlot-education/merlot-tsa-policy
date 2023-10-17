// Code generated by goa v3.12.3, DO NOT EDIT.
//
// health client HTTP transport
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package client

import (
	"context"
	"net/http"

	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// Client lists the health service endpoint HTTP clients.
type Client struct {
	// Liveness Doer is the HTTP client used to make requests to the Liveness
	// endpoint.
	LivenessDoer goahttp.Doer

	// Readiness Doer is the HTTP client used to make requests to the Readiness
	// endpoint.
	ReadinessDoer goahttp.Doer

	// RestoreResponseBody controls whether the response bodies are reset after
	// decoding so they can be read again.
	RestoreResponseBody bool

	scheme  string
	host    string
	encoder func(*http.Request) goahttp.Encoder
	decoder func(*http.Response) goahttp.Decoder
}

// NewClient instantiates HTTP clients for all the health service servers.
func NewClient(
	scheme string,
	host string,
	doer goahttp.Doer,
	enc func(*http.Request) goahttp.Encoder,
	dec func(*http.Response) goahttp.Decoder,
	restoreBody bool,
) *Client {
	return &Client{
		LivenessDoer:        doer,
		ReadinessDoer:       doer,
		RestoreResponseBody: restoreBody,
		scheme:              scheme,
		host:                host,
		decoder:             dec,
		encoder:             enc,
	}
}

// Liveness returns an endpoint that makes HTTP requests to the health service
// Liveness server.
func (c *Client) Liveness() goa.Endpoint {
	var (
		decodeResponse = DecodeLivenessResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildLivenessRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.LivenessDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("health", "Liveness", err)
		}
		return decodeResponse(resp)
	}
}

// Readiness returns an endpoint that makes HTTP requests to the health service
// Readiness server.
func (c *Client) Readiness() goa.Endpoint {
	var (
		decodeResponse = DecodeReadinessResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v any) (any, error) {
		req, err := c.BuildReadinessRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.ReadinessDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("health", "Readiness", err)
		}
		return decodeResponse(resp)
	}
}
