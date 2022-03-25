// Code generated by goa v3.7.0, DO NOT EDIT.
//
// health client
//
// Command:
// $ goa gen code.vereign.com/gaiax/tsa/policy/design

package health

import (
	"context"

	goa "goa.design/goa/v3/pkg"
)

// Client is the "health" service client.
type Client struct {
	LivenessEndpoint  goa.Endpoint
	ReadinessEndpoint goa.Endpoint
}

// NewClient initializes a "health" service client given the endpoints.
func NewClient(liveness, readiness goa.Endpoint) *Client {
	return &Client{
		LivenessEndpoint:  liveness,
		ReadinessEndpoint: readiness,
	}
}

// Liveness calls the "Liveness" endpoint of the "health" service.
func (c *Client) Liveness(ctx context.Context) (err error) {
	_, err = c.LivenessEndpoint(ctx, nil)
	return
}

// Readiness calls the "Readiness" endpoint of the "health" service.
func (c *Client) Readiness(ctx context.Context) (err error) {
	_, err = c.ReadinessEndpoint(ctx, nil)
	return
}
