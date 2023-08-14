// Code generated by goa v3.12.1, DO NOT EDIT.
//
// policy endpoints
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package policy

import (
	"context"

	goa "goa.design/goa/v3/pkg"
)

// Endpoints wraps the "policy" service endpoints.
type Endpoints struct {
	Evaluate goa.Endpoint
	Lock     goa.Endpoint
	Unlock   goa.Endpoint
}

// NewEndpoints wraps the methods of the "policy" service with endpoints.
func NewEndpoints(s Service) *Endpoints {
	return &Endpoints{
		Evaluate: NewEvaluateEndpoint(s),
		Lock:     NewLockEndpoint(s),
		Unlock:   NewUnlockEndpoint(s),
	}
}

// Use applies the given middleware to all the "policy" service endpoints.
func (e *Endpoints) Use(m func(goa.Endpoint) goa.Endpoint) {
	e.Evaluate = m(e.Evaluate)
	e.Lock = m(e.Lock)
	e.Unlock = m(e.Unlock)
}

// NewEvaluateEndpoint returns an endpoint function that calls the method
// "Evaluate" of service "policy".
func NewEvaluateEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		p := req.(*EvaluateRequest)
		return s.Evaluate(ctx, p)
	}
}

// NewLockEndpoint returns an endpoint function that calls the method "Lock" of
// service "policy".
func NewLockEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		p := req.(*LockRequest)
		return nil, s.Lock(ctx, p)
	}
}

// NewUnlockEndpoint returns an endpoint function that calls the method
// "Unlock" of service "policy".
func NewUnlockEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		p := req.(*UnlockRequest)
		return nil, s.Unlock(ctx, p)
	}
}
