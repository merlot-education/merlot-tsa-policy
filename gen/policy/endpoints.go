// Code generated by goa v3.12.3, DO NOT EDIT.
//
// policy endpoints
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package policy

import (
	"context"
	"io"

	goa "goa.design/goa/v3/pkg"
)

// Endpoints wraps the "policy" service endpoints.
type Endpoints struct {
	Evaluate                 goa.Endpoint
	Lock                     goa.Endpoint
	Unlock                   goa.Endpoint
	ExportBundle             goa.Endpoint
	ListPolicies             goa.Endpoint
	SubscribeForPolicyChange goa.Endpoint
}

// ExportBundleResponseData holds both the result and the HTTP response body
// reader of the "ExportBundle" method.
type ExportBundleResponseData struct {
	// Result is the method result.
	Result *ExportBundleResult
	// Body streams the HTTP response body.
	Body io.ReadCloser
}

// NewEndpoints wraps the methods of the "policy" service with endpoints.
func NewEndpoints(s Service) *Endpoints {
	return &Endpoints{
		Evaluate:                 NewEvaluateEndpoint(s),
		Lock:                     NewLockEndpoint(s),
		Unlock:                   NewUnlockEndpoint(s),
		ExportBundle:             NewExportBundleEndpoint(s),
		ListPolicies:             NewListPoliciesEndpoint(s),
		SubscribeForPolicyChange: NewSubscribeForPolicyChangeEndpoint(s),
	}
}

// Use applies the given middleware to all the "policy" service endpoints.
func (e *Endpoints) Use(m func(goa.Endpoint) goa.Endpoint) {
	e.Evaluate = m(e.Evaluate)
	e.Lock = m(e.Lock)
	e.Unlock = m(e.Unlock)
	e.ExportBundle = m(e.ExportBundle)
	e.ListPolicies = m(e.ListPolicies)
	e.SubscribeForPolicyChange = m(e.SubscribeForPolicyChange)
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

// NewExportBundleEndpoint returns an endpoint function that calls the method
// "ExportBundle" of service "policy".
func NewExportBundleEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		p := req.(*ExportBundleRequest)
		res, body, err := s.ExportBundle(ctx, p)
		if err != nil {
			return nil, err
		}
		return &ExportBundleResponseData{Result: res, Body: body}, nil
	}
}

// NewListPoliciesEndpoint returns an endpoint function that calls the method
// "ListPolicies" of service "policy".
func NewListPoliciesEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		p := req.(*PoliciesRequest)
		return s.ListPolicies(ctx, p)
	}
}

// NewSubscribeForPolicyChangeEndpoint returns an endpoint function that calls
// the method "SubscribeForPolicyChange" of service "policy".
func NewSubscribeForPolicyChangeEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		p := req.(*SubscribeRequest)
		return s.SubscribeForPolicyChange(ctx, p)
	}
}
