// Code generated by goa v3.12.3, DO NOT EDIT.
//
// health service
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package health

import (
	"context"
)

// Health service provides health check endpoints.
type Service interface {
	// Liveness implements Liveness.
	Liveness(context.Context) (res *HealthResponse, err error)
	// Readiness implements Readiness.
	Readiness(context.Context) (res *HealthResponse, err error)
}

// ServiceName is the name of the service as defined in the design. This is the
// same value that is set in the endpoint request contexts under the ServiceKey
// key.
const ServiceName = "health"

// MethodNames lists the service method names as defined in the design. These
// are the same values that are set in the endpoint request contexts under the
// MethodKey key.
var MethodNames = [2]string{"Liveness", "Readiness"}

// HealthResponse is the result type of the health service Liveness method.
type HealthResponse struct {
	// Service name.
	Service string
	// Status message.
	Status string
	// Service runtime version.
	Version string
}
