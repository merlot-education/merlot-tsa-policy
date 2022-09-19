// Code generated by goa v3.8.5, DO NOT EDIT.
//
// HTTP request path constructors for the health service.
//
// Command:
// $ goa gen
// gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/design

package server

// LivenessHealthPath returns the URL path to the health service Liveness HTTP endpoint.
func LivenessHealthPath() string {
	return "/liveness"
}

// ReadinessHealthPath returns the URL path to the health service Readiness HTTP endpoint.
func ReadinessHealthPath() string {
	return "/readiness"
}
