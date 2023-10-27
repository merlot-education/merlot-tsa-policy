package health

import (
	"context"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/gen/health"
)

type Service struct {
	ver string
}

func New(version string) *Service {
	return &Service{ver: version}
}

func (s *Service) Liveness(_ context.Context) (*health.HealthResponse, error) {
	return &health.HealthResponse{
		Service: "policy",
		Status:  "up",
		Version: s.ver,
	}, nil
}

func (s *Service) Readiness(_ context.Context) (*health.HealthResponse, error) {
	return &health.HealthResponse{
		Service: "policy",
		Status:  "up",
		Version: s.ver,
	}, nil
}
