package health

import "context"

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) Liveness(_ context.Context) error {
	return nil
}

func (s *Service) Readiness(_ context.Context) error {
	return nil
}
