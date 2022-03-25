package health

import "context"

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) Liveness(ctx context.Context) error {
	return nil
}

func (s *Service) Readiness(ctx context.Context) error {
	return nil
}
