package policy

import (
	"context"

	"code.vereign.com/gaiax/tsa/golib/errors"
	"code.vereign.com/gaiax/tsa/policy/gen/policy"
)

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) Evaluate(context.Context, *policy.EvaluateRequest) (*policy.EvaluateResult, error) {
	return nil, errors.New("not implemented")
}
