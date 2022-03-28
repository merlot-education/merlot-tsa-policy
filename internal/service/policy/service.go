package policy

import (
	"context"

	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/zap"

	"code.vereign.com/gaiax/tsa/golib/errors"
	"code.vereign.com/gaiax/tsa/policy/gen/policy"
	"code.vereign.com/gaiax/tsa/policy/internal/storage"
)

type Storage interface {
	Policy(ctx context.Context, name, group, version string) (*storage.Policy, error)
}

type Service struct {
	storage Storage
	logger  *zap.Logger
}

func New(storage Storage, logger *zap.Logger) *Service {
	return &Service{
		storage: storage,
		logger:  logger,
	}
}

func (s *Service) Evaluate(ctx context.Context, req *policy.EvaluateRequest) (*policy.EvaluateResult, error) {
	pol, err := s.storage.Policy(ctx, req.PolicyName, req.Group, req.Version)
	if err != nil {
		s.logger.Error("error getting policy from storage", zap.Error(err))
		if errors.Is(errors.NotFound, err) {
			return nil, err
		}
		return nil, errors.New("error evaluating policy", err)
	}

	if pol.Locked {
		return nil, errors.New(errors.Forbidden, "policy is locked")
	}

	query, err := rego.New(
		rego.Module(pol.Filename, pol.Rego),
		rego.Query("result = data.gaiax.result"),
	).PrepareForEval(ctx)
	if err != nil {
		s.logger.Error("error preparing rego query", zap.Error(err))
		return nil, errors.New("error preparing rego query", err)
	}

	resultSet, err := query.Eval(ctx, rego.EvalInput(req.Data))
	if err != nil {
		s.logger.Error("error evaluating rego query", zap.Error(err))
		return nil, errors.New("error evaluating rego query", err)
	}

	if len(resultSet) == 0 {
		s.logger.Error("policy evaluation result set is empty")
		return nil, errors.New("policy evaluation result set is empty")
	}

	result, ok := resultSet[0].Bindings["result"]
	if !ok {
		s.logger.Error("policy result bindings not found")
		return nil, errors.New("policy result bindings not found")
	}

	return &policy.EvaluateResult{Result: result}, nil
}
