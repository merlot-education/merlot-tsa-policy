package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/zap"

	"code.vereign.com/gaiax/tsa/golib/errors"
	"code.vereign.com/gaiax/tsa/policy/gen/policy"
	"code.vereign.com/gaiax/tsa/policy/internal/regofunc"
	"code.vereign.com/gaiax/tsa/policy/internal/storage"
)

//go:generate counterfeiter . Storage
//go:generate counterfeiter . RegoCache

type Storage interface {
	Policy(ctx context.Context, name, group, version string) (*storage.Policy, error)
	SetPolicyLock(ctx context.Context, name, group, version string, lock bool) error
}

type RegoCache interface {
	Set(key string, query *rego.PreparedEvalQuery)
	Get(key string) (query *rego.PreparedEvalQuery, found bool)
}

type Service struct {
	storage  Storage
	cache    RegoCache
	regoFunc *regofunc.RegoFunc
	logger   *zap.Logger
}

func New(storage Storage, cache RegoCache, regoFunc *regofunc.RegoFunc, logger *zap.Logger) *Service {
	return &Service{
		storage:  storage,
		cache:    cache,
		regoFunc: regoFunc,
		logger:   logger,
	}
}

// Evaluate executes a policy with the given input.
//
// Note: The policy must follow strict conventions so that such generic
// evaluation function could work: package declaration inside the policy must
// be exactly the same as 'group.policy'. For example:
// Evaluating the URL: `.../policies/mygroup/example/1.0/evaluation` will
// return results correctly, only if the package declaration inside the policy is:
// `package mygroup.example`
func (s *Service) Evaluate(ctx context.Context, req *policy.EvaluateRequest) (interface{}, error) {
	logger := s.logger.With(
		zap.String("name", req.PolicyName),
		zap.String("group", req.Group),
		zap.String("version", req.Version),
	)

	query, err := s.prepareQuery(ctx, req.PolicyName, req.Group, req.Version)
	if err != nil {
		logger.Error("error getting prepared query", zap.Error(err))
		return nil, errors.New("error evaluating policy", err)
	}

	resultSet, err := query.Eval(ctx, rego.EvalInput(req.Input))
	if err != nil {
		logger.Error("error evaluating rego query", zap.Error(err))
		return nil, errors.New("error evaluating rego query", err)
	}

	if len(resultSet) == 0 {
		logger.Error("policy evaluation results are empty")
		return nil, errors.New("policy evaluation results are empty")
	}

	if len(resultSet[0].Expressions) == 0 {
		logger.Error("policy evaluation result expressions are empty")
		return nil, errors.New("policy evaluation result expressions are empty")
	}

	return resultSet[0].Expressions[0].Value, nil
}

// Lock a policy so that it cannot be evaluated.
func (s *Service) Lock(ctx context.Context, req *policy.LockRequest) error {
	logger := s.logger.With(
		zap.String("name", req.PolicyName),
		zap.String("group", req.Group),
		zap.String("version", req.Version),
	)

	pol, err := s.storage.Policy(ctx, req.PolicyName, req.Group, req.Version)
	if err != nil {
		logger.Error("error getting policy from storage", zap.Error(err))
		if errors.Is(errors.NotFound, err) {
			return err
		}
		return errors.New("error locking policy", err)
	}

	if pol.Locked {
		return errors.New(errors.Forbidden, "policy is already locked")
	}

	if err := s.storage.SetPolicyLock(ctx, req.PolicyName, req.Group, req.Version, true); err != nil {
		logger.Error("error locking policy", zap.Error(err))
		return errors.New("error locking policy", err)
	}

	logger.Debug("policy is locked")

	return nil
}

// Unlock a policy so it can be evaluated again.
func (s *Service) Unlock(ctx context.Context, req *policy.UnlockRequest) error {
	logger := s.logger.With(
		zap.String("name", req.PolicyName),
		zap.String("group", req.Group),
		zap.String("version", req.Version),
	)

	pol, err := s.storage.Policy(ctx, req.PolicyName, req.Group, req.Version)
	if err != nil {
		logger.Error("error getting policy from storage", zap.Error(err))
		if errors.Is(errors.NotFound, err) {
			return err
		}
		return errors.New("error unlocking policy", err)
	}

	if !pol.Locked {
		return errors.New(errors.Forbidden, "policy is unlocked")
	}

	if err := s.storage.SetPolicyLock(ctx, req.PolicyName, req.Group, req.Version, false); err != nil {
		logger.Error("error unlocking policy", zap.Error(err))
		return errors.New("error unlocking policy", err)
	}

	logger.Debug("policy is unlocked")

	return nil
}

// prepareQuery tries to get a prepared query from the regocache.
// If the cache entry is not found, it will try to prepare a new
// query and will set it into the cache for future use.
func (s *Service) prepareQuery(ctx context.Context, policyName, group, version string) (*rego.PreparedEvalQuery, error) {
	key := s.queryCacheKey(policyName, group, version)
	query, ok := s.cache.Get(key)
	if ok {
		return query, nil
	}

	// retrieve policy from database storage
	pol, err := s.storage.Policy(ctx, policyName, group, version)
	if err != nil {
		if errors.Is(errors.NotFound, err) {
			return nil, err
		}
		return nil, errors.New("error getting policy from storage", err)
	}

	// if policy is locked, return an error
	if pol.Locked {
		return nil, errors.New(errors.Forbidden, "policy is locked")
	}

	// regoQuery must match both the package declaration inside the policy
	// and the group and policy name.
	regoQuery := fmt.Sprintf("data.%s.%s", group, policyName)

	newQuery, err := rego.New(
		rego.Module(pol.Filename, pol.Rego),
		rego.Query(regoQuery),
		rego.Function3(s.regoFunc.CacheGetFunc()),
		rego.Function4(s.regoFunc.CacheSetFunc()),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, errors.New("error preparing rego query", err)
	}

	s.cache.Set(key, &newQuery)

	return &newQuery, nil
}

func (s *Service) queryCacheKey(policyName, group, version string) string {
	return fmt.Sprintf("%s,%s,%s", policyName, group, version)
}
