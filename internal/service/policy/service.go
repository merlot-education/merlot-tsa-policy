package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/zap"

	"code.vereign.com/gaiax/tsa/golib/errors"
	"code.vereign.com/gaiax/tsa/policy/gen/policy"
	"code.vereign.com/gaiax/tsa/policy/internal/regofunc"
	"code.vereign.com/gaiax/tsa/policy/internal/storage"
)

//go:generate counterfeiter . Cache
//go:generate counterfeiter . Storage
//go:generate counterfeiter . RegoCache

type Cache interface {
	Set(ctx context.Context, key, namespace, scope string, value []byte) error
	Get(ctx context.Context, key, namespace, scope string) ([]byte, error)
}

type Storage interface {
	Policy(ctx context.Context, group, name, version string) (*storage.Policy, error)
	SetPolicyLock(ctx context.Context, group, name, version string, lock bool) error
}

type RegoCache interface {
	Set(key string, query *rego.PreparedEvalQuery)
	Get(key string) (query *rego.PreparedEvalQuery, found bool)
}

type Service struct {
	storage    Storage
	queryCache RegoCache
	cache      Cache
	logger     *zap.Logger
}

func New(storage Storage, queryCache RegoCache, cache Cache, logger *zap.Logger) *Service {
	return &Service{
		storage:    storage,
		queryCache: queryCache,
		cache:      cache,
		logger:     logger,
	}
}

// Evaluate executes a policy with the given input.
//
// Note: The policy must follow strict conventions so that such generic
// evaluation function could work: package declaration inside the policy must
// be exactly the same as 'group.policy'. For example:
// Evaluating the URL: `.../policies/mygroup/example/1.0/evaluation` will
// return results correctly, only if the package declaration inside the policy is:
// `package mygroup.example`.
func (s *Service) Evaluate(ctx context.Context, req *policy.EvaluateRequest) (interface{}, error) {
	var evaluationID string
	if req.EvaluationID != nil && *req.EvaluationID != "" {
		evaluationID = *req.EvaluationID
	} else {
		evaluationID = uuid.NewString()
	}

	logger := s.logger.With(
		zap.String("group", req.Group),
		zap.String("name", req.PolicyName),
		zap.String("version", req.Version),
		zap.String("evaluationID", evaluationID),
	)

	query, err := s.prepareQuery(ctx, req.Group, req.PolicyName, req.Version)
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

	jsonValue, err := json.Marshal(resultSet[0].Expressions[0].Value)
	if err != nil {
		logger.Error("error encoding result to json", zap.Error(err))
		return nil, errors.New("error encoding result to json")
	}

	if err := s.cache.Set(ctx, evaluationID, "", "", jsonValue); err != nil {
		logger.Error("error storing policy result in cache", zap.Error(err))
		return nil, errors.New("error storing policy result in cache")
	}

	result := map[string]interface{}{
		"evaluationID": evaluationID,
		"result":       resultSet[0].Expressions[0].Value,
	}

	return result, nil
}

// Lock a policy so that it cannot be evaluated.
func (s *Service) Lock(ctx context.Context, req *policy.LockRequest) error {
	logger := s.logger.With(
		zap.String("group", req.Group),
		zap.String("name", req.PolicyName),
		zap.String("version", req.Version),
	)

	pol, err := s.storage.Policy(ctx, req.Group, req.PolicyName, req.Version)
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

	if err := s.storage.SetPolicyLock(ctx, req.Group, req.PolicyName, req.Version, true); err != nil {
		logger.Error("error locking policy", zap.Error(err))
		return errors.New("error locking policy", err)
	}

	logger.Debug("policy is locked")

	return nil
}

// Unlock a policy so it can be evaluated again.
func (s *Service) Unlock(ctx context.Context, req *policy.UnlockRequest) error {
	logger := s.logger.With(
		zap.String("group", req.Group),
		zap.String("name", req.PolicyName),
		zap.String("version", req.Version),
	)

	pol, err := s.storage.Policy(ctx, req.Group, req.PolicyName, req.Version)
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

	if err := s.storage.SetPolicyLock(ctx, req.Group, req.PolicyName, req.Version, false); err != nil {
		logger.Error("error unlocking policy", zap.Error(err))
		return errors.New("error unlocking policy", err)
	}

	logger.Debug("policy is unlocked")

	return nil
}

// prepareQuery tries to get a prepared query from the regocache.
// If the queryCache entry is not found, it will try to prepare a new
// query and will set it into the queryCache for future use.
func (s *Service) prepareQuery(ctx context.Context, group, policyName, version string) (*rego.PreparedEvalQuery, error) {
	key := s.queryCacheKey(group, policyName, version)
	query, ok := s.queryCache.Get(key)
	if ok {
		return query, nil
	}

	// retrieve policy from database storage
	pol, err := s.storage.Policy(ctx, group, policyName, version)
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
		buildRegoArgs(pol.Filename, pol.Rego, regoQuery)...,
	).PrepareForEval(ctx)
	if err != nil {
		return nil, errors.New("error preparing rego query", err)
	}

	s.queryCache.Set(key, &newQuery)

	return &newQuery, nil
}

func buildRegoArgs(filename, regoPolicy, regoQuery string) (availableFuncs []func(*rego.Rego)) {
	availableFuncs = make([]func(*rego.Rego), 2)
	availableFuncs[0] = rego.Module(filename, regoPolicy)
	availableFuncs[1] = rego.Query(regoQuery)
	extensions := regofunc.List()
	for i := range extensions {
		availableFuncs = append(availableFuncs, extensions[i])
	}
	return
}

func (s *Service) queryCacheKey(group, policyName, version string) string {
	return fmt.Sprintf("%s,%s,%s", group, policyName, version)
}
