package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"go.uber.org/zap"

	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/golib/errors"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/gen/policy"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/header"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/regofunc"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/storage"
)

//go:generate counterfeiter . Cache
//go:generate counterfeiter . Storage
//go:generate counterfeiter . RegoCache

const HeaderKey = "header"

type Cache interface {
	Set(ctx context.Context, key, namespace, scope string, value []byte, ttl int) error
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
func (s *Service) Evaluate(ctx context.Context, req *policy.EvaluateRequest) (*policy.EvaluateResult, error) {
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

	// add headers to the request input
	input, err := s.addHeadersToEvaluateInput(ctx, req.Input)
	if err != nil {
		logger.Error("error adding headers to evaluate input", zap.Error(err))
		return nil, errors.New("error adding headers to evaluate input", err)
	}

	resultSet, err := query.Eval(ctx, rego.EvalInput(input))
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

	// If there is only a single result from the policy evaluation and it was assigned to an empty
	// variable, then we'll return a custom response containing only the value of the empty variable
	// without any mapping.
	result := resultSet[0].Expressions[0].Value
	if resultMap, ok := result.(map[string]interface{}); ok {
		if len(resultMap) == 1 {
			for k, v := range resultMap {
				if k == "$0" {
					result = v
				}
			}
		}
	}

	jsonValue, err := json.Marshal(result)
	if err != nil {
		logger.Error("error encoding result to json", zap.Error(err))
		return nil, errors.New("error encoding result to json")
	}

	var ttl int
	if req.TTL != nil {
		ttl = *req.TTL
	}
	if err := s.cache.Set(ctx, evaluationID, "", "", jsonValue, ttl); err != nil {
		logger.Error("error storing policy result in cache", zap.Error(err))
		return nil, errors.New("error storing policy result in cache")
	}

	return &policy.EvaluateResult{
		Result: result,
		ETag:   evaluationID,
	}, nil
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

	// regoArgs contains all rego functions passed to evaluation runtime
	regoArgs, err := s.buildRegoArgs(pol.Filename, pol.Rego, regoQuery, pol.Data)
	if err != nil {
		return nil, errors.New("error building rego runtime functions", err)
	}

	newQuery, err := rego.New(
		regoArgs...,
	).PrepareForEval(ctx)
	if err != nil {
		return nil, errors.New("error preparing rego query", err)
	}

	s.queryCache.Set(key, &newQuery)

	return &newQuery, nil
}

func (s *Service) buildRegoArgs(filename, regoPolicy, regoQuery, regoData string) (availableFuncs []func(*rego.Rego), err error) {
	availableFuncs = make([]func(*rego.Rego), 3)
	availableFuncs[0] = rego.Module(filename, regoPolicy)
	availableFuncs[1] = rego.Query(regoQuery)
	availableFuncs[2] = rego.StrictBuiltinErrors(true)
	extensions := regofunc.List()
	for i := range extensions {
		availableFuncs = append(availableFuncs, extensions[i])
	}

	// add static data to evaluation runtime
	if regoData != "" {
		var data map[string]interface{}
		err := json.Unmarshal([]byte(regoData), &data)
		if err != nil {
			return nil, err
		}

		store := inmem.NewFromObject(data)
		availableFuncs = append(availableFuncs, rego.Store(store))
	}

	return availableFuncs, nil
}

func (s *Service) queryCacheKey(group, policyName, version string) string {
	return fmt.Sprintf("%s,%s,%s", group, policyName, version)
}

func (s *Service) addHeadersToEvaluateInput(ctx context.Context, in interface{}) (map[string]interface{}, error) {
	// goa framework decodes the body of the request into a pointer to interface
	// for this reason we cast it first to interface pointer and then to map, which is the expected value
	i, ok := in.(*interface{})
	if !ok {
		return nil, errors.New("unexpected request body: unsuccessful casting to interface")
	}

	i2 := *i
	if i2 == nil { // no request body
		i2 = map[string]interface{}{}
	}
	input, ok := i2.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected request body: unsuccessful casting to map")
	}

	header, ok := header.FromContext(ctx)
	if !ok {
		return nil, errors.New("error getting headers from context")
	}
	input[HeaderKey] = header

	return input, nil
}
