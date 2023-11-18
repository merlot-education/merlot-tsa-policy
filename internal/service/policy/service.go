package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"go.uber.org/zap"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/ptr"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/gen/policy"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/header"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/regofunc"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/storage"
)

//go:generate counterfeiter . Cache
//go:generate counterfeiter . Storage
//go:generate counterfeiter . RegoCache
//go:generate counterfeiter . Signer

type Cache interface {
	Set(ctx context.Context, key, namespace, scope string, value []byte, ttl int) error
}

type RegoCache interface {
	Set(key string, policy *storage.Policy)
	Get(key string) (policy *storage.Policy, found bool)
}

type Signer interface {
	Sign(ctx context.Context, namespace string, key string, data []byte) ([]byte, error)
}

type Service struct {
	storage     Storage
	policyCache RegoCache
	cache       Cache
	signer      Signer
	logger      *zap.Logger
}

func New(storage Storage, policyCache RegoCache, cache Cache, signer Signer, logger *zap.Logger) *Service {
	signerFactory := func(signer Signer) func() (jws.Signer, error) {
		return func() (jws.Signer, error) {
			return &signAdapter{signer: signer}, nil
		}
	}

	// This unregister/register sequence is done mainly for the unit tests
	// because each tests creates a new service instance, but the jws.Signer
	// implementations are kept in a global variable map, which is the same
	// for all test cases. In order for tests to work and to be able to register
	// different signer implementations, the previous signer must be explicitly
	// unregistered.
	jws.UnregisterSigner(JwaVaultSignature)
	jwa.UnregisterSignatureAlgorithm(JwaVaultSignature)
	jwa.RegisterSignatureAlgorithm(JwaVaultSignature)
	jws.RegisterSigner(JwaVaultSignature, jws.SignerFactoryFn(signerFactory(signer)))

	return &Service{
		storage:     storage,
		policyCache: policyCache,
		cache:       cache,
		signer:      signer,
		logger:      logger,
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
		zap.String("operation", "evaluate"),
		zap.String("repository", req.Repository),
		zap.String("group", req.Group),
		zap.String("name", req.PolicyName),
		zap.String("version", req.Version),
		zap.String("evaluationID", evaluationID),
	)

	headers, _ := header.FromContext(ctx)
	query, err := s.prepareQuery(ctx, req.Repository, req.Group, req.PolicyName, req.Version, headers)
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

	err = s.cache.Set(ctx, evaluationID, "", "", jsonValue, ttl)
	if err != nil {
		// if the cache service is not available, don't stop but continue with returning the result
		if !errors.Is(errors.ServiceUnavailable, err) {
			logger.Error("error storing policy result in cache", zap.Error(err))
			return nil, errors.New("error storing policy result in cache")
		}
	}

	return &policy.EvaluateResult{
		Result: result,
		ETag:   evaluationID,
	}, nil
}

// Lock a policy so that it cannot be evaluated.
func (s *Service) Lock(ctx context.Context, req *policy.LockRequest) error {
	logger := s.logger.With(
		zap.String("operation", "lock"),
		zap.String("repository", req.Repository),
		zap.String("group", req.Group),
		zap.String("name", req.PolicyName),
		zap.String("version", req.Version),
	)

	pol, err := s.storage.Policy(ctx, req.Repository, req.Group, req.PolicyName, req.Version)
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

	if err := s.storage.SetPolicyLock(ctx, req.Repository, req.Group, req.PolicyName, req.Version, true); err != nil {
		logger.Error("error locking policy", zap.Error(err))
		return errors.New("error locking policy", err)
	}

	logger.Debug("policy is locked")

	return nil
}

// Unlock a policy so it can be evaluated again.
func (s *Service) Unlock(ctx context.Context, req *policy.UnlockRequest) error {
	logger := s.logger.With(
		zap.String("operation", "unlock"),
		zap.String("repository", req.Repository),
		zap.String("group", req.Group),
		zap.String("name", req.PolicyName),
		zap.String("version", req.Version),
	)

	pol, err := s.storage.Policy(ctx, req.Repository, req.Group, req.PolicyName, req.Version)
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

	if err := s.storage.SetPolicyLock(ctx, req.Repository, req.Group, req.PolicyName, req.Version, false); err != nil {
		logger.Error("error unlocking policy", zap.Error(err))
		return errors.New("error unlocking policy", err)
	}

	logger.Debug("policy is unlocked")

	return nil
}

func (s *Service) ExportBundle(ctx context.Context, req *policy.ExportBundleRequest) (*policy.ExportBundleResult, io.ReadCloser, error) {
	logger := s.logger.With(
		zap.String("operation", "exportBundle"),
		zap.String("repository", req.Repository),
		zap.String("group", req.Group),
		zap.String("name", req.PolicyName),
		zap.String("version", req.Version),
	)

	pol, err := s.storage.Policy(ctx, req.Repository, req.Group, req.PolicyName, req.Version)
	if err != nil {
		logger.Error("error getting policy from storage", zap.Error(err))
		return nil, nil, err
	}

	// bundle is the complete policy bundle zip file
	bundle, err := s.createPolicyBundle(pol)
	if err != nil {
		logger.Error("error creating policy bundle", zap.Error(err))
		return nil, nil, err
	}

	// only the sha256 file digest will be signed, not the file itself
	bundleDigest := sha256.Sum256(bundle)

	// TODO(penkovski): namespace and key must be taken from policy export configuration
	// This will be implemented with issue #41, for now some test values are hardcoded
	// https://gitlab.eclipse.org/eclipse/xfsc/tsa/policy/-/issues/41
	signature, err := s.sign("transit", "key1", bundleDigest[:])
	if err != nil {
		logger.Error("error signing policy bundle", zap.Error(err))
		return nil, nil, err
	}

	// the final ZIP file that will be exported to the client wraps the policy bundle
	// zip file and the jws detached payload signature file
	var files = []ZipFile{
		{
			Name:    "policy_bundle.zip",
			Content: bundle,
		},
		{
			Name:    "policy_bundle.jws",
			Content: signature,
		},
	}

	signedBundle, err := s.createZipArchive(files)
	if err != nil {
		logger.Error("error making final zip with signature", zap.Error(err))
		return nil, nil, err
	}

	filename := fmt.Sprintf("%s_%s_%s_%s.zip", pol.Repository, pol.Group, pol.Name, pol.Version)
	filename = strings.TrimSpace(filename)

	return &policy.ExportBundleResult{
		ContentType:        "application/zip",
		ContentLength:      len(signedBundle),
		ContentDisposition: fmt.Sprintf(`attachment; filename="%s"`, filename),
	}, io.NopCloser(bytes.NewReader(signedBundle)), nil
}

func (s *Service) ListPolicies(ctx context.Context, req *policy.PoliciesRequest) (*policy.PoliciesResult, error) {
	logger := s.logger.With(zap.String("operation", "listPolicies"))

	policies, err := s.storage.GetPolicies(ctx, req.Locked)
	if err != nil {
		logger.Error("error retrieving policies", zap.Error(err))
		return nil, errors.New("error retrieving policies", err)
	}

	policiesResult := make([]*policy.Policy, 0, len(policies))

	for _, p := range policies {
		policy := &policy.Policy{
			Repository: p.Repository,
			PolicyName: p.Name,
			Group:      p.Group,
			Version:    p.Version,
			Locked:     p.Locked,
			LastUpdate: p.LastUpdate.Unix(),
		}

		if req.Rego != nil && *req.Rego {
			policy.Rego = ptr.String(p.Rego)
		}

		if req.Data != nil && *req.Data {
			policy.Data = ptr.String(p.Data)
		}

		if req.DataConfig != nil && *req.DataConfig {
			policy.DataConfig = ptr.String(p.DataConfig)
		}

		policiesResult = append(policiesResult, policy)
	}

	return &policy.PoliciesResult{Policies: policiesResult}, nil
}

func (s *Service) SubscribeForPolicyChange(ctx context.Context, req *policy.SubscribeRequest) (any, error) {
	logger := s.logger.With(zap.String("operation", "subscribeForPolicyChange"))

	subscriber, err := s.storage.CreateSubscriber(ctx, &storage.Subscriber{
		Name:             req.Subscriber,
		WebhookURL:       req.WebhookURL,
		PolicyRepository: req.Repository,
		PolicyName:       req.PolicyName,
		PolicyGroup:      req.Group,
		PolicyVersion:    req.Version,
	})
	if err != nil {
		logger.Error("error storing policy change subscription", zap.Error(err))
		return nil, err
	}

	return subscriber, nil
}

// prepareQuery tries to get a prepared query from the regocache.
// If the policyCache entry is not found, it will try to prepare a new
// query and will set it into the policyCache for future use.
func (s *Service) prepareQuery(ctx context.Context, repository, group, policyName, version string, headers map[string]string) (*rego.PreparedEvalQuery, error) {
	// retrieve policy from cache
	key := s.queryCacheKey(repository, group, policyName, version)
	pol, ok := s.policyCache.Get(key)
	if !ok {
		// retrieve policy from database storage
		var err error
		pol, err = s.storage.Policy(ctx, repository, group, policyName, version)
		if err != nil {
			if errors.Is(errors.NotFound, err) {
				return nil, err
			}
			return nil, errors.New("error getting policy from storage", err)
		}
		s.policyCache.Set(key, pol)
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

	// Append dynamically the external.http.header function on every request,
	// because it is populated with different headers each time.
	regoArgs = append(regoArgs, rego.Function1(regofunc.GetHeaderFunc(headers)))

	newQuery, err := rego.New(
		regoArgs...,
	).PrepareForEval(ctx)
	if err != nil {
		return nil, errors.New("error preparing rego query", err)
	}

	return &newQuery, nil
}

func (s *Service) buildRegoArgs(filename, regoPolicy, regoQuery, regoData string) (availableFuncs []func(*rego.Rego), err error) {
	availableFuncs = make([]func(*rego.Rego), 3)
	availableFuncs[0] = rego.Module(filename, regoPolicy)
	availableFuncs[1] = rego.Query(regoQuery)
	availableFuncs[2] = rego.StrictBuiltinErrors(true)
	extensionFuncs := regofunc.List()
	for i := range extensionFuncs {
		availableFuncs = append(availableFuncs, extensionFuncs[i])
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

func (s *Service) queryCacheKey(repository, group, policyName, version string) string {
	return fmt.Sprintf("%s,%s,%s,%s", repository, group, policyName, version)
}
