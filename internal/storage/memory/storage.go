package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/storage"
)

//go:generate counterfeiter . KeyConstructor

type KeyConstructor interface {
	ConstructKey(repo, group, name, version string) string
}

type Storage struct {
	keyConstructor KeyConstructor
	subscribers    []storage.PolicyChangeSubscriber
	changes        chan storage.Policy

	mu       sync.RWMutex
	policies map[string]*storage.Policy

	muCommonStorage sync.RWMutex
	commonStorage   map[string]interface{}

	logger *zap.Logger
}

func New(c KeyConstructor, p map[string]*storage.Policy, l *zap.Logger) *Storage {
	ch := make(chan storage.Policy)

	return &Storage{
		keyConstructor: c,
		changes:        ch,
		policies:       p,
		commonStorage:  map[string]interface{}{},
		logger:         l,
	}
}

func (s *Storage) Policy(_ context.Context, repository, group, name, version string) (*storage.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[s.keyConstructor.ConstructKey(repository, group, name, version)]
	if !ok {
		return nil, errors.New(errors.NotFound, "policy not found in memory storage")
	}

	res := *p // don't return the Policy by reference
	return &res, nil
}

func (s *Storage) SetPolicyLock(_ context.Context, repository, group, name, version string, lock bool) error {
	key := s.keyConstructor.ConstructKey(repository, group, name, version)

	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[key]
	if !ok {
		return errors.New(errors.NotFound, "policy not found in memory storage")
	}

	p.Locked = lock

	// send the changed policy to subscribers
	go func(policy *storage.Policy) {
		s.changes <- *policy
	}(p)

	return nil
}

func (s *Storage) GetPolicies(_ context.Context, locked *bool) ([]*storage.Policy, error) {
	var res []*storage.Policy

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.policies {
		if locked == nil || *locked == p.Locked {
			cpy := *p
			res = append(res, &cpy)
		}
	}

	return res, nil
}

func (s *Storage) GetRefreshPolicies(_ context.Context) ([]*storage.Policy, error) {
	var res []*storage.Policy

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.policies {
		if p.NextDataRefreshTime.Before(time.Now()) && p.NextDataRefreshTime.After(time.Time{}) {
			cpy := *p
			res = append(res, &cpy)

			// postpone next refresh time for this policy
			s.policies[i].NextDataRefreshTime = time.Now().Add(storage.RefreshPostponePeriod)
		}
	}

	return res, nil
}

func (s *Storage) UpdateNextRefreshTime(_ context.Context, p *storage.Policy, nextDataRefreshTime time.Time) error {
	key := s.keyConstructor.ConstructKey(p.Repository, p.Group, p.Name, p.Version)

	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.policies[key]
	if !ok {
		return errors.New(errors.NotFound, "policy not found in memory storage")
	}

	s.policies[key].NextDataRefreshTime = nextDataRefreshTime

	return nil
}

func (s *Storage) AddPolicyChangeSubscribers(subscribers ...storage.PolicyChangeSubscriber) {
	s.subscribers = subscribers
}

func (s *Storage) ListenPolicyDataChanges(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p := <-s.changes:
			for _, subscriber := range s.subscribers {
				err := subscriber.PolicyDataChange(
					ctx,
					p.Repository,
					p.Name,
					p.Version,
					p.Group,
				)
				if err != nil {
					return err
				}
			}

			s.logger.Info("memory policy data changed")
		}
	}
}

func (s *Storage) GetData(_ context.Context, key string) (any, error) {
	s.muCommonStorage.Lock()
	defer s.muCommonStorage.Unlock()

	data, ok := s.commonStorage[key]
	if !ok {
		return nil, fmt.Errorf("key: %s doesn't exist", key)
	}

	return data, nil
}
func (s *Storage) SetData(_ context.Context, key string, data map[string]interface{}) error {
	s.muCommonStorage.Lock()
	defer s.muCommonStorage.Unlock()

	s.commonStorage[key] = data

	return nil
}
func (s *Storage) DeleteData(_ context.Context, key string) error {
	s.muCommonStorage.Lock()
	defer s.muCommonStorage.Unlock()

	if _, ok := s.commonStorage[key]; !ok {
		return fmt.Errorf("key: %s doesn't exist", key)
	}

	delete(s.commonStorage, key)

	return nil
}

func (s *Storage) Close(_ context.Context) {}

func (s *Storage) CreateSubscriber(_ context.Context, _ *storage.Subscriber) (*storage.Subscriber, error) {
	return nil, errors.New(errors.Internal, "function CreateSubscriber is not implemented for memory storage")
}
