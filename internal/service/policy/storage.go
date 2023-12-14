package policy

import (
	"context"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/storage"
)

type Storage interface {
	Policy(ctx context.Context, repository, group, name, version string) (*storage.Policy, error)
	SavePolicy(ctx context.Context, policy *storage.Policy) error
	SetPolicyLock(ctx context.Context, repository, group, name, version string, lock bool) error
	GetPolicies(ctx context.Context, locked *bool) ([]*storage.Policy, error)
	AddPolicyChangeSubscribers(subscribers ...storage.PolicyChangeSubscriber)
	ListenPolicyDataChanges(ctx context.Context) error
	CreateSubscriber(ctx context.Context, subscriber *storage.Subscriber) (*storage.Subscriber, error)
	Close(ctx context.Context)
	GetData(ctx context.Context, key string) (any, error)
	SetData(ctx context.Context, key string, data map[string]interface{}) error
	DeleteData(ctx context.Context, key string) error
	// SaveAutoImportConfig stores a new autoimport configuration for a given policy bundle.
	SaveAutoImportConfig(ctx context.Context, importConfig *storage.PolicyAutoImport) error
	// AutoImportConfig returns config for single policy import.
	AutoImportConfig(ctx context.Context, policyURL string) (*storage.PolicyAutoImport, error)
	// AutoImportConfigs returns all autoimport configurations.
	AutoImportConfigs(ctx context.Context) ([]*storage.PolicyAutoImport, error)
	// DeleteAutoImportConfig removes a single automatic import configuration.
	DeleteAutoImportConfig(ctx context.Context, policyURL string) error
	// ActiveImportConfigs returns all import configurations which specify
	// that the time to automatically import a policy bundle has been reached.
	ActiveImportConfigs(ctx context.Context) ([]*storage.PolicyAutoImport, error)
}
