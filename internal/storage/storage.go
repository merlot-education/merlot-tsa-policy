package storage

import (
	"context"
	"fmt"
	"time"

	"code.vereign.com/gaiax/tsa/golib/errors"
)

type Policy struct {
	Filename    string
	Name        string
	Group       string
	Version     string
	Rego        string
	Locked      bool
	LastUpdated time.Time
}

type Storage struct{}

func New() *Storage {
	return &Storage{}
}

func (s *Storage) Policy(ctx context.Context, name, group, version string) (*Policy, error) {
	key := fmt.Sprintf("%s:%s:%s", name, group, version)

	policy, ok := policies[key]
	if !ok {
		return nil, errors.New(errors.NotFound, "policy not found in storage")
	}

	return policy, nil
}
