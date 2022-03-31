package storage

import (
	"context"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"code.vereign.com/gaiax/tsa/golib/errors"
)

type Policy struct {
	Filename   string
	Name       string
	Group      string
	Version    string
	Rego       string
	Locked     bool
	LastUpdate time.Time
}

type Storage struct {
	policy *mongo.Collection
}

func New(db *mongo.Client, dbname, collection string) *Storage {
	return &Storage{
		policy: db.Database(dbname).Collection(collection),
	}
}

func (s *Storage) Policy(ctx context.Context, name, group, version string) (*Policy, error) {
	result := s.policy.FindOne(ctx, bson.M{
		"name":    name,
		"group":   group,
		"version": version,
	})

	if result.Err() != nil {
		if strings.Contains(result.Err().Error(), "no documents in result") {
			return nil, errors.New(errors.NotFound, "policy not found")
		}
		return nil, result.Err()
	}

	var policy Policy
	if err := result.Decode(&policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

func (s *Storage) SetPolicyLock(ctx context.Context, name, group, version string, lock bool) error {
	_, err := s.policy.UpdateOne(
		ctx,
		bson.M{
			"name":    name,
			"group":   group,
			"version": version,
		},
		bson.M{
			"$set": bson.M{
				"locked":     lock,
				"lastUpdate": time.Now(),
			},
		},
	)
	return err
}
