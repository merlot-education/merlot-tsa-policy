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
	Filename    string
	Name        string
	Group       string
	Version     string
	Rego        string
	Locked      bool
	LastUpdated time.Time
}

type Storage struct {
	db         *mongo.Client
	dbname     string
	collection string
}

func New(db *mongo.Client, dbname, collection string) *Storage {
	return &Storage{
		db:         db,
		dbname:     dbname,
		collection: collection,
	}
}

func (s *Storage) Policy(ctx context.Context, name, group, version string) (*Policy, error) {
	result := s.db.Database(s.dbname).Collection(s.collection).FindOne(ctx, bson.M{
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

func (s *Storage) LockPolicy(ctx context.Context, name, group, version string) error {
	_, err := s.db.Database(s.dbname).Collection(s.collection).UpdateOne(
		ctx,
		bson.M{
			"name":    name,
			"group":   group,
			"version": version,
		},
		bson.M{
			"$set": bson.M{
				"locked": true,
			},
		},
	)
	return err
}

func (s *Storage) UnlockPolicy(ctx context.Context, name, group, version string) error {
	_, err := s.db.Database(s.dbname).Collection(s.collection).UpdateOne(
		ctx,
		bson.M{
			"name":    name,
			"group":   group,
			"version": version,
		},
		bson.M{
			"$set": bson.M{
				"locked": false,
			},
		},
	)
	return err
}
