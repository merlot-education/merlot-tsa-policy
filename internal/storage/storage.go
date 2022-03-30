package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
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

type MongoStorage struct {
	db         *mongo.Client
	dbname     string
	collection string
}

func NewMongo(db *mongo.Client, dbname, collection string) *MongoStorage {
	return &MongoStorage{
		db:         db,
		dbname:     dbname,
		collection: collection,
	}
}

func (s *MongoStorage) Policy(ctx context.Context, name, group, version string) (*Policy, error) {
	fmt.Println("name =", name)
	fmt.Println("group =", group)
	fmt.Println("version =", version)

	fmt.Println("dbname = ", s.dbname)
	fmt.Println("col = ", s.collection)

	result := s.db.Database(s.dbname).Collection(s.collection).FindOne(ctx, bson.M{
		"name":    name,
		"group":   group,
		"version": version,
	})

	fmt.Printf("result = %#+v\n", result)

	if result.Err() != nil {
		return nil, result.Err()
	}

	var policy Policy
	if err := result.Decode(&policy); err != nil {
		return nil, err
	}

	return &policy, nil

	//key := fmt.Sprintf("%s:%s:%s", name, group, version)
	//
	//policy, ok := policies[key]
	//if !ok {
	//	return nil, errors.New(errors.NotFound, "policy not found in storage")
	//}
	//
	//return policy, nil
}
