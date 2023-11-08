package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Subscriber struct {
	ID               primitive.ObjectID `bson:"_id"`
	Name             string
	WebhookURL       string
	PolicyRepository string
	PolicyName       string
	PolicyGroup      string
	PolicyVersion    string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (s *Storage) CreateSubscriber(ctx context.Context, subscriber *Subscriber) (*Subscriber, error) {
	_, err := s.policyExist(ctx, subscriber.PolicyRepository, subscriber.PolicyName, subscriber.PolicyGroup, subscriber.PolicyVersion)
	if err != nil {
		return nil, err
	}

	subscriberExist, err := s.subscriberExist(ctx, subscriber)
	if err != nil {
		return nil, err
	}

	if subscriberExist {
		return nil, fmt.Errorf("subscriber already exists")
	}

	subscriber.CreatedAt = time.Now()
	subscriber.UpdatedAt = time.Now()
	subscriber.ID = primitive.NewObjectID()
	_, err = s.subscriber.InsertOne(ctx, subscriber)
	if err != nil {
		return nil, err
	}

	return subscriber, nil
}

func (s *Storage) PolicyChangeSubscribers(ctx context.Context, policyRepository, policyName, policyGroup, policyVersion string) ([]*Subscriber, error) {
	cursor, err := s.subscriber.Find(ctx, bson.M{
		"policyrepository": policyRepository,
		"policyname":       policyName,
		"policygroup":      policyGroup,
		"policyversion":    policyVersion,
	})
	if err != nil {
		return nil, err
	}

	subscribers := []*Subscriber{}
	if err := cursor.All(ctx, &subscribers); err != nil {
		return nil, err
	}

	return subscribers, nil
}

func (s *Storage) subscriberExist(ctx context.Context, subscriber *Subscriber) (bool, error) {
	err := s.subscriber.FindOne(ctx, bson.M{
		"name":             subscriber.Name,
		"webhookurl":       subscriber.WebhookURL,
		"policyrepository": subscriber.PolicyRepository,
		"policyname":       subscriber.PolicyName,
		"policygroup":      subscriber.PolicyGroup,
		"policyversion":    subscriber.PolicyVersion,
	}).Err()
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *Storage) policyExist(ctx context.Context, repository, name, group, version string) (bool, error) {
	err := s.policy.FindOne(ctx, bson.M{
		"repository": repository,
		"name":       name,
		"group":      group,
		"version":    version,
	}).Err()
	if err != nil {
		return false, err
	}
	return true, nil
}
