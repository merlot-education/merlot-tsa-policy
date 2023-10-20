package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	zap "go.uber.org/zap"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/clients/event"
)

const (
	lockedField              = "locked"
	dataField                = "data"
	nextDataRefreshTimeField = "nextDataRefreshTime"
	refreshPostponePeriod    = 5 * time.Minute
)

type PolicyChangeSubscriber interface {
	PolicyDataChange(ctx context.Context, data *event.Data) error
}

type Policy struct {
	ID                  primitive.ObjectID `bson:"_id"`
	Filename            string
	Name                string
	Group               string
	Version             string
	Rego                string
	Data                string
	DataConfig          string
	Locked              bool
	LastUpdate          time.Time
	NextDataRefreshTime time.Time
}

type Storage struct {
	db          *mongo.Client
	policy      *mongo.Collection
	subscribers []PolicyChangeSubscriber
	logger      *zap.Logger
}

func New(db *mongo.Client, dbname, collection string, logger *zap.Logger) (*Storage, error) {
	if err := db.Ping(context.Background(), nil); err != nil {
		return nil, err
	}

	return &Storage{
		db:     db,
		policy: db.Database(dbname).Collection(collection),
		logger: logger,
	}, nil
}

func (s *Storage) Policy(ctx context.Context, group, name, version string) (*Policy, error) {
	s.logger.Debug("get policy from storage",
		zap.String("group", group),
		zap.String("policy", name),
		zap.String("version", version),
	)

	result := s.policy.FindOne(ctx, bson.M{
		"group":   group,
		"name":    name,
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

func (s *Storage) SetPolicyLock(ctx context.Context, group, name, version string, lock bool) error {
	_, err := s.policy.UpdateOne(
		ctx,
		bson.M{
			"group":   group,
			"name":    name,
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

type PolicyEvent struct {
	OperationType string `bson:"operationType"`
	Policy        Policy `bson:"fullDocument"`
}

func (s *Storage) ListenPolicyDataChanges(ctx context.Context) error {
	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	stream, err := s.policy.Watch(ctx, mongo.Pipeline{}, opts)
	if err != nil {
		return errors.New("cannot subscribe for policy data changes", err)
	}
	defer stream.Close(ctx)

	for stream.Next(ctx) {
		var policyEvent PolicyEvent
		err := stream.Decode(&policyEvent)
		if err != nil {
			return err
		}

		policy := policyEvent.Policy

		fmt.Println("Version = ", policy.Version, "Name = ", policy.Name, "Group = ", policy.Group)

		for _, subscriber := range s.subscribers {
			err := subscriber.PolicyDataChange(ctx, &event.Data{Name: policy.Name, Version: policy.Version, Group: policy.Group})
			if err != nil {
				return err
			}
		}

		s.logger.Info("mongo policy data changed")
	}

	return stream.Err()
}

func (s *Storage) AddPolicyChangeSubscriber(subscriber ...PolicyChangeSubscriber) {
	s.subscribers = subscriber
}

func (s *Storage) GetRefreshPolicies(ctx context.Context) ([]*Policy, error) {
	// create a callback for the mongodb transaction
	callback := func(mCtx mongo.SessionContext) (interface{}, error) {
		filter := bson.M{nextDataRefreshTimeField: bson.M{
			"$gt":  time.Time{}, // greater than the Go's zero date
			"$lte": time.Now(),
		}}

		cursor, err := s.policy.Find(ctx, filter)
		if err != nil {
			return nil, err
		}

		var policies []*Policy
		if err := cursor.All(ctx, &policies); err != nil {
			return nil, err
		}
		if len(policies) == 0 {
			return nil, errors.New(errors.NotFound, "policies for data refresh not found")
		}

		err = s.PostponeRefresh(ctx, policies)
		if err != nil {
			return nil, err
		}

		return policies, nil
	}

	// execute transaction
	res, err := s.Transaction(ctx, callback)
	if err != nil {
		return nil, err
	}
	policies, _ := res.([]*Policy)

	return policies, nil
}

// PostponeRefresh adds a refreshPostponePeriod Duration to each policy's
// nextDataRefreshTimeField in order to prevent concurrent data refresh
func (s *Storage) PostponeRefresh(ctx context.Context, policies []*Policy) error {
	var ids []primitive.ObjectID
	for _, p := range policies {
		ids = append(ids, p.ID)
	}

	filter := bson.M{"_id": bson.M{"$in": ids}}
	update := bson.M{"$set": bson.M{nextDataRefreshTimeField: time.Now().Add(refreshPostponePeriod)}}
	_, err := s.policy.UpdateMany(ctx, filter, update)

	return err
}

// UpdateNextRefreshTime updates policy's data and nextDataRefreshTimeField fields
func (s *Storage) UpdateNextRefreshTime(ctx context.Context, p *Policy, nextDataRefreshTime time.Time) error {
	filter := bson.M{"_id": p.ID}
	update := bson.M{"$set": bson.M{
		nextDataRefreshTimeField: nextDataRefreshTime,
		dataField:                p.Data,
	}}
	_, err := s.policy.UpdateOne(ctx, filter, update)

	return err
}

func (s *Storage) Transaction(ctx context.Context, callback func(mCtx mongo.SessionContext) (interface{}, error)) (interface{}, error) {
	session, err := s.db.StartSession()
	if err != nil {
		return nil, errors.New("failed creating session", err)
	}
	defer session.EndSession(ctx)

	res, err := session.WithTransaction(ctx, callback)
	if err != nil {
		return nil, errors.New("failed executing transaction", err)
	}

	return res, nil
}

func (s *Storage) GetPolicies(ctx context.Context, locked *bool) ([]*Policy, error) {
	var filter bson.M
	if locked != nil {
		filter = bson.M{lockedField: locked}
	}

	cursor, err := s.policy.Find(ctx, filter)
	if err != nil {
		return nil, err
	}

	var policies []*Policy
	if err := cursor.All(ctx, &policies); err != nil {
		return nil, err
	}

	return policies, nil
}
