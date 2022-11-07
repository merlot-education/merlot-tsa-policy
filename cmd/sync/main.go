// Package main provides a script to clone a repository containing Rego policies
// and add them to a Mongo DB collection
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	repoFolder         = "policies"
	policyFilename     = "policy.rego"
	dataFilename       = "data.json"
	dataConfigFilename = "data-config.json"
	policyDatabase     = "policy"
	policyCollection   = "policies"
)

type Policy struct {
	Filename   string
	Name       string
	Group      string
	Version    string
	Rego       string
	Locked     bool
	Data       interface{}
	DataConfig interface{}
	LastUpdate time.Time
}

func main() {
	var repoURL, repoUser, repoPass, branch, dbAddr, dbUser, dbPass string

	flag.StringVar(&repoURL, "repoURL", "", "Policy repository URL.")
	flag.StringVar(&repoUser, "repoUser", "", "GIT Server username.")
	flag.StringVar(&repoPass, "repoPass", "", "GIT Server password.")
	flag.StringVar(&dbAddr, "dbAddr", "", "Mongo DB connection string.")
	flag.StringVar(&dbUser, "dbUser", "", "Mongo DB username")
	flag.StringVar(&dbPass, "dbPass", "", "Mongo DB password")
	flag.StringVar(&branch, "branch", "", "GIT branch for explicit checkout. This flag is optional.")
	flag.Parse()

	// validate the number of passed command-line flags
	err := validateFlags("repoURL", "repoUser", "repoPass", "dbAddr", "dbUser", "dbPass")
	if err != nil {
		log.Fatalf(" Error: %s", err)
	}

	log.Println("Started updating policies...")

	// delete policy repository local folder in case the script failed last time it was executed
	err = os.RemoveAll(repoFolder)
	if err != nil {
		log.Fatalf(" Error: %s", err)
	}

	// connect to mongo db
	db, err := mongo.Connect(
		context.Background(),
		options.Client().ApplyURI(dbAddr).SetAuth(options.Credential{
			Username: dbUser,
			Password: dbPass,
		}),
	)
	if err != nil {
		log.Fatalf(" Error: %s", err)
	}
	defer db.Disconnect(context.Background()) //nolint:errcheck

	// clone policy repository
	err = cloneRepo(context.Background(), repoURL, repoUser, repoPass, branch)
	if err != nil {
		log.Fatalf(" Error: %s", err)
	}
	log.Println("Repository successfully cloned.")

	// get all policies from the repository
	policies, err := iterateRepo()
	if err != nil {
		log.Fatalf(" Error: %s", err)
	}
	log.Println("Policies are extracted successfully")

	// insert or update policies in Mongo DB
	err = upsertPolicies(context.Background(), db, policies)
	if err != nil {
		log.Fatalf(" Error: %s", err)
	}

	// delete policy repository folder
	err = os.RemoveAll(repoFolder)
	if err != nil {
		log.Fatalf(" Error: %s", err)
	}

	log.Println("Policies are updated successfully.")
}

// cloneRepo clones the Policy repository to repoFolder
func cloneRepo(ctx context.Context, url, user, pass, branch string) error {
	log.Println("Cloning repository...")
	opts := &git.CloneOptions{
		Auth: &http.BasicAuth{
			Username: user,
			Password: pass,
		},
		URL:   url,
		Depth: 1,
	}
	if branch != "" {
		opts.ReferenceName = plumbing.NewBranchReferenceName(branch)
		opts.SingleBranch = true
	}

	_, err := git.PlainCloneContext(ctx, repoFolder, false, opts)

	return err
}

// iterateRepo iterates over the repoFolder and returns a map
// of Policy structs
func iterateRepo() (map[string]*Policy, error) {
	log.Println("Getting policies from the cloned repository...")

	policies := make(map[string]*Policy)
	err := filepath.WalkDir(repoFolder, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == policyFilename {
			policy, err := createPolicy(p, d)
			if err != nil {
				return err
			}
			policies[constructKey(policy)] = policy
		}
		return nil
	})

	return policies, err
}

// createPolicy instantiates a Policy struct out of a policy file on given path
func createPolicy(p string, d os.DirEntry) (*Policy, error) {
	// path to Rego policy must be {group}/{name}/{version}/policy.rego
	// strings.Split on the path give us an array containing at least group, name, version and filename
	ss := strings.Split(p, "/")
	if len(ss) < 4 {
		return nil, fmt.Errorf("failed to get policy filename, name, version and group out of policy path: %s", p)
	}

	version := ss[len(ss)-2] // second last element is the version
	name := ss[len(ss)-3]    // third last element is the policy name
	group := ss[len(ss)-4]   // fourth last element is the policy group
	bytes, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	regoSrc := string(bytes)

	// generate policy filename for DB from pattern {group}/{name}/{version}/policy.rego
	dbFilename := group + "/" + name + "/" + version + "/" + policyFilename

	// check if there is a data.json file in the same folder as the policy
	dataBytes, err := os.ReadFile(strings.TrimSuffix(p, policyFilename) + dataFilename)
	if err != nil && !strings.Contains(err.Error(), "no such file or directory") {
		return nil, err
	}
	data := string(dataBytes)

	// check if there is a data-config.json file in the same folder as the policy
	configBytes, err := os.ReadFile(strings.TrimSuffix(p, policyFilename) + dataConfigFilename)
	if err != nil && !strings.Contains(err.Error(), "no such file or directory") {
		return nil, err
	}
	dataConfig := string(configBytes)

	// if both data.json and data-config.json files exist, log a warning message
	if len(dataBytes) > 0 && len(configBytes) > 0 {
		fmt.Printf("Policy data will be overwritten by a data configuration execution for policy '%s', group '%s' and version '%s'\n", name, group, version)
	}

	return &Policy{
		Filename:   dbFilename,
		Name:       name,
		Group:      group,
		Version:    version,
		Rego:       regoSrc,
		Data:       data,
		DataConfig: dataConfig,
		Locked:     false,
	}, nil
}

// upsertPolicies compares policies from Git repository and MongoDB
// and then updates the modified policies or inserts new ones
func upsertPolicies(ctx context.Context, db *mongo.Client, repoPolicies map[string]*Policy) error {
	log.Println("Updating policies in Database...")
	collection := db.Database(policyDatabase).Collection(policyCollection)

	currPolicies, err := fetchCurrPolicies(ctx, collection)
	if err != nil {
		return err
	}

	forUpsert := compare(currPolicies, repoPolicies)
	if len(forUpsert) > 0 {
		err = upsert(ctx, forUpsert, collection)
		if err != nil {
			return err
		}
	}

	return nil
}

// fetchCurrPolicies fetches all policies currently stored in MongoDB
// and returns a map with keys constructed out of the "group", "name" and
// "version" fields of a Policy and value - a reference to the Policy
func fetchCurrPolicies(ctx context.Context, db *mongo.Collection) (map[string]*Policy, error) {
	results, err := db.Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer results.Close(ctx)

	currPolicies := make(map[string]*Policy)
	for results.Next(ctx) {
		var p Policy
		err := results.Decode(&p)
		if err != nil {
			return nil, err
		}
		currPolicies[constructKey(&p)] = &p
	}
	if results.Err() != nil {
		return nil, results.Err()
	}

	return currPolicies, nil
}

// compare analyzes policies from Git repository and policies from MongoDB
// and returns a slice containing new and modified policies
func compare(currPolicies map[string]*Policy, repoPolicies map[string]*Policy) []*Policy {
	var forUpsert []*Policy
	for k, rPolicy := range repoPolicies {
		// check if the policy from GIT (by key) exists in MongoDB
		if cPolicy, ok := currPolicies[k]; ok {
			// if GIT policy exists in MongoDB, check if it is modified
			if !cPolicy.equals(rPolicy) {
				// if GIT policy is modified, save the 'lock' state before updating in MongoDB
				rPolicy.Locked = cPolicy.Locked
				forUpsert = append(forUpsert, rPolicy)
			}
		} else { // policy from GIT does not exist in MongoDB
			forUpsert = append(forUpsert, rPolicy)
		}
	}

	return forUpsert
}

// upsert inserts or updates policies in MongoDB collection
//
// Decision whether to insert or update is taken based on the composition of
// Policy "group", "name" and "version" fields
func upsert(ctx context.Context, policies []*Policy, db *mongo.Collection) error {
	var ops []mongo.WriteModel
	for _, policy := range policies {
		op := mongo.NewUpdateOneModel()
		op.SetFilter(bson.M{
			"group":   policy.Group,
			"name":    policy.Name,
			"version": policy.Version,
		})
		op.SetUpdate(bson.M{
			"$set": bson.M{
				"filename":            policy.Filename,
				"locked":              policy.Locked,
				"rego":                policy.Rego,
				"data":                policy.Data,
				"dataConfig":          policy.DataConfig,
				"lastUpdate":          time.Now(),
				"nextConfigExecution": nextConfigExecution(policy),
			},
		})
		op.SetUpsert(true)
		ops = append(ops, op)
	}

	_, err := db.BulkWrite(ctx, ops, &options.BulkWriteOptions{})
	if err != nil {
		return err
	}

	return nil
}

func nextConfigExecution(p *Policy) time.Time {
	if p.DataConfig != "" {
		return time.Now()
	}

	return time.Time{}
}

func (p1 *Policy) equals(p2 *Policy) bool {
	if p1.Rego == p2.Rego &&
		p1.Data == p2.Data &&
		p1.DataConfig == p2.DataConfig &&
		p1.Name == p2.Name &&
		p1.Version == p2.Version &&
		p1.Filename == p2.Filename &&
		p1.Group == p2.Group {
		return true
	}

	return false
}

func constructKey(p *Policy) string {
	return fmt.Sprintf("%s.%s.%s", p.Group, p.Name, p.Version)
}

func validateFlags(flags ...string) error {
	if flag.NFlag() < len(flags) {
		return errors.New("required command-line flag is not provided")
	}

	return nil
}
