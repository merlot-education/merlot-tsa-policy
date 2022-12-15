// Package main provides a script to clone a repository containing Rego policies
// and add them to a Mongo DB collection
package main

import (
	"context"
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
	pathSeperator      = string(os.PathSeparator)
	cloneFolder        = "temp"
	defaultRepoFolder  = "policies"
	policyFilename     = "policy.rego"
	dataFilename       = "data.json"
	dataConfigFilename = "data-config.json"
	policyCollection   = "policies"
)

type Policy struct {
	Filename   string
	Name       string
	Group      string
	Version    string
	Rego       string
	Locked     bool
	Data       string
	DataConfig string
	LastUpdate time.Time
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalln("failed to setup the sync: ", err)
	}

	log.Println("start updating policies...")

	mongoOpts := options.Client().ApplyURI(cfg.DB.Addr)
	if cfg.DB.User != "" && cfg.DB.Pass != "" {
		mongoOpts.SetAuth(options.Credential{
			Username: cfg.DB.User,
			Password: cfg.DB.Pass,
		})
	}

	// connect to mongo db
	db, err := mongo.Connect(context.Background(), mongoOpts)
	if err != nil {
		log.Fatalln("error connecting to database: ", err)
	}
	defer db.Disconnect(context.Background()) //nolint:errcheck

	for {
		if err := sync(cfg, db); err != nil {
			log.Println(err)
		}

		if cfg.KeepAlive {
			// TODO catch SIGTERM/INTERRUPT here instead of hanging the program

			time.Sleep(cfg.SyncInterval)
			continue
		}

		break // quit sync
	}
}

func sync(cfg *Config, db *mongo.Client) error {
	// delete policy repository local folder in case the script failed last time it was executed
	if err := os.RemoveAll(cloneFolder); err != nil {
		return fmt.Errorf("failed to remove clone folder: %v", err)
	}

	// clone policy repository
	if err := cloneRepo(context.Background(), cfg.Repo.URL, cfg.Repo.User, cfg.Repo.Pass, cfg.Repo.Branch); err != nil {
		return fmt.Errorf("error cloning repo: %v", err)
	}

	log.Println("Repository is cloned successfully.")

	// get all policies from the repository and the given directory
	policies, err := iterateRepo(cfg.Repo.Folder)
	if err != nil {
		return fmt.Errorf("error iterating repo: %v", err)
	}

	log.Println("Policies are extracted successfully.")

	// insert or update policies in Mongo DB
	if err := upsertPolicies(context.Background(), db, policies, cfg.DB.Name); err != nil {
		return fmt.Errorf("error updating policies: %v", err)
	}

	// delete policy repository folder
	if err := os.RemoveAll(cfg.Repo.Folder); err != nil {
		return fmt.Errorf("error deleting policy repo folder: %v", err)
	}

	log.Println("Policies are updated successfully.")

	return nil
}

// cloneRepo clones the Policy repository to repoFolder
func cloneRepo(ctx context.Context, url, user, pass, branch string) error {
	log.Println("Cloning repository...")

	opts := &git.CloneOptions{
		URL:   url,
		Depth: 1,
	}

	if user != "" && pass != "" {
		opts.Auth = &http.BasicAuth{
			Username: user,
			Password: pass,
		}
	}

	if branch != "" {
		opts.ReferenceName = plumbing.NewBranchReferenceName(branch)
		opts.SingleBranch = true
	}

	_, err := git.PlainCloneContext(ctx, cloneFolder, false, opts)

	return err
}

// iterateRepo iterates over the repoFolder and returns a map
// of Policy structs
func iterateRepo(repoFolder string) (map[string]*Policy, error) {
	if repoFolder == "" {
		repoFolder = cloneFolder
	} else {
		repoFolder = filepath.Join(cloneFolder, repoFolder)
	}

	log.Println("Getting policies from the cloned repository...")

	policies := make(map[string]*Policy)
	err := filepath.WalkDir(repoFolder, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == policyFilename {
			policy, err := createPolicy(p)
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
func createPolicy(p string) (*Policy, error) {
	ex, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("error getting executable path: %v", err)
	}

	exPath := filepath.Dir(ex)
	// path to Rego policy must be {group}/{name}/{version}/policy.rego
	// strings.Split on the path give us an array containing at least group, name, version and filename
	ss := strings.Split(p, pathSeperator)
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
	dataBytes, err := os.ReadFile(filepath.Join(exPath, strings.TrimSuffix(p, policyFilename)+dataFilename))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// check if there is a data-config.json file in the same folder as the policy
	configBytes, err := os.ReadFile(strings.TrimSuffix(p, policyFilename) + dataConfigFilename)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// if both data.json and data-config.json files exist, log a warning message
	if len(dataBytes) > 0 && len(configBytes) > 0 {
		log.Printf("[WARNING] policy data will be overwritten by a data configuration execution for policy %q, group %q and version %q\n", name, group, version)
	}

	return &Policy{
		Filename:   dbFilename,
		Name:       name,
		Group:      group,
		Version:    version,
		Rego:       regoSrc,
		Data:       string(dataBytes),
		DataConfig: string(configBytes),
		Locked:     false,
	}, nil
}

// upsertPolicies compares policies from Git repository and MongoDB
// and then updates the modified policies and inserts new ones.
func upsertPolicies(ctx context.Context, db *mongo.Client, repoPolicies map[string]*Policy, policyDatabase string) error {
	log.Println("Updating policies in Database...")
	collection := db.Database(policyDatabase).Collection(policyCollection)

	currPolicies, err := fetchCurrPolicies(ctx, collection)
	if err != nil {
		return err
	}

	forUpsert := compare(currPolicies, repoPolicies)
	if len(forUpsert) > 0 {
		return upsert(ctx, forUpsert, collection)
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
				"nextDataRefreshTime": nextDataRefreshTime(policy),
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

func nextDataRefreshTime(p *Policy) time.Time {
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
