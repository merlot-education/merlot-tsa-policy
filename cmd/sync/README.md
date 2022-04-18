# Sync

Sync is a small Go program used for synchronization between a GIT repository containing REGO policies
and a MongoDB collection storing policies.

## Script

The `sync` program executes the following steps:
* Clones the REGO policy GIT repository on the local filesystem;
* Fetches all REPO policy documents from the MongoDB policy collection;
* Compares policies from the GIT repository and the MongoDB collection;
* Inserts new policies and updates modified ones in MongoDB;
* Deletes cloned repository from local filesystem.

## Build 

The script is written in [Go](https://go.dev/dl/). In order to use it as an executable binary, 
the script should be built by running the following command from the root of the repository:
```go
cd cmd/sync

go build 
```
Now an executable binary called `sync` is available in the current directory.

## Usage

Basic usage documentation is available when executing the following command on MacOS or Linux:
```shell
./sync --help
```

The flags passed to the script are as follows:
```    
    -dbAddr string
        Mongo DB connection string.    
    -dbUser string
        Mongo DB username.
    -dbPass string
        Mongo DB password.
    -repoURL string
        Policy repository URL.
    -repoUser string
        GIT Server username.        
    -repoPass string
        GIT Server password.
    -branch string
        GIT branch for explicit checkout. This flag is optional.
```

Usage example:
```shell
./sync -repoURL "https://path/to/repo.git" -repoUser "user" -repoPass "pass" -dbAddr "mongodb://localhost:27017/policy" -dbUser "user" -dbPass "pass" -branch "feature-branch"
```
