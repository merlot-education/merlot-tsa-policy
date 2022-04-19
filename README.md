[![pipeline status](https://code.vereign.com/gaiax/tsa/policy/badges/main/pipeline.svg)](https://code.vereign.com/gaiax/tsa/policy/-/commits/main)
[![coverage report](https://code.vereign.com/gaiax/tsa/policy/badges/main/coverage.svg)](https://code.vereign.com/gaiax/tsa/policy/-/commits/main)

# Policy Service

The policy service provides HTTP API to evaluate/execute 
[OPA](https://www.openpolicyagent.org/) policies.

It is developed using the [Goa v3](https://goa.design/) framework
and uses the [Go OPA framework](https://github.com/open-policy-agent/opa) 
as a library.

While the service is up and running, you can see a live Swagger API 
description at `servicehost:serviceport/swagger-ui`. In the local docker-compose 
environment, the Swagger URL is available at http://localhost:8081/swagger-ui/ 

### High-level Overview

```mermaid
flowchart LR
	A([client]) -- HTTP --> B[Policy API]
	subgraph policy
		B --> C[(policies DB)]
	end
	C --sync--- D[Git Server]
```

### Policy Evaluation

The policy service exposes HTTP endpoints to evaluate/execute policies.
The endpoint interface is conformant to the TSA requirements document.

To evaluate a policy a POST request is sent to the evaluation URL.
The example URL below is given for the local docker-compose environment. 
The `host` and `port` parts will be different for the different environments.

```
# URL with example policy group, name and version
http://localhost:8081/policy/gaiax/didresolve/1.0/evaluation

# URL with parameter placeholders
http://localhost:8081/policy/{group}/{policy}/{version}/evaluation
```

There are three parameters in the URL specifying which exact policy 
should be evaluated - `group`, `policy` and `version`. These parameters 
are also important during policy development (see below) as `group` 
and `policy` **must** be used as package name inside the policy 
source code file.

The body of the POST request **must** be JSON and it is passed directly
to the policy execution runtime. Inside the policy it is accessed with
the global variable name `input`. For example, if you pass to the evaluation
endpoint the following JSON, it will be accessible by `input.message`:
```json
{
  "message": "hello world"
}
```

Here is a complete example CURL request:
```shell
curl -X POST http://localhost:8081/policy/gaiax/didresolve/1.0/evaluation -d '{"message":"hello world"}'
```

### Policy Locking

The service exposes HTTP endpoints to lock and unlock policies. Locking a policy
means that it's not allowed for evaluation (execution). Unlocking a policy allows
its evaluation/execution to proceed normally.

Lock a policy with POST request:
```shell
curl -X POST http://localhost:8081/policy/gaiax/didresolve/1.0/lock
```

Unlock a policy with DELETE request:
```shell
curl -X DELETE http://localhost:8081/policy/gaiax/didresolve/1.0/lock
```

### Policy Storage

Policies (rego source code and metadata) are stored in a MongoDB collection `policies`,
with one collection document representing one policy. A document contains additional 
policy state un-related to OPA and Rego, but necessary for implementing the TSA 
requirements (e.g. policy lock/unlock).

The database is used as read-only source of truth for the current policy state when
policies need to be evaluated. Policy storage is updated externally from a separate
component. The update process is automatically triggered by updating policy source 
code files in an external Git server.

```mermaid
flowchart LR
	A[Policy\nDeveloper] --git push/merge--> B[Git branch]
	subgraph Git Server
		B --> C[example_1.0.rego]
		B --> D[example_2.0.rego]
		B --> G[example_3.0.rego]
	end
	C --> E[Sync]
	D --> E[Sync]
	G --> E[Sync]
	E --update--> F
	subgraph policy service
		F[(policies DB)]
	end
```

### Policy Development

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) 
language. Please refer to the [OPA documentation](https://www.openpolicyagent.org/docs/latest/)
for detailed overview of Rego and OPA capabilities.

**Some conventions *must* be followed when writing policies.**

1. The filename of the policy *must* follow rules for the naming and directory structure:
the `group` is a directory inside the Git repo, while the policy name and version are used
for naming the file. For example: `/gaiax/example_1.0.rego`.
2. The policy package name inside the policy source code file *must* exactly match
the `group` and `policy` (name) of the policy.

*What does all this mean?*

Let's see an example for the 1st convention.
```
package gaiax.example

allow {
    input.message == "hello world"
}
```

Next, the filename must be `/gaiax/example_1.0.rego`. When such file is synchronized
with the policy service (storage), the naming convention allows the service to understand
which part is the policy group, which part is policy name and which part is version.

If we create the above policy and store it in the Git repo as `/gaiax/example_1.0.rego`, 
after the Git server is synchronized with the Policy Storage, the policy service will
automatically expose URLs for working with the policy at:
```
http://localhost:8081/policy/gaiax/example/1.0/evaluation
http://localhost:8081/policy/gaiax/example/1.0/lock
```

The 2nd rule for package naming is needed so that a generic evaluation function 
can be mapped and used for evaluating all kinds of different policies. Without a 
package naming rule, there's no way the service can automatically generate HTTP 
endpoints for working with arbitrary dynamically uploaded policies.


