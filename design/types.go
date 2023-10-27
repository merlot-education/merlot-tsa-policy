// nolint:revive
package design

import . "goa.design/goa/v3/dsl"

var EvaluateRequest = Type("EvaluateRequest", func() {
	Field(1, "repository", String, "Policy repository.", func() {
		Example("policies")
	})
	Field(2, "group", String, "Policy group.", func() {
		Example("example")
	})
	Field(3, "policyName", String, "Policy name.", func() {
		Example("example")
	})
	Field(4, "version", String, "Policy version.", func() {
		Example("1.0")
	})
	Field(5, "input", Any, "Input data passed to the policy execution runtime.")
	Field(6, "evaluationID", String, "Identifier created by external system and passed as parameter to overwrite the randomly generated evaluationID.")
	Field(7, "ttl", Int, "TTL for storing policy result in cache")
	Required("repository", "group", "policyName", "version")
})

var EvaluateResult = Type("EvaluateResult", func() {
	Field(1, "result", Any, "Arbitrary JSON response.")
	Field(2, "ETag", String, "ETag contains unique identifier of the policy evaluation and can be used to later retrieve the results from Cache.")
	Required("result", "ETag")
})

var LockRequest = Type("LockRequest", func() {
	Field(1, "repository", String, "Policy repository.")
	Field(2, "group", String, "Policy group.")
	Field(3, "policyName", String, "Policy name.")
	Field(4, "version", String, "Policy version.")
	Required("repository", "group", "policyName", "version")
})

var UnlockRequest = Type("UnlockRequest", func() {
	Field(1, "repository", String, "Policy repository.")
	Field(2, "group", String, "Policy group.")
	Field(3, "policyName", String, "Policy name.")
	Field(4, "version", String, "Policy version.")
	Required("repository", "group", "policyName", "version")
})

var Policy = Type("Policy", func() {
	Field(1, "repository", String, "Policy repository.")
	Field(2, "policyName", String, "Policy name.")
	Field(3, "group", String, "Policy group.")
	Field(4, "version", String, "Policy version.")
	Field(5, "rego", String, "Policy rego source code.")
	Field(6, "data", String, "Policy static data.")
	Field(7, "dataConfig", String, "Policy static data optional configuration.")
	Field(8, "locked", Boolean, "Locked specifies if the policy is locked or allowed to execute.")
	Field(9, "lastUpdate", Int64, "Last update (Unix timestamp).")
	Required("repository", "group", "policyName", "version", "locked", "lastUpdate")
})

var PoliciesRequest = Type("PoliciesRequest", func() {
	Field(1, "locked", Boolean)
	Field(2, "rego", Boolean)
	Field(3, "data", Boolean)
	Field(4, "dataConfig", Boolean)
})

var PoliciesResult = Type("PoliciesResult", func() {
	Field(1, "policies", ArrayOf(Policy), "JSON array of policies.")
	Required("policies")
})
