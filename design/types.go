// nolint:revive
package design

import . "goa.design/goa/v3/dsl"

var EvaluateRequest = Type("EvaluateRequest", func() {
	Field(1, "group", String, "Policy group.", func() {
		Example("example")
	})
	Field(2, "policyName", String, "Policy name.", func() {
		Example("example")
	})
	Field(3, "version", String, "Policy version.", func() {
		Example("1.0")
	})
	Field(4, "input", Any, "Input data passed to the policy execution runtime.")
	Field(5, "evaluationID", String, "Identifier created by external system and passed as parameter to overwrite the randomly generated evaluationID.")
	Field(6, "ttl", Int, "TTL for storing policy result in cache")
	Required("group", "policyName", "version")
})

var EvaluateResult = Type("EvaluateResult", func() {
	Field(1, "result", Any, "Arbitrary JSON response.")
	Field(2, "ETag", String, "ETag contains unique identifier of the policy evaluation and can be used to later retrieve the results from Cache.")
	Required("result", "ETag")
})

var LockRequest = Type("LockRequest", func() {
	Field(1, "group", String, "Policy group.")
	Field(2, "policyName", String, "Policy name.")
	Field(3, "version", String, "Policy version.")
	Required("group", "policyName", "version")
})

var UnlockRequest = Type("UnlockRequest", func() {
	Field(1, "group", String, "Policy group.")
	Field(2, "policyName", String, "Policy name.")
	Field(3, "version", String, "Policy version.")
	Required("group", "policyName", "version")
})

var Policy = Type("Policy", func() {
	Field(1, "policyName", String, "Policy name.")
	Field(2, "group", String, "Policy group.")
	Field(3, "version", String, "Policy version.")
	Field(4, "rego", String, "Policy rego source code.")
	Field(5, "data", String, "Policy static data.")
	Field(6, "dataConfig", String, "Policy static data optional configuration.")
	Field(7, "locked", Boolean, "Locked specifies if the policy is locked or allowed to execute.")
	Field(8, "lastUpdate", Int64, "Last update (Unix timestamp).")
	Required("group", "policyName", "version", "locked", "lastUpdate")
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

var HealthResponse = Type("HealthResponse", func() {
	Field(1, "service", String, "Service name.")
	Field(2, "status", String, "Status message.")
	Field(3, "version", String, "Service runtime version.")
	Required("service", "status", "version")
})
