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
	Field(1, "policyName", String, "policy name")
	Field(2, "group", String, "policy group")
	Field(3, "version", String, "policy version")
	Field(4, "rego", String, "policy rego code")
	Field(5, "data", String, "policy data")
	Field(6, "dataConfig", String, "policy data config")
	Field(7, "locked", Boolean, "if it true gives locked status on the policy")
	Field(8, "lastUpdate", Int64, "Last update (timestamp).")
	Required("group", "policyName", "version", "locked", "lastUpdate")
})

var PoliciesRequest = Type("PoliciesRequest", func() {
	Field(1, "locked", Boolean)
	Field(2, "rego", Boolean)
	Field(3, "data", Boolean)
	Field(4, "dataConfig", Boolean)
})

var PoliciesResult = Type("PoliciesResult", func() {
	Field(1, "policies", ArrayOf(Policy), "policy list")
	Required("policies")
})
