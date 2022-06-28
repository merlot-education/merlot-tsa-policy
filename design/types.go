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
