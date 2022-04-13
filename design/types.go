// nolint:revive
package design

import . "goa.design/goa/v3/dsl"

var EvaluateRequest = Type("EvaluateRequest", func() {
	Field(1, "group", String, "Policy group.")
	Field(2, "policyName", String, "Policy name.")
	Field(3, "version", String, "Policy version.")
	Field(4, "input", Any, "Input data passed to the policy execution runtime.")
	Required("group", "policyName", "version", "input")
})

var EvaluateResult = Type("EvaluateResult", func() {
	Field(1, "result", Any, "Arbitrary JSON response.")
	Required("result")
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
