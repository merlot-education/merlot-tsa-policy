// nolint:revive
package design

import . "goa.design/goa/v3/dsl"

var EvaluateRequest = Type("EvaluateRequest", func() {
	Field(1, "group", String, "Policy group")
	Field(2, "policyName", String, "Policy name")
	Field(3, "version", String, "Policy version")
	Field(4, "data", Any, "Data passed as input to the policy execution runtime")
	Required("group", "policyName", "version", "data")
})

var EvaluateResult = Type("EvaluateResult", func() {
	Field(1, "result", Any, "Arbitrary JSON response.")
	Required("result")
})
