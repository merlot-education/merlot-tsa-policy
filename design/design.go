// nolint:revive
package design

import . "goa.design/goa/v3/dsl"

var _ = API("policy", func() {
	Title("Policy Service")
	Description("The policy service exposes HTTP API for executing policies.")
	Server("policy", func() {
		Description("Policy Server")
		Host("development", func() {
			Description("Local development server")
			URI("http://localhost:8081")
		})
	})
})

var _ = Service("policy", func() {
	Description("Policy Service provides evaluation of policies through Open Policy Agent.")

	Method("Evaluate", func() {
		Description("Evaluate executes a policy with the given 'data' as input.")
		Payload(EvaluateRequest)
		Result(EvaluateResult)
		HTTP(func() {
			GET("/policy/{group}/{policyName}/{version}/evaluation/did.json")
			GET("/policy/{group}/{policyName}/{version}/evaluation")
			POST("/policy/{group}/{policyName}/{version}/evaluation")
			Header("evaluationID:x-evaluation-id", String, "EvaluationID allows overwriting the randomly generated evaluationID", func() {
				Example("did:web:example.com")
			})
			Header("ttl:x-cache-ttl", Int, "Policy result cache TTL in seconds", func() {
				Example(60)
			})
			Body("input")
			Response(StatusOK, func() {
				Body("result")
				Header("ETag")
			})
		})
	})

	Method("Lock", func() {
		Description("Lock a policy so that it cannot be evaluated.")
		Payload(LockRequest)
		Result(Empty)
		HTTP(func() {
			POST("/policy/{group}/{policyName}/{version}/lock")
			Response(StatusOK)
		})
	})

	Method("Unlock", func() {
		Description("Unlock a policy so it can be evaluated again.")
		Payload(UnlockRequest)
		Result(Empty)
		HTTP(func() {
			DELETE("/policy/{group}/{policyName}/{version}/lock")
			Response(StatusOK)
		})
	})

	Method("ListPolicies", func() {
		Description("List policies from storage with optional filters.")
		Payload(PoliciesRequest)
		Result(PoliciesResult)
		HTTP(func() {
			GET("/v1/policies")
			Params(func() {
				Param("locked", Boolean, "Filter to return locked/unlocked policies (optional).")
				Param("rego", Boolean, "Include policy source code in results (optional).")
				Param("data", Boolean, "Include policy static data in results (optional). ")
				Param("dataConfig", Boolean, "Include static data config (optional).")
			})
			Response(StatusOK)
		})
	})
})

var _ = Service("health", func() {
	Description("Health service provides health check endpoints.")

	Method("Liveness", func() {
		Payload(Empty)
		Result(Empty)
		HTTP(func() {
			GET("/liveness")
			Response(StatusOK)
		})
	})

	Method("Readiness", func() {
		Payload(Empty)
		Result(Empty)
		HTTP(func() {
			GET("/readiness")
			Response(StatusOK)
		})
	})
})

var _ = Service("openapi", func() {
	Description("The openapi service serves the OpenAPI(v3) definition.")
	Meta("swagger:generate", "false")
	HTTP(func() {
		Path("/swagger-ui")
	})
	Files("/openapi.json", "./gen/http/openapi3.json", func() {
		Description("JSON document containing the OpenAPI(v3) service definition")
	})
	Files("/{*filepath}", "./swagger/")
})
