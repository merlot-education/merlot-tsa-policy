// Code generated by goa v3.7.0, DO NOT EDIT.
//
// policy HTTP client CLI support package
//
// Command:
// $ goa gen code.vereign.com/gaiax/tsa/policy/design

package cli

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	healthc "code.vereign.com/gaiax/tsa/policy/gen/http/health/client"
	policyc "code.vereign.com/gaiax/tsa/policy/gen/http/policy/client"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// UsageCommands returns the set of commands and sub-commands using the format
//
//    command (subcommand1|subcommand2|...)
//
func UsageCommands() string {
	return `health (liveness|readiness)
policy (evaluate|lock|unlock)
`
}

// UsageExamples produces an example of a valid invocation of the CLI tool.
func UsageExamples() string {
	return os.Args[0] + ` health liveness` + "\n" +
		os.Args[0] + ` policy evaluate --body "Illum ad assumenda consectetur minima voluptatibus." --group "example" --policy-name "example" --version "1.0" --evaluation-id "Ab accusamus voluptatem et est."` + "\n" +
		""
}

// ParseEndpoint returns the endpoint and payload as specified on the command
// line.
func ParseEndpoint(
	scheme, host string,
	doer goahttp.Doer,
	enc func(*http.Request) goahttp.Encoder,
	dec func(*http.Response) goahttp.Decoder,
	restore bool,
) (goa.Endpoint, interface{}, error) {
	var (
		healthFlags = flag.NewFlagSet("health", flag.ContinueOnError)

		healthLivenessFlags = flag.NewFlagSet("liveness", flag.ExitOnError)

		healthReadinessFlags = flag.NewFlagSet("readiness", flag.ExitOnError)

		policyFlags = flag.NewFlagSet("policy", flag.ContinueOnError)

		policyEvaluateFlags            = flag.NewFlagSet("evaluate", flag.ExitOnError)
		policyEvaluateBodyFlag         = policyEvaluateFlags.String("body", "REQUIRED", "")
		policyEvaluateGroupFlag        = policyEvaluateFlags.String("group", "REQUIRED", "Policy group.")
		policyEvaluatePolicyNameFlag   = policyEvaluateFlags.String("policy-name", "REQUIRED", "Policy name.")
		policyEvaluateVersionFlag      = policyEvaluateFlags.String("version", "REQUIRED", "Policy version.")
		policyEvaluateEvaluationIDFlag = policyEvaluateFlags.String("evaluation-id", "", "")

		policyLockFlags          = flag.NewFlagSet("lock", flag.ExitOnError)
		policyLockGroupFlag      = policyLockFlags.String("group", "REQUIRED", "Policy group.")
		policyLockPolicyNameFlag = policyLockFlags.String("policy-name", "REQUIRED", "Policy name.")
		policyLockVersionFlag    = policyLockFlags.String("version", "REQUIRED", "Policy version.")

		policyUnlockFlags          = flag.NewFlagSet("unlock", flag.ExitOnError)
		policyUnlockGroupFlag      = policyUnlockFlags.String("group", "REQUIRED", "Policy group.")
		policyUnlockPolicyNameFlag = policyUnlockFlags.String("policy-name", "REQUIRED", "Policy name.")
		policyUnlockVersionFlag    = policyUnlockFlags.String("version", "REQUIRED", "Policy version.")
	)
	healthFlags.Usage = healthUsage
	healthLivenessFlags.Usage = healthLivenessUsage
	healthReadinessFlags.Usage = healthReadinessUsage

	policyFlags.Usage = policyUsage
	policyEvaluateFlags.Usage = policyEvaluateUsage
	policyLockFlags.Usage = policyLockUsage
	policyUnlockFlags.Usage = policyUnlockUsage

	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		return nil, nil, err
	}

	if flag.NArg() < 2 { // two non flag args are required: SERVICE and ENDPOINT (aka COMMAND)
		return nil, nil, fmt.Errorf("not enough arguments")
	}

	var (
		svcn string
		svcf *flag.FlagSet
	)
	{
		svcn = flag.Arg(0)
		switch svcn {
		case "health":
			svcf = healthFlags
		case "policy":
			svcf = policyFlags
		default:
			return nil, nil, fmt.Errorf("unknown service %q", svcn)
		}
	}
	if err := svcf.Parse(flag.Args()[1:]); err != nil {
		return nil, nil, err
	}

	var (
		epn string
		epf *flag.FlagSet
	)
	{
		epn = svcf.Arg(0)
		switch svcn {
		case "health":
			switch epn {
			case "liveness":
				epf = healthLivenessFlags

			case "readiness":
				epf = healthReadinessFlags

			}

		case "policy":
			switch epn {
			case "evaluate":
				epf = policyEvaluateFlags

			case "lock":
				epf = policyLockFlags

			case "unlock":
				epf = policyUnlockFlags

			}

		}
	}
	if epf == nil {
		return nil, nil, fmt.Errorf("unknown %q endpoint %q", svcn, epn)
	}

	// Parse endpoint flags if any
	if svcf.NArg() > 1 {
		if err := epf.Parse(svcf.Args()[1:]); err != nil {
			return nil, nil, err
		}
	}

	var (
		data     interface{}
		endpoint goa.Endpoint
		err      error
	)
	{
		switch svcn {
		case "health":
			c := healthc.NewClient(scheme, host, doer, enc, dec, restore)
			switch epn {
			case "liveness":
				endpoint = c.Liveness()
				data = nil
			case "readiness":
				endpoint = c.Readiness()
				data = nil
			}
		case "policy":
			c := policyc.NewClient(scheme, host, doer, enc, dec, restore)
			switch epn {
			case "evaluate":
				endpoint = c.Evaluate()
				data, err = policyc.BuildEvaluatePayload(*policyEvaluateBodyFlag, *policyEvaluateGroupFlag, *policyEvaluatePolicyNameFlag, *policyEvaluateVersionFlag, *policyEvaluateEvaluationIDFlag)
			case "lock":
				endpoint = c.Lock()
				data, err = policyc.BuildLockPayload(*policyLockGroupFlag, *policyLockPolicyNameFlag, *policyLockVersionFlag)
			case "unlock":
				endpoint = c.Unlock()
				data, err = policyc.BuildUnlockPayload(*policyUnlockGroupFlag, *policyUnlockPolicyNameFlag, *policyUnlockVersionFlag)
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}

	return endpoint, data, nil
}

// healthUsage displays the usage of the health command and its subcommands.
func healthUsage() {
	fmt.Fprintf(os.Stderr, `Health service provides health check endpoints.
Usage:
    %[1]s [globalflags] health COMMAND [flags]

COMMAND:
    liveness: Liveness implements Liveness.
    readiness: Readiness implements Readiness.

Additional help:
    %[1]s health COMMAND --help
`, os.Args[0])
}
func healthLivenessUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] health liveness

Liveness implements Liveness.

Example:
    %[1]s health liveness
`, os.Args[0])
}

func healthReadinessUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] health readiness

Readiness implements Readiness.

Example:
    %[1]s health readiness
`, os.Args[0])
}

// policyUsage displays the usage of the policy command and its subcommands.
func policyUsage() {
	fmt.Fprintf(os.Stderr, `Policy Service provides evaluation of policies through Open Policy Agent.
Usage:
    %[1]s [globalflags] policy COMMAND [flags]

COMMAND:
    evaluate: Evaluate executes a policy with the given 'data' as input.
    lock: Lock a policy so that it cannot be evaluated.
    unlock: Unlock a policy so it can be evaluated again.

Additional help:
    %[1]s policy COMMAND --help
`, os.Args[0])
}
func policyEvaluateUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] policy evaluate -body JSON -group STRING -policy-name STRING -version STRING -evaluation-id STRING

Evaluate executes a policy with the given 'data' as input.
    -body JSON: 
    -group STRING: Policy group.
    -policy-name STRING: Policy name.
    -version STRING: Policy version.
    -evaluation-id STRING: 

Example:
    %[1]s policy evaluate --body "Illum ad assumenda consectetur minima voluptatibus." --group "example" --policy-name "example" --version "1.0" --evaluation-id "Ab accusamus voluptatem et est."
`, os.Args[0])
}

func policyLockUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] policy lock -group STRING -policy-name STRING -version STRING

Lock a policy so that it cannot be evaluated.
    -group STRING: Policy group.
    -policy-name STRING: Policy name.
    -version STRING: Policy version.

Example:
    %[1]s policy lock --group "Commodi vitae voluptatem." --policy-name "Similique quisquam optio." --version "Explicabo beatae quisquam officiis libero voluptatibus."
`, os.Args[0])
}

func policyUnlockUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] policy unlock -group STRING -policy-name STRING -version STRING

Unlock a policy so it can be evaluated again.
    -group STRING: Policy group.
    -policy-name STRING: Policy name.
    -version STRING: Policy version.

Example:
    %[1]s policy unlock --group "In illum est et hic." --policy-name "Deleniti non nihil dolor aut sed." --version "Incidunt unde consequatur voluptas dolorem nisi temporibus."
`, os.Args[0])
}
