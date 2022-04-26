package regofunc

import (
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

type regoFuncFactory func(*rego.Rego)

var regoFuncFactories = make(map[string]regoFuncFactory)

func Initialize(name string, factory regoFuncFactory) {
	if factory == nil {
		panic(fmt.Errorf("datastore factory %s does not exist", name))
	}

	_, registered := regoFuncFactories[name]
	if !registered {
		regoFuncFactories[name] = factory
	}
}

func FuncList() []regoFuncFactory {

	list := make([]regoFuncFactory, 0)

	for _, value := range regoFuncFactories {
		list = append(list, value)
	}
	return list
}
