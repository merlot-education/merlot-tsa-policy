package regofunc_test

import (
	"fmt"
	"testing"

	"code.vereign.com/gaiax/tsa/policy/internal/regofunc"
	"github.com/open-policy-agent/opa/rego"
)

func TestFactory_FuncList(t *testing.T) {
	regofuncCache := regofunc.NewCache(
		"localhost:8080",
	)
	regofunc.Initialize("cacheGet", rego.Function3(regofuncCache.CacheGetFunc()))
	regofunc.Initialize("cacheSet", rego.Function3(regofuncCache.CacheGetFunc()))
	go func() {
		l := regofunc.FuncList()
		fmt.Println(l)
	}()
	go func() {
		l := regofunc.FuncList()
		fmt.Println(l)
	}()
}
