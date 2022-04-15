package regoext_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"code.vereign.com/gaiax/tsa/policy/regoext"
	"github.com/open-policy-agent/opa/rego"
)

func TestCacheExt_GetCacheFunc(t *testing.T) {
	expected := "{}"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, expected)
	}))
	defer srv.Close()

	cache := regoext.NewCacheExt(srv.URL)

	r := rego.New(
		rego.Query(`cache.get("open-policy-agent", "opa", "111")`),
		rego.Function3(cache.GetCacheFunc()),
	)

	rs, err := r.Eval(context.Background())

	if err != nil {
		t.Errorf("unexpected error, %v", err)
		return
	}

	bs, err := json.MarshalIndent(rs[0].Expressions[0].Value, "", "  ")
	if err != nil {
		t.Errorf("unexpected error, %v", err)
		return
	}
	if string(bs) != expected {
		t.Errorf("expected %s, got %s", expected, string(bs))
	}
}
