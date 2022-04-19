package regoext_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
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

func TestCacheExt_SetCacheFuncSuccess(t *testing.T) {
	expected := `{ "result": "success" }`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedRequestBody := "test"
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, "")

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		if bodyString != expectedRequestBody {
			t.Errorf("unexpected body string, expected %s, got %s", expectedRequestBody, bodyString)
		}
	}))
	defer srv.Close()

	cache := regoext.NewCacheExt(srv.URL)

	r := rego.New(
		rego.Query(`cache.set("open-policy-agent", "opa", "111", "test")`),
		rego.Function4(cache.SetCacheFunc()),
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

	re := regexp.MustCompile(`(\s+)|(\n)+`)
	s := re.ReplaceAllString(string(bs), " ")
	if s != expected {
		t.Errorf("unexpected result, expected %s, got %s", expected, s)
	}
}

func TestCacheExt_SetCacheFuncError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedRequestBody := "test"
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "")

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		if bodyString != expectedRequestBody {
			t.Errorf("unexpected body string, expected %s, got %s", expectedRequestBody, bodyString)
		}
	}))
	defer srv.Close()

	cache := regoext.NewCacheExt(srv.URL)

	r := rego.New(
		rego.Query(`cache.set("open-policy-agent", "opa", "111", "test")`),
		rego.Function4(cache.SetCacheFunc()),
	)

	rs, err := r.Eval(context.Background())

	if err != nil {
		t.Errorf("unexpected error, %v", err)
		return
	}

	if len(rs) != 0 {
		t.Errorf("result set should be empty, got %v", rs)
	}
}
