package header_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/header"
)

func TestMiddleware(t *testing.T) {
	expected := map[string]string{"Authorization": "my-token", "Host": "example.com"}

	req := httptest.NewRequest("POST", "/example", nil)
	req.Header = http.Header{"Authorization": []string{"my-token"}}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, ok := header.FromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, expected, value)
	})

	middleware := header.Middleware()
	handlerToTest := middleware(nextHandler)
	handlerToTest.ServeHTTP(httptest.NewRecorder(), req)
}
