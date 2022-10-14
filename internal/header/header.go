package header

import (
	"context"
	"net/http"
)

type key string

const headerKey key = "header"

// Middleware is an HTTP server middleware that gets all HTTP headers
// and adds them to a request context value.
func Middleware() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := ToContext(r.Context(), r)
			req := r.WithContext(ctx)

			h.ServeHTTP(w, req)
		})
	}
}

func ToContext(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, headerKey, r.Header)
}

func FromContext(ctx context.Context) (http.Header, bool) {
	header, ok := ctx.Value(headerKey).(http.Header)
	return header, ok
}
