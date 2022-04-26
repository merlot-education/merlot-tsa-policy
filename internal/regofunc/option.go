package regofunc

import (
	"net/http"

	"go.uber.org/zap"
)

type Option func(*RegoFunc)

func WithHTTPClient(client *http.Client) Option {
	return func(r *RegoFunc) {
		r.httpClient = client
	}
}

func WithLogger(logger *zap.Logger) Option {
	return func(c *RegoFunc) {
		c.logger = logger
	}
}
