// Code generated by goa v3.12.1, DO NOT EDIT.
//
// openapi HTTP server
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package server

import (
	"context"
	"net/http"

	openapi "gitlab.eclipse.org/eclipse/xfsc/tsa/policy/gen/openapi"
	goahttp "goa.design/goa/v3/http"
)

// Server lists the openapi service endpoint HTTP handlers.
type Server struct {
	Mounts              []*MountPoint
	GenHTTPOpenapi3JSON http.Handler
	Swagger             http.Handler
}

// MountPoint holds information about the mounted endpoints.
type MountPoint struct {
	// Method is the name of the service method served by the mounted HTTP handler.
	Method string
	// Verb is the HTTP method used to match requests to the mounted handler.
	Verb string
	// Pattern is the HTTP request path pattern used to match requests to the
	// mounted handler.
	Pattern string
}

// New instantiates HTTP handlers for all the openapi service endpoints using
// the provided encoder and decoder. The handlers are mounted on the given mux
// using the HTTP verb and path defined in the design. errhandler is called
// whenever a response fails to be encoded. formatter is used to format errors
// returned by the service methods prior to encoding. Both errhandler and
// formatter are optional and can be nil.
func New(
	e *openapi.Endpoints,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
	fileSystemGenHTTPOpenapi3JSON http.FileSystem,
	fileSystemSwagger http.FileSystem,
) *Server {
	if fileSystemGenHTTPOpenapi3JSON == nil {
		fileSystemGenHTTPOpenapi3JSON = http.Dir(".")
	}
	if fileSystemSwagger == nil {
		fileSystemSwagger = http.Dir(".")
	}
	return &Server{
		Mounts: []*MountPoint{
			{"./gen/http/openapi3.json", "GET", "/swagger-ui/openapi.json"},
			{"./swagger/", "GET", "/swagger-ui"},
		},
		GenHTTPOpenapi3JSON: http.FileServer(fileSystemGenHTTPOpenapi3JSON),
		Swagger:             http.FileServer(fileSystemSwagger),
	}
}

// Service returns the name of the service served.
func (s *Server) Service() string { return "openapi" }

// Use wraps the server handlers with the given middleware.
func (s *Server) Use(m func(http.Handler) http.Handler) {
}

// MethodNames returns the methods served.
func (s *Server) MethodNames() []string { return openapi.MethodNames[:] }

// Mount configures the mux to serve the openapi endpoints.
func Mount(mux goahttp.Muxer, h *Server) {
	MountGenHTTPOpenapi3JSON(mux, goahttp.Replace("", "/./gen/http/openapi3.json", h.GenHTTPOpenapi3JSON))
	MountSwagger(mux, goahttp.Replace("/swagger-ui", "/./swagger/", h.Swagger))
}

// Mount configures the mux to serve the openapi endpoints.
func (s *Server) Mount(mux goahttp.Muxer) {
	Mount(mux, s)
}

// MountGenHTTPOpenapi3JSON configures the mux to serve GET request made to
// "/swagger-ui/openapi.json".
func MountGenHTTPOpenapi3JSON(mux goahttp.Muxer, h http.Handler) {
	mux.Handle("GET", "/swagger-ui/openapi.json", h.ServeHTTP)
}

// MountSwagger configures the mux to serve GET request made to "/swagger-ui".
func MountSwagger(mux goahttp.Muxer, h http.Handler) {
	mux.Handle("GET", "/swagger-ui/", h.ServeHTTP)
	mux.Handle("GET", "/swagger-ui/*filepath", h.ServeHTTP)
}
