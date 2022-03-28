package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
	"golang.org/x/sync/errgroup"

	"code.vereign.com/gaiax/tsa/golib/graceful"
	goahealth "code.vereign.com/gaiax/tsa/policy/gen/health"
	goahealthsrv "code.vereign.com/gaiax/tsa/policy/gen/http/health/server"
	goaopenapisrv "code.vereign.com/gaiax/tsa/policy/gen/http/openapi/server"
	goapolicysrv "code.vereign.com/gaiax/tsa/policy/gen/http/policy/server"
	"code.vereign.com/gaiax/tsa/policy/gen/openapi"
	goapolicy "code.vereign.com/gaiax/tsa/policy/gen/policy"
	"code.vereign.com/gaiax/tsa/policy/internal/config"
	"code.vereign.com/gaiax/tsa/policy/internal/service"
	"code.vereign.com/gaiax/tsa/policy/internal/service/health"
	"code.vereign.com/gaiax/tsa/policy/internal/service/policy"
)

var Version = "0.0.0+development"

func main() {
	var cfg config.Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("cannot load configuration: %v", err)
	}

	logger, err := createLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalln(err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("staring policy service", zap.String("version", Version), zap.String("goa", goa.Version()))

	// create services
	var (
		policySvc goapolicy.Service
		healthSvc goahealth.Service
	)
	{
		policySvc = policy.New()
		healthSvc = health.New()
	}

	// create endpoints
	var (
		policyEndpoints  *goapolicy.Endpoints
		healthEndpoints  *goahealth.Endpoints
		openapiEndpoints *openapi.Endpoints
	)
	{
		policyEndpoints = goapolicy.NewEndpoints(policySvc)
		healthEndpoints = goahealth.NewEndpoints(healthSvc)
		openapiEndpoints = openapi.NewEndpoints(nil)
	}

	// Provide the transport specific request decoder and response encoder.
	// The goa http package has built-in support for JSON, XML and gob.
	// Other encodings can be used by providing the corresponding functions,
	// see goa.design/implement/encoding.
	var (
		dec = goahttp.RequestDecoder
		enc = goahttp.ResponseEncoder
	)

	// Build the service HTTP request multiplexer and configure it to serve
	// HTTP requests to the service endpoints.
	mux := goahttp.NewMuxer()

	// Wrap the endpoints with the transport specific layers. The generated
	// server packages contains code generated from the design which maps
	// the service input and output data structures to HTTP requests and
	// responses.
	var (
		policyServer  *goapolicysrv.Server
		healthServer  *goahealthsrv.Server
		openapiServer *goaopenapisrv.Server
	)
	{
		policyServer = goapolicysrv.New(policyEndpoints, mux, dec, enc, nil, errFormatter)
		healthServer = goahealthsrv.New(healthEndpoints, mux, dec, enc, nil, errFormatter)
		openapiServer = goaopenapisrv.New(openapiEndpoints, mux, dec, enc, nil, errFormatter, nil, nil)
	}

	// Configure the mux.
	goapolicysrv.Mount(mux, policyServer)
	goahealthsrv.Mount(mux, healthServer)
	goaopenapisrv.Mount(mux, openapiServer)

	var handler http.Handler = mux
	srv := &http.Server{
		Addr:         cfg.HTTP.Host + ":" + cfg.HTTP.Port,
		Handler:      handler,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
	}

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		if err := graceful.Shutdown(ctx, srv, 20*time.Second); err != nil {
			logger.Error("server shutdown error", zap.Error(err))
			return err
		}
		return errors.New("server stopped successfully")
	})
	if err := g.Wait(); err != nil {
		logger.Error("run group stopped", zap.Error(err))
	}

	logger.Info("bye bye")
}

func createLogger(logLevel string, opts ...zap.Option) (*zap.Logger, error) {
	var level = zapcore.InfoLevel
	if logLevel != "" {
		err := level.UnmarshalText([]byte(logLevel))
		if err != nil {
			return nil, err
		}
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(level)
	config.DisableStacktrace = true
	config.EncoderConfig.TimeKey = "ts"
	config.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	return config.Build(opts...)
}

func errFormatter(e error) goahttp.Statuser {
	return service.NewErrorResponse(e)
}
