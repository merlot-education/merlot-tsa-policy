package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/open-policy-agent/opa/rego"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
	"golang.org/x/sync/errgroup"

	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/golib/graceful"
	goahealth "gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/gen/health"
	goahealthsrv "gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/gen/http/health/server"
	goaopenapisrv "gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/gen/http/openapi/server"
	goapolicysrv "gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/gen/http/policy/server"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/gen/openapi"
	goapolicy "gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/gen/policy"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/clients/cache"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/config"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/regocache"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/regofunc"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/service"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/service/health"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/service/policy"
	"gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/internal/storage"
)

var Version = "0.0.0+development"

func main() {
	// load configuration from environment
	var cfg config.Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("cannot load configuration: %v", err)
	}

	// create logger
	logger, err := createLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalln(err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("policy service started", zap.String("version", Version), zap.String("goa", goa.Version()))

	// connect to mongo db
	db, err := mongo.Connect(
		context.Background(),
		options.Client().ApplyURI(cfg.Mongo.Addr).SetAuth(options.Credential{
			Username: cfg.Mongo.User,
			Password: cfg.Mongo.Pass,
		}),
	)
	if err != nil {
		logger.Fatal("error connecting to mongodb", zap.Error(err))
	}
	defer db.Disconnect(context.Background()) //nolint:errcheck

	httpClient := httpClient()

	// create storage
	storage, err := storage.New(db, cfg.Mongo.DB, cfg.Mongo.Collection, logger)
	if err != nil {
		logger.Fatal("error connecting to database", zap.Error(err))
	}

	// create rego query cache
	regocache := regocache.New()

	// register rego extension functions
	{
		cacheFuncs := regofunc.NewCacheFuncs(cfg.Cache.Addr, httpClient)
		didResolverFuncs := regofunc.NewDIDResolverFuncs(cfg.DIDResolver.Addr, httpClient)
		taskFuncs := regofunc.NewTaskFuncs(cfg.Task.Addr, httpClient)
		ocmFuncs := regofunc.NewOcmFuncs(cfg.OCM.Addr, httpClient)
		signerFuncs := regofunc.NewSignerFuncs(cfg.Signer.Addr, httpClient)
		regofunc.Register("cacheGet", rego.Function3(cacheFuncs.CacheGetFunc()))
		regofunc.Register("cacheSet", rego.Function4(cacheFuncs.CacheSetFunc()))
		regofunc.Register("didResolve", rego.Function1(didResolverFuncs.ResolveFunc()))
		regofunc.Register("taskCreate", rego.Function2(taskFuncs.CreateTaskFunc()))
		regofunc.Register("taskListCreate", rego.Function2(taskFuncs.CreateTaskListFunc()))
		regofunc.Register("getKey", rego.Function1(signerFuncs.GetKeyFunc()))
		regofunc.Register("getAllKeys", rego.FunctionDyn(signerFuncs.GetAllKeysFunc()))
		regofunc.Register("issuer", rego.FunctionDyn(signerFuncs.IssuerDID()))
		regofunc.Register("createProof", rego.Function1(signerFuncs.CreateProof()))
		regofunc.Register("verifyProof", rego.Function1(signerFuncs.VerifyProof()))
		regofunc.Register("ocmLoginProofInvitation", rego.Function2(ocmFuncs.GetLoginProofInvitation()))
		regofunc.Register("ocmLoginProofResult", rego.Function1(ocmFuncs.GetLoginProofResult()))
	}

	// subscribe the cache for policy data changes
	storage.AddPolicyChangeSubscriber(regocache)

	// create cache client
	cache := cache.New(cfg.Cache.Addr, cache.WithHTTPClient(httpClient))

	// create services
	var (
		policySvc goapolicy.Service
		healthSvc goahealth.Service
	)
	{
		policySvc = policy.New(storage, regocache, cache, logger)
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

	// Apply middlewares on the servers
	policyServer.Evaluate = policy.HeadersMiddleware()(policyServer.Evaluate)

	// Configure the mux.
	goapolicysrv.Mount(mux, policyServer)
	goahealthsrv.Mount(mux, healthServer)
	goaopenapisrv.Mount(mux, openapiServer)

	// expose metrics
	go exposeMetrics(cfg.Metrics.Addr, logger)

	var handler http.Handler = mux
	srv := &http.Server{
		Addr:              cfg.HTTP.Host + ":" + cfg.HTTP.Port,
		Handler:           handler,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
	}

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		if err := graceful.Shutdown(ctx, srv, 20*time.Second); err != nil {
			logger.Error("server shutdown error", zap.Error(err))
			return err
		}
		return errors.New("server stopped successfully")
	})
	g.Go(func() error {
		if err := storage.ListenPolicyDataChanges(ctx); err != nil {
			logger.Error("mongo change streams listener stopped", zap.Error(err))
			return err
		}
		return nil
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

func httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     60 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

func exposeMetrics(addr string, logger *zap.Logger) {
	promMux := http.NewServeMux()
	promMux.Handle("/metrics", promhttp.Handler())
	logger.Info(fmt.Sprintf("exposing prometheus metrics at %s/metrics", addr))
	if err := http.ListenAndServe(addr, promMux); err != nil { //nolint:gosec
		logger.Error("error exposing prometheus metrics", zap.Error(err))
	}
}
