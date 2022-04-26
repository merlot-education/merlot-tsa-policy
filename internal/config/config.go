package config

import "time"

type Config struct {
	HTTP  httpConfig
	Mongo mongoConfig
	Cache cacheConfig

	LogLevel string `envconfig:"LOG_LEVEL" default:"INFO"`
}

type httpConfig struct {
	Host         string        `envconfig:"HTTP_HOST"`
	Port         string        `envconfig:"HTTP_PORT" default:"8080"`
	IdleTimeout  time.Duration `envconfig:"HTTP_IDLE_TIMEOUT" default:"120s"`
	ReadTimeout  time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"10s"`
	WriteTimeout time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"10s"`
}

type cacheConfig struct {
	Addr string `envconfig:"CACHE_ADDR" required:"true"`
}

type mongoConfig struct {
	Addr       string `envconfig:"MONGO_ADDR" required:"true"`
	User       string `envconfig:"MONGO_USER" required:"true"`
	Pass       string `envconfig:"MONGO_PASS" required:"true"`
	DB         string `envconfig:"MONGO_DBNAME" default:"policy"`
	Collection string `envconfig:"MONGO_COLLECTION" default:"policies"`
}
