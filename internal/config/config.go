package config

import "time"

type Config struct {
	HTTP  httpConfig
	Redis redisConfig
	Mongo mongoConfig

	LogLevel string `envconfig:"LOG_LEVEL" default:"INFO"`
}

type httpConfig struct {
	Host         string        `envconfig:"HTTP_HOST"`
	Port         string        `envconfig:"HTTP_PORT" default:"8080"`
	IdleTimeout  time.Duration `envconfig:"HTTP_IDLE_TIMEOUT" default:"120s"`
	ReadTimeout  time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"10s"`
	WriteTimeout time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"10s"`
}

type redisConfig struct {
	Addr string        `envconfig:"REDIS_ADDR" required:"true"`
	User string        `envconfig:"REDIS_USER" required:"true"`
	Pass string        `envconfig:"REDIS_PASS" required:"true"`
	DB   int           `envconfig:"REDIS_DB" default:"1"`
	TTL  time.Duration `envconfig:"REDIS_EXPIRATION"` //  no default expiration, keys are set to live forever
}

type mongoConfig struct {
	Addr       string `envconfig:"MONGO_ADDR" required:"true"`
	User       string `envconfig:"MONGO_USER" required:"true"`
	Pass       string `envconfig:"MONGO_PASS" required:"true"`
	DB         string `envconfig:"MONGO_DBNAME" default:"policy"`
	Collection string `envconfig:"MONGO_COLLECTION" default:"policies"`
}
