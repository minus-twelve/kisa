package kisa

import "time"

type RedisConfig struct {
	Addr     string        `yaml:"addr"`
	Password string        `yaml:"password"`
	DB       int           `yaml:"db"`
	Prefix   string        `yaml:"prefix"`
	TTL      time.Duration `yaml:"ttl"`
}

type Config struct {
	StoreType string `yaml:"store_type"`
	Memory    struct {
		MaxSessions int `yaml:"max_sessions"`
	} `yaml:"memory"`
	Redis RedisConfig `yaml:"redis"`
}
