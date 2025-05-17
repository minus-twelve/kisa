package types

import "time"

type Config struct {
	StoreType string `yaml:"store_type"`
	Memory    struct {
		MaxSessions int `yaml:"max_sessions"`
	} `yaml:"memory"`
	Redis RedisConfig `yaml:"redis"`
}
