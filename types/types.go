package types

import "time"

type SessionData struct {
	UserID       string
	CreatedAt    time.Time
	LastActivity time.Time
	IP           string
	Data         map[string]interface{}
	CSRFToken    string
	Nonce        string
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
	Prefix   string
	TTL      time.Duration
}
