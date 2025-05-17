package kisa

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

type Store interface {
	Save(token string, session SessionData) error
	Get(token string) (SessionData, error)
	Delete(token string) error
	Cleanup(ttl time.Duration) error
	GetAllByUserID(userID string) ([]string, error)
}
