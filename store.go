package kisa

import (
	"github.com/minus-twelve/kisa/types"
	"time"
)

type Store interface {
	Save(token string, session types.SessionData) error
	Get(token string) (types.SessionData, error)
	Delete(token string) error
	Cleanup(ttl time.Duration) error
	GetAllByUserID(userID string) ([]string, error)
}
