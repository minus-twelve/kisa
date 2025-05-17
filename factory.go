package kisa

import (
	"errors"
	"github.com/minus-twelve/kisa/storage"
	"github.com/minus-twelve/kisa/types"
)

func NewInMemoryStore(maxSessions int) Store {
	return storage.NewMemoryStore(maxSessions)
}

func CreateStore(cfg types.Config) (Store, error) {
	switch cfg.StoreType {
	case "memory":
		return NewInMemoryStore(cfg.Memory.MaxSessions), nil
	case "redis":
		return storage.NewRedisStore(cfg.Redis)
	default:
		return nil, errors.New("invalid store type")
	}
}
