package kisa

import (
	"errors"
	"github.com/minus-twelve/kisa/storage"
)

func CreateStore(cfg Config) (Store, error) {
	switch cfg.StoreType {
	case "memory":
		return storage.NewMemoryStore(cfg.Memory.MaxSessions), nil
	case "redis":
		return storage.NewRedisStore(cfg.Redis)
	default:
		return nil, errors.New("invalid store type")
	}
}
