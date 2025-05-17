package kisa

import (
	"errors"
	"github.com/minus-twelve/kisa/storage"
	"github.com/minus-twelve/kisa/types"
)

func CreateStore(cfg types.Config) (Store, error) {
	switch cfg.StoreType {
	case "memory":
		return storage.NewMemoryStore(cfg.Memory.MaxSessions), nil
	case "redis":
		return storage.NewRedisStore(cfg.Redis)
	default:
		return nil, errors.New("invalid store type")
	}
}
