package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/minus-twelve/kisa"
	"github.com/redis/go-redis/v9"
	"time"
)

type RedisStore struct {
	client *redis.Client
	prefix string
	ctx    context.Context
	ttl    time.Duration
}

func NewRedisStore(cfg kisa.RedisConfig) (*RedisStore, error) {
	if cfg.Prefix == "" {
		cfg.Prefix = "sess:"
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisStore{
		client: client,
		prefix: cfg.Prefix,
		ctx:    ctx,
		ttl:    cfg.TTL,
	}, nil
}

func (r *RedisStore) Save(token string, session kisa.SessionData) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	return r.client.SetEx(r.ctx, r.prefix+token, data, r.ttl).Err()
}

func (r *RedisStore) Delete(token string) error {
	return r.client.Del(r.ctx, r.prefix+token).Err()
}

func (r *RedisStore) Cleanup(ttl time.Duration) error {
	return nil
}

func (r *RedisStore) GetAllByUserID(userID string) ([]string, error) {
	return nil, errors.New("not implemented")
}
