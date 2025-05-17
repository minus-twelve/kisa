package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/minus-twelve/kisa/types"
	"github.com/redis/go-redis/v9"
	"time"
)

type RedisStore struct {
	client *redis.Client
	prefix string
	ctx    context.Context
	ttl    time.Duration
}

func NewRedisStore(cfg types.RedisConfig) (*RedisStore, error) {
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

func (r *RedisStore) Save(token string, session types.SessionData) error {
	session.LastActivity = time.Now()

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	pipe := r.client.TxPipeline()
	pipe.SetEx(r.ctx, r.prefix+"session:"+token, data, r.ttl)
	pipe.SAdd(r.ctx, r.prefix+"user_sessions:"+session.UserID, token)
	pipe.Expire(r.ctx, r.prefix+"user_sessions:"+session.UserID, r.ttl)

	_, err = pipe.Exec(r.ctx)
	return err
}

func (r *RedisStore) Get(token string) (types.SessionData, error) {
	data, err := r.client.Get(r.ctx, r.prefix+"session:"+token).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return types.SessionData{}, errors.New("session not found")
		}
		return types.SessionData{}, err
	}

	var session types.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return types.SessionData{}, err
	}

	return session, nil
}

func (r *RedisStore) Delete(token string) error {
	session, err := r.Get(token)
	if err != nil {
		return err
	}

	pipe := r.client.TxPipeline()
	pipe.Del(r.ctx, r.prefix+"session:"+token)
	pipe.SRem(r.ctx, r.prefix+"user_sessions:"+session.UserID, token)
	_, err = pipe.Exec(r.ctx)
	return err
}

func (r *RedisStore) Cleanup(ttl time.Duration) error {
	return nil
}

func (r *RedisStore) GetAllByUserID(userID string) ([]string, error) {
	tokens, err := r.client.SMembers(r.ctx, r.prefix+"user_sessions:"+userID).Result()
	if err != nil {
		return nil, err
	}

	var validTokens []string
	for _, token := range tokens {
		exists, err := r.client.Exists(r.ctx, r.prefix+"session:"+token).Result()
		if err != nil {
			return nil, err
		}
		if exists == 1 {
			validTokens = append(validTokens, token)
		} else {
			r.client.SRem(r.ctx, r.prefix+"user_sessions:"+userID, token)
		}
	}

	return validTokens, nil
}

func (r *RedisStore) Client() *redis.Client {
    return r.client
}

func (r *RedisStore) SaveAll() error {
    return r.client.Save(r.ctx).Err()
}