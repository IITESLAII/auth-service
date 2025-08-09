package repo

import (
	"context"
	"fmt"
	"log"
	"mssngr/authErrors"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

func CreateRedisDatabase() (*redis.Client, error) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return nil, fmt.Errorf("environment variable REDIS_URL is not set. Please define it before running the application")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opt)
	return client, nil
}

type RedisRepository interface {
	AddToMap(s string, value interface{}, exp time.Duration) error
	RemoveFromMap(s string) error
	IsExist(s string) (bool, error)
	GetValue(key string) (interface{}, error)
}

type RedisBlackListRepository struct {
	db  *redis.Client
	ctx context.Context
}

func NewRedis(r *redis.Client, ctx context.Context) *RedisBlackListRepository {
	return &RedisBlackListRepository{
		db:  r,
		ctx: ctx,
	}
}

func (r *RedisBlackListRepository) AddToMap(s string, value interface{}, exp time.Duration) error {
	err := r.db.Set(r.ctx, s, value, exp).Err()
	if err != nil {
		log.Printf("Error while adding value '%s' to blacklist: %v", s, err)
		return authErrors.ErrInternal
	}
	return nil
}
func (r *RedisBlackListRepository) RemoveFromMap(s string) error {
	err := r.db.Del(r.ctx, s).Err()
	if err != nil {
		log.Printf("Error while removing value '%s' from blacklist: %v", s, err)
		return authErrors.ErrInternal
	}
	return nil
}
func (r *RedisBlackListRepository) IsExist(s string) (bool, error) {
	exists, err := r.db.Exists(r.ctx, s).Result()
	if err != nil {
		log.Printf("Error while checking value in blacklist: %v", err)
		return false, authErrors.ErrInternal
	}
	return exists == 1, nil
}
func (r *RedisBlackListRepository) GetValue(key string) (interface{}, error) {
	res, err := r.db.Get(r.ctx, key).Result()
	if err != nil {
		return nil, authErrors.ErrInternal
	}
	return res, nil
}
